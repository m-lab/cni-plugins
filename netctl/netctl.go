// Copyright 2021 M-Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This small CNI plugin is more or less a stripped down version of this plugin:
//
// https://github.com/containernetworking/plugins/tree/master/plugins/meta/tuning
//
// ... also borrowing some of the IPAM code from the ipvlan plugin:
//
// https://github.com/containernetworking/plugins/tree/master/plugins/main/ipvlan
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// NetctlConf represents the net sysctls that should be set.
type NetctlConf struct {
	types.NetConf
	SysCtl map[string]string `json:"sysctl"`
}

// parseConf takes the JSON configuration data passed to stdin and unmarshalls
// it into a NetctlConf{}.
func parseConf(data []byte, envArgs string) (*NetctlConf, error) {
	conf := NetctlConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}
	return &conf, nil
}

// cmdAdd modifies net sysctls according to the passed in configuration.
// NOTE: this function ignores the prevResult field and unconditionally uses the
// output of the configured IPAM plugin.
func cmdAdd(args *skel.CmdArgs) error {
	netctlConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// The directory /proc/sys/net is per network namespace. Enter in the
	// network namespace before writing on it.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		for key, value := range netctlConf.SysCtl {
			fileName := filepath.Join("/proc/sys", strings.Replace(key, ".", "/", -1))
			fileName = filepath.Clean(fileName)

			// Refuse to modify sysctl parameters that don't belong
			// to the network subsystem.
			if !strings.HasPrefix(fileName, "/proc/sys/net/") {
				return fmt.Errorf("invalid net sysctl key: %q", key)
			}
			content := []byte(value)
			err := ioutil.WriteFile(fileName, content, 0644)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// IPAM _must_ be configured with this plugin.
	if netctlConf.IPAM.Type == "" {
		return fmt.Errorf("missing required IPAM configuration")
	}

	// Run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(netctlConf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(netctlConf.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	return types.PrintResult(result, netctlConf.CNIVersion)
}

// cmdDel inovokes the configured IPAM plugin to remove any IP config.
func cmdDel(args *skel.CmdArgs) error {
	netctlConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// On chained invocation, IPAM block can be empty
	if netctlConf.IPAM.Type != "" {
		err = ipam.ExecDel(netctlConf.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	netctlConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		// Check each configured value vs what's currently in the container
		for key, confValue := range netctlConf.SysCtl {
			fileName := filepath.Join("/proc/sys", strings.Replace(key, ".", "/", -1))
			fileName = filepath.Clean(fileName)

			contents, err := ioutil.ReadFile(fileName)
			if err != nil {
				return err
			}
			curValue := strings.TrimSuffix(string(contents), "\n")
			if confValue != curValue {
				return fmt.Errorf("tuning configured value of %s is %s, current value is %s", fileName, confValue, curValue)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("netctl"))
}
