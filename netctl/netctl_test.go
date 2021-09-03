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

package main

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

const CMDLINE = "epoxy.ip=10.10.10.99::10.10.10.65:255.255.255.192:mlab3-abc0t.mlab-sandbox.measurement-lab.org:eth0:off:8.8.8.8:8.8.4.4 epoxy.ipv4=10.10.10.99/26,10.10.10.65,8.8.8.8,8.8.4.4 epoxy.ipv6=2001:2001:2001:2001::99/64,2001:2001:2001:2001::1,2001:4860:4860::8888,2001:4860:4860::8844 epoxy.interface=eth0 epoxy.hostname=mlab3-abc0t.mlab-sandbox.measurement-lab.org epoxy.stage3=https://epoxy-boot-api.mlab-sandbox.measurementlab.net/v1/boot/mlab3-abc0t.mlab-sandbox.measurement-lab.org/ZZZZZ_Uj_iNsZZaOdW_3ZZfDs/stage3 epoxy.report=https://epoxy-boot-api.mlab-sandbox.measurementlab.net/v1/boot/mlab3-abc0t.mlab-sandbox.measurement-lab.org/W2zzzzzzzzzzdRYCvwNUKiAqtDM/report epoxy.allocate_k8s_token=https://epoxy-boot-api.mlab-sandbox.measurementlab.net/v1/boot/mlab3-abc0t.mlab-sandbox.measurement-lab.org/W_jsRjKWQjLxpzCqqqqqqqqqqAU/extension/allocate_k8s_token epoxy.server=epoxy-boot-api.mlab-sandbox.measurementlab.net:4430 epoxy.project=mlab-sandbox epoxy.images_version=latest net.ifnames=0 autoconf=0"

// Known, original sysctl values to set in the target net namespaces.
var originalSysctls = map[string]string{
	"net.ipv6.conf.default.accept_ra": "1",
	"net.ipv6.conf.default.autoconf":  "1",
}

// Sysctl values that we expect the plugin to produce.
var expectedSysctls = map[string]string{
	"net.ipv6.conf.default.accept_ra": "0",
	"net.ipv6.conf.default.autoconf":  "0",
}

// Standard, correct CNI conf.
var cniConf = []byte(`{
	"cniVersion": "0.2.0",
	"name": "test-index-2",
	"type": "netctl",
	"ipam": {
		"index": 2,
		"type": "index2ip"
	},
	"sysctl": {
		"net.ipv6.conf.default.accept_ra": "0",
		"net.ipv6.conf.default.autoconf": "0"
	}
}`)

func TestAdd(t *testing.T) {
	targetNS, err := testutils.NewNS()
	rtx.Must(err, "failed to create target test network namespace")

	defer targetNS.Close()
	defer testutils.UnmountNS(targetNS)

	// Tells index2ip IPAM plugin to use this env variable as the content of
	// /proc/cmdline instead of the actual file.
	osx.MustSetenv("PROC_CMDLINE_FOR_TESTING", CMDLINE)

	err = writeSysctls(targetNS, originalSysctls)
	rtx.Must(err, "failed to set sysctls in target namespace")

	args := &skel.CmdArgs{
		ContainerID: "test",
		Netns:       targetNS.Path(),
		IfName:      "test0",
		StdinData:   cniConf,
	}

	// Test successful add case.
	_, _, err = testutils.CmdAddWithArgs(args, func() error {
		return cmdAdd(args)
	})
	rtx.Must(err, "cmdAdd() produced an error")

	// Verify that the netctl plugin set the sysctls to what we think they should be.
	err = targetNS.Do(func(ns.NetNS) error {
		for key := range originalSysctls {
			fileName := filepath.Join("/proc/sys", strings.Replace(key, ".", "/", -1))
			fileName = filepath.Clean(fileName)
			content, err := ioutil.ReadFile(fileName)
			if err != nil {
				return err
			}
			value := strings.TrimSpace(string(content))
			if value != expectedSysctls[key] {
				t.Fatalf("expected sysctl %s value of %s, but got %s.", key, expectedSysctls[key], value)
			}
		}
		return nil
	})
	rtx.Must(err, "failed to read sysctls in target namespace")
}

func TestAddFailsWithNoIPAM(t *testing.T) {
	targetNS, err := testutils.NewNS()
	rtx.Must(err, "failed to create target test network namespace")

	defer targetNS.Close()
	defer testutils.UnmountNS(targetNS)

	conf := []byte(`{
		"cniVersion": "0.2.0",
		"name": "test-index-2",
		"type": "netctl"
	}`)

	args := &skel.CmdArgs{
		ContainerID: "test",
		Netns:       targetNS.Path(),
		IfName:      "test0",
		StdinData:   conf,
	}

	_, _, err = testutils.CmdAddWithArgs(args, func() error {
		return cmdAdd(args)
	})
	if err == nil {
		t.Fatal("TestAddFailsWithNoIPAM(): expected an error but did not get one")
	}
}

func TestAddFailsWithBadSysctl(t *testing.T) {
	targetNS, err := testutils.NewNS()
	rtx.Must(err, "failed to create target test network namespace")

	defer targetNS.Close()
	defer testutils.UnmountNS(targetNS)

	conf := []byte(`{
		"cniVersion": "0.2.0",
		"name": "test-index-2",
		"type": "netctl",
		"sysctl": {
			"kernel.shmmax": "0"
		}
	}`)

	args := &skel.CmdArgs{
		ContainerID: "test",
		Netns:       targetNS.Path(),
		IfName:      "test0",
		StdinData:   conf,
	}

	_, _, err = testutils.CmdAddWithArgs(args, func() error {
		return cmdAdd(args)
	})
	if err == nil {
		t.Fatal("TestAddFailsWithBadSysctl(): expected an error but did not get one")
	}
}

func TestCheck(t *testing.T) {
	targetNS, err := testutils.NewNS()
	rtx.Must(err, "failed to create target test network namespace")

	defer targetNS.Close()
	defer testutils.UnmountNS(targetNS)

	err = writeSysctls(targetNS, originalSysctls)
	rtx.Must(err, "failed to set sysctls in target namespace")

	args := &skel.CmdArgs{
		ContainerID: "test",
		Netns:       targetNS.Path(),
		IfName:      "test0",
		StdinData:   cniConf,
	}

	// Run cmdAdd() to set state in the target NS.
	_, _, err = testutils.CmdAddWithArgs(args, func() error {
		return cmdAdd(args)
	})
	rtx.Must(err, "cmdAdd() produced an error")

	// Test successfull check case.
	err = testutils.CmdCheckWithArgs(args, func() error {
		return cmdCheck(args)
	})
	rtx.Must(err, "cmdCheck() produced an error")

	// Modify one of the sysctls to an unexpected value.
	s := map[string]string{
		"net.ipv6.conf.default.accept_ra": "1",
	}
	err = writeSysctls(targetNS, s)
	rtx.Must(err, "failed to set sysctls in target namespace")

	// Test unsuccessfull check case.
	err = testutils.CmdCheckWithArgs(args, func() error {
		return cmdCheck(args)
	})
	if err == nil {
		t.Fatal("expected cmdCheck() to produce an error, but got none")
	}
}

// writeSysctls modifies the values of the passed net sysctls in the passed
// network namespace.
func writeSysctls(netns ns.NetNS, sysctls map[string]string) error {
	err := netns.Do(func(ns.NetNS) error {
		for key, value := range sysctls {
			fileName := filepath.Join("/proc/sys", strings.Replace(key, ".", "/", -1))
			fileName = filepath.Clean(fileName)
			content := []byte(value)
			err := ioutil.WriteFile(fileName, content, 0644)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
