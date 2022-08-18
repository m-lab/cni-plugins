#!/usr/bin/env bash
#
# Run CNI plugin tests.
#
# This needs sudo, as we'll be creating net interfaces.
#
set -e

# Install any necessary test dependencies.
GOBIN=$(pwd)/bin go install github.com/m-lab/index2ip@latest

echo "Running tests"

function testrun {
    sudo -E bash -c "umask 0; PATH=${GOPATH}/bin:$(pwd)/bin:${PATH} go test $@"
}

PKG=${PKG:-$(go list ./... | xargs echo)}

for t in ${PKG}; do
    echo "${t}"
    testrun "${t}"
done

echo "Checking gofmt..."
fmtRes=$(go fmt $PKG)
if [ -n "${fmtRes}" ]; then
    echo -e "go fmt checking failed:\n${fmtRes}"
    exit 255
fi

echo "Checking govet..."
vetRes=$(go vet $PKG)
if [ -n "${vetRes}" ]; then
    echo -e "govet checking failed:\n${vetRes}"
    exit 255
fi
