#!/usr/bin/env bash
# This script is used to compile C code into shared libraries usable by Python.
# Recommended way to run is through docker. For hyperscan5, this must be run against disco. For hyperscan4, use bionic.
# sudo docker run --rm -it -v ~/Development/pyhypergrep:/mnt/pyhypergrep ubuntu:disco bash -c '/mnt/pyhypergrep/pyhypergrep/common/shared/c/build.sh'

# Update the base dependencies.
apt-get update && apt-get install -y gcc git libhyperscan5 libhyperscan-dev zlib1g-dev pkg-config

# Find this script's root as this has all the source files.
REPO=$(cd $(dirname $0) && git rev-parse --show-toplevel)
echo $REPO

# Move into the source to allow for compiling.
cd $REPO/pyhypergrep/common/shared/c

# Compile to position independent code, and then into a shared library. All warnings are failures to enforce clean code.
gcc -c -Wall -Werror -fpic hyperscanner.c $(pkg-config --cflags --libs libhs zlib)
gcc -shared -o $REPO/pyhypergrep/common/shared/libhyperscanner.so hyperscanner.o $(pkg-config --cflags --libs libhs zlib)

# Also, copy the Hyperscan shared library that this was built with back to the Python source for bundling.
cp -v /usr/lib/x86_64-linux-gnu/libhs.so.5 $REPO/pyhypergrep/common/shared/
