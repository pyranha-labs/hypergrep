#!/usr/bin/env bash
# This script is used to compile C code into shared libraries usable by Python.
# Recommended way to run is through docker on lowest supported Ubuntu version to maximize dependency compatibility.
# The compiled binaries should be forwards compatible, allowing them to be saved without need to compile per version.
# Example:
# docker run --rm -it -v ~/Development/pyhypergrep:/mnt/pyhypergrep ubuntu:trusty bash -c '/mnt/pyhypergrep/pyhypergrep/common/shared/c/build.sh'

# Ensure the whole script exits on failures.
set -e
# Turn on command echoing to show all commands as they run.
set -x

# Set the versions to build so they are consistent throughout the script when updates are performed.
ZSTD_BUILD_VERSION=1.5.0
HYPERSCAN_BUILD_VERSION=5.4.0

# Update the base dependencies.
apt-get update && apt-get install -y build-essential cmake gcc pkg-config python liblzma-dev liblz4-dev ragel software-properties-common zlib1g-dev

# Install git from latest PPA, default on U14.04 (Trusty) is too old for multi-threaded submodule clones.
add-apt-repository -y ppa:git-core/ppa
apt-get update && apt-get install -y git

# Track the original root location of the script to reference in later commands.
script_dir="$(cd "$(dirname "$0")" && git rev-parse --show-toplevel)"

# Create a new temporary location to allow for isolated compiling.
build_dir=$(mktemp -d -t hsbuild-XXXXXXXX)
cd "${build_dir}"
git clone --depth 1 --branch "v${ZSTD_BUILD_VERSION}" https://github.com/facebook/zstd.git
# Boost and Hyperscan5 must be pulled from source to support as low as U14.04 (Trusty). Do not use OS packages.
git clone --depth 1 --branch "v${HYPERSCAN_BUILD_VERSION}" https://github.com/intel/hyperscan
# Use 32 jobs to speed up Boost clone, it has 100+ submodules.
git clone --depth 1 --branch boost-1.75.0 --recursive --jobs 32 https://github.com/boostorg/boost

# Setup only Boost headers for Hyperscan, full compilation is not required.
cd "${build_dir}"/boost
./bootstrap.sh
./b2 headers

# Compile Hyperscan shared library and install, so that hyperscanner can reference in build.
cd "${build_dir}"/hyperscan
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=on -DBOOST_ROOT="${build_dir}"/boost/
# Build is very memory intensive, use 2 job max to reduce chance of being killed.
make -j 2
make install

# Compile ZSTD shared library and install, so that hyperscanner can reference in build.
cd "${build_dir}"/zstd
make -j 4
make install

# Compile custom hyperscanner and ZSTD wrapper to position independent code, and then into a shared library.
# All warnings are failures to enforce clean code.
cd "${script_dir}"/pyhypergrep/common/shared/c
# Must use "-std=c99" to be compatible down to U14.04 (Trusty).
# Do not quote (SC2046) pkg-config output to ensure arguments expand correctly. Word splitting is required.
# shellcheck disable=SC2046
gcc -I "${build_dir}"/zstd/lib -I "${build_dir}"/zstd/zlibWrapper/ -std=c99 -c -Wall -Werror -fpic hyperscanner.c "${build_dir}"/zstd/zlibWrapper/gz*.c "${build_dir}"/zstd/zlibWrapper/zstd_zlibwrapper.c $(pkg-config --cflags --libs libhs libzstd zlib)
# shellcheck disable=SC2046
gcc -shared -o "${script_dir}"/pyhypergrep/common/shared/libhyperscanner.so hyperscanner.o gz*.o zstd*.o $(pkg-config --cflags --libs libhs libzstd zlib)

# Copy the external shared libraries that were built back to the source for bundling with the hyperscanner as fallbacks.
cp -v "${build_dir}/hyperscan/lib/libhs.so.${HYPERSCAN_BUILD_VERSION}" "${script_dir}/pyhypergrep/common/shared/libhs.so.${HYPERSCAN_BUILD_VERSION}"
cp -v "${build_dir}/zstd/lib/libzstd.so.${ZSTD_BUILD_VERSION}" "${script_dir}/pyhypergrep/common/shared/libzstd.so.${ZSTD_BUILD_VERSION}"
