#!/usr/bin/env bash

. .ci/common.sh

check_platform

sudo apt-get update -q -y
sudo apt-get install -q -y qemu-user

# Clang/LLVM is natively a cross-compiler, meaning that one set of programs
# can compile to all targets by setting the -target option.
if [ $(printenv CXX | grep clang) ]; then
    exit
fi

set -x

sudo apt-get install -y curl xz-utils

curl -L \
    ${ARM_MIRROR}/arm-gnu-toolchain-${GCC_REL}-x86_64-arm-none-linux-gnueabihf.tar.xz \
    | tar -Jx || exit 1

curl -L \
    ${ARM_MIRROR}/arm-gnu-toolchain-${GCC_REL}-x86_64-aarch64-none-linux-gnu.tar.xz \
    | tar -Jx || exit 1
