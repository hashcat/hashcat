GCC_REL=14.2.rel1
ARM_MIRROR=https://github.com/DLTcollab/toolchain-arm/raw/main

SOURCES=$(find $(git rev-parse --show-toplevel) | egrep "\.(cpp|h)\$" | egrep -v "arm-gnu-toolchain-${GCC_REL}-x86_64-aarch64-none-linux-gnu|arm-gnu-toolchain-${GCC_REL}-x86_64-arm-none-linux-gnueabihf")

# Expect host is Linux/x86_64
check_platform()
{
    MACHINE_TYPE=`uname -m`
    if [ ${MACHINE_TYPE} != 'x86_64' ]; then
        exit
    fi

    OS_TYPE=`uname -s`
    if [ ${OS_TYPE} != 'Linux' ]; then
        exit
    fi
}
