#!/bin/bash
# Author: Gabriele Gristina <matrix@hashcat.net>
# Revision: 1.03

## global vars
DEPS="make gcc g++ gcc-multilib g++-multilib libc6-dev-i386 mingw-w64 build-essential unzip opencl-headers ocl-icd-libopencl1"
DEPS_AMD_DEV="ocl-icd-opencl-dev"
DOWNLOAD_DEPS="ADL_SDK8.zip R352-developer.zip gdk_linux_amd64_352_55_release.run"

## enter the deps directory
cur_directory=$(dirname ${0})
script_directory=$(cd ${cur_directory} && pwd -P)
deps_dir=${script_directory}/../deps

mkdir -p ${deps_dir} # but it should already exist (is part of the repository)
cd ${deps_dir}

## cleanup the directories under the 'deps' folder
rm -rf {adl-sdk*,nvidia-gdk,R352-developer} && \
mkdir -p {tmp,adl-sdk,nvidia-gdk,R352-developer} && \
cd tmp/

if [ $? -ne 0 ]; then
  echo "! Cannot create deps directories."
  exit 1
fi

## check dependencies
i=0
for d in ${DOWNLOAD_DEPS}; do
  if [ ! -f "${d}" ]; then
    echo "! ${d} not found."
    ((i++))
  fi
done

if [ ${i} -gt 0 ]; then
  echo "! Please manually download all the above dependencies to the deps/tmp/ directory"
  exit 1
fi

## installing needed packages
for pkg in ${DEPS}; do

  # check if the package is already installed
  dpkg -s ${pkg} &>/dev/null
  if [ $? -ne 0 ]; then
    ## root check
    if [ $(id -u) -ne 0 ]; then
      echo "! Must be root to install the required package '${pkg}' with apt-get"
      exit 1
    fi

    apt-get -y install ${pkg}
    if [ $? -ne 0 ]; then
      echo "! failed to install ${pkg}"
      exit 1
    fi
  fi
done

## extract ADL SDK
unzip ADL_SDK8.zip -d ${deps_dir}/adl-sdk-8
ret=$?

if [[ ${ret} -ne 0 ]] && [[ ${ret} -ne 1 ]]; then
  echo "! failed to extract ADL SDK"
  exit 1
fi

rm -rf ${deps_dir}/adl-sdk && ln -s ${deps_dir}/adl-sdk-8 ${deps_dir}/adl-sdk

if [ $? -ne 0 ]; then
  echo "! failed to setup ADL SDK link"
  exit 1
fi

## extract NVAPI
unzip R352-developer.zip -d ${deps_dir}
ret=$?

if [[ ${ret} -ne 0 ]] && [[ ${ret} -ne 1 ]]; then
  echo "! failed to extract NVAPI"
  exit 1
fi

## install NVIDIA GPU Deployment Kit
chmod +x gdk_linux_amd64_352_55_release.run && \
./gdk_linux_amd64_352_55_release.run --silent --installdir=${deps_dir}/nvidia-gdk

if [ $? -ne 0 ]; then
  echo "! failed to install NVIDIA GPU Deployment Kit"
  exit 1
fi

## check if libOpenCL.so is available (and if not install DEPS_AMD_DEV)

ls /usr/lib/*/libOpenCL.so &> /dev/null

if [ $? -ne 0 ]; then
  ## root check
  if [ $(id -u) -ne 0 ]; then
    echo "! Must be root to install '${DEPS_AMD_DEV}'"
    exit 1
  fi

  apt-get -y install ${DEPS_AMD_DEV}
  if [ $? -ne 0 ]; then
    echo "! failed to install ${DEPS_AMD_DEV}"
    exit 1
  fi
fi

echo "> oclHashcat dependencies have been resolved."
