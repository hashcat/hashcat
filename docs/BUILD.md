oclHashcat build documentation
=
# Revision:
* 1.0

# Authors:
* Gabriele Gristina <<matrix@hashcat.net>>
* Christoph Heuwieser <<dropdead@hashcat.net>>

# Dependencies

To compile **oclHashcat** the following third party libraries are required:

    ADL_SDK v8.0 - http://developer.amd.com/tools-and-sdks/graphics-development/display-library-adl-sdk/
    cuda v7.5 - https://developer.nvidia.com/cuda-downloads
    GDK v352_55 - https://developer.nvidia.com/gpu-deployment-kit
    NVIDIA Driver v352.21 - https://www.nvidia.com/download/driverResults.aspx/86390/en-us
    NVAPI R352 - https://developer.nvidia.com/nvapi
    AMD-APP-SDK v3.0 - http://developer.amd.com/tools-and-sdks/opencl-zone/amd-accelerated-parallel-processing-app-sdk/
    
To be able to compile the ocl binaries, it is required to have the latest stable driver from AMD installed.
(fglxr must be installed and initialized)

    http://support.amd.com/

The next thing to do is download all the third party libraries listed above and put files into */opt/hashcat-deps/tmp* directory.

The following files are needed inside the */opt/hashcat-deps/tmp* directory:
    
    ADL_SDK8.zip
    R352-developer.zip
    cuda_7.5.18_linux.run
    NVIDIA-Linux-x86_64-352.21.run
    gdk_linux_amd64_352_55_release.run
    AMDAPPSDK-3.0-linux64.tar.bz2

Now just execute the following script to complete the installation of dependencies (check for an updated version in **docs/deps.sh**):

    #!/bin/bash
    # Author: Gabriele Gristina <matrix@hashcat.net>
    # Revision: 1.0
    
    ## global vars
    DEPS="make gcc-4.9 g++-4.9 gcc-4.9-multilib g++-4.9-multilib libc6-dev-i386 mingw-w64 build-essential unzip"
    DOWNLOAD_DEPS="ADL_SDK8.zip R352-developer.zip cuda_7.5.18_linux.run NVIDIA-Linux-x86_64-352.21.run gdk_linux_amd64_352_55_release.run AMDAPPSDK-3.0-linux64.tar.bz2"
    
    ## root check
    if [ $(id -u) -ne 0 ]; then
    	echo "! Must be root"
    	exit 1
    fi
    
    ## cleanup 'hashcat-deps' directories
    rm -rf /opt/hashcat-deps/{adl-sdk,cuda-7.5,NVIDIA-Linux-x86_64-352.21,nvidia-gdk,amd-app-sdk} && \
    mkdir -p /opt/hashcat-deps/{tmp,adl-sdk,cuda-7.5,NVIDIA-Linux-x86_64-352.21,nvidia-gdk,amd-app-sdk} && \
    cd /opt/hashcat-deps/tmp
    
    if [ $? -ne 0 ]; then
    	echo "! Cannot create hashcat-deps directories."
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
    	echo "! Please download manually into the directory /opt/hashcat-deps/tmp"
    	exit 1
    fi
    
    ## installing needed packages
    for pkg in ${DEPS}; do
    	apt-get -y install ${pkg}
    	if [ $? -ne 0 ]; then
    		echo "! failed to install ${pkg}"
    		exit 1
    	fi
    done
    
    ## extract ADL SDK
    unzip ADL_SDK8.zip -d /opt/hashcat-deps/adl-sdk-8
    ret=$?
    
    if [[ ${ret} -ne 0 ]] && [[ ${ret} -ne 1 ]]; then
    	echo "! failed to extract ADL SDK"
    	exit 1
    fi
    
    rm -rf /opt/hashcat-deps/adl-sdk && ln -s /opt/hashcat-deps/adl-sdk-8 /opt/hashcat-deps/adl-sdk

    if [ $? -ne 0 ]; then
    	echo "! failed to setup ADL SDK link"
    	exit 1
    fi
    
    ## extract NVAPI
    unzip R352-developer.zip -d /opt/hashcat-deps/
    ret=$?
    
    if [[ ${ret} -ne 0 ]] && [[ ${ret} -ne 1 ]]; then
    	echo "! failed to extract NVAPI"
    	exit 1
    fi
    
    ## install CUDA SDK
    chmod +x cuda_7.5.18_linux.run && \
    ./cuda_7.5.18_linux.run -toolkit -silent -override --toolkitpath=/opt/hashcat-deps/cuda-7.5
    
    if [ $? -ne 0 ]; then
    	echo "! failed to install CUDA SDK"
    	exit 1
    fi
    
    ## install NVIDIA Driver
    chmod +x NVIDIA-Linux-x86_64-352.21.run && \
    ./NVIDIA-Linux-x86_64-352.21.run -x && \
    mv NVIDIA-Linux-x86_64-352.21 /opt/hashcat-deps/ && \
    cd /opt/hashcat-deps/NVIDIA-Linux-x86_64-352.21 && \
    ln -s libnvidia-ml.so.352.21 libnvidia-ml.so && \
    ln -s libcuda.so.352.21 libcuda.so && \
    cd 32 && \
    ln -s libnvidia-ml.so.352.21 libnvidia-ml.so && \
    ln -s libcuda.so.352.21 libcuda.so && \
    cd /opt/hashcat-deps/tmp
    
    if [ $? -ne 0 ]; then
    	echo "! failed to install NVIDIA Driver"
    	exit 1
    fi
    
    ## install NVIDIA GPU Deployment Kit
    chmod +x gdk_linux_amd64_352_55_release.run && \
    ./gdk_linux_amd64_352_55_release.run --silent --installdir=/opt/hashcat-deps/nvidia-gdk
    
    if [ $? -ne 0 ]; then
    	echo "! failed to install NVIDIA GPU Deployment Kit"
    	exit 1
    fi
    
    ## extract AMD APP SDK
    tar xjf AMDAPPSDK-3.0-linux64.tar.bz2 && \
    ./AMD-APP-SDK-v3.0.130.135-GA-linux64.sh --noexec --target /opt/hashcat-deps/amd-app-sdk-v3.0.130.135
    
    if [ $? -ne 0 ]; then
    	echo "! failed to extract AMD APP SDK"
    	exit 1
    fi
    
    rm -rf /opt/hashcat-deps/amd-app-sdk && ln -s /opt/hashcat-deps/amd-app-sdk-v3.0.130.135 /opt/hashcat-deps/amd-app-sdk

    if [ $? -ne 0 ]; then
    	echo "! failed to setup ADL SDK link"
    	exit 1
    fi
    
    echo "> oclHashcat dependencies have been resolved."
    
# Building oclHashcat
First get a copy of **oclHashcat** repository

```sh
$ git clone https://github.com/hashcat/oclHashcat.git
```

Now simply jump in and type "make all"

```sh
$ cd oclHashcat
$ make all
```

Useful tricks:
- build only *Linux* binaries
```sh
$ make linux
```
- build only *Windows* binaries
```sh
$ make windows
```
- build only *AMD kernel* binaries
```sh
$ make amd_all
```
- build only *NVIDIA kernel* binaries
```sh
$ make nv_all
```

=
Enjoy your fresh **oclHashcat** binaries ;)
