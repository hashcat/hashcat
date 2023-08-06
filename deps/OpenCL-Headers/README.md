# OpenCL<sup>TM</sup> API Headers

This repository contains C language headers for the OpenCL API.

The authoritative public repository for these headers is located at:

https://github.com/KhronosGroup/OpenCL-Headers

Issues, proposed fixes for issues, and other suggested changes should be
created using Github.

## Build instructions

> While the OpenCL Headers can be built and installed in isolation, it is part of the [OpenCL SDK](https://github.com/KhronosGroup/OpenCL-SDK). If looking for streamlined build experience and a complete development package, refer to the SDK build instructions instead of the following guide.

### Dependencies

- The OpenCL Headers CMake package support uses CMake for its build system.
If CMake is not provided by your build system or OS package manager, please consult the [CMake website](https://cmake.org).

### Example Build
While the headers may just be copied as-is, this repository also contains a
CMake script with an install rule to allow for packaging the headers.

```bash
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/chosen/install/prefix
cmake --build build --target install
```
 
### Example Use

Example CMake invocation

```bash
cmake -D CMAKE_PREFIX_PATH=/chosen/install/prefix /path/to/opencl/app 
```

and sample `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0...3.18.4)
project(proj)
add_executable(app main.cpp)
find_package(OpenCLHeaders REQUIRED)
target_link_libraries(app PRIVATE OpenCL::Headers)
```

## Branch Structure

The OpenCL API headers in this repository are Unified headers and are designed
to work with all released OpenCL versions. This differs from previous OpenCL
API headers, where version-specific API headers either existed in separate
branches, or in separate folders in a branch.

## Compiling for a Specific OpenCL Version

By default, the OpenCL API headers in this repository are for the latest
OpenCL version (currently OpenCL 3.0).  To use these API headers to target
a different OpenCL version, an application may `#define` the preprocessor
value `CL_TARGET_OPENCL_VERSION` before including the OpenCL API headers.
The `CL_TARGET_OPENCL_VERSION` is a three digit decimal value representing
the OpenCL API version.

For example, to enforce usage of no more than the OpenCL 1.2 APIs, you may
include the OpenCL API headers as follows:

```c
#define CL_TARGET_OPENCL_VERSION 120
#include <CL/opencl.h>
```

## Controlling Function Prototypes

By default, the OpenCL API headers in this repository declare function
prototypes for every known core OpenCL API and OpenCL extension API.  If this is
not desired, the declared function prototypes can be controlled by the following
preprocessor defines:

* `CL_NO_PROTOTYPES`: No function prototypes will be declared.  This control
  applies to core OpenCL APIs and OpenCL extension APIs.
* `CL_NO_CORE_PROTOTYPES`: No function prototypes will be declared for core
  OpenCL APIs.  
* `CL_NO_EXTENSION_PROTOTYPES`: No function prototypes will be declared for
  OpenCL extension APIs.  This control applies to all OpenCL extension APIs.
* `CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES`: No function prototypes will be
  declared for OpenCL extension APIs that are in the ICD dispatch table for
  historical reasons.
* `CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES`: No function prototypes will be
  declared for OpenCL extension APIs that are not in the ICD dispatch table.

For example, to declare function prototypes for core OpenCL 3.0 APIs only, you
may include the OpenCL API headers as follows:

```c
#define CL_TARGET_OPENCL_VERSION 300
#define CL_NO_EXTENSION_PROTOTYPES
#include <CL/opencl.h>
```

## Directory Structure

```
README.md               This file
LICENSE                 Source license for the OpenCL API headers
CL/                     Unified OpenCL API headers tree
```

## License

See [LICENSE](LICENSE).

---

OpenCL and the OpenCL logo are trademarks of Apple Inc. used by permission by Khronos.
