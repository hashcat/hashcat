/*******************************************************************************
 * Copyright (c) 2008-2023 The Khronos Group Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

#ifndef OPENCL_CL_LAYER_H_
#define OPENCL_CL_LAYER_H_

/*
** This header is generated from the Khronos OpenCL XML API Registry.
*/

#include <CL/cl_icd.h>

#include <CL/cl.h>

/* CL_NO_PROTOTYPES implies CL_NO_EXTENSION_PROTOTYPES: */
#if defined(CL_NO_PROTOTYPES) && !defined(CL_NO_EXTENSION_PROTOTYPES)
#define CL_NO_EXTENSION_PROTOTYPES
#endif

/* CL_NO_EXTENSION_PROTOTYPES implies
   CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES and
   CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES: */
#if defined(CL_NO_EXTENSION_PROTOTYPES) && \
    !defined(CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES)
#define CL_NO_ICD_DISPATCH_EXTENSION_PROTOTYPES
#endif
#if defined(CL_NO_EXTENSION_PROTOTYPES) && \
    !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)
#define CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES
#endif

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************
* cl_loader_layers
***************************************************************/
#define cl_loader_layers 1
#define CL_LOADER_LAYERS_EXTENSION_NAME \
    "cl_loader_layers"


#define CL_LOADER_LAYERS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)

typedef cl_uint             cl_layer_info;
typedef cl_uint             cl_layer_api_version;

/* cl_layer_info */
#define CL_LAYER_API_VERSION                                0x4240
#define CL_LAYER_NAME                                       0x4241

/* Misc API enums */
#define CL_LAYER_API_VERSION_100                            100


typedef cl_int CL_API_CALL
clGetLayerInfo_t(
    cl_layer_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret);

typedef clGetLayerInfo_t *
clGetLayerInfo_fn ;

typedef cl_int CL_API_CALL
clInitLayer_t(
    cl_uint num_entries,
    const cl_icd_dispatch* target_dispatch,
    cl_uint* num_entries_ret,
    const cl_icd_dispatch** layer_dispatch_ret);

typedef clInitLayer_t *
clInitLayer_fn ;

/*
** The function pointer typedefs prefixed with "pfn_" are provided for
** compatibility with earlier versions of the headers.  New code is
** encouraged to use the function pointer typedefs that are suffixed with
** "_fn" instead, for consistency.
*/

typedef clGetLayerInfo_t *
pfn_clGetLayerInfo ;

typedef clInitLayer_t *
pfn_clInitLayer ;

#if !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)

extern CL_API_ENTRY cl_int CL_API_CALL
clGetLayerInfo(
    cl_layer_info param_name,
    size_t param_value_size,
    void* param_value,
    size_t* param_value_size_ret) ;

extern CL_API_ENTRY cl_int CL_API_CALL
clInitLayer(
    cl_uint num_entries,
    const cl_icd_dispatch* target_dispatch,
    cl_uint* num_entries_ret,
    const cl_icd_dispatch** layer_dispatch_ret) ;

#endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */

#ifdef __cplusplus
}
#endif

#endif /* OPENCL_CL_LAYER_H_ */
