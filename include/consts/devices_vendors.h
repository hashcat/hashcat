#pragma once
static const char CL_VENDOR_AMD[] = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[] = "Apple";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[] = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[] = "Mesa";
static const char CL_VENDOR_NV[] = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[] = "The pocl project";

typedef enum VENDOR_ID_ {
  VENDOR_ID_AMD = (1u << 0),
  VENDOR_ID_APPLE = (1u << 1),
  VENDOR_ID_INTEL_BEIGNET = (1u << 2),
  VENDOR_ID_INTEL_SDK = (1u << 3),
  VENDOR_ID_MESA = (1u << 4),
  VENDOR_ID_NV = (1u << 5),
  VENDOR_ID_POCL = (1u << 6),
  VENDOR_ID_AMD_USE_INTEL = (1u << 7),
  VENDOR_ID_GENERIC = (1u << 31)
}VENDOR_ID;
