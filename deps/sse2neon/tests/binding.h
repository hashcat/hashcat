#ifndef SSE2NEONBINDING_H
#define SSE2NEONBINDING_H

#include <stdlib.h>

// The SSE2NEON unit tests run both within our own internal project
// as well as within the open source framework.
// This header file is used to abstract any distinctions between
// those two build environments.
//
// Initially, this is for how 16 byte aligned memory is allocated
namespace SSE2NEON
{
void *platformAlignedAlloc(size_t size);
void platformAlignedFree(void *ptr);

}  // namespace SSE2NEON

#endif
