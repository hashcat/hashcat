#include "binding.h"

#include <stdio.h>
#include <stdlib.h>

namespace SSE2NEON
{
void *platformAlignedAlloc(size_t size)
{
    void *address;
#if defined(_WIN32)
    address = _aligned_malloc(size, 16);
    if (!address) {
#else
    int ret = posix_memalign(&address, 16, size);
    if (ret != 0) {
#endif
        fprintf(stderr, "Error at File %s line number %d\n", __FILE__,
                __LINE__);
        exit(EXIT_FAILURE);
    }
    return address;
}

void platformAlignedFree(void *ptr)
{
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}


}  // namespace SSE2NEON
