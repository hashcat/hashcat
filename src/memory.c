/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"

void *hccalloc (const size_t nmemb, const size_t sz)
{
  void *p = calloc (nmemb, sz);

  if (p == NULL)
  {
    fprintf (stderr, "%s\n", MSG_ENOMEM);

    return (NULL);
  }

  return (p);
}

void *hcmalloc (const size_t sz)
{
  //calloc is faster than malloc with big allocations, so just use that.
  void *p = hccalloc (sz, 1);

  return (p);
}

void *hcrealloc (void *ptr, const size_t oldsz, const size_t addsz)
{
  void *p = realloc (ptr, oldsz + addsz);

  if (p == NULL)
  {
    fprintf (stderr, "%s\n", MSG_ENOMEM);

    return (NULL);
  }

  memset ((char *) p + oldsz, 0, addsz);

  return (p);
}

char *hcstrdup (const char *s)
{
  const size_t len = strlen (s);

  char *b = (char *) hcmalloc (len + 1);

  if (b == NULL) return (NULL);

  memcpy (b, s, len);

  b[len] = 0;

  return (b);
}

void hcfree (void *ptr)
{
  if (ptr == NULL) return;

  free (ptr);
}

void *hc_alloc_aligned (size_t alignment, size_t size)
{
  void *ptr = NULL;

  #if defined (__linux__)   || defined (__APPLE__)     || defined (__OpenBSD__) || defined (__NetBSD__) || \
      defined (__FreeBSD__) || defined (__DragonFly__) || defined (__CYGWIN__)  || defined (__MSYS__)

  if (posix_memalign (&ptr, alignment, size) != 0)
  {
    fprintf (stderr, "! hc_aligned_alloc: %s\n", MSG_ENOMEM);

    return NULL;
  }

  #elif defined (_WIN)

  ptr = _aligned_malloc (size, alignment);

  if (ptr == NULL)
  {
    fprintf (stderr, "! hc_aligned_alloc: %s\n", MSG_ENOMEM);

    return NULL;
  }

  #else

  #error "Platform not supported for aligned allocation"

  #endif

  memset (ptr, 0, size);

  return ptr;
}

void hc_free_aligned (void **ptr)
{
  if (ptr == NULL || *ptr == NULL) return;

  #if defined (_WIN)

  _aligned_free (*ptr);

  #else

  free (*ptr);

  #endif

  *ptr = NULL;
}

void *hcmalloc_bridge_aligned (const size_t sz, const int align)
{
  uintptr_t align_mask = (uintptr_t) (align - 1);

  // Check for integer overflow before allocation
  size_t total_size = sz + align + sizeof (void *);
  if (total_size < sz) return NULL; // Overflow detected

  void *raw = malloc (total_size);

  if (raw == NULL) return NULL;

  uintptr_t raw_addr = (uintptr_t) raw + sizeof (void *);

  uintptr_t aligned_addr = (raw_addr + align_mask) & ~align_mask;

  void **aligned_ptr = (void **) aligned_addr;

  aligned_ptr[-1] = raw;

  return aligned_ptr;
}

void hcfree_bridge_aligned (void *ptr)
{
  if (ptr != NULL)
  {
    free (((void **) ptr)[-1]);
  }
}
