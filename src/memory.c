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

void *hcmalloc_aligned (const size_t sz, const int align)
{
  uintptr_t align_mask = (uintptr_t) (align - 1);

  void *raw = malloc (sz + align + sizeof (void *));

  if (raw == NULL) return NULL;

  uintptr_t raw_addr = (uintptr_t) raw + sizeof (void *);

  uintptr_t aligned_addr = (raw_addr + align_mask) & ~align_mask;

  void **aligned_ptr = (void **) aligned_addr;

  aligned_ptr[-1] = raw;

  return aligned_ptr;
}

void hcfree_aligned(void *ptr)
{
  if (ptr != NULL)
  {
    free (((void **) ptr)[-1]);
  }
}
