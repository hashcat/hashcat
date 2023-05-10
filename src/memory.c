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
  // store the original allocated address so we can later use it to free the memory
  // this is convinient to use because we don't need to store two memory addresses

  const int align1 = align - 1;

  void *ptr1 = hcmalloc (sz + sizeof (void *) + align1);

  void *ptr2 = (void **) ((uintptr_t) (ptr1 + sizeof (void *) + align1) & ~align1);

  ((void **) ptr2)[-1] = ptr1;

  return ptr2;
}

void hcfree_aligned (void *ptr)
{
  if (ptr == NULL) return;

  free (((void **) ptr)[-1]);
}
