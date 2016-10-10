/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"

void *hccalloc (hashcat_ctx_t *hashcat_ctx, const size_t nmemb, const size_t sz)
{
  void *p = calloc (nmemb, sz);

  if (p == NULL)
  {
    event_log_error (hashcat_ctx, "ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  return (p);
}

void *hcmalloc (hashcat_ctx_t *hashcat_ctx, const size_t sz)
{
  void *p = malloc (sz);

  if (p == NULL)
  {
    event_log_error (hashcat_ctx, "ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  memset (p, 0, sz);

  return (p);
}

void *hcrealloc (hashcat_ctx_t *hashcat_ctx, void *ptr, const size_t oldsz, const size_t addsz)
{
  void *p = realloc (ptr, oldsz + addsz);

  if (p == NULL)
  {
    event_log_error (hashcat_ctx, "ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  memset ((char *) p + oldsz, 0, addsz);

  return (p);
}

char *hcstrdup (hashcat_ctx_t *hashcat_ctx, const char *s)
{
  const size_t len = strlen (s);

  char *b = (char *) hcmalloc (hashcat_ctx, len + 1);

  strncpy (b, s, len);

  b[len] = 0;

  return (b);
}

void hcfree (void *ptr)
{
  if (ptr == NULL) return;

  free (ptr);
}
