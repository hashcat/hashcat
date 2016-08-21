#include <shared.h>
#include <logging.h>

/**
* mem alloc
*/

const static char MSG_ENOMEM[] = "Insufficient memory available";

void *mycalloc(size_t nmemb, size_t size)
{
  void *p = calloc(nmemb, size);

  if (p == NULL)
  {
    log_error("ERROR: %s", MSG_ENOMEM);

    exit(-1);
  }

  return (p);
}

void *mymalloc(size_t size)
{
  void *p = malloc(size);

  if (p == NULL)
  {
    log_error("ERROR: %s", MSG_ENOMEM);

    exit(-1);
  }

  memset(p, 0, size);

  return (p);
}

void myfree(void *ptr)
{
  if (ptr == NULL) return;

  free(ptr);
}

void *myrealloc(void *ptr, size_t oldsz, size_t add)
{
  void *p = realloc(ptr, oldsz + add);

  if (p == NULL)
  {
    log_error("ERROR: %s", MSG_ENOMEM);

    exit(-1);
  }

  memset((char *)p + oldsz, 0, add);

  return (p);
}

char *mystrdup(const char *s)
{
  const size_t len = strlen(s);

  char *b = (char *)mymalloc(len + 1);

  memcpy(b, s, len);

  return (b);
}
