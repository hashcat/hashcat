/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _MEMORY_H
#define _MEMORY_H

#include <string.h>
#include <stdlib.h>

#define MSG_ENOMEM "Insufficient memory available"

void *mycalloc (size_t nmemb, size_t size);
void myfree (void *ptr);
void *mymalloc (size_t size);
void *myrealloc (void *ptr, size_t oldsz, size_t add);
char *mystrdup (const char *s);

#endif // _MEMORY_H
