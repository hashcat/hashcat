/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

#include <string.h>
#include <stdlib.h>

#define MSG_ENOMEM "Insufficient memory available"

void *mycalloc (size_t nmemb, size_t size);
void myfree (void *ptr);
void *mymalloc (size_t size);
void *myrealloc (void *ptr, size_t oldsz, size_t add);
char *mystrdup (const char *s);
