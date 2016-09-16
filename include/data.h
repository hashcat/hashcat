/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DATA_H
#define _DATA_H

#define global_free(attr)       \
{                               \
  myfree ((void *) data.attr);  \
                                \
  data.attr = NULL;             \
}

#define local_free(attr)  \
{                         \
  myfree ((void *) attr); \
                          \
  attr = NULL;            \
}

#endif // _DATA_H
