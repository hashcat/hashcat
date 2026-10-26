/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PKZIP_STREAM_H
#define INC_PKZIP_STREAM_H

#define PKZIP_STREAM_SAMPLE 256
#define PKZIP_STREAM_PREFIX 32

#define PKZIP_STREAM_REJECT 0
#define PKZIP_STREAM_VERIFY 1
#define PKZIP_STREAM_MATCH  2

typedef struct pkzip_stream
{
  u32 data[PKZIP_STREAM_SAMPLE / 4];
  u32 sample_len;
  u32 method;
  u32 check;
} pkzip_stream_t;

typedef struct pkzip_stream_tmp
{
  u32 key[3];
  u32 valid;
} pkzip_stream_tmp_t;

typedef struct pkzip_stream_hook
{
  u32 key[3];
  u32 state;
} pkzip_stream_hook_t;

#endif
