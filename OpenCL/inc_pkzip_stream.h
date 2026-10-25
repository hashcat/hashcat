/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PKZIP_STREAM_H
#define INC_PKZIP_STREAM_H

#define PKZIP_STREAM_SAMPLE 256

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
  u32 valid;
  u32 success;
} pkzip_stream_hook_t;

#endif
