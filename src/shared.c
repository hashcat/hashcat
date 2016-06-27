/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifdef DARWIN
#include <stdio.h>
#endif

#include <shared.h>
#include <limits.h>

/**
 * basic bit handling
 */

u32 is_power_of_2(u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 rotl32 (const u32 a, const u32 n)
{
  return ((a << n) | (a >> (32 - n)));
}

u32 rotr32 (const u32 a, const u32 n)
{
  return ((a >> n) | (a << (32 - n)));
}

u64 rotl64 (const u64 a, const u64 n)
{
  return ((a << n) | (a >> (64 - n)));
}

u64 rotr64 (const u64 a, const u64 n)
{
  return ((a >> n) | (a << (64 - n)));
}

u32 byte_swap_32 (const u32 n)
{
  return (n & 0xff000000) >> 24
       | (n & 0x00ff0000) >>  8
       | (n & 0x0000ff00) <<  8
       | (n & 0x000000ff) << 24;
}

u64 byte_swap_64 (const u64 n)
{
  return (n & 0xff00000000000000ULL) >> 56
       | (n & 0x00ff000000000000ULL) >> 40
       | (n & 0x0000ff0000000000ULL) >> 24
       | (n & 0x000000ff00000000ULL) >>  8
       | (n & 0x00000000ff000000ULL) <<  8
       | (n & 0x0000000000ff0000ULL) << 24
       | (n & 0x000000000000ff00ULL) << 40
       | (n & 0x00000000000000ffULL) << 56;
}

/**
 * ciphers for use on cpu
 */

#include "cpu-des.c"
#include "cpu-aes.c"

/**
 * hashes for use on cpu
 */

#include "cpu-md5.c"
#include "cpu-sha1.c"
#include "cpu-sha256.c"

/**
 * logging
 */

int last_len = 0;

int log_final (FILE *fp, const char *fmt, va_list ap)
{
  if (last_len)
  {
    fputc ('\r', fp);

    for (int i = 0; i < last_len; i++)
    {
      fputc (' ', fp);
    }

    fputc ('\r', fp);
  }

  char s[4096] = { 0 };

  int max_len = (int) sizeof (s);

  int len = vsnprintf (s, max_len, fmt, ap);

  if (len > max_len) len = max_len;

  fwrite (s, len, 1, fp);

  fflush (fp);

  last_len = len;

  return len;
}

int log_out_nn (FILE *fp, const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (fp, fmt, ap);

  va_end (ap);

  return len;
}

int log_info_nn (const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stdout, fmt, ap);

  va_end (ap);

  return len;
}

int log_error_nn (const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stderr, fmt, ap);

  va_end (ap);

  return len;
}

int log_out (FILE *fp, const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (fp, fmt, ap);

  va_end (ap);

  fputc ('\n', fp);

  last_len = 0;

  return len;
}

int log_info (const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stdout, fmt, ap);

  va_end (ap);

  fputc ('\n', stdout);

  last_len = 0;

  return len;
}

int log_error (const char *fmt, ...)
{
  if (SUPPRESS_OUTPUT) return 0;

  fputc ('\n', stderr);
  fputc ('\n', stderr);

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stderr, fmt, ap);

  va_end (ap);

  fputc ('\n', stderr);
  fputc ('\n', stderr);

  last_len = 0;

  return len;
}

/**
 * converter
 */

u8 int_to_base32 (const u8 c)
{
  static const u8 tbl[0x20] =
  {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  return tbl[c];
}

u8 base32_to_int (const u8 c)
{
       if ((c >= 'A') && (c <= 'Z')) return c - 'A';
  else if ((c >= '2') && (c <= '7')) return c - '2' + 26;

  return 0;
}

u8 int_to_itoa32 (const u8 c)
{
  static const u8 tbl[0x20] =
  {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
  };

  return tbl[c];
}

u8 itoa32_to_int (const u8 c)
{
       if ((c >= '0') && (c <= '9')) return c - '0';
  else if ((c >= 'a') && (c <= 'v')) return c - 'a' + 10;

  return 0;
}

u8 int_to_itoa64 (const u8 c)
{
  static const u8 tbl[0x40] =
  {
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
  };

  return tbl[c];
}

u8 itoa64_to_int (const u8 c)
{
  static const u8 tbl[0x100] =
  {
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01, 0x02, 0x03, 0x04,
  };

  return tbl[c];
}

u8 int_to_base64 (const u8 c)
{
  static const u8 tbl[0x40] =
  {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f,
  };

  return tbl[c];
}

u8 base64_to_int (const u8 c)
{
  static const u8 tbl[0x100] =
  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  return tbl[c];
}

u8 int_to_bf64 (const u8 c)
{
  static const u8 tbl[0x40] =
  {
    0x2e, 0x2f, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
    0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  };

  return tbl[c];
}

u8 bf64_to_int (const u8 c)
{
  static const u8 tbl[0x100] =
  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  return tbl[c];
}

u8 int_to_lotus64 (const u8 c)
{
       if (c  < 10) return '0' + c;
  else if (c  < 36) return 'A' + c - 10;
  else if (c  < 62) return 'a' + c - 36;
  else if (c == 62) return '+';
  else if (c == 63) return '/';

  return 0;
}

u8 lotus64_to_int (const u8 c)
{
       if ((c >= '0') && (c <= '9')) return c - '0';
  else if ((c >= 'A') && (c <= 'Z')) return c - 'A' + 10;
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 36;
  else if (c == '+') return 62;
  else if (c == '/') return 63;
  else

  return 0;
}

int base32_decode (u8 (*f) (const u8), const u8 *in_buf, int in_len, u8 *out_buf)
{
  const u8 *in_ptr = in_buf;

  u8 *out_ptr = out_buf;

  for (int i = 0; i < in_len; i += 8)
  {
    const u8 out_val0 = f (in_ptr[0] & 0x7f);
    const u8 out_val1 = f (in_ptr[1] & 0x7f);
    const u8 out_val2 = f (in_ptr[2] & 0x7f);
    const u8 out_val3 = f (in_ptr[3] & 0x7f);
    const u8 out_val4 = f (in_ptr[4] & 0x7f);
    const u8 out_val5 = f (in_ptr[5] & 0x7f);
    const u8 out_val6 = f (in_ptr[6] & 0x7f);
    const u8 out_val7 = f (in_ptr[7] & 0x7f);

    out_ptr[0] =                            ((out_val0 << 3) & 0xf8) | ((out_val1 >> 2) & 0x07);
    out_ptr[1] = ((out_val1 << 6) & 0xc0) | ((out_val2 << 1) & 0x3e) | ((out_val3 >> 4) & 0x01);
    out_ptr[2] =                            ((out_val3 << 4) & 0xf0) | ((out_val4 >> 1) & 0x0f);
    out_ptr[3] = ((out_val4 << 7) & 0x80) | ((out_val5 << 2) & 0x7c) | ((out_val6 >> 3) & 0x03);
    out_ptr[4] =                            ((out_val6 << 5) & 0xe0) | ((out_val7 >> 0) & 0x1f);

    in_ptr  += 8;
    out_ptr += 5;
  }

  for (int i = 0; i < in_len; i++)
  {
    if (in_buf[i] != '=') continue;

    in_len = i;
  }

  int out_len = (in_len * 5) / 8;

  return out_len;
}

int base32_encode (u8 (*f) (const u8), const u8 *in_buf, int in_len, u8 *out_buf)
{
  const u8 *in_ptr = in_buf;

  u8 *out_ptr = out_buf;

  for (int i = 0; i < in_len; i += 5)
  {
    const u8 out_val0 = f (                            ((in_ptr[0] >> 3) & 0x1f));
    const u8 out_val1 = f (((in_ptr[0] << 2) & 0x1c) | ((in_ptr[1] >> 6) & 0x03));
    const u8 out_val2 = f (                            ((in_ptr[1] >> 1) & 0x1f));
    const u8 out_val3 = f (((in_ptr[1] << 4) & 0x10) | ((in_ptr[2] >> 4) & 0x0f));
    const u8 out_val4 = f (((in_ptr[2] << 1) & 0x1e) | ((in_ptr[3] >> 7) & 0x01));
    const u8 out_val5 = f (                            ((in_ptr[3] >> 2) & 0x1f));
    const u8 out_val6 = f (((in_ptr[3] << 3) & 0x18) | ((in_ptr[4] >> 5) & 0x07));
    const u8 out_val7 = f (                            ((in_ptr[4] >> 0) & 0x1f));

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;
    out_ptr[4] = out_val4 & 0x7f;
    out_ptr[5] = out_val5 & 0x7f;
    out_ptr[6] = out_val6 & 0x7f;
    out_ptr[7] = out_val7 & 0x7f;

    in_ptr  += 5;
    out_ptr += 8;
  }

  int out_len = (int) (((0.5 + (float) in_len) * 8) / 5); // ceil (in_len * 8 / 5)

  while (out_len % 8)
  {
    out_buf[out_len] = '=';

    out_len++;
  }

  return out_len;
}

int base64_decode (u8 (*f) (const u8), const u8 *in_buf, int in_len, u8 *out_buf)
{
  const u8 *in_ptr = in_buf;

  u8 *out_ptr = out_buf;

  for (int i = 0; i < in_len; i += 4)
  {
    const u8 out_val0 = f (in_ptr[0] & 0x7f);
    const u8 out_val1 = f (in_ptr[1] & 0x7f);
    const u8 out_val2 = f (in_ptr[2] & 0x7f);
    const u8 out_val3 = f (in_ptr[3] & 0x7f);

    out_ptr[0] = ((out_val0 << 2) & 0xfc) | ((out_val1 >> 4) & 0x03);
    out_ptr[1] = ((out_val1 << 4) & 0xf0) | ((out_val2 >> 2) & 0x0f);
    out_ptr[2] = ((out_val2 << 6) & 0xc0) | ((out_val3 >> 0) & 0x3f);

    in_ptr  += 4;
    out_ptr += 3;
  }

  for (int i = 0; i < in_len; i++)
  {
    if (in_buf[i] != '=') continue;

    in_len = i;
  }

  int out_len = (in_len * 6) / 8;

  return out_len;
}

int base64_encode (u8 (*f) (const u8), const u8 *in_buf, int in_len, u8 *out_buf)
{
  const u8 *in_ptr = in_buf;

  u8 *out_ptr = out_buf;

  for (int i = 0; i < in_len; i += 3)
  {
    const u8 out_val0 = f (                            ((in_ptr[0] >> 2) & 0x3f));
    const u8 out_val1 = f (((in_ptr[0] << 4) & 0x30) | ((in_ptr[1] >> 4) & 0x0f));
    const u8 out_val2 = f (((in_ptr[1] << 2) & 0x3c) | ((in_ptr[2] >> 6) & 0x03));
    const u8 out_val3 = f (                            ((in_ptr[2] >> 0) & 0x3f));

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;

    in_ptr  += 3;
    out_ptr += 4;
  }

  int out_len = (int) (((0.5 + (float) in_len) * 8) / 6); // ceil (in_len * 8 / 6)

  while (out_len % 4)
  {
    out_buf[out_len] = '=';

    out_len++;
  }

  return out_len;
}

int is_valid_hex_char (const u8 c)
{
  if ((c >= '0') && (c <= '9')) return 1;
  if ((c >= 'A') && (c <= 'F')) return 1;
  if ((c >= 'a') && (c <= 'f')) return 1;

  return 0;
}

u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

u8 hex_to_u8 (const u8 hex[2])
{
  u8 v = 0;

  v |= (hex_convert (hex[1]) <<  0);
  v |= (hex_convert (hex[0]) <<  4);

  return (v);
}

u32 hex_to_u32 (const u8 hex[8])
{
  u32 v = 0;

  v |= ((u32) hex_convert (hex[7])) <<  0;
  v |= ((u32) hex_convert (hex[6])) <<  4;
  v |= ((u32) hex_convert (hex[5])) <<  8;
  v |= ((u32) hex_convert (hex[4])) << 12;
  v |= ((u32) hex_convert (hex[3])) << 16;
  v |= ((u32) hex_convert (hex[2])) << 20;
  v |= ((u32) hex_convert (hex[1])) << 24;
  v |= ((u32) hex_convert (hex[0])) << 28;

  return (v);
}

u64 hex_to_u64 (const u8 hex[16])
{
  u64 v = 0;

  v |= ((u64) hex_convert (hex[15]) <<  0);
  v |= ((u64) hex_convert (hex[14]) <<  4);
  v |= ((u64) hex_convert (hex[13]) <<  8);
  v |= ((u64) hex_convert (hex[12]) << 12);
  v |= ((u64) hex_convert (hex[11]) << 16);
  v |= ((u64) hex_convert (hex[10]) << 20);
  v |= ((u64) hex_convert (hex[ 9]) << 24);
  v |= ((u64) hex_convert (hex[ 8]) << 28);
  v |= ((u64) hex_convert (hex[ 7]) << 32);
  v |= ((u64) hex_convert (hex[ 6]) << 36);
  v |= ((u64) hex_convert (hex[ 5]) << 40);
  v |= ((u64) hex_convert (hex[ 4]) << 44);
  v |= ((u64) hex_convert (hex[ 3]) << 48);
  v |= ((u64) hex_convert (hex[ 2]) << 52);
  v |= ((u64) hex_convert (hex[ 1]) << 56);
  v |= ((u64) hex_convert (hex[ 0]) << 60);

  return (v);
}

void bin_to_hex_lower (const u32 v, u8 hex[8])
{
  hex[0] = v >> 28 & 15;
  hex[1] = v >> 24 & 15;
  hex[2] = v >> 20 & 15;
  hex[3] = v >> 16 & 15;
  hex[4] = v >> 12 & 15;
  hex[5] = v >>  8 & 15;
  hex[6] = v >>  4 & 15;
  hex[7] = v >>  0 & 15;

  u32 add;

  hex[0] += 6; add = ((hex[0] & 0x10) >> 4) * 39; hex[0] += 42 + add;
  hex[1] += 6; add = ((hex[1] & 0x10) >> 4) * 39; hex[1] += 42 + add;
  hex[2] += 6; add = ((hex[2] & 0x10) >> 4) * 39; hex[2] += 42 + add;
  hex[3] += 6; add = ((hex[3] & 0x10) >> 4) * 39; hex[3] += 42 + add;
  hex[4] += 6; add = ((hex[4] & 0x10) >> 4) * 39; hex[4] += 42 + add;
  hex[5] += 6; add = ((hex[5] & 0x10) >> 4) * 39; hex[5] += 42 + add;
  hex[6] += 6; add = ((hex[6] & 0x10) >> 4) * 39; hex[6] += 42 + add;
  hex[7] += 6; add = ((hex[7] & 0x10) >> 4) * 39; hex[7] += 42 + add;
}

/**
 * decoder
 */

static void AES128_decrypt_cbc (const u32 key[4], const u32 iv[4], const u32 in[16], u32 out[16])
{
  AES_KEY skey;

  AES_set_decrypt_key ((const u8 *) key, 128, &skey);

  u32 _iv[4] = { 0 };

  _iv[0] = iv[0];
  _iv[1] = iv[1];
  _iv[2] = iv[2];
  _iv[3] = iv[3];

  for (int i = 0; i < 16; i += 4)
  {
    u32 _in[4] = { 0 };
    u32 _out[4] = { 0 };

    _in[0] = in[i + 0];
    _in[1] = in[i + 1];
    _in[2] = in[i + 2];
    _in[3] = in[i + 3];

    AES_decrypt (&skey, (const u8 *) _in, (u8 *) _out);

    _out[0] ^= _iv[0];
    _out[1] ^= _iv[1];
    _out[2] ^= _iv[2];
    _out[3] ^= _iv[3];

    out[i + 0] = _out[0];
    out[i + 1] = _out[1];
    out[i + 2] = _out[2];
    out[i + 3] = _out[3];

    _iv[0] = _in[0];
    _iv[1] = _in[1];
    _iv[2] = _in[2];
    _iv[3] = _in[3];
  }
}

static void juniper_decrypt_hash (char *in, char *out)
{
  // base64 decode

  u8 base64_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) in, DISPLAY_LEN_MIN_501, base64_buf);

  // iv stuff

  u32 juniper_iv[4] = { 0 };

  memcpy (juniper_iv, base64_buf, 12);

  memcpy (out, juniper_iv, 12);

  // reversed key

  u32 juniper_key[4] = { 0 };

  juniper_key[0] = byte_swap_32 (0xa6707a7e);
  juniper_key[1] = byte_swap_32 (0x8df91059);
  juniper_key[2] = byte_swap_32 (0xdea70ae5);
  juniper_key[3] = byte_swap_32 (0x2f9c2442);

  // AES decrypt

  u32 *in_ptr  = (u32 *) (base64_buf + 12);
  u32 *out_ptr = (u32 *) (out        + 12);

  AES128_decrypt_cbc (juniper_key, juniper_iv, in_ptr, out_ptr);
}

void phpass_decode (u8 digest[16], u8 buf[22])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;

  digest[15] = (l >>  0) & 0xff;
}

void phpass_encode (u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[15] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f);
}

void md5crypt_decode (u8 digest[16], u8 buf[22])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5crypt_encode (u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
}

void sha512crypt_decode (u8 digest[64], u8 buf[86])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[21] = (l >>  8) & 0xff;
  digest[42] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[ 1] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[ 2] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[24] = (l >>  8) & 0xff;
  digest[45] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[ 4] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[ 5] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[27] = (l >>  8) & 0xff;
  digest[48] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[ 7] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[30] = (l >>  8) & 0xff;
  digest[51] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[10] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[44]) <<  0;
  l |= itoa64_to_int (buf[45]) <<  6;
  l |= itoa64_to_int (buf[46]) << 12;
  l |= itoa64_to_int (buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >>  8) & 0xff;
  digest[32] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[48]) <<  0;
  l |= itoa64_to_int (buf[49]) <<  6;
  l |= itoa64_to_int (buf[50]) << 12;
  l |= itoa64_to_int (buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >>  8) & 0xff;
  digest[54] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[52]) <<  0;
  l |= itoa64_to_int (buf[53]) <<  6;
  l |= itoa64_to_int (buf[54]) << 12;
  l |= itoa64_to_int (buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[56]) <<  0;
  l |= itoa64_to_int (buf[57]) <<  6;
  l |= itoa64_to_int (buf[58]) << 12;
  l |= itoa64_to_int (buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >>  8) & 0xff;
  digest[35] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[60]) <<  0;
  l |= itoa64_to_int (buf[61]) <<  6;
  l |= itoa64_to_int (buf[62]) << 12;
  l |= itoa64_to_int (buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >>  8) & 0xff;
  digest[57] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[64]) <<  0;
  l |= itoa64_to_int (buf[65]) <<  6;
  l |= itoa64_to_int (buf[66]) << 12;
  l |= itoa64_to_int (buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[16] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[68]) <<  0;
  l |= itoa64_to_int (buf[69]) <<  6;
  l |= itoa64_to_int (buf[70]) << 12;
  l |= itoa64_to_int (buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >>  8) & 0xff;
  digest[38] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[72]) <<  0;
  l |= itoa64_to_int (buf[73]) <<  6;
  l |= itoa64_to_int (buf[74]) << 12;
  l |= itoa64_to_int (buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >>  8) & 0xff;
  digest[60] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[76]) <<  0;
  l |= itoa64_to_int (buf[77]) <<  6;
  l |= itoa64_to_int (buf[78]) << 12;
  l |= itoa64_to_int (buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[19] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[80]) <<  0;
  l |= itoa64_to_int (buf[81]) <<  6;
  l |= itoa64_to_int (buf[82]) << 12;
  l |= itoa64_to_int (buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >>  8) & 0xff;
  digest[41] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[84]) <<  0;
  l |= itoa64_to_int (buf[85]) <<  6;

  digest[63] = (l >>  0) & 0xff;
}

void sha512crypt_encode (u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[ 0] << 16) | (digest[21] << 8) | (digest[42] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[22] << 16) | (digest[43] << 8) | (digest[ 1] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[44] << 16) | (digest[ 2] << 8) | (digest[23] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 3] << 16) | (digest[24] << 8) | (digest[45] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[25] << 16) | (digest[46] << 8) | (digest[ 4] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[47] << 16) | (digest[ 5] << 8) | (digest[26] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 6] << 16) | (digest[27] << 8) | (digest[48] << 0);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[28] << 16) | (digest[49] << 8) | (digest[ 7] << 0);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[50] << 16) | (digest[ 8] << 8) | (digest[29] << 0);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 9] << 16) | (digest[30] << 8) | (digest[51] << 0);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[31] << 16) | (digest[52] << 8) | (digest[10] << 0);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[53] << 16) | (digest[11] << 8) | (digest[32] << 0);

  buf[44] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[12] << 16) | (digest[33] << 8) | (digest[54] << 0);

  buf[48] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[34] << 16) | (digest[55] << 8) | (digest[13] << 0);

  buf[52] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[56] << 16) | (digest[14] << 8) | (digest[35] << 0);

  buf[56] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[15] << 16) | (digest[36] << 8) | (digest[57] << 0);

  buf[60] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[37] << 16) | (digest[58] << 8) | (digest[16] << 0);

  buf[64] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[59] << 16) | (digest[17] << 8) | (digest[38] << 0);

  buf[68] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[18] << 16) | (digest[39] << 8) | (digest[60] << 0);

  buf[72] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[40] << 16) | (digest[61] << 8) | (digest[19] << 0);

  buf[76] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[62] << 16) | (digest[20] << 8) | (digest[41] << 0);

  buf[80] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l =                  0 |                 0 | (digest[63] << 0);

  buf[84] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64 (l & 0x3f); l >>= 6;
}

void sha1aix_decode (u8 digest[20], u8 buf[27])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1aix_encode (u8 digest[20], u8 buf[27])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l =                 0 | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f);
}

void sha256aix_decode (u8 digest[32], u8 buf[43])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;

  //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256aix_encode (u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l =                 0 | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f);
}

void sha512aix_decode (u8 digest[64], u8 buf[86])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[44]) <<  0;
  l |= itoa64_to_int (buf[45]) <<  6;
  l |= itoa64_to_int (buf[46]) << 12;
  l |= itoa64_to_int (buf[47]) << 18;

  digest[35] = (l >>  0) & 0xff;
  digest[34] = (l >>  8) & 0xff;
  digest[33] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[48]) <<  0;
  l |= itoa64_to_int (buf[49]) <<  6;
  l |= itoa64_to_int (buf[50]) << 12;
  l |= itoa64_to_int (buf[51]) << 18;

  digest[38] = (l >>  0) & 0xff;
  digest[37] = (l >>  8) & 0xff;
  digest[36] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[52]) <<  0;
  l |= itoa64_to_int (buf[53]) <<  6;
  l |= itoa64_to_int (buf[54]) << 12;
  l |= itoa64_to_int (buf[55]) << 18;

  digest[41] = (l >>  0) & 0xff;
  digest[40] = (l >>  8) & 0xff;
  digest[39] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[56]) <<  0;
  l |= itoa64_to_int (buf[57]) <<  6;
  l |= itoa64_to_int (buf[58]) << 12;
  l |= itoa64_to_int (buf[59]) << 18;

  digest[44] = (l >>  0) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[42] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[60]) <<  0;
  l |= itoa64_to_int (buf[61]) <<  6;
  l |= itoa64_to_int (buf[62]) << 12;
  l |= itoa64_to_int (buf[63]) << 18;

  digest[47] = (l >>  0) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[45] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[64]) <<  0;
  l |= itoa64_to_int (buf[65]) <<  6;
  l |= itoa64_to_int (buf[66]) << 12;
  l |= itoa64_to_int (buf[67]) << 18;

  digest[50] = (l >>  0) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[48] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[68]) <<  0;
  l |= itoa64_to_int (buf[69]) <<  6;
  l |= itoa64_to_int (buf[70]) << 12;
  l |= itoa64_to_int (buf[71]) << 18;

  digest[53] = (l >>  0) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[51] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[72]) <<  0;
  l |= itoa64_to_int (buf[73]) <<  6;
  l |= itoa64_to_int (buf[74]) << 12;
  l |= itoa64_to_int (buf[75]) << 18;

  digest[56] = (l >>  0) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[54] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[76]) <<  0;
  l |= itoa64_to_int (buf[77]) <<  6;
  l |= itoa64_to_int (buf[78]) << 12;
  l |= itoa64_to_int (buf[79]) << 18;

  digest[59] = (l >>  0) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[57] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[80]) <<  0;
  l |= itoa64_to_int (buf[81]) <<  6;
  l |= itoa64_to_int (buf[82]) << 12;
  l |= itoa64_to_int (buf[83]) << 18;

  digest[62] = (l >>  0) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[60] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[84]) <<  0;
  l |= itoa64_to_int (buf[85]) <<  6;

  digest[63] = (l >> 16) & 0xff;
}

void sha512aix_encode (u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l = (digest[32] << 0) | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64 (l & 0x3f);

  l = (digest[35] << 0) | (digest[34] << 8) | (digest[33] << 16);

  buf[44] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64 (l & 0x3f);

  l = (digest[38] << 0) | (digest[37] << 8) | (digest[36] << 16);

  buf[48] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64 (l & 0x3f);

  l = (digest[41] << 0) | (digest[40] << 8) | (digest[39] << 16);

  buf[52] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64 (l & 0x3f);

  l = (digest[44] << 0) | (digest[43] << 8) | (digest[42] << 16);

  buf[56] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64 (l & 0x3f);

  l = (digest[47] << 0) | (digest[46] << 8) | (digest[45] << 16);

  buf[60] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64 (l & 0x3f);

  l = (digest[50] << 0) | (digest[49] << 8) | (digest[48] << 16);

  buf[64] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64 (l & 0x3f);

  l = (digest[53] << 0) | (digest[52] << 8) | (digest[51] << 16);

  buf[68] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64 (l & 0x3f);

  l = (digest[56] << 0) | (digest[55] << 8) | (digest[54] << 16);

  buf[72] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64 (l & 0x3f);

  l = (digest[59] << 0) | (digest[58] << 8) | (digest[57] << 16);

  buf[76] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64 (l & 0x3f);

  l = (digest[62] << 0) | (digest[61] << 8) | (digest[60] << 16);

  buf[80] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64 (l & 0x3f);

  l =                 0 |                 0 | (digest[63] << 16);

  buf[84] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64 (l & 0x3f); l >>= 6;
}

void sha256crypt_decode (u8 digest[32], u8 buf[43])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[20] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[21] = (l >> 16) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[11] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[ 2] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[24] = (l >> 16) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[27] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[17] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[ 8] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;

  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >>  0) & 0xff;
}

void sha256crypt_encode (u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[ 0] << 16) | (digest[10] << 8) | (digest[20] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[21] << 16) | (digest[ 1] << 8) | (digest[11] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[12] << 16) | (digest[22] << 8) | (digest[ 2] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 3] << 16) | (digest[13] << 8) | (digest[23] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[24] << 16) | (digest[ 4] << 8) | (digest[14] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[15] << 16) | (digest[25] << 8) | (digest[ 5] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 6] << 16) | (digest[16] << 8) | (digest[26] << 0);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[27] << 16) | (digest[ 7] << 8) | (digest[17] << 0);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[18] << 16) | (digest[28] << 8) | (digest[ 8] << 0);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l = (digest[ 9] << 16) | (digest[19] << 8) | (digest[29] << 0);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f); l >>= 6;

  l =                  0 | (digest[31] << 8) | (digest[30] << 0);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f);
}

void drupal7_decode (u8 digest[64], u8 buf[44])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[15] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[18] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[21] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[24] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[27] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[30] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[32] = (l >> 16) & 0xff;

  digest[33] = 0;
  digest[34] = 0;
  digest[35] = 0;
  digest[36] = 0;
  digest[37] = 0;
  digest[38] = 0;
  digest[39] = 0;
  digest[40] = 0;
  digest[41] = 0;
  digest[42] = 0;
  digest[43] = 0;
  digest[44] = 0;
  digest[45] = 0;
  digest[46] = 0;
  digest[47] = 0;
  digest[48] = 0;
  digest[49] = 0;
  digest[50] = 0;
  digest[51] = 0;
  digest[52] = 0;
  digest[53] = 0;
  digest[54] = 0;
  digest[55] = 0;
  digest[56] = 0;
  digest[57] = 0;
  digest[58] = 0;
  digest[59] = 0;
  digest[60] = 0;
  digest[61] = 0;
  digest[62] = 0;
  digest[63] = 0;
}

void drupal7_encode (u8 digest[64], u8 buf[43])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); l >>= 6;
  //buf[43] = int_to_itoa64 (l & 0x3f);
}

/**
 * tty
 */

#ifdef LINUX
static struct termio savemodes;
static int havemodes = 0;

int tty_break()
{
  struct termio modmodes;

  if (ioctl (fileno (stdin), TCGETA, &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return ioctl (fileno (stdin), TCSETAW, &modmodes);
}

int tty_getchar()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar();
}

int tty_fix()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TCSETAW, &savemodes);
}
#endif

#ifdef DARWIN
static struct termios savemodes;
static int havemodes = 0;

int tty_break()
{
  struct termios modmodes;

  if (ioctl (fileno (stdin), TIOCGETA, &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return ioctl (fileno (stdin), TIOCSETAW, &modmodes);
}

int tty_getchar()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar();
}

int tty_fix()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TIOCSETAW, &savemodes);
}
#endif

#ifdef WIN
static DWORD saveMode = 0;

int tty_break()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  GetConsoleMode (stdinHandle, &saveMode);
  SetConsoleMode (stdinHandle, ENABLE_PROCESSED_INPUT);

  return 0;
}

int tty_getchar()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  DWORD rc = WaitForSingleObject (stdinHandle, 1000);

  if (rc == WAIT_TIMEOUT)   return  0;
  if (rc == WAIT_ABANDONED) return -1;
  if (rc == WAIT_FAILED)    return -1;

  // The whole ReadConsoleInput () part is a workaround.
  // For some unknown reason, maybe a mingw bug, a random signal
  // is sent to stdin which unblocks WaitForSingleObject () and sets rc 0.
  // Then it wants to read with getche () a keyboard input
  // which has never been made.

  INPUT_RECORD buf[100];

  DWORD num = 0;

  memset (buf, 0, sizeof (buf));

  ReadConsoleInput (stdinHandle, buf, 100, &num);

  FlushConsoleInputBuffer (stdinHandle);

  for (uint i = 0; i < num; i++)
  {
    if (buf[i].EventType != KEY_EVENT) continue;

    KEY_EVENT_RECORD KeyEvent = buf[i].Event.KeyEvent;

    if (KeyEvent.bKeyDown != TRUE) continue;

    return KeyEvent.uChar.AsciiChar;
  }

  return 0;
}

int tty_fix()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  SetConsoleMode (stdinHandle, saveMode);

  return 0;
}
#endif

/**
 * mem alloc
 */

#define MSG_ENOMEM "Insufficient memory available"

void *mycalloc (size_t nmemb, size_t size)
{
  void *p = calloc (nmemb, size);

  if (p == NULL)
  {
    log_error ("ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  return (p);
}

void *mymalloc (size_t size)
{
  void *p = malloc (size);

  if (p == NULL)
  {
    log_error ("ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  memset (p, 0, size);

  return (p);
}

void myfree (void *ptr)
{
  if (ptr == NULL) return;

  free (ptr);
}

void *myrealloc (void *ptr, size_t oldsz, size_t add)
{
  void *p = realloc (ptr, oldsz + add);

  if (p == NULL)
  {
    log_error ("ERROR: %s", MSG_ENOMEM);

    exit (-1);
  }

  memset ((char *) p + oldsz, 0, add);

  return (p);
}

char *mystrdup (const char *s)
{
  const size_t len = strlen (s);

  char *b = (char *) mymalloc (len + 1);

  memcpy (b, s, len);

  return (b);
}

FILE *logfile_open (char *logfile)
{
  FILE *fp = fopen (logfile, "ab");

  if (fp == NULL)
  {
    fp = stdout;
  }

  return fp;
}

void logfile_close (FILE *fp)
{
  if (fp == stdout) return;

  fclose (fp);
}

void logfile_append (const char *fmt, ...)
{
  if (data.logfile_disable == 1) return;

  FILE *fp = logfile_open (data.logfile);

  va_list ap;

  va_start (ap, fmt);

  vfprintf (fp, fmt, ap);

  va_end (ap);

  fputc ('\n', fp);

  fflush (fp);

  logfile_close (fp);
}

int logfile_generate_id ()
{
  const int n = rand ();

  time_t t;

  time (&t);

  return t + n;
}

char *logfile_generate_topid ()
{
  const int id = logfile_generate_id ();

  char *topid = (char *) mymalloc (1 + 16 + 1);

  snprintf (topid, 1 + 16, "TOP%08x", id);

  return topid;
}

char *logfile_generate_subid ()
{
  const int id = logfile_generate_id ();

  char *subid = (char *) mymalloc (1 + 16 + 1);

  snprintf (subid, 1 + 16, "SUB%08x", id);

  return subid;
}

/**
 * system
 */

#if F_SETLKW
void lock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_WRLCK;
  while (fcntl(fileno(fp), F_SETLKW, &lock))
  {
    if (errno != EINTR)
    {
      log_error ("ERROR: Failed acquiring write lock: %s", strerror (errno));

      exit (-1);
    }
  }
}

void unlock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_UNLCK;
  fcntl(fileno(fp), F_SETLK, &lock);
}
#endif // F_SETLKW

#ifdef WIN
void fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  FlushFileBuffers (h);
}
#endif

/**
 * thermal
 */

#ifdef HAVE_HWMON

int get_adapters_num_adl (void *adl, int *iNumberAdapters)
{
  if (hm_ADL_Adapter_NumberOfAdapters_Get ((ADL_PTR *) adl, iNumberAdapters) != ADL_OK) return -1;

  if (iNumberAdapters == 0)
  {
    log_info ("WARN: No ADL adapters found.");

    return -1;
  }

  return 0;
}

/*
int hm_show_performance_level (HM_LIB hm_dll, int iAdapterIndex)
{
  ADLODPerformanceLevels *lpOdPerformanceLevels = NULL;
  ADLODParameters lpOdParameters;

  lpOdParameters.iSize = sizeof (ADLODParameters);
  size_t plevels_size = 0;

  if (hm_ADL_Overdrive_ODParameters_Get (hm_dll, iAdapterIndex, &lpOdParameters) != ADL_OK) return -1;

  log_info ("[DEBUG] %s, adapter %d performance level (%d) : %s %s",
          __func__, iAdapterIndex,
          lpOdParameters.iNumberOfPerformanceLevels,
          (lpOdParameters.iActivityReportingSupported) ? "activity reporting" : "",
          (lpOdParameters.iDiscretePerformanceLevels) ? "discrete performance levels" : "performance ranges");

  plevels_size = sizeof (ADLODPerformanceLevels) + sizeof (ADLODPerformanceLevel) * (lpOdParameters.iNumberOfPerformanceLevels - 1);

  lpOdPerformanceLevels = (ADLODPerformanceLevels *) mymalloc (plevels_size);

  lpOdPerformanceLevels->iSize = sizeof (ADLODPerformanceLevels) + sizeof (ADLODPerformanceLevel) * (lpOdParameters.iNumberOfPerformanceLevels - 1);

  if (hm_ADL_Overdrive_ODPerformanceLevels_Get (hm_dll, iAdapterIndex, 0, lpOdPerformanceLevels) != ADL_OK) return -1;

  for (int j = 0; j < lpOdParameters.iNumberOfPerformanceLevels; j++)
    log_info ("[DEBUG] %s, adapter %d, level %d : engine %d, memory %d, voltage: %d",
    __func__, iAdapterIndex, j,
    lpOdPerformanceLevels->aLevels[j].iEngineClock / 100, lpOdPerformanceLevels->aLevels[j].iMemoryClock / 100, lpOdPerformanceLevels->aLevels[j].iVddc);

  myfree (lpOdPerformanceLevels);

  return 0;
}
*/

LPAdapterInfo hm_get_adapter_info_adl (void *adl, int iNumberAdapters)
{
  size_t AdapterInfoSize = iNumberAdapters * sizeof (AdapterInfo);

  LPAdapterInfo lpAdapterInfo = (LPAdapterInfo) mymalloc (AdapterInfoSize);

  if (hm_ADL_Adapter_AdapterInfo_Get ((ADL_PTR *) adl, lpAdapterInfo, AdapterInfoSize) != ADL_OK) return NULL;

  return lpAdapterInfo;
}

int hm_get_adapter_index_nvapi (HM_ADAPTER_NVAPI nvapiGPUHandle[DEVICES_MAX])
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs (data.hm_nvapi, nvapiGPUHandle, &pGpuCount) != NVAPI_OK) return (0);

  if (pGpuCount == 0)
  {
    log_info ("WARN: No NvAPI adapters found");

    return (0);
  }

  return (pGpuCount);
}

int hm_get_adapter_index_nvml (HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX])
{
  int pGpuCount = 0;

  for (uint i = 0; i < DEVICES_MAX; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex (data.hm_nvml, 1, i, &nvmlGPUHandle[i]) != NVML_SUCCESS) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (data.hm_nvml, nvGPUHandle[i], name, sizeof (name) - 1);

    pGpuCount++;
  }

  if (pGpuCount == 0)
  {
    log_info ("WARN: No NVML adapters found");

    return (0);
  }

  return (pGpuCount);
}

/*
//
// does not help at all, since ADL does not assign different bus id, device id when we have multi GPU setups
//

int hm_get_opencl_device_index (hm_attrs_t *hm_device, uint num_adl_adapters, int bus_num, int dev_num)
{
  u32 idx = -1;

  for (uint i = 0; i < num_adl_adapters; i++)
  {
    int opencl_bus_num = hm_device[i].busid;
    int opencl_dev_num = hm_device[i].devid;

    if ((opencl_bus_num == bus_num) && (opencl_dev_num == dev_num))
    {
      idx = i;

      break;
    }
  }

  if (idx >= DEVICES_MAX) return -1;

  return idx;
}

void hm_get_opencl_busid_devid (hm_attrs_t *hm_device, uint opencl_num_devices, cl_device_id *devices)
{
  for (uint i = 0; i < opencl_num_devices; i++)
  {
    cl_device_topology_amd device_topology;

    hc_clGetDeviceInfo (devices[i], CL_DEVICE_TOPOLOGY_AMD, sizeof (device_topology), &device_topology, NULL);

    hm_device[i].busid = device_topology.pcie.bus;
    hm_device[i].devid = device_topology.pcie.device;
  }
}
*/

void hm_sort_adl_adapters_by_busid_devid (u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // basically bubble sort

  for (int i = 0; i < num_adl_adapters; i++)
  {
    for (int j = 0; j < num_adl_adapters - 1; j++)
    {
      // get info of adapter [x]

      u32 adapter_index_x = valid_adl_device_list[j];
      AdapterInfo info_x = lpAdapterInfo[adapter_index_x];

      u32 bus_num_x = info_x.iBusNumber;
      u32 dev_num_x = info_x.iDeviceNumber;

      // get info of adapter [y]

      u32 adapter_index_y = valid_adl_device_list[j + 1];
      AdapterInfo info_y = lpAdapterInfo[adapter_index_y];

      u32 bus_num_y = info_y.iBusNumber;
      u32 dev_num_y = info_y.iDeviceNumber;

      uint need_swap = 0;

      if (bus_num_y < bus_num_x)
      {
        need_swap = 1;
      }
      else if (bus_num_y == bus_num_x)
      {
        if (dev_num_y < dev_num_x)
        {
          need_swap = 1;
        }
      }

      if (need_swap == 1)
      {
        u32 temp = valid_adl_device_list[j + 1];

        valid_adl_device_list[j + 1] = valid_adl_device_list[j];
        valid_adl_device_list[j + 0] = temp;
      }
    }
  }
}

u32 *hm_get_list_valid_adl_adapters (int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  *num_adl_adapters = 0;

  u32 *adl_adapters = NULL;

  int *bus_numbers    = NULL;
  int *device_numbers = NULL;

  for (int i = 0; i < iNumberAdapters; i++)
  {
    AdapterInfo info = lpAdapterInfo[i];

    if (strlen (info.strUDID) < 1) continue;

    #ifdef WIN
    if (info.iVendorID !=   1002) continue;
    #else
    if (info.iVendorID != 0x1002) continue;
    #endif

    if (info.iBusNumber    < 0) continue;
    if (info.iDeviceNumber < 0) continue;

    int found = 0;

    for (int pos = 0; pos < *num_adl_adapters; pos++)
    {
      if ((bus_numbers[pos] == info.iBusNumber) && (device_numbers[pos] == info.iDeviceNumber))
      {
        found = 1;
        break;
      }
    }

    if (found) continue;

    // add it to the list

    adl_adapters = (u32 *) myrealloc (adl_adapters, (*num_adl_adapters) * sizeof (int), sizeof (int));

    adl_adapters[*num_adl_adapters] = i;

    // rest is just bookkeeping

    bus_numbers    = (int*) myrealloc (bus_numbers,    (*num_adl_adapters) * sizeof (int), sizeof (int));
    device_numbers = (int*) myrealloc (device_numbers, (*num_adl_adapters) * sizeof (int), sizeof (int));

    bus_numbers[*num_adl_adapters]    = info.iBusNumber;
    device_numbers[*num_adl_adapters] = info.iDeviceNumber;

    (*num_adl_adapters)++;
  }

  myfree (bus_numbers);
  myfree (device_numbers);

  // sort the list by increasing bus id, device id number

  hm_sort_adl_adapters_by_busid_devid (adl_adapters, *num_adl_adapters, lpAdapterInfo);

  return adl_adapters;
}

int hm_check_fanspeed_control (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  // loop through all valid devices

  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    // if (hm_show_performance_level (adl, info.iAdapterIndex) != 0) return -1;

    // get fanspeed info

    if (hm_device[opencl_device_index].od_version == 5)
    {
      ADLFanSpeedInfo FanSpeedInfo;

      memset (&FanSpeedInfo, 0, sizeof (ADLFanSpeedInfo));

      FanSpeedInfo.iSize = sizeof (ADLFanSpeedInfo);

      if (hm_ADL_Overdrive5_FanSpeedInfo_Get (adl, info.iAdapterIndex, 0, &FanSpeedInfo) != ADL_OK) return -1;

      // check read and write capability in fanspeedinfo

      if ((FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ) &&
          (FanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE))
      {
        hm_device[opencl_device_index].fan_get_supported = 1;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = 0;
      }
    }
    else // od_version == 6
    {
      ADLOD6FanSpeedInfo faninfo;

      memset (&faninfo, 0, sizeof (faninfo));

      if (hm_ADL_Overdrive6_FanSpeed_Get (adl, info.iAdapterIndex, &faninfo) != ADL_OK) return -1;

      // check read capability in fanspeedinfo

      if (faninfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_PERCENT)
      {
        hm_device[opencl_device_index].fan_get_supported = 1;
      }
      else
      {
        hm_device[opencl_device_index].fan_get_supported = 0;
      }
    }
  }

  return 0;
}

int hm_get_overdrive_version (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // get overdrive version

    int od_supported = 0;
    int od_enabled   = 0;
    int od_version   = 0;

    if (hm_ADL_Overdrive_Caps (adl, info.iAdapterIndex, &od_supported, &od_enabled, &od_version) != ADL_OK) return -1;

    // store the overdrive version in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].od_version = od_version;
  }

  return 0;
}

int hm_get_adapter_index_adl (hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo)
{
  for (int i = 0; i < num_adl_adapters; i++)
  {
    u32 adapter_index = valid_adl_device_list[i];

    // get AdapterInfo

    AdapterInfo info = lpAdapterInfo[adapter_index];

    // store the iAdapterIndex in hm_device

    // unfortunately this doesn't work since bus id and dev id are not unique
    // int opencl_device_index = hm_get_opencl_device_index (hm_device, num_adl_adapters, info.iBusNumber, info.iDeviceNumber);
    // if (opencl_device_index == -1) continue;

    int opencl_device_index = i;

    hm_device[opencl_device_index].adl = info.iAdapterIndex;
  }

  return num_adl_adapters;
}

int hm_get_threshold_slowdown_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {

      }
      else if (data.hm_device[device_id].od_version == 6)
      {
        int CurrentValue = 0;
        int DefaultValue = 0;

        if (hm_ADL_Overdrive6_TargetTemperatureData_Get (data.hm_adl, data.hm_device[device_id].adl, &CurrentValue, &DefaultValue) != ADL_OK) return -1;

        // the return value has never been tested since hm_ADL_Overdrive6_TargetTemperatureData_Get() never worked on any system. expect problems.

        return DefaultValue;
      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_threshold_shutdown_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {

      }
      else if (data.hm_device[device_id].od_version == 6)
      {

      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int target = 0;

    if (hm_NVML_nvmlDeviceGetTemperatureThreshold (data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) != NVML_SUCCESS) return -1;

    return target;
  }

  return -1;
}

int hm_get_temperature_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      if (data.hm_device[device_id].od_version == 5)
      {
        ADLTemperature Temperature;

        Temperature.iSize = sizeof (ADLTemperature);

        if (hm_ADL_Overdrive5_Temperature_Get (data.hm_adl, data.hm_device[device_id].adl, 0, &Temperature) != ADL_OK) return -1;

        return Temperature.iTemperature / 1000;
      }
      else if (data.hm_device[device_id].od_version == 6)
      {
        int Temperature = 0;

        if (hm_ADL_Overdrive6_Temperature_Get (data.hm_adl, data.hm_device[device_id].adl, &Temperature) != ADL_OK) return -1;

        return Temperature / 1000;
      }
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    int temperature = 0;

    if (hm_NVML_nvmlDeviceGetTemperature (data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_TEMPERATURE_GPU, (uint *) &temperature) != NVML_SUCCESS) return -1;

    return temperature;
  }

  return -1;
}

int hm_get_fanpolicy_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.hm_device[device_id].fan_get_supported == 1)
  {
    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (data.hm_adl)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

          if (hm_ADL_Overdrive5_FanSpeed_Get (data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
        }
        else // od_version == 6
        {
          return 1;
        }
      }
    }

    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      return 1;
    }
  }

  return -1;
}

int hm_get_fanspeed_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.hm_device[device_id].fan_get_supported == 1)
  {
    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
    {
      if (data.hm_adl)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

          if (hm_ADL_Overdrive5_FanSpeed_Get (data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return lpFanSpeedValue.iFanSpeed;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedInfo faninfo;

          memset (&faninfo, 0, sizeof (faninfo));

          if (hm_ADL_Overdrive6_FanSpeed_Get (data.hm_adl, data.hm_device[device_id].adl, &faninfo) != ADL_OK) return -1;

          return faninfo.iFanSpeedPercent;
        }
      }
    }

    if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (data.hm_nvml, 0, data.hm_device[device_id].nvml, (uint *) &speed) != NVML_SUCCESS) return -1;

      return speed;
    }
  }

  return -1;
}

int hm_get_buslanes_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iCurrentBusLanes;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int currLinkWidth;

    if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (data.hm_nvml, 1, data.hm_device[device_id].nvml, &currLinkWidth) != NVML_SUCCESS) return -1;

    return currLinkWidth;
  }

  return -1;
}

int hm_get_utilization_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iActivityPercent;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    nvmlUtilization_t utilization;

    if (hm_NVML_nvmlDeviceGetUtilizationRates (data.hm_nvml, 1, data.hm_device[device_id].nvml, &utilization) != NVML_SUCCESS) return -1;

    return utilization.gpu;
  }

  return -1;
}

int hm_get_memoryspeed_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iMemoryClock / 100;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_CLOCK_MEM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_corespeed_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {
    if (data.hm_adl)
    {
      ADLPMActivity PMActivity;

      PMActivity.iSize = sizeof (ADLPMActivity);

      if (hm_ADL_Overdrive_CurrentActivity_Get (data.hm_adl, data.hm_device[device_id].adl, &PMActivity) != ADL_OK) return -1;

      return PMActivity.iEngineClock / 100;
    }
  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned int clock;

    if (hm_NVML_nvmlDeviceGetClockInfo (data.hm_nvml, 1, data.hm_device[device_id].nvml, NVML_CLOCK_SM, &clock) != NVML_SUCCESS) return -1;

    return clock;
  }

  return -1;
}

int hm_get_throttle_with_device_id (const uint device_id)
{
  if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) return -1;

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
  {

  }

  if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
  {
    unsigned long long clocksThrottleReasons = 0;
    unsigned long long supportedThrottleReasons = 0;

    if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (data.hm_nvml, 1, data.hm_device[device_id].nvml, &clocksThrottleReasons)    != NVML_SUCCESS) return -1;
    if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (data.hm_nvml, 1, data.hm_device[device_id].nvml, &supportedThrottleReasons) != NVML_SUCCESS) return -1;

    clocksThrottleReasons &=  supportedThrottleReasons;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
    clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

    if (data.kernel_power_final)
    {
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
    }

    return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_adl (const uint device_id, const int fanspeed, const int fanpolicy)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_adl)
    {
      if (fanpolicy == 1)
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          ADLFanSpeedValue lpFanSpeedValue;

          memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

          lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
          lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
          lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;
          lpFanSpeedValue.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive5_FanSpeed_Set (data.hm_adl, data.hm_device[device_id].adl, 0, &lpFanSpeedValue) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          ADLOD6FanSpeedValue fan_speed_value;

          memset (&fan_speed_value, 0, sizeof (fan_speed_value));

          fan_speed_value.iSpeedType = ADL_OD6_FANSPEED_TYPE_PERCENT;
          fan_speed_value.iFanSpeed  = fanspeed;

          if (hm_ADL_Overdrive6_FanSpeed_Set (data.hm_adl, data.hm_device[device_id].adl, &fan_speed_value) != ADL_OK) return -1;

          return 0;
        }
      }
      else
      {
        if (data.hm_device[device_id].od_version == 5)
        {
          if (hm_ADL_Overdrive5_FanSpeedToDefault_Set (data.hm_adl, data.hm_device[device_id].adl, 0) != ADL_OK) return -1;

          return 0;
        }
        else // od_version == 6
        {
          if (hm_ADL_Overdrive6_FanSpeed_Reset (data.hm_adl, data.hm_device[device_id].adl) != ADL_OK) return -1;

          return 0;
        }
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_nvapi (const uint device_id, const int fanspeed, const int fanpolicy)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_nvapi)
    {
      if (fanpolicy == 1)
      {
        NV_GPU_COOLER_LEVELS CoolerLevels = { 0 };

        CoolerLevels.Version = GPU_COOLER_LEVELS_VER | sizeof (NV_GPU_COOLER_LEVELS);

        CoolerLevels.Levels[0].Level  = fanspeed;
        CoolerLevels.Levels[0].Policy = 1;

        if (hm_NvAPI_GPU_SetCoolerLevels (data.hm_nvapi, data.hm_device[device_id].nvapi, 0, &CoolerLevels) != NVAPI_OK) return -1;

        return 0;
      }
      else
      {
        if (hm_NvAPI_GPU_RestoreCoolerSettings (data.hm_nvapi, data.hm_device[device_id].nvapi, 0) != NVAPI_OK) return -1;

        return 0;
      }
    }
  }

  return -1;
}

int hm_set_fanspeed_with_device_id_xnvctrl (const uint device_id, const int fanspeed)
{
  if (data.hm_device[device_id].fan_set_supported == 1)
  {
    if (data.hm_xnvctrl)
    {
      if (set_fan_speed_target (data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, fanspeed) != 0) return -1;

      return 0;
    }
  }

  return -1;
}

#endif // HAVE_HWMON

/**
 * maskprocessor
 */

void mp_css_to_uniq_tbl (uint css_cnt, cs_t *css, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    log_error ("ERROR: Mask length is too long");

    exit (-1);
  }

  for (uint css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    uint *uniq_tbl = uniq_tbls[css_pos];

    uint *cs_buf = css[css_pos].cs_buf;
    uint  cs_len = css[css_pos].cs_len;

    for (uint cs_pos = 0; cs_pos < cs_len; cs_pos++)
    {
      uint c = cs_buf[cs_pos] & 0xff;

      uniq_tbl[c] = 1;
    }
  }
}

void mp_add_cs_buf (uint *in_buf, size_t in_len, cs_t *css, int css_cnt)
{
  cs_t *cs = &css[css_cnt];

  size_t css_uniq_sz = CHARSIZ * sizeof (uint);

  uint *css_uniq = (uint *) mymalloc (css_uniq_sz);

  size_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    const uint u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    uint u = in_buf[i] & 0xff;

    if (data.opts_type & OPTS_TYPE_PT_UPPER) u = toupper (u);

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  myfree (css_uniq);
}

void mp_expand (char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, int mp_usr_offset, int interpret)
{
  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    uint p0 = in_buf[in_pos] & 0xff;

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      uint p1 = in_buf[in_pos] & 0xff;

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { log_error ("ERROR: Custom-charset 1 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[0].cs_buf, mp_usr[0].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { log_error ("ERROR: Custom-charset 2 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[1].cs_buf, mp_usr[1].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { log_error ("ERROR: Custom-charset 3 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[2].cs_buf, mp_usr[2].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { log_error ("ERROR: Custom-charset 4 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[3].cs_buf, mp_usr[3].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '?': mp_add_cs_buf (&p0, 1, mp_usr, mp_usr_offset);
                  break;
        default:  log_error ("Syntax error: %s", in_buf);
                  exit (-1);
      }
    }
    else
    {
      if (data.hex_charset)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

          exit (-1);
        }

        uint p1 = in_buf[in_pos] & 0xff;

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", in_buf);

          exit (-1);
        }

        uint chr = 0;

        chr  = hex_convert (p1) << 0;
        chr |= hex_convert (p0) << 4;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset);
      }
      else
      {
        uint chr = p0;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset);
      }
    }
  }
}

u64 mp_get_sum (uint css_cnt, cs_t *css)
{
  u64 sum = 1;

  for (uint css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    sum *= css[css_pos].cs_len;
  }

  return (sum);
}

cs_t *mp_gen_css (char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint *css_cnt)
{
  cs_t *css = (cs_t *) mycalloc (256, sizeof (cs_t));

  uint mask_pos;
  uint css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    char p0 = mask_buf[mask_pos];

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      char p1 = mask_buf[mask_pos];

      uint chr = p1;

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, css, css_pos);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, css, css_pos);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, css, css_pos);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, css, css_pos);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, css, css_pos);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, css, css_pos);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { log_error ("ERROR: Custom-charset 1 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[0].cs_buf, mp_usr[0].cs_len, css, css_pos);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { log_error ("ERROR: Custom-charset 2 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[1].cs_buf, mp_usr[1].cs_len, css, css_pos);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { log_error ("ERROR: Custom-charset 3 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[2].cs_buf, mp_usr[2].cs_len, css, css_pos);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { log_error ("ERROR: Custom-charset 4 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[3].cs_buf, mp_usr[3].cs_len, css, css_pos);
                  break;
        case '?': mp_add_cs_buf (&chr, 1, css, css_pos);
                  break;
        default:  log_error ("ERROR: Syntax error: %s", mask_buf);
                  exit (-1);
      }
    }
    else
    {
      if (data.hex_charset)
      {
        mask_pos++;

        // if there is no 2nd hex character, show an error:

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", mask_buf);

          exit (-1);
        }

        uint chr = 0;

        chr |= hex_convert (p1) << 0;
        chr |= hex_convert (p0) << 4;

        mp_add_cs_buf (&chr, 1, css, css_pos);
      }
      else
      {
        uint chr = p0;

        mp_add_cs_buf (&chr, 1, css, css_pos);
      }
    }
  }

  if (css_pos == 0)
  {
    log_error ("ERROR: Invalid mask length (0)");

    exit (-1);
  }

  *css_cnt = css_pos;

  return (css);
}

void mp_exec (u64 val, char *buf, cs_t *css, int css_cnt)
{
  for (int i = 0; i < css_cnt; i++)
  {
    uint len  = css[i].cs_len;
    u64 next = val / len;
    uint pos  = val % len;
    buf[i] = (char) css[i].cs_buf[pos] & 0xff;
    val = next;
  }
}

void mp_cut_at (char *mask, uint max)
{
  uint i;
  uint j;
  uint mask_len = strlen (mask);

  for (i = 0, j = 0; i < mask_len && j < max; i++, j++)
  {
    if (mask[i] == '?') i++;
  }

  mask[i] = 0;
}

void mp_setup_sys (cs_t *mp_sys)
{
  uint pos;
  uint chr;
  uint donec[CHARSIZ] = { 0 };

  for (pos = 0, chr =  'a'; chr <=  'z'; chr++) { donec[chr] = 1;
                                                  mp_sys[0].cs_buf[pos++] = chr;
                                                  mp_sys[0].cs_len = pos; }

  for (pos = 0, chr =  'A'; chr <=  'Z'; chr++) { donec[chr] = 1;
                                                  mp_sys[1].cs_buf[pos++] = chr;
                                                  mp_sys[1].cs_len = pos; }

  for (pos = 0, chr =  '0'; chr <=  '9'; chr++) { donec[chr] = 1;
                                                  mp_sys[2].cs_buf[pos++] = chr;
                                                  mp_sys[2].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { if (donec[chr]) continue;
                                                  mp_sys[3].cs_buf[pos++] = chr;
                                                  mp_sys[3].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { mp_sys[4].cs_buf[pos++] = chr;
                                                  mp_sys[4].cs_len = pos; }

  for (pos = 0, chr = 0x00; chr <= 0xff; chr++) { mp_sys[5].cs_buf[pos++] = chr;
                                                  mp_sys[5].cs_len = pos; }
}

void mp_setup_usr (cs_t *mp_sys, cs_t *mp_usr, char *buf, uint index)
{
  FILE *fp = fopen (buf, "rb");

  if (fp == NULL || feof (fp)) // feof() in case if file is empty
  {
    mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1);
  }
  else
  {
    char mp_file[1024] = { 0 };

    size_t len = fread (mp_file, 1, sizeof (mp_file) - 1, fp);

    fclose (fp);

    len = in_superchop (mp_file);

    if (len == 0)
    {
      log_info ("WARNING: Charset file corrupted");

      mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1);
    }
    else
    {
      mp_expand (mp_file, len, mp_sys, mp_usr, index, 0);
    }
  }
}

void mp_reset_usr (cs_t *mp_usr, uint index)
{
  mp_usr[index].cs_len = 0;

  memset (mp_usr[index].cs_buf, 0, sizeof (mp_usr[index].cs_buf));
}

char *mp_get_truncated_mask (char *mask_buf, size_t mask_len, uint len)
{
  char *new_mask_buf = (char *) mymalloc (256);

  uint mask_pos;

  uint css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    if (css_pos == len) break;

    char p0 = mask_buf[mask_pos];

    new_mask_buf[mask_pos] = p0;

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      new_mask_buf[mask_pos] = mask_buf[mask_pos];
    }
    else
    {
      if (data.hex_charset)
      {
        mask_pos++;

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: Invalid hex character detected in mask: %s", mask_buf);

          exit (-1);
        }

        new_mask_buf[mask_pos] = p1;
      }
    }
  }

  if (css_pos == len) return (new_mask_buf);

  myfree (new_mask_buf);

  return (NULL);
}

/**
 * statprocessor
 */

u64 sp_get_sum (uint start, uint stop, cs_t *root_css_buf)
{
  u64 sum = 1;

  uint i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
}

void sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint start, uint stop)
{
  u64 v = ctx;

  cs_t *cs = &root_css_buf[start];

  uint i;

  for (i = start; i < stop; i++)
  {
    const u64 m = v % cs->cs_len;
    const u64 d = v / cs->cs_len;

    v = d;

    const uint k = cs->cs_buf[m];

    pw_buf[i - start] = (char) k;

    cs = &markov_css_buf[(i * CHARSIZ) + k];
  }
}

int sp_comp_val (const void *p1, const void *p2)
{
  hcstat_table_t *b1 = (hcstat_table_t *) p1;
  hcstat_table_t *b2 = (hcstat_table_t *) p2;

  return b2->val - b1->val;
}

void sp_setup_tbl (const char *shared_dir, char *hcstat, uint disable, uint classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf)
{
  uint i;
  uint j;
  uint k;

  /**
   * Initialize hcstats
   */

  u64 *root_stats_buf = (u64 *) mycalloc (SP_ROOT_CNT, sizeof (u64));

  u64 *root_stats_ptr = root_stats_buf;

  u64 *root_stats_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  u64 *markov_stats_buf = (u64 *) mycalloc (SP_MARKOV_CNT, sizeof (u64));

  u64 *markov_stats_ptr = markov_stats_buf;

  u64 *markov_stats_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /**
   * Load hcstats File
   */

  if (hcstat == NULL)
  {
    char hcstat_tmp[256] = { 0 };

    snprintf (hcstat_tmp, sizeof (hcstat_tmp) - 1, "%s/%s", shared_dir, SP_HCSTAT);

    hcstat = hcstat_tmp;
  }

  FILE *fd = fopen (hcstat, "rb");

  if (fd == NULL)
  {
    log_error ("%s: %s", hcstat, strerror (errno));

    exit (-1);
  }

  if (fread (root_stats_buf, sizeof (u64), SP_ROOT_CNT, fd) != SP_ROOT_CNT)
  {
    log_error ("%s: Could not load data", hcstat);

    fclose (fd);

    exit (-1);
  }

  if (fread (markov_stats_buf, sizeof (u64), SP_MARKOV_CNT, fd) != SP_MARKOV_CNT)
  {
    log_error ("%s: Could not load data", hcstat);

    fclose (fd);

    exit (-1);
  }

  fclose (fd);

  /**
   * Markov modifier of hcstat_table on user request
   */

  if (disable)
  {
    memset (root_stats_buf,   0, SP_ROOT_CNT   * sizeof (u64));
    memset (markov_stats_buf, 0, SP_MARKOV_CNT * sizeof (u64));
  }

  if (classic)
  {
    /* Add all stats to first position */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = root_stats_buf_by_pos[0];
      u64 *in  = root_stats_buf_by_pos[i];

      for (j = 0; j < CHARSIZ; j++)
      {
        *out++ += *in++;
      }
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = markov_stats_buf_by_key[0][0];
      u64 *in  = markov_stats_buf_by_key[i][0];

      for (j = 0; j < CHARSIZ; j++)
      {
        for (k = 0; k < CHARSIZ; k++)
        {
          *out++ += *in++;
        }
      }
    }

    /* copy them to all pw_positions */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (root_stats_buf_by_pos[i], root_stats_buf_by_pos[0], CHARSIZ * sizeof (u64));
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (markov_stats_buf_by_key[i][0], markov_stats_buf_by_key[0][0], CHARSIZ * CHARSIZ * sizeof (u64));
    }
  }

  /**
   * Initialize tables
   */

  hcstat_table_t *root_table_ptr = root_table_buf;

  hcstat_table_t *root_table_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_table_buf_by_pos[i] = root_table_ptr;

    root_table_ptr += CHARSIZ;
  }

  hcstat_table_t *markov_table_ptr = markov_table_buf;

  hcstat_table_t *markov_table_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_table_buf_by_key[i][j] = markov_table_ptr;

      markov_table_ptr += CHARSIZ;
    }
  }

  /**
   * Convert hcstat to tables
   */

  for (i = 0; i < SP_ROOT_CNT; i++)
  {
    uint key = i % CHARSIZ;

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint key = i % CHARSIZ;

    markov_table_buf[i].key = key;
    markov_table_buf[i].val = markov_stats_buf[i];
  }

  myfree (root_stats_buf);
  myfree (markov_stats_buf);

  /**
   * Finally sort them
   */

  for (i = 0; i < SP_PW_MAX; i++)
  {
    qsort (root_table_buf_by_pos[i], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
  }

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      qsort (markov_table_buf_by_key[i][j], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
    }
  }
}

void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint threshold, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /**
   * Convert tables to css
   */

  for (uint i = 0; i < SP_ROOT_CNT; i++)
  {
    uint pw_pos = i / CHARSIZ;

    cs_t *cs = &root_css_buf[pw_pos];

    if (cs->cs_len == threshold) continue;

    uint key = root_table_buf[i].key;

    if (uniq_tbls[pw_pos][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /**
   * Convert table to css
   */

  for (uint i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint c = i / CHARSIZ;

    cs_t *cs = &markov_css_buf[c];

    if (cs->cs_len == threshold) continue;

    uint pw_pos = c / CHARSIZ;

    uint key = markov_table_buf[i].key;

    if ((pw_pos + 1) < SP_PW_MAX) if (uniq_tbls[pw_pos + 1][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /*
  for (uint i = 0; i < 8; i++)
  {
    for (uint j = 0x20; j < 0x80; j++)
    {
      cs_t *ptr = &markov_css_buf[(i * CHARSIZ) + j];

      printf ("pos:%u key:%u len:%u\n", i, j, ptr->cs_len);

      for (uint k = 0; k < 10; k++)
      {
        printf ("  %u\n",  ptr->cs_buf[k]);
      }
    }
  }
  */
}

void sp_stretch_root (hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ;
    in  += CHARSIZ;

    out->key = 0;
    out->val = 1;

    out++;

    for (uint j = 1; j < CHARSIZ; j++)
    {
      out->key = j;
      out->val = 0;

      out++;
    }
  }
}

void sp_stretch_markov (hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ * CHARSIZ;
    in  += CHARSIZ * CHARSIZ;

    for (uint j = 0; j < CHARSIZ; j++)
    {
      out->key = 0;
      out->val = 1;

      out++;

      for (uint k = 1; k < CHARSIZ; k++)
      {
        out->key = k;
        out->val = 0;

        out++;
      }
    }
  }
}

/**
 * mixed shared functions
 */

void dump_hex (const u8 *s, const int sz)
{
  for (int i = 0; i < sz; i++)
  {
    log_info_nn ("%02x ", s[i]);
  }

  log_info ("");
}

void usage_mini_print (const char *progname)
{
  for (uint i = 0; USAGE_MINI[i] != NULL; i++) log_info (USAGE_MINI[i], progname);
}

void usage_big_print (const char *progname)
{
  for (uint i = 0; USAGE_BIG[i] != NULL; i++) log_info (USAGE_BIG[i], progname);
}

char *get_exec_path ()
{
  int exec_path_len = 1024;

  char *exec_path = (char *) mymalloc (exec_path_len);

  #ifdef LINUX

  char tmp[32] = { 0 };

  snprintf (tmp, sizeof (tmp) - 1, "/proc/%d/exe", getpid ());

  const int len = readlink (tmp, exec_path, exec_path_len - 1);

  #elif WIN

  const int len = GetModuleFileName (NULL, exec_path, exec_path_len - 1);

  #elif DARWIN

  uint size = exec_path_len;

  if (_NSGetExecutablePath (exec_path, &size) != 0)
  {
    log_error("! executable path buffer too small\n");

    exit (-1);
  }

  const int len = strlen (exec_path);

  #else
  #error Your Operating System is not supported or detected
  #endif

  exec_path[len] = 0;

  return exec_path;
}

char *get_install_dir (const char *progname)
{
  char *install_dir = mystrdup (progname);
  char *last_slash  = NULL;

  if ((last_slash = strrchr (install_dir, '/')) != NULL)
  {
    *last_slash = 0;
  }
  else if ((last_slash = strrchr (install_dir, '\\')) != NULL)
  {
    *last_slash = 0;
  }
  else
  {
    install_dir[0] = '.';
    install_dir[1] = 0;
  }

  return (install_dir);
}

char *get_profile_dir (const char *homedir)
{
  #define DOT_HASHCAT ".hashcat"

  size_t len = strlen (homedir) + 1 + strlen (DOT_HASHCAT) + 1;

  char *profile_dir = (char *) mymalloc (len + 1);

  snprintf (profile_dir, len, "%s/%s", homedir, DOT_HASHCAT);

  return profile_dir;
}

char *get_session_dir (const char *profile_dir)
{
  #define SESSIONS_FOLDER "sessions"

  size_t len = strlen (profile_dir) + 1 + strlen (SESSIONS_FOLDER) + 1;

  char *session_dir = (char *) mymalloc (len + 1);

  snprintf (session_dir, len, "%s/%s", profile_dir, SESSIONS_FOLDER);

  return session_dir;
}

uint count_lines (FILE *fd)
{
  uint cnt = 0;

  char *buf = (char *) mymalloc (HCBUFSIZ + 1);

  char prev = '\n';

  while (!feof (fd))
  {
    size_t nread = fread (buf, sizeof (char), HCBUFSIZ, fd);

    if (nread < 1) continue;

    size_t i;

    for (i = 0; i < nread; i++)
    {
      if (prev == '\n') cnt++;

      prev = buf[i];
    }
  }

  myfree (buf);

  return cnt;
}

void truecrypt_crc32 (const char *filename, u8 keytab[64])
{
  uint crc = ~0;

  FILE *fd = fopen (filename, "rb");

  if (fd == NULL)
  {
    log_error ("%s: %s", filename, strerror (errno));

    exit (-1);
  }

  #define MAX_KEY_SIZE (1024 * 1024)

  u8 *buf = (u8 *) mymalloc (MAX_KEY_SIZE + 1);

  int nread = fread (buf, sizeof (u8), MAX_KEY_SIZE, fd);

  fclose (fd);

  int kpos = 0;

  for (int fpos = 0; fpos < nread; fpos++)
  {
    crc = crc32tab[(crc ^ buf[fpos]) & 0xff] ^ (crc >> 8);

    keytab[kpos++] += (crc >> 24) & 0xff;
    keytab[kpos++] += (crc >> 16) & 0xff;
    keytab[kpos++] += (crc >>  8) & 0xff;
    keytab[kpos++] += (crc >>  0) & 0xff;

    if (kpos >= 64) kpos = 0;
  }

  myfree (buf);
}

#ifdef DARWIN
int pthread_setaffinity_np (pthread_t thread, size_t cpu_size, cpu_set_t *cpu_set)
{
  int core;

  for (core = 0; core < (8 * (int)cpu_size); core++)
    if (CPU_ISSET(core, cpu_set)) break;

  thread_affinity_policy_data_t policy = { core };

  const int rc = thread_policy_set (pthread_mach_thread_np (thread), THREAD_AFFINITY_POLICY, (thread_policy_t) &policy, 1);

  if (data.quiet == 0)
  {
    if (rc != KERN_SUCCESS)
    {
      log_error ("ERROR: %s : %d", "thread_policy_set()", rc);
    }
  }

  return rc;
}
#endif

void set_cpu_affinity (char *cpu_affinity)
{
  #ifdef _WIN
  DWORD_PTR aff_mask = 0;
  #elif _POSIX
  cpu_set_t cpuset;
  CPU_ZERO (&cpuset);
  #endif

  if (cpu_affinity)
  {
    char *devices = strdup (cpu_affinity);

    char *next = strtok (devices, ",");

    do
    {
      uint cpu_id = atoi (next);

      if (cpu_id == 0)
      {
        #ifdef _WIN
        aff_mask = 0;
        #elif _POSIX
        CPU_ZERO (&cpuset);
        #endif

        break;
      }

      if (cpu_id > 32)
      {
        log_error ("ERROR: Invalid cpu_id %u specified", cpu_id);

        exit (-1);
      }

      #ifdef _WIN
      aff_mask |= 1 << (cpu_id - 1);
      #elif _POSIX
      CPU_SET ((cpu_id - 1), &cpuset);
      #endif

    } while ((next = strtok (NULL, ",")) != NULL);

    free (devices);
  }

  #ifdef _WIN
  SetProcessAffinityMask (GetCurrentProcess (), aff_mask);
  SetThreadAffinityMask (GetCurrentThread (), aff_mask);
  #elif _POSIX
  pthread_t thread = pthread_self ();
  pthread_setaffinity_np (thread, sizeof (cpu_set_t), &cpuset);
  #endif
}

void *rulefind (const void *key, void *base, int nmemb, size_t size, int (*compar) (const void *, const void *))
{
  char *element, *end;

  end = (char *) base + nmemb * size;

  for (element = (char *) base; element < end; element += size)
    if (!compar (element, key))
      return element;

  return NULL;
}

int sort_by_u32 (const void *v1, const void *v2)
{
  const u32 *s1 = (const u32 *) v1;
  const u32 *s2 = (const u32 *) v2;

  return *s1 - *s2;
}

int sort_by_salt (const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *) v1;
  const salt_t *s2 = (const salt_t *) v2;

  const int res1 = s1->salt_len - s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = s1->salt_iter - s2->salt_iter;

  if (res2 != 0) return (res2);

  uint n;

  n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return (-1);
  }

  n = 8;

  while (n--)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return ( 1);
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return (-1);
  }

  return (0);
}

int sort_by_salt_buf (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return (-1);
  }

  return 0;
}

int sort_by_hash_t_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // testphase: this should work
  uint n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return (-1);
  }

  /* original code, seems buggy since salt_len can be very big (had a case with 131 len)
     also it thinks salt_buf[x] is a char but its a uint so salt_len should be / 4
  if (s1->salt_len > s2->salt_len) return ( 1);
  if (s1->salt_len < s2->salt_len) return (-1);

  uint n = s1->salt_len;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return (-1);
  }
  */

  return 0;
}

int sort_by_hash_t_salt_hccap (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // 16 - 2 (since last 2 uints contain the digest)
  uint n = 14;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return (-1);
  }

  return 0;
}

int sort_by_hash_no_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest (d1, d2);
}

int sort_by_hash (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  if (data.isSalted)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return data.sort_by_digest (d1, d2);
}

int sort_by_pot (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  return sort_by_hash (h1, h2);
}

int sort_by_mtime (const void *p1, const void *p2)
{
  const char **f1 = (const char **) p1;
  const char **f2 = (const char **) p2;

  struct stat s1; stat (*f1, &s1);
  struct stat s2; stat (*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}

int sort_by_cpu_rule (const void *p1, const void *p2)
{
  const cpu_rule_t *r1 = (const cpu_rule_t *) p1;
  const cpu_rule_t *r2 = (const cpu_rule_t *) p2;

  return memcmp (r1, r2, sizeof (cpu_rule_t));
}

int sort_by_kernel_rule (const void *p1, const void *p2)
{
  const kernel_rule_t *r1 = (const kernel_rule_t *) p1;
  const kernel_rule_t *r2 = (const kernel_rule_t *) p2;

  return memcmp (r1, r2, sizeof (kernel_rule_t));
}

int sort_by_stringptr (const void *p1, const void *p2)
{
  const char **s1 = (const char **) p1;
  const char **s2 = (const char **) p2;

  return strcmp (*s1, *s2);
}

int sort_by_dictstat (const void *s1, const void *s2)
{
  dictstat_t *d1 = (dictstat_t *) s1;
  dictstat_t *d2 = (dictstat_t *) s2;

  #ifdef _LINUX
  d2->stat.st_atim = d1->stat.st_atim;
  #else
  d2->stat.st_atime = d1->stat.st_atime;
  #endif

  return memcmp (&d1->stat, &d2->stat, sizeof (struct stat));
}

int sort_by_bitmap (const void *p1, const void *p2)
{
  const bitmap_result_t *b1 = (const bitmap_result_t *) p1;
  const bitmap_result_t *b2 = (const bitmap_result_t *) p2;

  return b1->collisions - b2->collisions;
}

int sort_by_digest_4_2 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 2;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_4 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 4;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_5 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 5;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_6 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 6;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_8 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_16 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_32 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 32;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_4_64 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  uint n = 64;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_8_8 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 8;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_8_16 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 16;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_8_25 (const void *v1, const void *v2)
{
  const u64 *d1 = (const u64 *) v1;
  const u64 *d2 = (const u64 *) v2;

  uint n = 25;

  while (n--)
  {
    if (d1[n] > d2[n]) return ( 1);
    if (d1[n] < d2[n]) return (-1);
  }

  return (0);
}

int sort_by_digest_p0p1 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  const uint dgst_pos0 = data.dgst_pos0;
  const uint dgst_pos1 = data.dgst_pos1;
  const uint dgst_pos2 = data.dgst_pos2;
  const uint dgst_pos3 = data.dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return ( 1);
  if (d1[dgst_pos3] < d2[dgst_pos3]) return (-1);
  if (d1[dgst_pos2] > d2[dgst_pos2]) return ( 1);
  if (d1[dgst_pos2] < d2[dgst_pos2]) return (-1);
  if (d1[dgst_pos1] > d2[dgst_pos1]) return ( 1);
  if (d1[dgst_pos1] < d2[dgst_pos1]) return (-1);
  if (d1[dgst_pos0] > d2[dgst_pos0]) return ( 1);
  if (d1[dgst_pos0] < d2[dgst_pos0]) return (-1);

  return (0);
}

int sort_by_tuning_db_alias (const void *v1, const void *v2)
{
  const tuning_db_alias_t *t1 = (const tuning_db_alias_t *) v1;
  const tuning_db_alias_t *t2 = (const tuning_db_alias_t *) v2;

  const int res1 = strcmp (t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  return 0;
}

int sort_by_tuning_db_entry (const void *v1, const void *v2)
{
  const tuning_db_entry_t *t1 = (const tuning_db_entry_t *) v1;
  const tuning_db_entry_t *t2 = (const tuning_db_entry_t *) v2;

  const int res1 = strcmp (t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  const int res2 = t1->attack_mode
                 - t2->attack_mode;

  if (res2 != 0) return (res2);

  const int res3 = t1->hash_type
                 - t2->hash_type;

  if (res3 != 0) return (res3);

  return 0;
}

void format_debug (char *debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len)
{
  uint outfile_autohex = data.outfile_autohex;

  unsigned char *rule_ptr = (unsigned char *) rule_buf;

  FILE *debug_fp = NULL;

  if (debug_file != NULL)
  {
    debug_fp = fopen (debug_file, "ab");

    lock_file (debug_fp);
  }
  else
  {
    debug_fp = stderr;
  }

  if (debug_fp == NULL)
  {
    log_info ("WARNING: Could not open debug-file for writing");
  }
  else
  {
    if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
    {
      format_plain (debug_fp, orig_plain_ptr, orig_plain_len, outfile_autohex);

      if ((debug_mode == 3) || (debug_mode == 4)) fputc (':', debug_fp);
    }

    fwrite (rule_ptr, rule_len, 1, debug_fp);

    if (debug_mode == 4)
    {
      fputc (':', debug_fp);

      format_plain (debug_fp, mod_plain_ptr, mod_plain_len, outfile_autohex);
    }

    fputc  ('\n', debug_fp);

    if (debug_file != NULL) fclose (debug_fp);
  }
}

void format_plain (FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex)
{
  int needs_hexify = 0;

  if (outfile_autohex == 1)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      if (plain_ptr[i] < 0x20)
      {
        needs_hexify = 1;

        break;
      }

      if (plain_ptr[i] > 0x7f)
      {
        needs_hexify = 1;

        break;
      }
    }
  }

  if (needs_hexify == 1)
  {
    fprintf (fp, "$HEX[");

    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (fp, "%02x", plain_ptr[i]);
    }

    fprintf (fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, fp);
  }
}

void format_output (FILE *out_fp, char *out_buf, unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, unsigned char *username, const uint user_len)
{
  uint outfile_format = data.outfile_format;

  char separator = data.separator;

  if (outfile_format & OUTFILE_FMT_HASH)
  {
    fprintf (out_fp, "%s", out_buf);

    if (outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }
  else if (data.username)
  {
    if (username != NULL)
    {
      for (uint i = 0; i < user_len; i++)
      {
        fprintf (out_fp, "%c", username[i]);
      }

      if (outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
      {
        fputc (separator, out_fp);
      }
    }
  }

  if (outfile_format & OUTFILE_FMT_PLAIN)
  {
    format_plain (out_fp, plain_ptr, plain_len, data.outfile_autohex);

    if (outfile_format & (OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }

  if (outfile_format & OUTFILE_FMT_HEXPLAIN)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (out_fp, "%02x", plain_ptr[i]);
    }

    if (outfile_format & (OUTFILE_FMT_CRACKPOS))
    {
      fputc (separator, out_fp);
    }
  }

  if (outfile_format & OUTFILE_FMT_CRACKPOS)
  {
    #ifdef _WIN
    __mingw_fprintf (out_fp, "%llu", crackpos);
    #endif

    #ifdef _POSIX
    #ifdef __x86_64__
    fprintf (out_fp, "%lu", (unsigned long) crackpos);
    #else
    fprintf (out_fp, "%llu", crackpos);
    #endif
    #endif
  }

  fputc ('\n', out_fp);
}

void handle_show_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  pot_t pot_key;

  pot_key.hash.salt   = hashes_buf->salt;
  pot_key.hash.digest = hashes_buf->digest;

  pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_ptr)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    // user
    unsigned char *username = NULL;
    uint user_len = 0;

    if (data.username)
    {
      user_t *user = hashes_buf->hash_info->user;

      if (user)
      {
        username = (unsigned char *) (user->user_name);

        user_len = user->user_len;
      }
    }

    // do output the line
    format_output (out_fp, input_buf, (unsigned char *) pot_ptr->plain_buf, pot_ptr->plain_len, 0, username, user_len);
  }
}

#define LM_WEAK_HASH    "\x4e\xcf\x0d\x0c\x0a\xe2\xfb\xc1"
#define LM_MASKED_PLAIN "[notfound]"

void handle_show_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  // left

  pot_t pot_left_key;

  pot_left_key.hash.salt   = hash_left->salt;
  pot_left_key.hash.digest = hash_left->digest;

  pot_t *pot_left_ptr = (pot_t *) bsearch (&pot_left_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  // right

  uint weak_hash_found = 0;

  pot_t pot_right_key;

  pot_right_key.hash.salt   = hash_right->salt;
  pot_right_key.hash.digest = hash_right->digest;

  pot_t *pot_right_ptr = (pot_t *) bsearch (&pot_right_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

      // in theory this is not needed, but we are paranoia:

      memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));
      pot_right_ptr->plain_len = 0;
    }
  }

  if ((pot_left_ptr == NULL) && (pot_right_ptr == NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr); // this shouldn't happen at all: if weak_hash_found == 1, than pot_right_ptr is not NULL for sure

    return;
  }

  // at least one half was found:

  log_info_nn ("");

  input_buf[input_len] = 0;

  // user

  unsigned char *username = NULL;
  uint user_len = 0;

  if (data.username)
  {
    user_t *user = hash_left->hash_info->user;

    if (user)
    {
      username = (unsigned char *) (user->user_name);

      user_len = user->user_len;
    }
  }

  // mask the part which was not found

  uint left_part_masked  = 0;
  uint right_part_masked = 0;

  uint mask_plain_len = strlen (LM_MASKED_PLAIN);

  if (pot_left_ptr == NULL)
  {
    left_part_masked = 1;

    pot_left_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_left_ptr->plain_buf, 0, sizeof (pot_left_ptr->plain_buf));

    memcpy (pot_left_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_left_ptr->plain_len = mask_plain_len;
  }

  if (pot_right_ptr == NULL)
  {
    right_part_masked = 1;

    pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));

    memcpy (pot_right_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_right_ptr->plain_len = mask_plain_len;
  }

  // create the pot_ptr out of pot_left_ptr and pot_right_ptr

  pot_t pot_ptr;

  pot_ptr.plain_len = pot_left_ptr->plain_len + pot_right_ptr->plain_len;

  memcpy (pot_ptr.plain_buf, pot_left_ptr->plain_buf, pot_left_ptr->plain_len);

  memcpy (pot_ptr.plain_buf + pot_left_ptr->plain_len, pot_right_ptr->plain_buf, pot_right_ptr->plain_len);

  // do output the line

  format_output (out_fp, input_buf, (unsigned char *) pot_ptr.plain_buf, pot_ptr.plain_len, 0, username, user_len);

  if (weak_hash_found == 1) myfree (pot_right_ptr);

  if (left_part_masked  == 1) myfree (pot_left_ptr);
  if (right_part_masked == 1) myfree (pot_right_ptr);
}

void handle_left_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  pot_t pot_key;

  memcpy (&pot_key.hash, hashes_buf, sizeof (hash_t));

  pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_ptr == NULL)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    format_output (out_fp, input_buf, NULL, 0, 0, NULL, 0);
  }
}

void handle_left_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp)
{
  // left

  pot_t pot_left_key;

  memcpy (&pot_left_key.hash, hash_left, sizeof (hash_t));

  pot_t *pot_left_ptr = (pot_t *) bsearch (&pot_left_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  // right

  pot_t pot_right_key;

  memcpy (&pot_right_key.hash, hash_right, sizeof (hash_t));

  pot_t *pot_right_ptr = (pot_t *) bsearch (&pot_right_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  uint weak_hash_found = 0;

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      // we just need that pot_right_ptr is not a NULL pointer

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));
    }
  }

  if ((pot_left_ptr != NULL) && (pot_right_ptr != NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr);

    return;
  }

  // ... at least one part was not cracked

  log_info_nn ("");

  input_buf[input_len] = 0;

  // only show the hash part which is still not cracked

  uint user_len = input_len - 32;

  char *hash_output = (char *) mymalloc (33);

  memcpy (hash_output, input_buf, input_len);

  if (pot_left_ptr != NULL)
  {
    // only show right part (because left part was already found)

    memcpy (hash_output + user_len, input_buf + user_len + 16, 16);

    hash_output[user_len + 16] = 0;
  }

  if (pot_right_ptr != NULL)
  {
    // only show left part (because right part was already found)

    memcpy (hash_output + user_len, input_buf + user_len, 16);

    hash_output[user_len + 16] = 0;
  }

  format_output (out_fp, hash_output, NULL, 0, 0, NULL, 0);

  myfree (hash_output);

  if (weak_hash_found == 1) myfree (pot_right_ptr);
}

uint setup_opencl_platforms_filter (char *opencl_platforms)
{
  uint opencl_platforms_filter = 0;

  if (opencl_platforms)
  {
    char *platforms = strdup (opencl_platforms);

    char *next = strtok (platforms, ",");

    do
    {
      int platform = atoi (next);

      if (platform < 1 || platform > 32)
      {
        log_error ("ERROR: Invalid OpenCL platform %u specified", platform);

        exit (-1);
      }

      opencl_platforms_filter |= 1 << (platform - 1);

    } while ((next = strtok (NULL, ",")) != NULL);

    free (platforms);
  }
  else
  {
    opencl_platforms_filter = -1;
  }

  return opencl_platforms_filter;
}

u32 setup_devices_filter (char *opencl_devices)
{
  u32 devices_filter = 0;

  if (opencl_devices)
  {
    char *devices = strdup (opencl_devices);

    char *next = strtok (devices, ",");

    do
    {
      int device_id = atoi (next);

      if (device_id < 1 || device_id > 32)
      {
        log_error ("ERROR: Invalid device_id %u specified", device_id);

        exit (-1);
      }

      devices_filter |= 1 << (device_id - 1);

    } while ((next = strtok (NULL, ",")) != NULL);

    free (devices);
  }
  else
  {
    devices_filter = -1;
  }

  return devices_filter;
}

cl_device_type setup_device_types_filter (char *opencl_device_types)
{
  cl_device_type device_types_filter = 0;

  if (opencl_device_types)
  {
    char *device_types = strdup (opencl_device_types);

    char *next = strtok (device_types, ",");

    do
    {
      int device_type = atoi (next);

      if (device_type < 1 || device_type > 3)
      {
        log_error ("ERROR: Invalid device_type %u specified", device_type);

        exit (-1);
      }

      device_types_filter |= 1 << device_type;

    } while ((next = strtok (NULL, ",")) != NULL);

    free (device_types);
  }
  else
  {
    // Do not use CPU by default, this often reduces GPU performance because
    // the CPU is too busy to handle GPU synchronization

    device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_CPU;
  }

  return device_types_filter;
}

u32 get_random_num (const u32 min, const u32 max)
{
  if (min == max) return (min);

  return ((rand () % (max - min)) + min);
}

u32 mydivc32 (const u32 dividend, const u32 divisor)
{
  u32 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

u64 mydivc64 (const u64 dividend, const u64 divisor)
{
  u64 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

void format_timer_display (struct tm *tm, char *buf, size_t len)
{
  const char *time_entities_s[] = { "year",  "day",  "hour",  "min",  "sec"  };
  const char *time_entities_m[] = { "years", "days", "hours", "mins", "secs" };

  if (tm->tm_year - 70)
  {
    char *time_entity1 = ((tm->tm_year - 70) == 1) ? (char *) time_entities_s[0] : (char *) time_entities_m[0];
    char *time_entity2 = ( tm->tm_yday       == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_year - 70, time_entity1, tm->tm_yday, time_entity2);
  }
  else if (tm->tm_yday)
  {
    char *time_entity1 = (tm->tm_yday == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];
    char *time_entity2 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_yday, time_entity1, tm->tm_hour, time_entity2);
  }
  else if (tm->tm_hour)
  {
    char *time_entity1 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];
    char *time_entity2 = (tm->tm_min  == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_hour, time_entity1, tm->tm_min, time_entity2);
  }
  else if (tm->tm_min)
  {
    char *time_entity1 = (tm->tm_min == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];
    char *time_entity2 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_min, time_entity1, tm->tm_sec, time_entity2);
  }
  else
  {
    char *time_entity1 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s", tm->tm_sec, time_entity1);
  }
}

void format_speed_display (float val, char *buf, size_t len)
{
  if (val <= 0)
  {
    buf[0] = '0';
    buf[1] = ' ';
    buf[2] = 0;

    return;
  }

  char units[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

  uint level = 0;

  while (val > 99999)
  {
    val /= 1000;

    level++;
  }

  /* generate output */

  if (level == 0)
  {
    snprintf (buf, len - 1, "%.0f ", val);
  }
  else
  {
    snprintf (buf, len - 1, "%.1f %c", val, units[level]);
  }
}

void lowercase (u8 *buf, int len)
{
  for (int i = 0; i < len; i++) buf[i] = tolower (buf[i]);
}

void uppercase (u8 *buf, int len)
{
  for (int i = 0; i < len; i++) buf[i] = toupper (buf[i]);
}

int fgetl (FILE *fp, char *line_buf)
{
  int line_len = 0;

  while (!feof (fp))
  {
    const int c = fgetc (fp);

    if (c == EOF) break;

    line_buf[line_len] = (char) c;

    line_len++;

    if (line_len == HCBUFSIZ) line_len--;

    if (c == '\n') break;
  }

  if (line_len == 0) return 0;

  if (line_buf[line_len - 1] == '\n')
  {
    line_len--;

    line_buf[line_len] = 0;
  }

  if (line_len == 0) return 0;

  if (line_buf[line_len - 1] == '\r')
  {
    line_len--;

    line_buf[line_len] = 0;
  }

  return (line_len);
}

int in_superchop (char *buf)
{
  int len = strlen (buf);

  while (len)
  {
    if (buf[len - 1] == '\n')
    {
      len--;

      continue;
    }

    if (buf[len - 1] == '\r')
    {
      len--;

      continue;
    }

    break;
  }

  buf[len] = 0;

  return len;
}

char **scan_directory (const char *path)
{
  char *tmp_path = mystrdup (path);

  size_t tmp_path_len = strlen (tmp_path);

  while (tmp_path[tmp_path_len - 1] == '/' || tmp_path[tmp_path_len - 1] == '\\')
  {
    tmp_path[tmp_path_len - 1] = 0;

    tmp_path_len = strlen (tmp_path);
  }

  char **files = NULL;

  int num_files = 0;

  DIR *d = NULL;

  if ((d = opendir (tmp_path)) != NULL)
  {
    #ifdef DARWIN
    struct dirent e;

    for (;;) {
      memset (&e, 0, sizeof (e));
      struct dirent *de = NULL;

      if (readdir_r (d, &e, &de) != 0)
      {
        log_error ("ERROR: readdir_r() failed");

        break;
      }

      if (de == NULL) break;
    #else
    struct dirent *de;

    while ((de = readdir (d)) != NULL)
    {
    #endif
      if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0)) continue;

      int path_size = strlen (tmp_path) + 1 + strlen (de->d_name);

      char *path_file = (char *) mymalloc (path_size + 1);

      snprintf (path_file, path_size + 1, "%s/%s", tmp_path, de->d_name);

      path_file[path_size] = 0;

      DIR *d_test;

      if ((d_test = opendir (path_file)) != NULL)
      {
        closedir (d_test);

        myfree (path_file);
      }
      else
      {
        files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

        num_files++;

        files[num_files - 1] = path_file;
      }
    }

    closedir (d);
  }
  else if (errno == ENOTDIR)
  {
    files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

    num_files++;

    files[num_files - 1] = mystrdup (path);
  }

  files = (char **) myrealloc (files, num_files * sizeof (char *), sizeof (char *));

  num_files++;

  files[num_files - 1] = NULL;

  myfree (tmp_path);

  return (files);
}

int count_dictionaries (char **dictionary_files)
{
  if (dictionary_files == NULL) return 0;

  int cnt = 0;

  for (int d = 0; dictionary_files[d] != NULL; d++)
  {
    cnt++;
  }

  return (cnt);
}

char *stroptitype (const uint opti_type)
{
  switch (opti_type)
  {
    case OPTI_TYPE_ZERO_BYTE:         return ((char *) OPTI_STR_ZERO_BYTE);         break;
    case OPTI_TYPE_PRECOMPUTE_INIT:   return ((char *) OPTI_STR_PRECOMPUTE_INIT);   break;
    case OPTI_TYPE_PRECOMPUTE_MERKLE: return ((char *) OPTI_STR_PRECOMPUTE_MERKLE); break;
    case OPTI_TYPE_PRECOMPUTE_PERMUT: return ((char *) OPTI_STR_PRECOMPUTE_PERMUT); break;
    case OPTI_TYPE_MEET_IN_MIDDLE:    return ((char *) OPTI_STR_MEET_IN_MIDDLE);    break;
    case OPTI_TYPE_EARLY_SKIP:        return ((char *) OPTI_STR_EARLY_SKIP);        break;
    case OPTI_TYPE_NOT_SALTED:        return ((char *) OPTI_STR_NOT_SALTED);        break;
    case OPTI_TYPE_NOT_ITERATED:      return ((char *) OPTI_STR_NOT_ITERATED);      break;
    case OPTI_TYPE_PREPENDED_SALT:    return ((char *) OPTI_STR_PREPENDED_SALT);    break;
    case OPTI_TYPE_APPENDED_SALT:     return ((char *) OPTI_STR_APPENDED_SALT);     break;
    case OPTI_TYPE_SINGLE_HASH:       return ((char *) OPTI_STR_SINGLE_HASH);       break;
    case OPTI_TYPE_SINGLE_SALT:       return ((char *) OPTI_STR_SINGLE_SALT);       break;
    case OPTI_TYPE_BRUTE_FORCE:       return ((char *) OPTI_STR_BRUTE_FORCE);       break;
    case OPTI_TYPE_RAW_HASH:          return ((char *) OPTI_STR_RAW_HASH);          break;
    case OPTI_TYPE_SLOW_HASH_SIMD:    return ((char *) OPTI_STR_SLOW_HASH_SIMD);    break;
    case OPTI_TYPE_USES_BITS_8:       return ((char *) OPTI_STR_USES_BITS_8);       break;
    case OPTI_TYPE_USES_BITS_16:      return ((char *) OPTI_STR_USES_BITS_16);      break;
    case OPTI_TYPE_USES_BITS_32:      return ((char *) OPTI_STR_USES_BITS_32);      break;
    case OPTI_TYPE_USES_BITS_64:      return ((char *) OPTI_STR_USES_BITS_64);      break;
  }

  return (NULL);
}

char *strparser (const uint parser_status)
{
  switch (parser_status)
  {
    case PARSER_OK:                   return ((char *) PA_000); break;
    case PARSER_COMMENT:              return ((char *) PA_001); break;
    case PARSER_GLOBAL_ZERO:          return ((char *) PA_002); break;
    case PARSER_GLOBAL_LENGTH:        return ((char *) PA_003); break;
    case PARSER_HASH_LENGTH:          return ((char *) PA_004); break;
    case PARSER_HASH_VALUE:           return ((char *) PA_005); break;
    case PARSER_SALT_LENGTH:          return ((char *) PA_006); break;
    case PARSER_SALT_VALUE:           return ((char *) PA_007); break;
    case PARSER_SALT_ITERATION:       return ((char *) PA_008); break;
    case PARSER_SEPARATOR_UNMATCHED:  return ((char *) PA_009); break;
    case PARSER_SIGNATURE_UNMATCHED:  return ((char *) PA_010); break;
    case PARSER_HCCAP_FILE_SIZE:      return ((char *) PA_011); break;
    case PARSER_HCCAP_EAPOL_SIZE:     return ((char *) PA_012); break;
    case PARSER_PSAFE2_FILE_SIZE:     return ((char *) PA_013); break;
    case PARSER_PSAFE3_FILE_SIZE:     return ((char *) PA_014); break;
    case PARSER_TC_FILE_SIZE:         return ((char *) PA_015); break;
    case PARSER_SIP_AUTH_DIRECTIVE:   return ((char *) PA_016); break;
  }

  return ((char *) PA_255);
}

char *strhashtype (const uint hash_mode)
{
  switch (hash_mode)
  {
    case     0: return ((char *) HT_00000); break;
    case    10: return ((char *) HT_00010); break;
    case    11: return ((char *) HT_00011); break;
    case    12: return ((char *) HT_00012); break;
    case    20: return ((char *) HT_00020); break;
    case    21: return ((char *) HT_00021); break;
    case    22: return ((char *) HT_00022); break;
    case    23: return ((char *) HT_00023); break;
    case    30: return ((char *) HT_00030); break;
    case    40: return ((char *) HT_00040); break;
    case    50: return ((char *) HT_00050); break;
    case    60: return ((char *) HT_00060); break;
    case   100: return ((char *) HT_00100); break;
    case   101: return ((char *) HT_00101); break;
    case   110: return ((char *) HT_00110); break;
    case   111: return ((char *) HT_00111); break;
    case   112: return ((char *) HT_00112); break;
    case   120: return ((char *) HT_00120); break;
    case   121: return ((char *) HT_00121); break;
    case   122: return ((char *) HT_00122); break;
    case   124: return ((char *) HT_00124); break;
    case   125: return ((char *) HT_00125); break;
    case   130: return ((char *) HT_00130); break;
    case   131: return ((char *) HT_00131); break;
    case   132: return ((char *) HT_00132); break;
    case   133: return ((char *) HT_00133); break;
    case   140: return ((char *) HT_00140); break;
    case   141: return ((char *) HT_00141); break;
    case   150: return ((char *) HT_00150); break;
    case   160: return ((char *) HT_00160); break;
    case   200: return ((char *) HT_00200); break;
    case   300: return ((char *) HT_00300); break;
    case   400: return ((char *) HT_00400); break;
    case   500: return ((char *) HT_00500); break;
    case   501: return ((char *) HT_00501); break;
    case   900: return ((char *) HT_00900); break;
    case   910: return ((char *) HT_00910); break;
    case  1000: return ((char *) HT_01000); break;
    case  1100: return ((char *) HT_01100); break;
    case  1400: return ((char *) HT_01400); break;
    case  1410: return ((char *) HT_01410); break;
    case  1420: return ((char *) HT_01420); break;
    case  1421: return ((char *) HT_01421); break;
    case  1430: return ((char *) HT_01430); break;
    case  1440: return ((char *) HT_01440); break;
    case  1441: return ((char *) HT_01441); break;
    case  1450: return ((char *) HT_01450); break;
    case  1460: return ((char *) HT_01460); break;
    case  1500: return ((char *) HT_01500); break;
    case  1600: return ((char *) HT_01600); break;
    case  1700: return ((char *) HT_01700); break;
    case  1710: return ((char *) HT_01710); break;
    case  1711: return ((char *) HT_01711); break;
    case  1720: return ((char *) HT_01720); break;
    case  1722: return ((char *) HT_01722); break;
    case  1730: return ((char *) HT_01730); break;
    case  1731: return ((char *) HT_01731); break;
    case  1740: return ((char *) HT_01740); break;
    case  1750: return ((char *) HT_01750); break;
    case  1760: return ((char *) HT_01760); break;
    case  1800: return ((char *) HT_01800); break;
    case  2100: return ((char *) HT_02100); break;
    case  2400: return ((char *) HT_02400); break;
    case  2410: return ((char *) HT_02410); break;
    case  2500: return ((char *) HT_02500); break;
    case  2600: return ((char *) HT_02600); break;
    case  2611: return ((char *) HT_02611); break;
    case  2612: return ((char *) HT_02612); break;
    case  2711: return ((char *) HT_02711); break;
    case  2811: return ((char *) HT_02811); break;
    case  3000: return ((char *) HT_03000); break;
    case  3100: return ((char *) HT_03100); break;
    case  3200: return ((char *) HT_03200); break;
    case  3710: return ((char *) HT_03710); break;
    case  3711: return ((char *) HT_03711); break;
    case  3800: return ((char *) HT_03800); break;
    case  4300: return ((char *) HT_04300); break;
    case  4400: return ((char *) HT_04400); break;
    case  4500: return ((char *) HT_04500); break;
    case  4700: return ((char *) HT_04700); break;
    case  4800: return ((char *) HT_04800); break;
    case  4900: return ((char *) HT_04900); break;
    case  5000: return ((char *) HT_05000); break;
    case  5100: return ((char *) HT_05100); break;
    case  5200: return ((char *) HT_05200); break;
    case  5300: return ((char *) HT_05300); break;
    case  5400: return ((char *) HT_05400); break;
    case  5500: return ((char *) HT_05500); break;
    case  5600: return ((char *) HT_05600); break;
    case  5700: return ((char *) HT_05700); break;
    case  5800: return ((char *) HT_05800); break;
    case  6000: return ((char *) HT_06000); break;
    case  6100: return ((char *) HT_06100); break;
    case  6211: return ((char *) HT_06211); break;
    case  6212: return ((char *) HT_06212); break;
    case  6213: return ((char *) HT_06213); break;
    case  6221: return ((char *) HT_06221); break;
    case  6222: return ((char *) HT_06222); break;
    case  6223: return ((char *) HT_06223); break;
    case  6231: return ((char *) HT_06231); break;
    case  6232: return ((char *) HT_06232); break;
    case  6233: return ((char *) HT_06233); break;
    case  6241: return ((char *) HT_06241); break;
    case  6242: return ((char *) HT_06242); break;
    case  6243: return ((char *) HT_06243); break;
    case  6300: return ((char *) HT_06300); break;
    case  6400: return ((char *) HT_06400); break;
    case  6500: return ((char *) HT_06500); break;
    case  6600: return ((char *) HT_06600); break;
    case  6700: return ((char *) HT_06700); break;
    case  6800: return ((char *) HT_06800); break;
    case  6900: return ((char *) HT_06900); break;
    case  7100: return ((char *) HT_07100); break;
    case  7200: return ((char *) HT_07200); break;
    case  7300: return ((char *) HT_07300); break;
    case  7400: return ((char *) HT_07400); break;
    case  7500: return ((char *) HT_07500); break;
    case  7600: return ((char *) HT_07600); break;
    case  7700: return ((char *) HT_07700); break;
    case  7800: return ((char *) HT_07800); break;
    case  7900: return ((char *) HT_07900); break;
    case  8000: return ((char *) HT_08000); break;
    case  8100: return ((char *) HT_08100); break;
    case  8200: return ((char *) HT_08200); break;
    case  8300: return ((char *) HT_08300); break;
    case  8400: return ((char *) HT_08400); break;
    case  8500: return ((char *) HT_08500); break;
    case  8600: return ((char *) HT_08600); break;
    case  8700: return ((char *) HT_08700); break;
    case  8800: return ((char *) HT_08800); break;
    case  8900: return ((char *) HT_08900); break;
    case  9000: return ((char *) HT_09000); break;
    case  9100: return ((char *) HT_09100); break;
    case  9200: return ((char *) HT_09200); break;
    case  9300: return ((char *) HT_09300); break;
    case  9400: return ((char *) HT_09400); break;
    case  9500: return ((char *) HT_09500); break;
    case  9600: return ((char *) HT_09600); break;
    case  9700: return ((char *) HT_09700); break;
    case  9710: return ((char *) HT_09710); break;
    case  9720: return ((char *) HT_09720); break;
    case  9800: return ((char *) HT_09800); break;
    case  9810: return ((char *) HT_09810); break;
    case  9820: return ((char *) HT_09820); break;
    case  9900: return ((char *) HT_09900); break;
    case 10000: return ((char *) HT_10000); break;
    case 10100: return ((char *) HT_10100); break;
    case 10200: return ((char *) HT_10200); break;
    case 10300: return ((char *) HT_10300); break;
    case 10400: return ((char *) HT_10400); break;
    case 10410: return ((char *) HT_10410); break;
    case 10420: return ((char *) HT_10420); break;
    case 10500: return ((char *) HT_10500); break;
    case 10600: return ((char *) HT_10600); break;
    case 10700: return ((char *) HT_10700); break;
    case 10800: return ((char *) HT_10800); break;
    case 10900: return ((char *) HT_10900); break;
    case 11000: return ((char *) HT_11000); break;
    case 11100: return ((char *) HT_11100); break;
    case 11200: return ((char *) HT_11200); break;
    case 11300: return ((char *) HT_11300); break;
    case 11400: return ((char *) HT_11400); break;
    case 11500: return ((char *) HT_11500); break;
    case 11600: return ((char *) HT_11600); break;
    case 11700: return ((char *) HT_11700); break;
    case 11800: return ((char *) HT_11800); break;
    case 11900: return ((char *) HT_11900); break;
    case 12000: return ((char *) HT_12000); break;
    case 12100: return ((char *) HT_12100); break;
    case 12200: return ((char *) HT_12200); break;
    case 12300: return ((char *) HT_12300); break;
    case 12400: return ((char *) HT_12400); break;
    case 12500: return ((char *) HT_12500); break;
    case 12600: return ((char *) HT_12600); break;
    case 12700: return ((char *) HT_12700); break;
    case 12800: return ((char *) HT_12800); break;
    case 12900: return ((char *) HT_12900); break;
    case 13000: return ((char *) HT_13000); break;
    case 13100: return ((char *) HT_13100); break;
    case 13200: return ((char *) HT_13200); break;
    case 13300: return ((char *) HT_13300); break;
    case 13400: return ((char *) HT_13400); break;
    case 13500: return ((char *) HT_13500); break;
    case 13600: return ((char *) HT_13600); break;
    case 13711: return ((char *) HT_13711); break;
    case 13712: return ((char *) HT_13712); break;
    case 13713: return ((char *) HT_13713); break;
    case 13721: return ((char *) HT_13721); break;
    case 13722: return ((char *) HT_13722); break;
    case 13723: return ((char *) HT_13723); break;
    case 13731: return ((char *) HT_13731); break;
    case 13732: return ((char *) HT_13732); break;
    case 13733: return ((char *) HT_13733); break;
    case 13741: return ((char *) HT_13741); break;
    case 13742: return ((char *) HT_13742); break;
    case 13743: return ((char *) HT_13743); break;
    case 13751: return ((char *) HT_13751); break;
    case 13752: return ((char *) HT_13752); break;
    case 13753: return ((char *) HT_13753); break;
    case 13761: return ((char *) HT_13761); break;
    case 13762: return ((char *) HT_13762); break;
    case 13763: return ((char *) HT_13763); break;
    case 13800: return ((char *) HT_13800); break;
  }

  return ((char *) "Unknown");
}

char *strstatus (const uint devices_status)
{
  switch (devices_status)
  {
    case  STATUS_INIT:               return ((char *) ST_0000); break;
    case  STATUS_STARTING:           return ((char *) ST_0001); break;
    case  STATUS_RUNNING:            return ((char *) ST_0002); break;
    case  STATUS_PAUSED:             return ((char *) ST_0003); break;
    case  STATUS_EXHAUSTED:          return ((char *) ST_0004); break;
    case  STATUS_CRACKED:            return ((char *) ST_0005); break;
    case  STATUS_ABORTED:            return ((char *) ST_0006); break;
    case  STATUS_QUIT:               return ((char *) ST_0007); break;
    case  STATUS_BYPASS:             return ((char *) ST_0008); break;
    case  STATUS_STOP_AT_CHECKPOINT: return ((char *) ST_0009); break;
    case  STATUS_AUTOTUNE:           return ((char *) ST_0010); break;
  }

  return ((char *) "Unknown");
}

void ascii_digest (char *out_buf, uint salt_pos, uint digest_pos)
{
  uint hash_type = data.hash_type;
  uint hash_mode = data.hash_mode;
  uint salt_type = data.salt_type;
  uint opts_type = data.opts_type;
  uint opti_type = data.opti_type;
  uint dgst_size = data.dgst_size;

  char *hashfile = data.hashfile;

  uint len = 4096;

  uint digest_buf[64] = { 0 };

  u64 *digest_buf64 = (u64 *) digest_buf;

  char *digests_buf_ptr = (char *) data.digests_buf;

  memcpy (digest_buf, digests_buf_ptr + (data.salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

  if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
  {
    uint tt;

    switch (hash_type)
    {
      case HASH_TYPE_DESCRYPT:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_DESRACF:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_LM:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_NETNTLM:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);
        digest_buf[2] = rotl32 (digest_buf[2], 29);
        digest_buf[3] = rotl32 (digest_buf[3], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        FP (digest_buf[3], digest_buf[2], tt);
        break;

      case HASH_TYPE_BSDICRYPT:
        digest_buf[0] = rotl32 (digest_buf[0], 31);
        digest_buf[1] = rotl32 (digest_buf[1], 31);

        FP (digest_buf[1], digest_buf[0], tt);
        break;
    }
  }

  if (opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    switch (hash_type)
    {
      case HASH_TYPE_MD4:
        digest_buf[0] += MD4M_A;
        digest_buf[1] += MD4M_B;
        digest_buf[2] += MD4M_C;
        digest_buf[3] += MD4M_D;
        break;

      case HASH_TYPE_MD5:
        digest_buf[0] += MD5M_A;
        digest_buf[1] += MD5M_B;
        digest_buf[2] += MD5M_C;
        digest_buf[3] += MD5M_D;
        break;

      case HASH_TYPE_SHA1:
        digest_buf[0] += SHA1M_A;
        digest_buf[1] += SHA1M_B;
        digest_buf[2] += SHA1M_C;
        digest_buf[3] += SHA1M_D;
        digest_buf[4] += SHA1M_E;
        break;

      case HASH_TYPE_SHA256:
        digest_buf[0] += SHA256M_A;
        digest_buf[1] += SHA256M_B;
        digest_buf[2] += SHA256M_C;
        digest_buf[3] += SHA256M_D;
        digest_buf[4] += SHA256M_E;
        digest_buf[5] += SHA256M_F;
        digest_buf[6] += SHA256M_G;
        digest_buf[7] += SHA256M_H;
        break;

      case HASH_TYPE_SHA384:
        digest_buf64[0] += SHA384M_A;
        digest_buf64[1] += SHA384M_B;
        digest_buf64[2] += SHA384M_C;
        digest_buf64[3] += SHA384M_D;
        digest_buf64[4] += SHA384M_E;
        digest_buf64[5] += SHA384M_F;
        digest_buf64[6] += 0;
        digest_buf64[7] += 0;
        break;

      case HASH_TYPE_SHA512:
        digest_buf64[0] += SHA512M_A;
        digest_buf64[1] += SHA512M_B;
        digest_buf64[2] += SHA512M_C;
        digest_buf64[3] += SHA512M_D;
        digest_buf64[4] += SHA512M_E;
        digest_buf64[5] += SHA512M_F;
        digest_buf64[6] += SHA512M_G;
        digest_buf64[7] += SHA512M_H;
        break;
    }
  }

  if (opts_type & OPTS_TYPE_PT_GENERATE_LE)
  {
    if (dgst_size == DGST_SIZE_4_2)
    {
      for (int i = 0; i < 2; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_4)
    {
      for (int i = 0; i < 4; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_5)
    {
      for (int i = 0; i < 5; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_6)
    {
      for (int i = 0; i < 6; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_8)
    {
      for (int i = 0; i < 8; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if ((dgst_size == DGST_SIZE_4_16) || (dgst_size == DGST_SIZE_8_8)) // same size, same result :)
    {
      if (hash_type == HASH_TYPE_WHIRLPOOL)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
      else if (hash_type == HASH_TYPE_SHA384)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_SHA512)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_GOST)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
    }
    else if (dgst_size == DGST_SIZE_4_64)
    {
      for (int i = 0; i < 64; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_8_25)
    {
      for (int i = 0; i < 25; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
    }
  }

  uint isSalted = ((data.salt_type == SALT_TYPE_INTERN)
                |  (data.salt_type == SALT_TYPE_EXTERN)
                |  (data.salt_type == SALT_TYPE_EMBEDDED));

  salt_t salt;

  if (isSalted)
  {
    memset (&salt, 0, sizeof (salt_t));

    memcpy (&salt, &data.salts_buf[salt_pos], sizeof (salt_t));

    char *ptr = (char *) salt.salt_buf;

    uint len = salt.salt_len;

    if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
    {
      uint tt;

      switch (hash_type)
      {
        case HASH_TYPE_NETNTLM:

          salt.salt_buf[0] = rotr32 (salt.salt_buf[0], 3);
          salt.salt_buf[1] = rotr32 (salt.salt_buf[1], 3);

          FP (salt.salt_buf[1], salt.salt_buf[0], tt);

          break;
      }
    }

    if (opts_type & OPTS_TYPE_ST_UNICODE)
    {
      for (uint i = 0, j = 0; i < len; i += 1, j += 2)
      {
        ptr[i] = ptr[j];
      }

      len = len / 2;
    }

    if (opts_type & OPTS_TYPE_ST_GENERATE_LE)
    {
      uint max = salt.salt_len / 4;

      if (len % 4) max++;

      for (uint i = 0; i < max; i++)
      {
        salt.salt_buf[i] = byte_swap_32 (salt.salt_buf[i]);
      }
    }

    if (opts_type & OPTS_TYPE_ST_HEX)
    {
      char tmp[64] = { 0 };

      for (uint i = 0, j = 0; i < len; i += 1, j += 2)
      {
        sprintf (tmp + j, "%02x", (unsigned char) ptr[i]);
      }

      len = len * 2;

      memcpy (ptr, tmp, len);
    }

    uint memset_size = ((48 - (int) len) > 0) ? (48 - len) : 0;

    memset (ptr + len, 0, memset_size);

    salt.salt_len = len;
  }

  //
  // some modes require special encoding
  //

  uint out_buf_plain[256] = { 0 };
  uint out_buf_salt[256] = { 0 };

  char tmp_buf[1024] = { 0 };

  char *ptr_plain = (char *) out_buf_plain;
  char *ptr_salt  = (char *) out_buf_salt;

  if (hash_mode == 22)
  {
    char username[30] = { 0 };

    memcpy (username, salt.salt_buf, salt.salt_len - 22);

    char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };

    u16 *ptr = (u16 *) digest_buf;

    tmp_buf[ 0] = sig[0];
    tmp_buf[ 1] = int_to_base64 (((ptr[1]) >> 12) & 0x3f);
    tmp_buf[ 2] = int_to_base64 (((ptr[1]) >>  6) & 0x3f);
    tmp_buf[ 3] = int_to_base64 (((ptr[1]) >>  0) & 0x3f);
    tmp_buf[ 4] = int_to_base64 (((ptr[0]) >> 12) & 0x3f);
    tmp_buf[ 5] = int_to_base64 (((ptr[0]) >>  6) & 0x3f);
    tmp_buf[ 6] = sig[1];
    tmp_buf[ 7] = int_to_base64 (((ptr[0]) >>  0) & 0x3f);
    tmp_buf[ 8] = int_to_base64 (((ptr[3]) >> 12) & 0x3f);
    tmp_buf[ 9] = int_to_base64 (((ptr[3]) >>  6) & 0x3f);
    tmp_buf[10] = int_to_base64 (((ptr[3]) >>  0) & 0x3f);
    tmp_buf[11] = int_to_base64 (((ptr[2]) >> 12) & 0x3f);
    tmp_buf[12] = sig[2];
    tmp_buf[13] = int_to_base64 (((ptr[2]) >>  6) & 0x3f);
    tmp_buf[14] = int_to_base64 (((ptr[2]) >>  0) & 0x3f);
    tmp_buf[15] = int_to_base64 (((ptr[5]) >> 12) & 0x3f);
    tmp_buf[16] = int_to_base64 (((ptr[5]) >>  6) & 0x3f);
    tmp_buf[17] = sig[3];
    tmp_buf[18] = int_to_base64 (((ptr[5]) >>  0) & 0x3f);
    tmp_buf[19] = int_to_base64 (((ptr[4]) >> 12) & 0x3f);
    tmp_buf[20] = int_to_base64 (((ptr[4]) >>  6) & 0x3f);
    tmp_buf[21] = int_to_base64 (((ptr[4]) >>  0) & 0x3f);
    tmp_buf[22] = int_to_base64 (((ptr[7]) >> 12) & 0x3f);
    tmp_buf[23] = sig[4];
    tmp_buf[24] = int_to_base64 (((ptr[7]) >>  6) & 0x3f);
    tmp_buf[25] = int_to_base64 (((ptr[7]) >>  0) & 0x3f);
    tmp_buf[26] = int_to_base64 (((ptr[6]) >> 12) & 0x3f);
    tmp_buf[27] = int_to_base64 (((ptr[6]) >>  6) & 0x3f);
    tmp_buf[28] = int_to_base64 (((ptr[6]) >>  0) & 0x3f);
    tmp_buf[29] = sig[5];

    snprintf (out_buf, len-1, "%s:%s",
      tmp_buf,
      username);
  }
  else if (hash_mode == 23)
  {
    // do not show the skyper part in output

    char *salt_buf_ptr = (char *) salt.salt_buf;

    salt_buf_ptr[salt.salt_len - 8] = 0;

    snprintf (out_buf, len-1, "%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      salt_buf_ptr);
  }
  else if (hash_mode == 101)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, len-1, "{SHA}%s", ptr_plain);
  }
  else if (hash_mode == 111)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, len-1, "{SSHA}%s", ptr_plain);
  }
  else if ((hash_mode == 122) || (hash_mode == 125))
  {
    snprintf (out_buf, len-1, "%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 124)
  {
    snprintf (out_buf, len-1, "sha1$%s$%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 131)
  {
    snprintf (out_buf, len-1, "0x0100%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      0, 0, 0, 0, 0,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 132)
  {
    snprintf (out_buf, len-1, "0x0100%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 133)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, len-1, "%s", ptr_plain);
  }
  else if (hash_mode == 141)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, (u8 *) ptr_salt);

    memset (tmp_buf, 0, sizeof (tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    ptr_plain[27] = 0;

    snprintf (out_buf, len-1, "%s%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 400)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    phpass_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, len-1, "%s%s%s", (char *) salt.salt_sign, (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 500)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf (out_buf, len-1, "$1$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, len-1, "$1$rounds=%i$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 501)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 1421)
  {
    u8 *salt_ptr = (u8 *) salt.salt_buf;

    snprintf (out_buf, len-1, "%c%c%c%c%c%c%08x%08x%08x%08x%08x%08x%08x%08x",
      salt_ptr[0],
      salt_ptr[1],
      salt_ptr[2],
      salt_ptr[3],
      salt_ptr[4],
      salt_ptr[5],
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 1441)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, (u8 *) ptr_salt);

    memset (tmp_buf, 0, sizeof (tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

    ptr_plain[43] = 0;

    snprintf (out_buf, len-1, "%s%s*%s", SIGNATURE_EPISERVER4, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1500)
  {
    out_buf[0] = salt.salt_sign[0] & 0xff;
    out_buf[1] = salt.salt_sign[1] & 0xff;
    //original method, but changed because of this ticket: https://hashcat.net/trac/ticket/269
    //out_buf[0] = int_to_itoa64 ((salt.salt_buf[0] >> 0) & 0x3f);
    //out_buf[1] = int_to_itoa64 ((salt.salt_buf[0] >> 6) & 0x3f);

    memset (tmp_buf, 0, sizeof (tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);

    memcpy (tmp_buf, digest_buf, 8);

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 8, (u8 *) ptr_plain);

    snprintf (out_buf + 2, len-1-2, "%s", ptr_plain);

    out_buf[13] = 0;
  }
  else if (hash_mode == 1600)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf (out_buf, len-1, "$apr1$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, len-1, "$apr1$rounds=%i$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 1711)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
    digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
    digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
    digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
    digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
    digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
    digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
    digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

    memcpy (tmp_buf, digest_buf, 64);
    memcpy (tmp_buf + 64, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 64 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, len-1, "%s%s", SIGNATURE_SHA512B64S, ptr_plain);
  }
  else if (hash_mode == 1722)
  {
    uint *ptr = digest_buf;

    snprintf (out_buf, len-1, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      ptr[ 1], ptr[ 0],
      ptr[ 3], ptr[ 2],
      ptr[ 5], ptr[ 4],
      ptr[ 7], ptr[ 6],
      ptr[ 9], ptr[ 8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 1731)
  {
    uint *ptr = digest_buf;

    snprintf (out_buf, len-1, "0x0200%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
  }
  else if (hash_mode == 1800)
  {
    // temp workaround

    digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
    digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
    digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
    digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
    digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
    digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
    digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
    digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

    sha512crypt_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA512CRYPT)
    {
      snprintf (out_buf, len-1, "$6$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, len-1, "$6$rounds=%i$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 2100)
  {
    uint pos = 0;

    snprintf (out_buf + pos, len-1, "%s%i#",
      SIGNATURE_DCC2,
      salt.salt_iter + 1);

    uint signature_len = strlen (out_buf);

    pos += signature_len;
    len -= signature_len;

    char *salt_ptr = (char *) salt.salt_buf;

    for (uint i = 0; i < salt.salt_len; i++, pos++, len--) snprintf (out_buf + pos, len-1, "%c", salt_ptr[i]);

    snprintf (out_buf + pos, len-1, "#%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if ((hash_mode == 2400) || (hash_mode == 2410))
  {
    memcpy (tmp_buf, digest_buf, 16);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    out_buf[ 0] = int_to_itoa64 ((digest_buf[0] >>  0) & 0x3f);
    out_buf[ 1] = int_to_itoa64 ((digest_buf[0] >>  6) & 0x3f);
    out_buf[ 2] = int_to_itoa64 ((digest_buf[0] >> 12) & 0x3f);
    out_buf[ 3] = int_to_itoa64 ((digest_buf[0] >> 18) & 0x3f);

    out_buf[ 4] = int_to_itoa64 ((digest_buf[1] >>  0) & 0x3f);
    out_buf[ 5] = int_to_itoa64 ((digest_buf[1] >>  6) & 0x3f);
    out_buf[ 6] = int_to_itoa64 ((digest_buf[1] >> 12) & 0x3f);
    out_buf[ 7] = int_to_itoa64 ((digest_buf[1] >> 18) & 0x3f);

    out_buf[ 8] = int_to_itoa64 ((digest_buf[2] >>  0) & 0x3f);
    out_buf[ 9] = int_to_itoa64 ((digest_buf[2] >>  6) & 0x3f);
    out_buf[10] = int_to_itoa64 ((digest_buf[2] >> 12) & 0x3f);
    out_buf[11] = int_to_itoa64 ((digest_buf[2] >> 18) & 0x3f);

    out_buf[12] = int_to_itoa64 ((digest_buf[3] >>  0) & 0x3f);
    out_buf[13] = int_to_itoa64 ((digest_buf[3] >>  6) & 0x3f);
    out_buf[14] = int_to_itoa64 ((digest_buf[3] >> 12) & 0x3f);
    out_buf[15] = int_to_itoa64 ((digest_buf[3] >> 18) & 0x3f);

    out_buf[16] = 0;
  }
  else if (hash_mode == 2500)
  {
    wpa_t *wpas = (wpa_t *) data.esalts_buf;

    wpa_t *wpa = &wpas[salt_pos];

    snprintf (out_buf, len-1, "%s:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x",
      (char *) salt.salt_buf,
      wpa->orig_mac1[0],
      wpa->orig_mac1[1],
      wpa->orig_mac1[2],
      wpa->orig_mac1[3],
      wpa->orig_mac1[4],
      wpa->orig_mac1[5],
      wpa->orig_mac2[0],
      wpa->orig_mac2[1],
      wpa->orig_mac2[2],
      wpa->orig_mac2[3],
      wpa->orig_mac2[4],
      wpa->orig_mac2[5]);
  }
  else if (hash_mode == 4400)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if (hash_mode == 4700)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 4800)
  {
    u8 chap_id_byte = (u8) salt.salt_buf[4];

    snprintf (out_buf, len-1, "%08x%08x%08x%08x:%08x%08x%08x%08x:%02x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      chap_id_byte);
  }
  else if (hash_mode == 4900)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 5100)
  {
    snprintf (out_buf, len-1, "%08x%08x",
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 5200)
  {
    snprintf (out_buf, len-1, "%s", hashfile);
  }
  else if (hash_mode == 5300)
  {
    ikepsk_t *ikepsks = (ikepsk_t *) data.esalts_buf;

    ikepsk_t *ikepsk  = &ikepsks[salt_pos];

    int buf_len = len -1;

    // msg_buf

    uint ikepsk_msg_len = ikepsk->msg_len / 4;

    for (uint i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    uint ikepsk_nr_len = ikepsk->nr_len / 4;

    for (uint i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (uint i = 0; i < 4; i++)
    {
      if (i == 0)
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5400)
  {
    ikepsk_t *ikepsks = (ikepsk_t *) data.esalts_buf;

    ikepsk_t *ikepsk  = &ikepsks[salt_pos];

    int buf_len = len -1;

    // msg_buf

    uint ikepsk_msg_len = ikepsk->msg_len / 4;

    for (uint i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    uint ikepsk_nr_len = ikepsk->nr_len / 4;

    for (uint i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (uint i = 0; i < 5; i++)
    {
      if (i == 0)
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5500)
  {
    netntlm_t *netntlms = (netntlm_t *) data.esalts_buf;

    netntlm_t *netntlm = &netntlms[salt_pos];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (uint i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (uint i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (uint i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (srvchall_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf (out_buf, len-1, "%s::%s:%s:%08x%08x%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32 (salt.salt_buf_pc[0]),
      byte_swap_32 (salt.salt_buf_pc[1]),
      clichall_buf);
  }
  else if (hash_mode == 5600)
  {
    netntlm_t *netntlms = (netntlm_t *) data.esalts_buf;

    netntlm_t *netntlm = &netntlms[salt_pos];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (uint i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (uint i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (uint i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (srvchall_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf (out_buf, len-1, "%s::%s:%s:%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      clichall_buf);
  }
  else if (hash_mode == 5700)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

    ptr_plain[43] = 0;

    snprintf (out_buf, len-1, "%s", ptr_plain);
  }
  else if (hash_mode == 5800)
  {
    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if ((hash_mode >= 6200) && (hash_mode <= 6299))
  {
    snprintf (out_buf, len-1, "%s", hashfile);
  }
  else if (hash_mode == 6300)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, len-1, "{smd5}%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6400)
  {
    sha256aix_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, len-1, "{ssha256}%02d$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6500)
  {
    sha512aix_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    snprintf (out_buf, len-1, "{ssha512}%02d$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6600)
  {
    agilekey_t *agilekeys = (agilekey_t *) data.esalts_buf;

    agilekey_t *agilekey = &agilekeys[salt_pos];

    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);

    uint buf_len = len - 1;

    uint off = snprintf (out_buf, buf_len, "%d:%08x%08x:", salt.salt_iter + 1, salt.salt_buf[0], salt.salt_buf[1]);
    buf_len -= 22;

    for (uint i = 0, j = off; i < 1040; i++, j += 2)
    {
      snprintf (out_buf + j, buf_len, "%02x", agilekey->cipher[i]);

      buf_len -= 2;
    }
  }
  else if (hash_mode == 6700)
  {
    sha1aix_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, len-1, "{ssha1}%02d$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6800)
  {
    snprintf (out_buf, len-1, "%s", (char *) salt.salt_buf);
  }
  else if (hash_mode == 7100)
  {
    uint *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *) data.esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512  = &pbkdf2_sha512s[salt_pos];

    uint esalt[8] = { 0 };

    esalt[0] = byte_swap_32 (pbkdf2_sha512->salt_buf[0]);
    esalt[1] = byte_swap_32 (pbkdf2_sha512->salt_buf[1]);
    esalt[2] = byte_swap_32 (pbkdf2_sha512->salt_buf[2]);
    esalt[3] = byte_swap_32 (pbkdf2_sha512->salt_buf[3]);
    esalt[4] = byte_swap_32 (pbkdf2_sha512->salt_buf[4]);
    esalt[5] = byte_swap_32 (pbkdf2_sha512->salt_buf[5]);
    esalt[6] = byte_swap_32 (pbkdf2_sha512->salt_buf[6]);
    esalt[7] = byte_swap_32 (pbkdf2_sha512->salt_buf[7]);

    snprintf (out_buf, len-1, "%s%i$%08x%08x%08x%08x%08x%08x%08x%08x$%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_SHA512OSX,
      salt.salt_iter + 1,
      esalt[ 0], esalt[ 1],
      esalt[ 2], esalt[ 3],
      esalt[ 4], esalt[ 5],
      esalt[ 6], esalt[ 7],
      ptr  [ 1], ptr  [ 0],
      ptr  [ 3], ptr  [ 2],
      ptr  [ 5], ptr  [ 4],
      ptr  [ 7], ptr  [ 6],
      ptr  [ 9], ptr  [ 8],
      ptr  [11], ptr  [10],
      ptr  [13], ptr  [12],
      ptr  [15], ptr  [14]);
  }
  else if (hash_mode == 7200)
  {
    uint *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *) data.esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512  = &pbkdf2_sha512s[salt_pos];

    uint len_used = 0;

    snprintf (out_buf + len_used, len - len_used - 1, "%s%i.", SIGNATURE_SHA512GRUB, salt.salt_iter + 1);

    len_used = strlen (out_buf);

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha512->salt_buf;

    for (uint i = 0; i < salt.salt_len; i++, len_used += 2)
    {
      snprintf (out_buf + len_used, len - len_used - 1, "%02x", salt_buf_ptr[i]);
    }

    snprintf (out_buf + len_used, len - len_used - 1, ".%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      ptr  [ 1], ptr  [ 0],
      ptr  [ 3], ptr  [ 2],
      ptr  [ 5], ptr  [ 4],
      ptr  [ 7], ptr  [ 6],
      ptr  [ 9], ptr  [ 8],
      ptr  [11], ptr  [10],
      ptr  [13], ptr  [12],
      ptr  [15], ptr  [14]);
  }
  else if (hash_mode == 7300)
  {
    rakp_t *rakps = (rakp_t *) data.esalts_buf;

    rakp_t *rakp = &rakps[salt_pos];

    for (uint i = 0, j = 0; (i * 4) < rakp->salt_len; i += 1, j += 8)
    {
      sprintf (out_buf + j, "%08x", rakp->salt_buf[i]);
    }

    snprintf (out_buf + rakp->salt_len * 2, len - 1, ":%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7400)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    sha256crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA256CRYPT)
    {
      snprintf (out_buf, len-1, "$5$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, len-1, "$5$rounds=%i$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 7500)
  {
    krb5pa_t *krb5pas = (krb5pa_t *) data.esalts_buf;

    krb5pa_t *krb5pa = &krb5pas[salt_pos];

    u8 *ptr_timestamp = (u8 *) krb5pa->timestamp;
    u8 *ptr_checksum  = (u8 *) krb5pa->checksum;

    char data[128] = { 0 };

    char *ptr_data = data;

    for (uint i = 0; i < 36; i++, ptr_data += 2)
    {
      sprintf (ptr_data, "%02x", ptr_timestamp[i]);
    }

    for (uint i = 0; i < 16; i++, ptr_data += 2)
    {
      sprintf (ptr_data, "%02x", ptr_checksum[i]);
    }

    *ptr_data = 0;

    snprintf (out_buf, len-1, "%s$%s$%s$%s$%s",
      SIGNATURE_KRB5PA,
      (char *) krb5pa->user,
      (char *) krb5pa->realm,
      (char *) krb5pa->salt,
      data);
  }
  else if (hash_mode == 7700)
  {
    snprintf (out_buf, len-1, "%s$%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 7800)
  {
    snprintf (out_buf, len-1, "%s$%08X%08X%08X%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7900)
  {
    drupal7_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    // ugly hack start

    char *tmp = (char *) salt.salt_buf_pc;

    ptr_plain[42] = tmp[0];

    // ugly hack end

    ptr_plain[43] = 0;

    snprintf (out_buf, len-1, "%s%s%s", (char *) salt.salt_sign, (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 8000)
  {
    snprintf (out_buf, len-1, "0xc007%s%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 8100)
  {
    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);

    snprintf (out_buf, len-1, "1%s%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 8200)
  {
    cloudkey_t *cloudkeys = (cloudkey_t *) data.esalts_buf;

    cloudkey_t *cloudkey = &cloudkeys[salt_pos];

    char data_buf[4096] = { 0 };

    for (int i = 0, j = 0; i < 512; i += 1, j += 8)
    {
      sprintf (data_buf + j, "%08x", cloudkey->data_buf[i]);
    }

    data_buf[cloudkey->data_len * 2] = 0;

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);
    salt.salt_buf[2] = byte_swap_32 (salt.salt_buf[2]);
    salt.salt_buf[3] = byte_swap_32 (salt.salt_buf[3]);

    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x:%08x%08x%08x%08x:%u:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_iter + 1,
      data_buf);
  }
  else if (hash_mode == 8300)
  {
    char digest_buf_c[34] = { 0 };

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    base32_encode (int_to_itoa32, (const u8 *) digest_buf, 20, (u8 *) digest_buf_c);

    digest_buf_c[32] = 0;

    // domain

    const uint salt_pc_len = salt.salt_buf_pc[7]; // what a hack

    char domain_buf_c[33] = { 0 };

    memcpy (domain_buf_c, (char *) salt.salt_buf_pc, salt_pc_len);

    for (uint i = 0; i < salt_pc_len; i++)
    {
      const char next = domain_buf_c[i];

      domain_buf_c[i] = '.';

      i += next;
    }

    domain_buf_c[salt_pc_len] = 0;

    // final

    snprintf (out_buf, len-1, "%s:%s:%s:%u", digest_buf_c, domain_buf_c, (char *) salt.salt_buf, salt.salt_iter);
  }
  else if (hash_mode == 8500)
  {
    snprintf (out_buf, len-1, "%s*%s*%08X%08X", SIGNATURE_RACF, (char *) salt.salt_buf, digest_buf[0], digest_buf[1]);
  }
  else if (hash_mode == 2612)
  {
    snprintf (out_buf, len-1, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_PHPS,
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 3711)
  {
    char *salt_ptr = (char *) salt.salt_buf;

    salt_ptr[salt.salt_len - 1] = 0;

    snprintf (out_buf, len-1, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_MEDIAWIKI_B,
      salt_ptr,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 8800)
  {
    androidfde_t *androidfdes = (androidfde_t *) data.esalts_buf;

    androidfde_t *androidfde = &androidfdes[salt_pos];

    char tmp[3073] = { 0 };

    for (uint i = 0, j = 0; i < 384; i += 1, j += 8)
    {
      sprintf (tmp + j, "%08x", androidfde->data[i]);
    }

    tmp[3072] = 0;

    snprintf (out_buf, len-1, "%s16$%08x%08x%08x%08x$16$%08x%08x%08x%08x$%s",
      SIGNATURE_ANDROIDFDE,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      tmp);
  }
  else if (hash_mode == 8900)
  {
    uint N = salt.scrypt_N;
    uint r = salt.scrypt_r;
    uint p = salt.scrypt_p;

    char base64_salt[32] = { 0 };

    base64_encode (int_to_base64, (const u8 *) salt.salt_buf, salt.salt_len, (u8 *) base64_salt);

    memset (tmp_buf, 0, 46);

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_base64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    snprintf (out_buf, len-1, "%s:%i:%i:%i:%s:%s",
      SIGNATURE_SCRYPT,
      N,
      r,
      p,
      base64_salt,
      tmp_buf);
  }
  else if (hash_mode == 9000)
  {
    snprintf (out_buf, len-1, "%s", hashfile);
  }
  else if (hash_mode == 9200)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) data.esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[salt_pos];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);
    tmp_buf[43] = 0; // cut it here

    // output

    snprintf (out_buf, len-1, "%s%s$%s", SIGNATURE_CISCO8, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9300)
  {
    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);
    tmp_buf[43] = 0; // cut it here

    unsigned char *salt_buf_ptr = (unsigned char *) salt.salt_buf;

    snprintf (out_buf, len-1, "%s%s$%s", SIGNATURE_CISCO9, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9400)
  {
    office2007_t *office2007s = (office2007_t *) data.esalts_buf;

    office2007_t *office2007 = &office2007s[salt_pos];

    snprintf (out_buf, len-1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2007,
      2007,
      20,
      office2007->keySize,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2007->encryptedVerifier[0],
      office2007->encryptedVerifier[1],
      office2007->encryptedVerifier[2],
      office2007->encryptedVerifier[3],
      office2007->encryptedVerifierHash[0],
      office2007->encryptedVerifierHash[1],
      office2007->encryptedVerifierHash[2],
      office2007->encryptedVerifierHash[3],
      office2007->encryptedVerifierHash[4]);
  }
  else if (hash_mode == 9500)
  {
    office2010_t *office2010s = (office2010_t *) data.esalts_buf;

    office2010_t *office2010 = &office2010s[salt_pos];

    snprintf (out_buf, len-1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x", SIGNATURE_OFFICE2010, 2010, 100000, 128, 16,

      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2010->encryptedVerifier[0],
      office2010->encryptedVerifier[1],
      office2010->encryptedVerifier[2],
      office2010->encryptedVerifier[3],
      office2010->encryptedVerifierHash[0],
      office2010->encryptedVerifierHash[1],
      office2010->encryptedVerifierHash[2],
      office2010->encryptedVerifierHash[3],
      office2010->encryptedVerifierHash[4],
      office2010->encryptedVerifierHash[5],
      office2010->encryptedVerifierHash[6],
      office2010->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9600)
  {
    office2013_t *office2013s = (office2013_t *) data.esalts_buf;

    office2013_t *office2013 = &office2013s[salt_pos];

    snprintf (out_buf, len-1, "%s*%u*%u*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x", SIGNATURE_OFFICE2013, 2013, 100000, 256, 16,

      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2013->encryptedVerifier[0],
      office2013->encryptedVerifier[1],
      office2013->encryptedVerifier[2],
      office2013->encryptedVerifier[3],
      office2013->encryptedVerifierHash[0],
      office2013->encryptedVerifierHash[1],
      office2013->encryptedVerifierHash[2],
      office2013->encryptedVerifierHash[3],
      office2013->encryptedVerifierHash[4],
      office2013->encryptedVerifierHash[5],
      office2013->encryptedVerifierHash[6],
      office2013->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9700)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9710)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9720)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) data.esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[salt_pos];

    u8 *rc4key = (u8 *) oldoffice01->rc4key;

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 9800)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9810)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9820)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) data.esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[salt_pos];

    u8 *rc4key = (u8 *) oldoffice34->rc4key;

    snprintf (out_buf, len-1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 10000)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) data.esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[salt_pos];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    char tmp_buf[64] = { 0 };

    base64_encode (int_to_base64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    // output

    snprintf (out_buf, len-1, "%s%i$%s$%s", SIGNATURE_DJANGOPBKDF2, salt.salt_iter + 1, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 10100)
  {
    snprintf (out_buf, len-1, "%08x%08x:%u:%u:%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      2,
      4,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]));
  }
  else if (hash_mode == 10200)
  {
    cram_md5_t *cram_md5s = (cram_md5_t *) data.esalts_buf;

    cram_md5_t *cram_md5 = &cram_md5s[salt_pos];

    // challenge

    char challenge[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) salt.salt_buf, salt.salt_len, (u8 *) challenge);

    // response

    char tmp_buf[100] = { 0 };

    uint tmp_len = snprintf (tmp_buf, 100, "%s %08x%08x%08x%08x",
      (char *) cram_md5->user,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);

    char response[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) response);

    snprintf (out_buf, len-1, "%s%s$%s", SIGNATURE_CRAM_MD5, challenge, response);
  }
  else if (hash_mode == 10300)
  {
    char tmp_buf[100] = { 0 };

    memcpy (tmp_buf +  0, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    uint tmp_len = 20 + salt.salt_len;

    // base64 encode it

    char base64_encoded[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) base64_encoded);

    snprintf (out_buf, len-1, "%s%i}%s", SIGNATURE_SAPH_SHA1, salt.salt_iter + 1, base64_encoded);
  }
  else if (hash_mode == 10400)
  {
    pdf_t *pdfs = (pdf_t *) data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    snprintf (out_buf, len-1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7])
    );
  }
  else if (hash_mode == 10410)
  {
    pdf_t *pdfs = (pdf_t *) data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    snprintf (out_buf, len-1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7])
    );
  }
  else if (hash_mode == 10420)
  {
    pdf_t *pdfs = (pdf_t *) data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    u8 *rc4key = (u8 *) pdf->rc4key;

    snprintf (out_buf, len-1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]
    );
  }
  else if (hash_mode == 10500)
  {
    pdf_t *pdfs = (pdf_t *) data.esalts_buf;

    pdf_t *pdf = &pdfs[salt_pos];

    if (pdf->id_len == 32)
    {
      snprintf (out_buf, len-1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32 (pdf->id_buf[0]),
        byte_swap_32 (pdf->id_buf[1]),
        byte_swap_32 (pdf->id_buf[2]),
        byte_swap_32 (pdf->id_buf[3]),
        byte_swap_32 (pdf->id_buf[4]),
        byte_swap_32 (pdf->id_buf[5]),
        byte_swap_32 (pdf->id_buf[6]),
        byte_swap_32 (pdf->id_buf[7]),
        pdf->u_len,
        byte_swap_32 (pdf->u_buf[0]),
        byte_swap_32 (pdf->u_buf[1]),
        byte_swap_32 (pdf->u_buf[2]),
        byte_swap_32 (pdf->u_buf[3]),
        byte_swap_32 (pdf->u_buf[4]),
        byte_swap_32 (pdf->u_buf[5]),
        byte_swap_32 (pdf->u_buf[6]),
        byte_swap_32 (pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32 (pdf->o_buf[0]),
        byte_swap_32 (pdf->o_buf[1]),
        byte_swap_32 (pdf->o_buf[2]),
        byte_swap_32 (pdf->o_buf[3]),
        byte_swap_32 (pdf->o_buf[4]),
        byte_swap_32 (pdf->o_buf[5]),
        byte_swap_32 (pdf->o_buf[6]),
        byte_swap_32 (pdf->o_buf[7])
      );
    }
    else
    {
      snprintf (out_buf, len-1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32 (pdf->id_buf[0]),
        byte_swap_32 (pdf->id_buf[1]),
        byte_swap_32 (pdf->id_buf[2]),
        byte_swap_32 (pdf->id_buf[3]),
        pdf->u_len,
        byte_swap_32 (pdf->u_buf[0]),
        byte_swap_32 (pdf->u_buf[1]),
        byte_swap_32 (pdf->u_buf[2]),
        byte_swap_32 (pdf->u_buf[3]),
        byte_swap_32 (pdf->u_buf[4]),
        byte_swap_32 (pdf->u_buf[5]),
        byte_swap_32 (pdf->u_buf[6]),
        byte_swap_32 (pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32 (pdf->o_buf[0]),
        byte_swap_32 (pdf->o_buf[1]),
        byte_swap_32 (pdf->o_buf[2]),
        byte_swap_32 (pdf->o_buf[3]),
        byte_swap_32 (pdf->o_buf[4]),
        byte_swap_32 (pdf->o_buf[5]),
        byte_swap_32 (pdf->o_buf[6]),
        byte_swap_32 (pdf->o_buf[7])
      );
    }
  }
  else if (hash_mode == 10600)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 10700)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 10900)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 11100)
  {
    u32 salt_challenge = salt.salt_buf[0];

    salt_challenge = byte_swap_32 (salt_challenge);

    unsigned char *user_name = (unsigned char *) (salt.salt_buf + 1);

    snprintf (out_buf, len-1, "%s%s*%08x*%08x%08x%08x%08x",
        SIGNATURE_POSTGRESQL_AUTH,
        user_name,
        salt_challenge,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
  }
  else if (hash_mode == 11200)
  {
    snprintf (out_buf, len-1, "%s%s*%08x%08x%08x%08x%08x",
        SIGNATURE_MYSQL_AUTH,
        (unsigned char *) salt.salt_buf,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
  }
  else if (hash_mode == 11300)
  {
    bitcoin_wallet_t *bitcoin_wallets = (bitcoin_wallet_t *) data.esalts_buf;

    bitcoin_wallet_t *bitcoin_wallet = &bitcoin_wallets[salt_pos];

    const uint cry_master_len = bitcoin_wallet->cry_master_len;
    const uint ckey_len       = bitcoin_wallet->ckey_len;
    const uint public_key_len = bitcoin_wallet->public_key_len;

    char *cry_master_buf = (char *) mymalloc ((cry_master_len * 2) + 1);
    char *ckey_buf       = (char *) mymalloc ((ckey_len * 2)       + 1);
    char *public_key_buf = (char *) mymalloc ((public_key_len * 2) + 1);

    for (uint i = 0, j = 0; i < cry_master_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->cry_master_buf;

      sprintf (cry_master_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < ckey_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->ckey_buf;

      sprintf (ckey_buf + j, "%02x", ptr[i]);
    }

    for (uint i = 0, j = 0; i < public_key_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->public_key_buf;

      sprintf (public_key_buf + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, len-1, "%s%d$%s$%d$%s$%d$%d$%s$%d$%s",
      SIGNATURE_BITCOIN_WALLET,
      cry_master_len * 2,
      cry_master_buf,
      salt.salt_len,
      (unsigned char *) salt.salt_buf,
      salt.salt_iter + 1,
      ckey_len * 2,
      ckey_buf,
      public_key_len * 2,
      public_key_buf
    );

    free (cry_master_buf);
    free (ckey_buf);
    free (public_key_buf);
  }
  else if (hash_mode == 11400)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 11600)
  {
    seven_zip_t *seven_zips = (seven_zip_t *) data.esalts_buf;

    seven_zip_t *seven_zip = &seven_zips[salt_pos];

    const uint data_len = seven_zip->data_len;

    char *data_buf = (char *) mymalloc ((data_len * 2) + 1);

    for (uint i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) seven_zip->data_buf;

      sprintf (data_buf + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, len-1, "%s%u$%u$%u$%s$%u$%08x%08x%08x%08x$%u$%u$%u$%s",
      SIGNATURE_SEVEN_ZIP,
      0,
      salt.salt_sign[0],
      0,
      (char *) seven_zip->salt_buf,
      seven_zip->iv_len,
      seven_zip->iv_buf[0],
      seven_zip->iv_buf[1],
      seven_zip->iv_buf[2],
      seven_zip->iv_buf[3],
      seven_zip->crc,
      seven_zip->data_len,
      seven_zip->unpack_size,
      data_buf);

    free (data_buf);
  }
  else if (hash_mode == 11700)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 11800)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[ 0],
      digest_buf[ 1],
      digest_buf[ 2],
      digest_buf[ 3],
      digest_buf[ 4],
      digest_buf[ 5],
      digest_buf[ 6],
      digest_buf[ 7],
      digest_buf[ 8],
      digest_buf[ 9],
      digest_buf[10],
      digest_buf[11],
      digest_buf[12],
      digest_buf[13],
      digest_buf[14],
      digest_buf[15]);
  }
  else if (hash_mode == 11900)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 12000)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 12100)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 12200)
  {
    uint *ptr_digest = digest_buf;
    uint *ptr_salt   = salt.salt_buf;

    snprintf (out_buf, len-1, "%s0$1$%08x%08x$%08x%08x",
      SIGNATURE_ECRYPTFS,
      ptr_salt[0],
      ptr_salt[1],
      ptr_digest[0],
      ptr_digest[1]);
  }
  else if (hash_mode == 12300)
  {
    uint *ptr_digest = digest_buf;
    uint *ptr_salt   = salt.salt_buf;

    snprintf (out_buf, len-1, "%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
      ptr_digest[ 0], ptr_digest[ 1],
      ptr_digest[ 2], ptr_digest[ 3],
      ptr_digest[ 4], ptr_digest[ 5],
      ptr_digest[ 6], ptr_digest[ 7],
      ptr_digest[ 8], ptr_digest[ 9],
      ptr_digest[10], ptr_digest[11],
      ptr_digest[12], ptr_digest[13],
      ptr_digest[14], ptr_digest[15],
      ptr_salt[0],
      ptr_salt[1],
      ptr_salt[2],
      ptr_salt[3]);
  }
  else if (hash_mode == 12400)
  {
    // encode iteration count

    char salt_iter[5] = { 0 };

    salt_iter[0] = int_to_itoa64 ((salt.salt_iter      ) & 0x3f);
    salt_iter[1] = int_to_itoa64 ((salt.salt_iter >>  6) & 0x3f);
    salt_iter[2] = int_to_itoa64 ((salt.salt_iter >> 12) & 0x3f);
    salt_iter[3] = int_to_itoa64 ((salt.salt_iter >> 18) & 0x3f);
    salt_iter[4] = 0;

    // encode salt

    ptr_salt[0] = int_to_itoa64 ((salt.salt_buf[0]      ) & 0x3f);
    ptr_salt[1] = int_to_itoa64 ((salt.salt_buf[0] >>  6) & 0x3f);
    ptr_salt[2] = int_to_itoa64 ((salt.salt_buf[0] >> 12) & 0x3f);
    ptr_salt[3] = int_to_itoa64 ((salt.salt_buf[0] >> 18) & 0x3f);
    ptr_salt[4] = 0;

    // encode digest

    memset (tmp_buf, 0, sizeof (tmp_buf));

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);

    memcpy (tmp_buf, digest_buf, 8);

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 8, (u8 *) ptr_plain);

    ptr_plain[11] = 0;

    // fill the resulting buffer

    snprintf (out_buf, len - 1, "_%s%s%s", salt_iter, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 12500)
  {
    snprintf (out_buf, len - 1, "%s*0*%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_RAR3,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5]);
  }
  else if (hash_mode == 12600)
  {
    snprintf (out_buf, len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0] + salt.salt_buf_pc[0],
      digest_buf[1] + salt.salt_buf_pc[1],
      digest_buf[2] + salt.salt_buf_pc[2],
      digest_buf[3] + salt.salt_buf_pc[3],
      digest_buf[4] + salt.salt_buf_pc[4],
      digest_buf[5] + salt.salt_buf_pc[5],
      digest_buf[6] + salt.salt_buf_pc[6],
      digest_buf[7] + salt.salt_buf_pc[7]);
  }
  else if (hash_mode == 12700)
  {
    uint digest_idx = salt.digests_offset + digest_pos;

    hashinfo_t **hashinfo_ptr = data.hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_idx]->orighash;

    snprintf (out_buf, len-1, "%s", hash_buf);
  }
  else if (hash_mode == 12800)
  {
    const u8 *ptr = (const u8 *) salt.salt_buf;

    snprintf (out_buf, len-1, "%s,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%d,%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_MS_DRSR,
      ptr[0],
      ptr[1],
      ptr[2],
      ptr[3],
      ptr[4],
      ptr[5],
      ptr[6],
      ptr[7],
      ptr[8],
      ptr[9],
      salt.salt_iter + 1,
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7])
    );
  }
  else if (hash_mode == 12900)
  {
    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      salt.salt_buf[ 4],
      salt.salt_buf[ 5],
      salt.salt_buf[ 6],
      salt.salt_buf[ 7],
      salt.salt_buf[ 8],
      salt.salt_buf[ 9],
      salt.salt_buf[10],
      salt.salt_buf[11],
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7]),
      salt.salt_buf[ 0],
      salt.salt_buf[ 1],
      salt.salt_buf[ 2],
      salt.salt_buf[ 3]
    );
  }
  else if (hash_mode == 13000)
  {
    rar5_t *rar5s = (rar5_t *) data.esalts_buf;

    rar5_t *rar5 = &rar5s[salt_pos];

    snprintf (out_buf, len-1, "$rar5$16$%08x%08x%08x%08x$%u$%08x%08x%08x%08x$8$%08x%08x",
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_sign[0],
      rar5->iv[0],
      rar5->iv[1],
      rar5->iv[2],
      rar5->iv[3],
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1])
    );
  }
  else if (hash_mode == 13100)
  {
    krb5tgs_t *krb5tgss = (krb5tgs_t *) data.esalts_buf;

    krb5tgs_t *krb5tgs = &krb5tgss[salt_pos];

    u8 *ptr_checksum  = (u8 *) krb5tgs->checksum;
    u8 *ptr_edata2 = (u8 *) krb5tgs->edata2;

    char data[2560 * 4 * 2] = { 0 };

    char *ptr_data = data;

    for (uint i = 0; i < 16; i++, ptr_data += 2)
      sprintf (ptr_data, "%02x", ptr_checksum[i]);

    /* skip '$' */
    ptr_data++;

    for (uint i = 0; i < krb5tgs->edata2_len; i++, ptr_data += 2)
      sprintf (ptr_data, "%02x", ptr_edata2[i]);

    snprintf (out_buf, len-1, "%s$%s$%s$%s",
      SIGNATURE_KRB5TGS,
      (char *) krb5tgs->account_info,
      data,
      data + 33);
  }
  else if (hash_mode == 13200)
  {
    snprintf (out_buf, len-1, "%s*%d*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT,
      salt.salt_iter,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5],
      salt.salt_buf[6],
      salt.salt_buf[7],
      salt.salt_buf[8],
      salt.salt_buf[9]);
  }
  else if (hash_mode == 13300)
  {
    snprintf (out_buf, len-1, "%s$%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT_SHA1,
              digest_buf[0],
              digest_buf[1],
              digest_buf[2],
              digest_buf[3]);
  }
  else if (hash_mode == 13400)
  {
    keepass_t *keepasss = (keepass_t *) data.esalts_buf;

    keepass_t *keepass = &keepasss[salt_pos];

    u32 version     = (u32) keepass->version;
    u32 rounds      = salt.salt_iter;
    u32 algorithm   = (u32) keepass->algorithm;
    u32 keyfile_len = (u32) keepass->keyfile_len;

    u32 *ptr_final_random_seed  = (u32 *) keepass->final_random_seed ;
    u32 *ptr_transf_random_seed = (u32 *) keepass->transf_random_seed ;
    u32 *ptr_enc_iv             = (u32 *) keepass->enc_iv ;
    u32 *ptr_contents_hash      = (u32 *) keepass->contents_hash ;
    u32 *ptr_keyfile            = (u32 *) keepass->keyfile ;

    /* specific to version 1 */
    u32 contents_len;
    u32 *ptr_contents;

    /* specific to version 2 */
    u32 expected_bytes_len;
    u32 *ptr_expected_bytes;

    u32 final_random_seed_len;
    u32 transf_random_seed_len;
    u32 enc_iv_len;
    u32 contents_hash_len;

    transf_random_seed_len = 8;
    enc_iv_len             = 4;
    contents_hash_len      = 8;
    final_random_seed_len  = 8;

    if (version == 1)
      final_random_seed_len = 4;

    snprintf (out_buf, len-1, "%s*%d*%d*%d",
      SIGNATURE_KEEPASS,
      version,
      rounds,
      algorithm);

    char *ptr_data = out_buf;

    ptr_data += strlen(out_buf);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < final_random_seed_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_final_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < transf_random_seed_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_transf_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (uint i = 0; i < enc_iv_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_enc_iv[i]);

    *ptr_data = '*';
    ptr_data++;

    if (version == 1)
    {
      contents_len = (u32)   keepass->contents_len;
      ptr_contents = (u32 *) keepass->contents;

      for (uint i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents_hash[i]);

      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      char ptr_contents_len[10] = { 0 };

      sprintf ((char*) ptr_contents_len, "%d", contents_len);

      sprintf (ptr_data, "%d", contents_len);

      ptr_data += strlen(ptr_contents_len);

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < contents_len / 4; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents[i]);
    }
    else if (version == 2)
    {
      expected_bytes_len = 8;
      ptr_expected_bytes = (u32 *) keepass->expected_bytes ;

      for (uint i = 0; i < expected_bytes_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_expected_bytes[i]);

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents_hash[i]);
    }
    if (keyfile_len)
    {
      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      sprintf (ptr_data, "%d", keyfile_len);

      ptr_data += 2;

      *ptr_data = '*';
      ptr_data++;

      for (uint i = 0; i < 8; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_keyfile[i]);
    }
  }
  else if (hash_mode == 13500)
  {
    pstoken_t *pstokens = (pstoken_t *) data.esalts_buf;

    pstoken_t *pstoken = &pstokens[salt_pos];

    const u32 salt_len = (pstoken->salt_len > 512) ? 512 : pstoken->salt_len;

    char pstoken_tmp[1024 + 1] = { 0 };

    for (uint i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) pstoken->salt_buf;

      sprintf (pstoken_tmp + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      pstoken_tmp);
  }
  else if (hash_mode == 13600)
  {
    zip2_t *zip2s = (zip2_t *) data.esalts_buf;

    zip2_t *zip2 = &zip2s[salt_pos];

    const u32 salt_len = zip2->salt_len;

    char salt_tmp[32 + 1] = { 0 };

    for (uint i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->salt_buf;

      sprintf (salt_tmp + j, "%02x", ptr[i]);
    }

    const u32 data_len = zip2->data_len;

    char data_tmp[8192 + 1] = { 0 };

    for (uint i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->data_buf;

      sprintf (data_tmp + j, "%02x", ptr[i]);
    }

    const u32 auth_len = zip2->auth_len;

    char auth_tmp[20 + 1] = { 0 };

    for (uint i = 0, j = 0; i < auth_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->auth_buf;

      sprintf (auth_tmp + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, 255, "%s*%u*%u*%u*%s*%x*%u*%s*%s*%s",
      SIGNATURE_ZIP2_START,
      zip2->type,
      zip2->mode,
      zip2->magic,
      salt_tmp,
      zip2->verify_bytes,
      zip2->compress_length,
      data_tmp,
      auth_tmp,
      SIGNATURE_ZIP2_STOP);
  }
  else if ((hash_mode >= 13700) && (hash_mode <= 13799))
  {
    snprintf (out_buf, len-1, "%s", hashfile);
  }
  else if (hash_mode == 13800)
  {
    win8phone_t *esalts = (win8phone_t *) data.esalts_buf;

    win8phone_t *esalt = &esalts[salt_pos];

    char buf[256 + 1] = { 0 };

    for (int i = 0, j = 0; i < 32; i += 1, j += 8)
    {
      sprintf (buf + j, "%08x", esalt->salt_buf[i]);
    }

    snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      buf);
  }
  else
  {
    if (hash_type == HASH_TYPE_MD4)
    {
      snprintf (out_buf, 255, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_MD5)
    {
      snprintf (out_buf, len-1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_SHA1)
    {
      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_SHA256)
    {
      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_SHA384)
    {
      uint *ptr = digest_buf;

      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10]);
    }
    else if (hash_type == HASH_TYPE_SHA512)
    {
      uint *ptr = digest_buf;

      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
    }
    else if (hash_type == HASH_TYPE_LM)
    {
      snprintf (out_buf, len-1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_ORACLEH)
    {
      snprintf (out_buf, len-1, "%08X%08X",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_BCRYPT)
    {
      base64_encode (int_to_bf64, (const u8 *) salt.salt_buf, 16, (u8 *) tmp_buf + 0);
      base64_encode (int_to_bf64, (const u8 *) digest_buf,    23, (u8 *) tmp_buf + 22);

      tmp_buf[22 + 31] = 0; // base64_encode wants to pad

      snprintf (out_buf, len-1, "%s$%s", (char *) salt.salt_sign, tmp_buf);
    }
    else if (hash_type == HASH_TYPE_KECCAK)
    {
      uint *ptr = digest_buf;

      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14],
        ptr[17], ptr[16],
        ptr[19], ptr[18],
        ptr[21], ptr[20],
        ptr[23], ptr[22],
        ptr[25], ptr[24],
        ptr[27], ptr[26],
        ptr[29], ptr[28],
        ptr[31], ptr[30],
        ptr[33], ptr[32],
        ptr[35], ptr[34],
        ptr[37], ptr[36],
        ptr[39], ptr[38],
        ptr[41], ptr[30],
        ptr[43], ptr[42],
        ptr[45], ptr[44],
        ptr[47], ptr[46],
        ptr[49], ptr[48]
      );

      out_buf[salt.keccak_mdlen * 2] = 0;
    }
    else if (hash_type == HASH_TYPE_RIPEMD160)
    {
      snprintf (out_buf, 255, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_WHIRLPOOL)
    {
      digest_buf[ 0] = digest_buf[ 0];
      digest_buf[ 1] = digest_buf[ 1];
      digest_buf[ 2] = digest_buf[ 2];
      digest_buf[ 3] = digest_buf[ 3];
      digest_buf[ 4] = digest_buf[ 4];
      digest_buf[ 5] = digest_buf[ 5];
      digest_buf[ 6] = digest_buf[ 6];
      digest_buf[ 7] = digest_buf[ 7];
      digest_buf[ 8] = digest_buf[ 8];
      digest_buf[ 9] = digest_buf[ 9];
      digest_buf[10] = digest_buf[10];
      digest_buf[11] = digest_buf[11];
      digest_buf[12] = digest_buf[12];
      digest_buf[13] = digest_buf[13];
      digest_buf[14] = digest_buf[14];
      digest_buf[15] = digest_buf[15];

      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[ 0],
        digest_buf[ 1],
        digest_buf[ 2],
        digest_buf[ 3],
        digest_buf[ 4],
        digest_buf[ 5],
        digest_buf[ 6],
        digest_buf[ 7],
        digest_buf[ 8],
        digest_buf[ 9],
        digest_buf[10],
        digest_buf[11],
        digest_buf[12],
        digest_buf[13],
        digest_buf[14],
        digest_buf[15]);
    }
    else if (hash_type == HASH_TYPE_GOST)
    {
      snprintf (out_buf, len-1, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_MYSQL)
    {
      snprintf (out_buf, len-1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_LOTUS5)
    {
      snprintf (out_buf, len-1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_LOTUS6)
    {
      digest_buf[ 0] = byte_swap_32 (digest_buf[ 0]);
      digest_buf[ 1] = byte_swap_32 (digest_buf[ 1]);
      digest_buf[ 2] = byte_swap_32 (digest_buf[ 2]);
      digest_buf[ 3] = byte_swap_32 (digest_buf[ 3]);

      char buf[16] = { 0 };

      memcpy (buf + 0, salt.salt_buf, 5);
      memcpy (buf + 5, digest_buf, 9);

      buf[3] -= -4;

      base64_encode (int_to_lotus64, (const u8 *) buf, 14, (u8 *) tmp_buf);

      tmp_buf[18] = salt.salt_buf_pc[7];
      tmp_buf[19] = 0;

      snprintf (out_buf, len-1, "(G%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_LOTUS8)
    {
      char buf[52] = { 0 };

      // salt

      memcpy (buf + 0, salt.salt_buf, 16);

      buf[3] -= -4;

      // iteration

      snprintf (buf + 16, 11, "%010i", salt.salt_iter + 1);

      // chars

      buf[26] = salt.salt_buf_pc[0];
      buf[27] = salt.salt_buf_pc[1];

      // digest

      memcpy (buf + 28, digest_buf, 8);

      base64_encode (int_to_lotus64, (const u8 *) buf, 36, (u8 *) tmp_buf);

      tmp_buf[49] = 0;

      snprintf (out_buf, len-1, "(H%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_CRC32)
    {
      snprintf (out_buf, len-1, "%08x", byte_swap_32 (digest_buf[0]));
    }
  }

  if (salt_type == SALT_TYPE_INTERN)
  {
    size_t pos = strlen (out_buf);

    out_buf[pos] = data.separator;

    char *ptr = (char *) salt.salt_buf;

    memcpy (out_buf + pos + 1, ptr, salt.salt_len);

    out_buf[pos + 1 + salt.salt_len] = 0;
  }
}

void to_hccap_t (hccap_t *hccap, uint salt_pos, uint digest_pos)
{
  memset (hccap, 0, sizeof (hccap_t));

  salt_t *salt = &data.salts_buf[salt_pos];

  memcpy (hccap->essid, salt->salt_buf, salt->salt_len);

  wpa_t *wpas = (wpa_t *) data.esalts_buf;
  wpa_t *wpa  = &wpas[salt_pos];

  hccap->keyver = wpa->keyver;

  hccap->eapol_size = wpa->eapol_size;

  if (wpa->keyver != 1)
  {
    uint eapol_tmp[64] = { 0 };

    for (uint i = 0; i < 64; i++)
    {
      eapol_tmp[i] = byte_swap_32 (wpa->eapol[i]);
    }

    memcpy (hccap->eapol, eapol_tmp, wpa->eapol_size);
  }
  else
  {
    memcpy (hccap->eapol, wpa->eapol, wpa->eapol_size);
  }

  memcpy (hccap->mac1,   wpa->orig_mac1,    6);
  memcpy (hccap->mac2,   wpa->orig_mac2,    6);
  memcpy (hccap->nonce1, wpa->orig_nonce1, 32);
  memcpy (hccap->nonce2, wpa->orig_nonce2, 32);

  char *digests_buf_ptr = (char *) data.digests_buf;

  uint dgst_size = data.dgst_size;

  uint *digest_ptr = (uint *) (digests_buf_ptr + (data.salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size));

  if (wpa->keyver != 1)
  {
    uint digest_tmp[4] = { 0 };

    digest_tmp[0] = byte_swap_32 (digest_ptr[0]);
    digest_tmp[1] = byte_swap_32 (digest_ptr[1]);
    digest_tmp[2] = byte_swap_32 (digest_ptr[2]);
    digest_tmp[3] = byte_swap_32 (digest_ptr[3]);

    memcpy (hccap->keymic, digest_tmp, 16);
  }
  else
  {
    memcpy (hccap->keymic, digest_ptr, 16);
  }
}

void SuspendThreads ()
{
  if (data.devices_status != STATUS_RUNNING) return;

  hc_timer_set (&data.timer_paused);

  data.devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

void ResumeThreads ()
{
  if (data.devices_status != STATUS_PAUSED) return;

  double ms_paused;

  hc_timer_get (data.timer_paused, ms_paused);

  data.ms_paused += ms_paused;

  data.devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}

void bypass ()
{
  data.devices_status = STATUS_BYPASS;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

void stop_at_checkpoint ()
{
  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    if (data.devices_status != STATUS_RUNNING) return;
  }

  // this feature only makes sense if --restore-disable was not specified

  if (data.restore_disable == 1)
  {
    log_info ("WARNING: This feature is disabled when --restore-disable is specified");

    return;
  }

  // check if monitoring of Restore Point updates should be enabled or disabled

  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    data.devices_status = STATUS_STOP_AT_CHECKPOINT;

    // save the current restore point value

    data.checkpoint_cur_words = get_lowest_words_done ();

    log_info ("Checkpoint enabled: Will quit at next Restore Point update");
  }
  else
  {
    data.devices_status = STATUS_RUNNING;

    // reset the global value for checkpoint checks

    data.checkpoint_cur_words = 0;

    log_info ("Checkpoint disabled: Restore Point updates will no longer be monitored");
  }
}

void myabort ()
{
  data.devices_status = STATUS_ABORTED;
}

void myquit ()
{
  data.devices_status = STATUS_QUIT;
}

void naive_replace (char *s, const u8 key_char, const u8 replace_char)
{
  const size_t len = strlen (s);

  for (size_t in = 0; in < len; in++)
  {
    const u8 c = s[in];

    if (c == key_char)
    {
      s[in] = replace_char;
    }
  }
}

void naive_escape (char *s, size_t s_max, const u8 key_char, const u8 escape_char)
{
  char s_escaped[1024] = { 0 };

  size_t s_escaped_max = sizeof (s_escaped);

  const size_t len = strlen (s);

  for (size_t in = 0, out = 0; in < len; in++, out++)
  {
    const u8 c = s[in];

    if (c == key_char)
    {
      s_escaped[out] = escape_char;

      out++;
    }

    if (out == s_escaped_max - 2) break;

    s_escaped[out] = c;
  }

  strncpy (s, s_escaped, s_max - 1);
}

void load_kernel (const char *kernel_file, int num_devices, size_t *kernel_lengths, const u8 **kernel_sources)
{
  FILE *fp = fopen (kernel_file, "rb");

  if (fp != NULL)
  {
    struct stat st;

    memset (&st, 0, sizeof (st));

    stat (kernel_file, &st);

    u8 *buf = (u8 *) mymalloc (st.st_size + 1);

    size_t num_read = fread (buf, sizeof (u8), st.st_size, fp);

    if (num_read != (size_t) st.st_size)
    {
      log_error ("ERROR: %s: %s", kernel_file, strerror (errno));

      exit (-1);
    }

    fclose (fp);

    buf[st.st_size] = 0;

    for (int i = 0; i < num_devices; i++)
    {
      kernel_lengths[i] = (size_t) st.st_size;

      kernel_sources[i] = buf;
    }
  }
  else
  {
    log_error ("ERROR: %s: %s", kernel_file, strerror (errno));

    exit (-1);
  }

  return;
}

void writeProgramBin (char *dst, u8 *binary, size_t binary_size)
{
  if (binary_size > 0)
  {
    FILE *fp = fopen (dst, "wb");

    lock_file (fp);
    fwrite (binary, sizeof (u8), binary_size, fp);

    fflush (fp);
    fclose (fp);
  }
}

/**
 * restore
 */

restore_data_t *init_restore (int argc, char **argv)
{
  restore_data_t *rd = (restore_data_t *) mymalloc (sizeof (restore_data_t));

  if (data.restore_disable == 0)
  {
    FILE *fp = fopen (data.eff_restore_file, "rb");

    if (fp)
    {
      size_t nread = fread (rd, sizeof (restore_data_t), 1, fp);

      if (nread != 1)
      {
        log_error ("ERROR: Cannot read %s", data.eff_restore_file);

        exit (-1);
      }

      fclose (fp);

      if (rd->pid)
      {
        char *pidbin = (char *) mymalloc (HCBUFSIZ);

        int pidbin_len = -1;

        #ifdef _POSIX
        snprintf (pidbin, HCBUFSIZ - 1, "/proc/%d/cmdline", rd->pid);

        FILE *fd = fopen (pidbin, "rb");

        if (fd)
        {
          pidbin_len = fread (pidbin, 1, HCBUFSIZ, fd);

          pidbin[pidbin_len] = 0;

          fclose (fd);

          char *argv0_r = strrchr (argv[0], '/');

          char *pidbin_r = strrchr (pidbin, '/');

          if (argv0_r == NULL) argv0_r = argv[0];

          if (pidbin_r == NULL) pidbin_r = pidbin;

          if (strcmp (argv0_r, pidbin_r) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin, rd->pid);

            exit (-1);
          }
        }

        #elif _WIN
        HANDLE hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, rd->pid);

        char *pidbin2 = (char *) mymalloc (HCBUFSIZ);

        int pidbin2_len = -1;

        pidbin_len = GetModuleFileName (NULL, pidbin, HCBUFSIZ);
        pidbin2_len = GetModuleFileNameEx (hProcess, NULL, pidbin2, HCBUFSIZ);

        pidbin[pidbin_len] = 0;
        pidbin2[pidbin2_len] = 0;

        if (pidbin2_len)
        {
          if (strcmp (pidbin, pidbin2) == 0)
          {
            log_error ("ERROR: Already an instance %s running on pid %d", pidbin2, rd->pid);

            exit (-1);
          }
        }

        myfree (pidbin2);

        #endif

        myfree (pidbin);
      }

      if (rd->version_bin < RESTORE_MIN)
      {
        log_error ("ERROR: Cannot use outdated %s. Please remove it.", data.eff_restore_file);

        exit (-1);
      }
    }
  }

  memset (rd, 0, sizeof (restore_data_t));

  rd->version_bin = VERSION_BIN;

  #ifdef _POSIX
  rd->pid = getpid ();
  #elif _WIN
  rd->pid = GetCurrentProcessId ();
  #endif

  if (getcwd (rd->cwd, 255) == NULL)
  {
    myfree (rd);

    return (NULL);
  }

  rd->argc = argc;
  rd->argv = argv;

  return (rd);
}

void read_restore (const char *eff_restore_file, restore_data_t *rd)
{
  FILE *fp = fopen (eff_restore_file, "rb");

  if (fp == NULL)
  {
    log_error ("ERROR: Restore file '%s': %s", eff_restore_file, strerror (errno));

    exit (-1);
  }

  if (fread (rd, sizeof (restore_data_t), 1, fp) != 1)
  {
    log_error ("ERROR: Can't read %s", eff_restore_file);

    exit (-1);
  }

  rd->argv = (char **) mycalloc (rd->argc, sizeof (char *));

  char *buf = (char *) mymalloc (HCBUFSIZ);

  for (uint i = 0; i < rd->argc; i++)
  {
    if (fgets (buf, HCBUFSIZ - 1, fp) == NULL)
    {
      log_error ("ERROR: Can't read %s", eff_restore_file);

      exit (-1);
    }

    size_t len = strlen (buf);

    if (len) buf[len - 1] = 0;

    rd->argv[i] = mystrdup (buf);
  }

  myfree (buf);

  fclose (fp);

  log_info ("INFO: Changing current working directory to the path found within the .restore file: '%s'", rd->cwd);

  if (chdir (rd->cwd))
  {
    log_error ("ERROR: The directory '%s' does not exist. It is needed to restore (--restore) the session.\n"
               "       You could either create this directory (or link it) or update the .restore file using e.g. the analyze_hc_restore.pl tool:\n"
               "       https://github.com/philsmd/analyze_hc_restore\n"
               "       The directory must be relative to (or contain) all files/folders mentioned within the command line.", rd->cwd);

    exit (-1);
  }
}

u64 get_lowest_words_done ()
{
  u64 words_cur = -1;

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point
  // There's also data.words_cur which is set to rd->words_cur but it changes while
  // the attack is running therefore we should stick to rd->words_cur.
  // Note that -s influences rd->words_cur we should keep a close look on that.

  if (words_cur < data.rd->words_cur) words_cur = data.rd->words_cur;

  return words_cur;
}

void write_restore (const char *new_restore_file, restore_data_t *rd)
{
  u64 words_cur = get_lowest_words_done ();

  rd->words_cur = words_cur;

  FILE *fp = fopen (new_restore_file, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  if (setvbuf (fp, NULL, _IONBF, 0))
  {
    log_error ("ERROR: setvbuf file '%s': %s", new_restore_file, strerror (errno));

    exit (-1);
  }

  fwrite (rd, sizeof (restore_data_t), 1, fp);

  for (uint i = 0; i < rd->argc; i++)
  {
    fprintf (fp, "%s", rd->argv[i]);
    fputc ('\n', fp);
  }

  fflush (fp);

  fsync (fileno (fp));

  fclose (fp);
}

void cycle_restore ()
{
  const char *eff_restore_file = data.eff_restore_file;
  const char *new_restore_file = data.new_restore_file;

  restore_data_t *rd = data.rd;

  write_restore (new_restore_file, rd);

  struct stat st;

  memset (&st, 0, sizeof(st));

  if (stat (eff_restore_file, &st) == 0)
  {
    if (unlink (eff_restore_file))
    {
      log_info ("WARN: Unlink file '%s': %s", eff_restore_file, strerror (errno));
    }
  }

  if (rename (new_restore_file, eff_restore_file))
  {
    log_info ("WARN: Rename file '%s' to '%s': %s", new_restore_file, eff_restore_file, strerror (errno));
  }
}

void check_checkpoint ()
{
  // if (data.restore_disable == 1) break;  (this is already implied by previous checks)

  u64 words_cur = get_lowest_words_done ();

  if (words_cur != data.checkpoint_cur_words)
  {
    myabort ();
  }
}

/**
 * tuning db
 */

void tuning_db_destroy (tuning_db_t *tuning_db)
{
  int i;

  for (i = 0; i < tuning_db->alias_cnt; i++)
  {
    tuning_db_alias_t *alias = &tuning_db->alias_buf[i];

    myfree (alias->device_name);
    myfree (alias->alias_name);
  }

  for (i = 0; i < tuning_db->entry_cnt; i++)
  {
    tuning_db_entry_t *entry = &tuning_db->entry_buf[i];

    myfree (entry->device_name);
  }

  myfree (tuning_db->alias_buf);
  myfree (tuning_db->entry_buf);

  myfree (tuning_db);
}

tuning_db_t *tuning_db_alloc (FILE *fp)
{
  tuning_db_t *tuning_db = (tuning_db_t *) mymalloc (sizeof (tuning_db_t));

  int num_lines = count_lines (fp);

  // a bit over-allocated

  tuning_db->alias_buf = (tuning_db_alias_t *) mycalloc (num_lines + 1, sizeof (tuning_db_alias_t));
  tuning_db->alias_cnt = 0;

  tuning_db->entry_buf = (tuning_db_entry_t *) mycalloc (num_lines + 1, sizeof (tuning_db_entry_t));
  tuning_db->entry_cnt = 0;

  return tuning_db;
}

tuning_db_t *tuning_db_init (const char *tuning_db_file)
{
  FILE *fp = fopen (tuning_db_file, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", tuning_db_file, strerror (errno));

    exit (-1);
  }

  tuning_db_t *tuning_db = tuning_db_alloc (fp);

  rewind (fp);

  int line_num = 0;

  char *buf = (char *) mymalloc (HCBUFSIZ);

  while (!feof (fp))
  {
    char *line_buf = fgets (buf, HCBUFSIZ - 1, fp);

    if (line_buf == NULL) break;

    line_num++;

    const int line_len = in_superchop (line_buf);

    if (line_len == 0) continue;

    if (line_buf[0] == '#') continue;

    // start processing

    char *token_ptr[7] = { NULL };

    int token_cnt = 0;

    char *next = strtok (line_buf, "\t ");

    token_ptr[token_cnt] = next;

    token_cnt++;

    while ((next = strtok (NULL, "\t ")) != NULL)
    {
      token_ptr[token_cnt] = next;

      token_cnt++;
    }

    if (token_cnt == 2)
    {
      char *device_name = token_ptr[0];
      char *alias_name  = token_ptr[1];

      tuning_db_alias_t *alias = &tuning_db->alias_buf[tuning_db->alias_cnt];

      alias->device_name = mystrdup (device_name);
      alias->alias_name  = mystrdup (alias_name);

      tuning_db->alias_cnt++;
    }
    else if (token_cnt == 6)
    {
      if ((token_ptr[1][0] != '0') &&
          (token_ptr[1][0] != '1') &&
          (token_ptr[1][0] != '3') &&
          (token_ptr[1][0] != '*'))
      {
        log_info ("WARNING: Tuning-db: Invalid attack_mode '%c' in Line '%u'", token_ptr[1][0], line_num);

        continue;
      }

      if ((token_ptr[3][0] != '1') &&
          (token_ptr[3][0] != '2') &&
          (token_ptr[3][0] != '4') &&
          (token_ptr[3][0] != '8') &&
          (token_ptr[3][0] != 'N'))
      {
        log_info ("WARNING: Tuning-db: Invalid vector_width '%c' in Line '%u'", token_ptr[3][0], line_num);

        continue;
      }

      char *device_name = token_ptr[0];

      int attack_mode      = -1;
      int hash_type        = -1;
      int vector_width     = -1;
      int kernel_accel     = -1;
      int kernel_loops     = -1;

      if (token_ptr[1][0] != '*') attack_mode      = atoi (token_ptr[1]);
      if (token_ptr[2][0] != '*') hash_type        = atoi (token_ptr[2]);
      if (token_ptr[3][0] != 'N') vector_width     = atoi (token_ptr[3]);

      if (token_ptr[4][0] != 'A')
      {
        kernel_accel = atoi (token_ptr[4]);

        if ((kernel_accel < 1) || (kernel_accel > 1024))
        {
          log_info ("WARNING: Tuning-db: Invalid kernel_accel '%d' in Line '%u'", kernel_accel, line_num);

          continue;
        }
      }
      else
      {
        kernel_accel = 0;
      }

      if (token_ptr[5][0] != 'A')
      {
        kernel_loops = atoi (token_ptr[5]);

        if ((kernel_loops < 1) || (kernel_loops > 1024))
        {
          log_info ("WARNING: Tuning-db: Invalid kernel_loops '%d' in Line '%u'", kernel_loops, line_num);

          continue;
        }
      }
      else
      {
        kernel_loops = 0;
      }

      tuning_db_entry_t *entry = &tuning_db->entry_buf[tuning_db->entry_cnt];

      entry->device_name  = mystrdup (device_name);
      entry->attack_mode  = attack_mode;
      entry->hash_type    = hash_type;
      entry->vector_width = vector_width;
      entry->kernel_accel = kernel_accel;
      entry->kernel_loops = kernel_loops;

      tuning_db->entry_cnt++;
    }
    else
    {
      log_info ("WARNING: Tuning-db: Invalid number of token in Line '%u'", line_num);

      continue;
    }
  }

  myfree (buf);

  fclose (fp);

  // todo: print loaded 'cnt' message

  // sort the database

  qsort (tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);
  qsort (tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

  return tuning_db;
}

tuning_db_entry_t *tuning_db_search (tuning_db_t *tuning_db, hc_device_param_t *device_param, int attack_mode, int hash_type)
{
  static tuning_db_entry_t s;

  // first we need to convert all spaces in the device_name to underscore

  char *device_name_nospace = strdup (device_param->device_name);

  int device_name_length = strlen (device_name_nospace);

  int i;

  for (i = 0; i < device_name_length; i++)
  {
    if (device_name_nospace[i] == ' ') device_name_nospace[i] = '_';
  }

  // find out if there's an alias configured

  tuning_db_alias_t a;

  a.device_name = device_name_nospace;

  tuning_db_alias_t *alias = bsearch (&a, tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);

  char *alias_name = (alias == NULL) ? NULL : alias->alias_name;

  // attack-mode 6 and 7 are attack-mode 1 basically

  if (attack_mode == 6) attack_mode = 1;
  if (attack_mode == 7) attack_mode = 1;

  // bsearch is not ideal but fast enough

  s.device_name = device_name_nospace;
  s.attack_mode = attack_mode;
  s.hash_type   = hash_type;

  tuning_db_entry_t *entry = NULL;

  // this will produce all 2^3 combinations required

  for (i = 0; i < 8; i++)
  {
    s.device_name = (i & 1) ? "*" : device_name_nospace;
    s.attack_mode = (i & 2) ?  -1 : attack_mode;
    s.hash_type   = (i & 4) ?  -1 : hash_type;

    entry = bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

    if (entry != NULL) break;

    // in non-wildcard mode do some additional checks:

    if ((i & 1) == 0)
    {
      // in case we have an alias-name

      if (alias_name != NULL)
      {
        s.device_name = alias_name;

        entry = bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

        if (entry != NULL) break;
      }

      // or by device type

      if (device_param->device_type & CL_DEVICE_TYPE_CPU)
      {
        s.device_name = "DEVICE_TYPE_CPU";
      }
      else if (device_param->device_type & CL_DEVICE_TYPE_GPU)
      {
        s.device_name = "DEVICE_TYPE_GPU";
      }
      else if (device_param->device_type & CL_DEVICE_TYPE_ACCELERATOR)
      {
        s.device_name = "DEVICE_TYPE_ACCELERATOR";
      }

      entry = bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

      if (entry != NULL) break;
    }
  }

  // free converted device_name

  myfree (device_name_nospace);

  return entry;
}

/**
 * parser
 */

uint parse_and_store_salt (char *out, char *in, uint salt_len)
{
  u8 tmp[256] = { 0 };

  if (salt_len > sizeof (tmp))
  {
    return UINT_MAX;
  }

  memcpy (tmp, in, salt_len);

  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((salt_len % 2) == 0)
    {
      u32 new_salt_len = salt_len / 2;

      for (uint i = 0, j = 0; i < new_salt_len; i += 1, j += 2)
      {
        u8 p0 = tmp[j + 0];
        u8 p1 = tmp[j + 1];

        tmp[i]  = hex_convert (p1) << 0;
        tmp[i] |= hex_convert (p0) << 4;
      }

      salt_len = new_salt_len;
    }
    else
    {
      return UINT_MAX;
    }
  }
  else if (data.opts_type & OPTS_TYPE_ST_BASE64)
  {
    salt_len = base64_decode (base64_to_int, (const u8 *) in, salt_len, (u8 *) tmp);
  }

  memset (tmp + salt_len, 0, sizeof (tmp) - salt_len);

  if (data.opts_type & OPTS_TYPE_ST_UNICODE)
  {
    if (salt_len < 20)
    {
      u32 *tmp_uint = (u32 *) tmp;

      tmp_uint[9] = ((tmp_uint[4] >> 8) & 0x00FF0000) | ((tmp_uint[4] >> 16) & 0x000000FF);
      tmp_uint[8] = ((tmp_uint[4] << 8) & 0x00FF0000) | ((tmp_uint[4] >>  0) & 0x000000FF);
      tmp_uint[7] = ((tmp_uint[3] >> 8) & 0x00FF0000) | ((tmp_uint[3] >> 16) & 0x000000FF);
      tmp_uint[6] = ((tmp_uint[3] << 8) & 0x00FF0000) | ((tmp_uint[3] >>  0) & 0x000000FF);
      tmp_uint[5] = ((tmp_uint[2] >> 8) & 0x00FF0000) | ((tmp_uint[2] >> 16) & 0x000000FF);
      tmp_uint[4] = ((tmp_uint[2] << 8) & 0x00FF0000) | ((tmp_uint[2] >>  0) & 0x000000FF);
      tmp_uint[3] = ((tmp_uint[1] >> 8) & 0x00FF0000) | ((tmp_uint[1] >> 16) & 0x000000FF);
      tmp_uint[2] = ((tmp_uint[1] << 8) & 0x00FF0000) | ((tmp_uint[1] >>  0) & 0x000000FF);
      tmp_uint[1] = ((tmp_uint[0] >> 8) & 0x00FF0000) | ((tmp_uint[0] >> 16) & 0x000000FF);
      tmp_uint[0] = ((tmp_uint[0] << 8) & 0x00FF0000) | ((tmp_uint[0] >>  0) & 0x000000FF);

      salt_len = salt_len * 2;
    }
    else
    {
      return UINT_MAX;
    }
  }

  if (data.opts_type & OPTS_TYPE_ST_LOWER)
  {
    lowercase (tmp, salt_len);
  }

  if (data.opts_type & OPTS_TYPE_ST_UPPER)
  {
    uppercase (tmp, salt_len);
  }

  u32 len = salt_len;

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    tmp[len++] = 0x80;
  }

  if (data.opts_type & OPTS_TYPE_ST_ADD01)
  {
    tmp[len++] = 0x01;
  }

  if (data.opts_type & OPTS_TYPE_ST_GENERATE_LE)
  {
    u32 *tmp_uint = (uint *) tmp;

    u32 max = len / 4;

    if (len % 4) max++;

    for (u32 i = 0; i < max; i++)
    {
      tmp_uint[i] = byte_swap_32 (tmp_uint[i]);
    }

    // Important: we may need to increase the length of memcpy since
    // we don't want to "loose" some swapped bytes (could happen if
    // they do not perfectly fit in the 4-byte blocks)
    // Memcpy does always copy the bytes in the BE order, but since
    // we swapped them, some important bytes could be in positions
    // we normally skip with the original len

    if (len % 4) len += 4 - (len % 4);
  }

  memcpy (out, tmp, len);

  return (salt_len);
}

int bcrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3200) || (input_len > DISPLAY_LEN_MAX_3200)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_BCRYPT1, input_buf, 4)) && (memcmp (SIGNATURE_BCRYPT2, input_buf, 4)) && (memcmp (SIGNATURE_BCRYPT3, input_buf, 4))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  memcpy ((char *) salt->salt_sign, input_buf, 6);

  char *iter_pos = input_buf + 4;

  salt->salt_iter = 1 << atoi (iter_pos);

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  uint salt_len = 16;

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (bf64_to_int, (const u8 *) salt_pos, 22, tmp_buf);

  char *salt_buf_ptr = (char *) salt->salt_buf;

  memcpy (salt_buf_ptr, tmp_buf, 16);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  char *hash_pos = salt_pos + 22;

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, (const u8 *) hash_pos, 31, tmp_buf);

  memcpy (digest, tmp_buf, 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);

  digest[5] &= ~0xff; // its just 23 not 24 !

  return (PARSER_OK);
}

int cisco4_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5700) || (input_len > DISPLAY_LEN_MAX_5700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf, 43, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int lm_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3000) || (input_len > DISPLAY_LEN_MAX_3000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  uint tt;

  IP (digest[0], digest[1], tt);

  digest[0] = digest[0];
  digest[1] = digest[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int arubaos_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_125) || (input_len > DISPLAY_LEN_MAX_125)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[8] != '0') || (input_buf[9] != '1')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 10;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  uint salt_len = 10;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_122) || (input_len > DISPLAY_LEN_MAX_122)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 8;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx512_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1722) || (input_len > DISPLAY_LEN_MAX_1722)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf + 8;

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osc_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_21H) || (input_len > DISPLAY_LEN_MAX_21H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_21) || (input_len > DISPLAY_LEN_MAX_21)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int netscreen_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_22H) || (input_len > DISPLAY_LEN_MAX_22H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_22) || (input_len > DISPLAY_LEN_MAX_22)) return (PARSER_GLOBAL_LENGTH);
  }

  // unscramble

  char clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = {   0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != input_buf[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = input_buf[i];

      k++;
    }
  }

  // base64 decode

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u32 a, b, c, d, e, f;

  a = base64_to_int (clean_input_buf[ 0] & 0x7f);
  b = base64_to_int (clean_input_buf[ 1] & 0x7f);
  c = base64_to_int (clean_input_buf[ 2] & 0x7f);
  d = base64_to_int (clean_input_buf[ 3] & 0x7f);
  e = base64_to_int (clean_input_buf[ 4] & 0x7f);
  f = base64_to_int (clean_input_buf[ 5] & 0x7f);

  digest[0] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[ 6] & 0x7f);
  b = base64_to_int (clean_input_buf[ 7] & 0x7f);
  c = base64_to_int (clean_input_buf[ 8] & 0x7f);
  d = base64_to_int (clean_input_buf[ 9] & 0x7f);
  e = base64_to_int (clean_input_buf[10] & 0x7f);
  f = base64_to_int (clean_input_buf[11] & 0x7f);

  digest[1] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[12] & 0x7f);
  b = base64_to_int (clean_input_buf[13] & 0x7f);
  c = base64_to_int (clean_input_buf[14] & 0x7f);
  d = base64_to_int (clean_input_buf[15] & 0x7f);
  e = base64_to_int (clean_input_buf[16] & 0x7f);
  f = base64_to_int (clean_input_buf[17] & 0x7f);

  digest[2] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[18] & 0x7f);
  b = base64_to_int (clean_input_buf[19] & 0x7f);
  c = base64_to_int (clean_input_buf[20] & 0x7f);
  d = base64_to_int (clean_input_buf[21] & 0x7f);
  e = base64_to_int (clean_input_buf[22] & 0x7f);
  f = base64_to_int (clean_input_buf[23] & 0x7f);

  digest[3] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[30] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 30 - 1;

  char *salt_buf = input_buf + 30 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32
  // 32 - 4 bytes (to fit w0lr for all attack modes) = 28

  if (salt_len > 28) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy (salt_buf_ptr + salt_len, ":Administration Tools:", 22);

  salt->salt_len += 22;

  return (PARSER_OK);
}

int smf_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_121H) || (input_len > DISPLAY_LEN_MAX_121H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_121) || (input_len > DISPLAY_LEN_MAX_121)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2100H) || (input_len > DISPLAY_LEN_MAX_2100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2100) || (input_len > DISPLAY_LEN_MAX_2100)) return (PARSER_GLOBAL_LENGTH);
  }

  if (memcmp (SIGNATURE_DCC2, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  char *iter_pos = input_buf + 6;

  salt_t *salt = hash_buf->salt;

  uint iter = atoi (iter_pos);

  if (iter < 1)
  {
    iter = ROUNDS_DCC2;
  }

  salt->salt_iter = iter - 1;

  char *salt_pos = strchr (iter_pos, '#');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *digest_pos = strchr (salt_pos, '#');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  digest_pos++;

  uint salt_len = digest_pos - salt_pos - 1;

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int wpa_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  wpa_t *wpa = (wpa_t *) hash_buf->esalt;

  hccap_t in;

  memcpy (&in, input_buf, input_len);

  if (in.eapol_size < 1 || in.eapol_size > 255) return (PARSER_HCCAP_EAPOL_SIZE);

  memcpy (digest, in.keymic, 16);

  /*
    http://www.one-net.eu/jsw/j_sec/m_ptype.html
    The phrase "Pairwise key expansion"
    Access Point Address (referred to as Authenticator Address AA)
    Supplicant Address (referred to as Supplicant Address SA)
    Access Point Nonce (referred to as Authenticator Anonce)
    Wireless Device Nonce (referred to as Supplicant Nonce Snonce)
  */

  uint salt_len = strlen (in.essid);

  if (salt_len > 36)
  {
    log_info ("WARNING: The ESSID length is too long, the hccap file may be invalid or corrupted");

    return (PARSER_SALT_LENGTH);
  }

  memcpy (salt->salt_buf, in.essid, salt_len);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_WPA2 - 1;

  unsigned char *pke_ptr = (unsigned char *) wpa->pke;

  memcpy (pke_ptr, "Pairwise key expansion", 23);

  if (memcmp (in.mac1, in.mac2, 6) < 0)
  {
    memcpy (pke_ptr + 23, in.mac1, 6);
    memcpy (pke_ptr + 29, in.mac2, 6);
  }
  else
  {
    memcpy (pke_ptr + 23, in.mac2, 6);
    memcpy (pke_ptr + 29, in.mac1, 6);
  }

  if (memcmp (in.nonce1, in.nonce2, 32) < 0)
  {
    memcpy (pke_ptr + 35, in.nonce1, 32);
    memcpy (pke_ptr + 67, in.nonce2, 32);
  }
  else
  {
    memcpy (pke_ptr + 35, in.nonce2, 32);
    memcpy (pke_ptr + 67, in.nonce1, 32);
  }

  for (int i = 0; i < 25; i++)
  {
    wpa->pke[i] = byte_swap_32 (wpa->pke[i]);
  }

  memcpy (wpa->orig_mac1,   in.mac1,   6);
  memcpy (wpa->orig_mac2,   in.mac2,   6);
  memcpy (wpa->orig_nonce1, in.nonce1, 32);
  memcpy (wpa->orig_nonce2, in.nonce2, 32);

  wpa->keyver = in.keyver;

  if (wpa->keyver > 255)
  {
    log_info ("ATTENTION!");
    log_info ("  The WPA/WPA2 key version in your .hccap file is invalid!");
    log_info ("  This could be due to a recent aircrack-ng bug.");
    log_info ("  The key version was automatically reset to a reasonable value.");
    log_info ("");

    wpa->keyver &= 0xff;
  }

  wpa->eapol_size = in.eapol_size;

  unsigned char *eapol_ptr = (unsigned char *) wpa->eapol;

  memcpy (eapol_ptr, in.eapol, wpa->eapol_size);

  memset (eapol_ptr + wpa->eapol_size, 0, 256 - wpa->eapol_size);

  eapol_ptr[wpa->eapol_size] = (unsigned char) 0x80;

  if (wpa->keyver == 1)
  {
    // nothing to do
  }
  else
  {
    digest[0] = byte_swap_32 (digest[0]);
    digest[1] = byte_swap_32 (digest[1]);
    digest[2] = byte_swap_32 (digest[2]);
    digest[3] = byte_swap_32 (digest[3]);

    for (int i = 0; i < 64; i++)
    {
      wpa->eapol[i] = byte_swap_32 (wpa->eapol[i]);
    }
  }

  uint32_t *p0 = (uint32_t *) in.essid;
  uint32_t c0 = 0;
  uint32_t c1 = 0;

  for (uint i = 0; i < sizeof (in.essid) / sizeof (uint32_t);    i++) c0 ^= *p0++;
  for (uint i = 0; i < sizeof (wpa->pke) / sizeof (wpa->pke[0]); i++) c1 ^= wpa->pke[i];

  salt->salt_buf[10] = c0;
  salt->salt_buf[11] = c1;

  return (PARSER_OK);
}

int psafe2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0)
  {
    log_error ("Password Safe v2 container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  psafe2_hdr buf;

  memset (&buf, 0, sizeof (psafe2_hdr));

  int n = fread (&buf, sizeof (psafe2_hdr), 1, fp);

  fclose (fp);

  if (n != 1) return (PARSER_PSAFE2_FILE_SIZE);

  salt->salt_buf[0] = buf.random[0];
  salt->salt_buf[1] = buf.random[1];

  salt->salt_len  = 8;
  salt->salt_iter = 1000;

  digest[0] = byte_swap_32 (buf.hash[0]);
  digest[1] = byte_swap_32 (buf.hash[1]);
  digest[2] = byte_swap_32 (buf.hash[2]);
  digest[3] = byte_swap_32 (buf.hash[3]);
  digest[4] = byte_swap_32 (buf.hash[4]);

  return (PARSER_OK);
}

int psafe3_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0)
  {
    log_error (".psafe3 not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  psafe3_t in;

  int n = fread (&in, sizeof (psafe3_t), 1, fp);

  fclose (fp);

  data.hashfile = input_buf; // we will need this in case it gets cracked

  if (memcmp (SIGNATURE_PSAFE3, in.signature, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  if (n != 1) return (PARSER_PSAFE3_FILE_SIZE);

  salt->salt_iter = in.iterations + 1;

  salt->salt_buf[0] = in.salt_buf[0];
  salt->salt_buf[1] = in.salt_buf[1];
  salt->salt_buf[2] = in.salt_buf[2];
  salt->salt_buf[3] = in.salt_buf[3];
  salt->salt_buf[4] = in.salt_buf[4];
  salt->salt_buf[5] = in.salt_buf[5];
  salt->salt_buf[6] = in.salt_buf[6];
  salt->salt_buf[7] = in.salt_buf[7];

  salt->salt_len = 32;

  digest[0] = in.hash_buf[0];
  digest[1] = in.hash_buf[1];
  digest[2] = in.hash_buf[2];
  digest[3] = in.hash_buf[3];
  digest[4] = in.hash_buf[4];
  digest[5] = in.hash_buf[5];
  digest[6] = in.hash_buf[6];
  digest[7] = in.hash_buf[7];

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int phpass_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_400) || (input_len > DISPLAY_LEN_MAX_400)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PHPASS1, input_buf, 3)) && (memcmp (SIGNATURE_PHPASS2, input_buf, 3))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 3;

  uint salt_iter = 1 << itoa64_to_int (iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy ((char *) salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  char *salt_pos = iter_pos + 1;

  uint salt_len = 8;

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char *hash_pos = salt_pos + salt_len;

  phpass_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int md5crypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (input_len < DISPLAY_LEN_MIN_500) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MD5CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi (salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if (input_len > (DISPLAY_LEN_MAX_500 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  uint hash_len = input_len - 3 - iterations_len - salt_len - 1;

  if (hash_len != 22) return (PARSER_HASH_LENGTH);

  md5crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int md5apr1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp (SIGNATURE_MD5APR1, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6;

  uint iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi (salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1600) || (input_len > DISPLAY_LEN_MAX_1600 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  md5crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int episerver_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_141) || (input_len > DISPLAY_LEN_MAX_141)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_EPISERVER, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 14;

  char *hash_pos = strchr (salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint salt_len = hash_pos - salt_pos - 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) hash_pos, 27, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int descrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1500) || (input_len > DISPLAY_LEN_MAX_1500)) return (PARSER_GLOBAL_LENGTH);

  unsigned char c12 = itoa64_to_int (input_buf[12]);

  if (c12 & 3) return (PARSER_HASH_VALUE);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // for ascii_digest
  salt->salt_sign[0] = input_buf[0];
  salt->salt_sign[1] = input_buf[1];

  salt->salt_buf[0] = itoa64_to_int (input_buf[0])
                    | itoa64_to_int (input_buf[1]) << 6;

  salt->salt_len = 2;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf + 2, 11, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  uint tt;

  IP (digest[0], digest[1], tt);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int md4_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_900) || (input_len > DISPLAY_LEN_MAX_900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  return (PARSER_OK);
}

int md4s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_910H) || (input_len > DISPLAY_LEN_MAX_910H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_910) || (input_len > DISPLAY_LEN_MAX_910)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_0) || (input_len > DISPLAY_LEN_MAX_0)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int md5half_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5100) || (input_len > DISPLAY_LEN_MAX_5100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  return (PARSER_OK);
}

int md5s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_10H) || (input_len > DISPLAY_LEN_MAX_10H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_10) || (input_len > DISPLAY_LEN_MAX_10)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5pix_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2400) || (input_len > DISPLAY_LEN_MAX_2400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = itoa64_to_int (input_buf[ 0]) <<  0
            | itoa64_to_int (input_buf[ 1]) <<  6
            | itoa64_to_int (input_buf[ 2]) << 12
            | itoa64_to_int (input_buf[ 3]) << 18;
  digest[1] = itoa64_to_int (input_buf[ 4]) <<  0
            | itoa64_to_int (input_buf[ 5]) <<  6
            | itoa64_to_int (input_buf[ 6]) << 12
            | itoa64_to_int (input_buf[ 7]) << 18;
  digest[2] = itoa64_to_int (input_buf[ 8]) <<  0
            | itoa64_to_int (input_buf[ 9]) <<  6
            | itoa64_to_int (input_buf[10]) << 12
            | itoa64_to_int (input_buf[11]) << 18;
  digest[3] = itoa64_to_int (input_buf[12]) <<  0
            | itoa64_to_int (input_buf[13]) <<  6
            | itoa64_to_int (input_buf[14]) << 12
            | itoa64_to_int (input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  return (PARSER_OK);
}

int md5asa_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2410H) || (input_len > DISPLAY_LEN_MAX_2410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2410) || (input_len > DISPLAY_LEN_MAX_2410)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = itoa64_to_int (input_buf[ 0]) <<  0
            | itoa64_to_int (input_buf[ 1]) <<  6
            | itoa64_to_int (input_buf[ 2]) << 12
            | itoa64_to_int (input_buf[ 3]) << 18;
  digest[1] = itoa64_to_int (input_buf[ 4]) <<  0
            | itoa64_to_int (input_buf[ 5]) <<  6
            | itoa64_to_int (input_buf[ 6]) << 12
            | itoa64_to_int (input_buf[ 7]) << 18;
  digest[2] = itoa64_to_int (input_buf[ 8]) <<  0
            | itoa64_to_int (input_buf[ 9]) <<  6
            | itoa64_to_int (input_buf[10]) << 12
            | itoa64_to_int (input_buf[11]) << 18;
  digest[3] = itoa64_to_int (input_buf[12]) <<  0
            | itoa64_to_int (input_buf[13]) <<  6
            | itoa64_to_int (input_buf[14]) << 12
            | itoa64_to_int (input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 16 - 1;

  char *salt_buf = input_buf + 16 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

void transform_netntlmv1_key (const u8 *nthash, u8 *key)
{
  key[0] =                    (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}

int netntlmv1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5500) || (input_len > DISPLAY_LEN_MAX_5500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *user_pos = input_buf;

  char *unused_pos = strchr (user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  char *domain_pos = strchr (unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  char *srvchall_pos = strchr (domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  char *hash_pos = strchr (srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint srvchall_len = hash_pos - srvchall_pos;

  // if (srvchall_len != 0) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *clichall_pos = strchr (hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = clichall_pos - hash_pos;

  if (hash_len != 48) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  uint clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len != 16) return (PARSER_SALT_LENGTH);

  /**
   * store some data for later use
   */

  netntlm->user_len     = user_len     * 2;
  netntlm->domain_len   = domain_len   * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  char *userdomain_ptr = (char *) netntlm->userdomain_buf;
  char *chall_ptr      = (char *) netntlm->chall_buf;

  /**
   * handle username and domainname
   */

  for (uint i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = user_pos[i];
    *userdomain_ptr++ = 0;
  }

  for (uint i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  /**
   * handle server challenge encoding
   */

  for (uint i = 0; i < srvchall_len; i += 2)
  {
    const char p0 = srvchall_pos[i + 0];
    const char p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * handle client challenge encoding
   */

  for (uint i = 0; i < clichall_len; i += 2)
  {
    const char p0 = clichall_pos[i + 0];
    const char p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * store data
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  uint salt_len = parse_and_store_salt (salt_buf_ptr, clichall_pos, clichall_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  /* special case, last 8 byte do not need to be checked since they are brute-forced next */

  uint digest_tmp[2] = { 0 };

  digest_tmp[0] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest_tmp[1] = hex_to_u32 ((const u8 *) &hash_pos[40]);

  digest_tmp[0] = byte_swap_32 (digest_tmp[0]);
  digest_tmp[1] = byte_swap_32 (digest_tmp[1]);

  /* special case 2: ESS */

  if (srvchall_len == 48)
  {
    if ((netntlm->chall_buf[2] == 0) && (netntlm->chall_buf[3] == 0) && (netntlm->chall_buf[4] == 0) && (netntlm->chall_buf[5] == 0))
    {
      uint w[16] = { 0 };

      w[ 0] = netntlm->chall_buf[6];
      w[ 1] = netntlm->chall_buf[7];
      w[ 2] = netntlm->chall_buf[0];
      w[ 3] = netntlm->chall_buf[1];
      w[ 4] = 0x80;
      w[14] = 16 * 8;

      uint dgst[4] = { 0 };

      dgst[0] = MAGIC_A;
      dgst[1] = MAGIC_B;
      dgst[2] = MAGIC_C;
      dgst[3] = MAGIC_D;

      md5_64 (w, dgst);

      salt->salt_buf[0] = dgst[0];
      salt->salt_buf[1] = dgst[1];
    }
  }

  /* precompute netntlmv1 exploit start */

  for (uint i = 0; i < 0x10000; i++)
  {
    uint key_md4[2] = { i, 0 };
    uint key_des[2] = { 0, 0 };

    transform_netntlmv1_key ((u8 *) key_md4, (u8 *) key_des);

    uint Kc[16] = { 0 };
    uint Kd[16] = { 0 };

    _des_keysetup (key_des, Kc, Kd, c_skb);

    uint data3[2] = { salt->salt_buf[0], salt->salt_buf[1] };

    _des_encrypt (data3, Kc, Kd, c_SPtrans);

    if (data3[0] != digest_tmp[0]) continue;
    if (data3[1] != digest_tmp[1]) continue;

    salt->salt_buf[2] = i;

    salt->salt_len = 24;

    break;
  }

  salt->salt_buf_pc[0] = digest_tmp[0];
  salt->salt_buf_pc[1] = digest_tmp[1];

  /* precompute netntlmv1 exploit stop */

  u32 tt;

  IP (digest[0], digest[1], tt);
  IP (digest[2], digest[3], tt);

  digest[0] = rotr32 (digest[0], 29);
  digest[1] = rotr32 (digest[1], 29);
  digest[2] = rotr32 (digest[2], 29);
  digest[3] = rotr32 (digest[3], 29);

  IP (salt->salt_buf[0], salt->salt_buf[1], tt);

  salt->salt_buf[0] = rotl32 (salt->salt_buf[0], 3);
  salt->salt_buf[1] = rotl32 (salt->salt_buf[1], 3);

  return (PARSER_OK);
}

int netntlmv2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5600) || (input_len > DISPLAY_LEN_MAX_5600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *user_pos = input_buf;

  char *unused_pos = strchr (user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  char *domain_pos = strchr (unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  char *srvchall_pos = strchr (domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  char *hash_pos = strchr (srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint srvchall_len = hash_pos - srvchall_pos;

  if (srvchall_len != 16) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *clichall_pos = strchr (hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = clichall_pos - hash_pos;

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  uint clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len > 1024) return (PARSER_SALT_LENGTH);

  if (clichall_len % 2) return (PARSER_SALT_VALUE);

  /**
   * store some data for later use
   */

  netntlm->user_len     = user_len     * 2;
  netntlm->domain_len   = domain_len   * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  char *userdomain_ptr = (char *) netntlm->userdomain_buf;
  char *chall_ptr      = (char *) netntlm->chall_buf;

  /**
   * handle username and domainname
   */

  for (uint i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = toupper (user_pos[i]);
    *userdomain_ptr++ = 0;
  }

  for (uint i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  *userdomain_ptr++ = 0x80;

  /**
   * handle server challenge encoding
   */

  for (uint i = 0; i < srvchall_len; i += 2)
  {
    const char p0 = srvchall_pos[i + 0];
    const char p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * handle client challenge encoding
   */

  for (uint i = 0; i < clichall_len; i += 2)
  {
    const char p0 = clichall_pos[i + 0];
    const char p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  *chall_ptr++ = 0x80;

  /**
   * handle hash itself
   */

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  /**
   * reuse challange data as salt_buf, its the buffer that is most likely unique
   */

  salt->salt_buf[0] = 0;
  salt->salt_buf[1] = 0;
  salt->salt_buf[2] = 0;
  salt->salt_buf[3] = 0;
  salt->salt_buf[4] = 0;
  salt->salt_buf[5] = 0;
  salt->salt_buf[6] = 0;
  salt->salt_buf[7] = 0;

  uint *uptr;

  uptr = (uint *) netntlm->userdomain_buf;

  for (uint i = 0; i < 16; i += 16)
  {
    md5_64 (uptr, salt->salt_buf);
  }

  uptr = (uint *) netntlm->chall_buf;

  for (uint i = 0; i < 256; i += 16)
  {
    md5_64 (uptr, salt->salt_buf);
  }

  salt->salt_len = 16;

  return (PARSER_OK);
}

int joomla_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_11H) || (input_len > DISPLAY_LEN_MAX_11H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_11) || (input_len > DISPLAY_LEN_MAX_11)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_12H) || (input_len > DISPLAY_LEN_MAX_12H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_12) || (input_len > DISPLAY_LEN_MAX_12)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5md5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2600) || (input_len > DISPLAY_LEN_MAX_2600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /**
   * This is a virtual salt. While the algorithm is basically not salted
   * we can exploit the salt buffer to set the 0x80 and the w[14] value.
   * This way we can save a special md5md5 kernel and reuse the one from vbull.
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  uint salt_len = parse_and_store_salt (salt_buf_ptr, (char *) "", 0);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb3_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2611H) || (input_len > DISPLAY_LEN_MAX_2611H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2611) || (input_len > DISPLAY_LEN_MAX_2611)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb30_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2711H) || (input_len > DISPLAY_LEN_MAX_2711H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2711) || (input_len > DISPLAY_LEN_MAX_2711)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1100H) || (input_len > DISPLAY_LEN_MAX_1100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1100) || (input_len > DISPLAY_LEN_MAX_1100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int ipb2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2811H) || (input_len > DISPLAY_LEN_MAX_2811H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2811) || (input_len > DISPLAY_LEN_MAX_2811)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  uint salt_pc_block[16] = { 0 };

  char *salt_pc_block_ptr = (char *) salt_pc_block;

  salt_len = parse_and_store_salt (salt_pc_block_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_pc_block_ptr[salt_len] = (unsigned char) 0x80;

  salt_pc_block[14] = salt_len * 8;

  uint salt_pc_digest[4] = { MAGIC_A, MAGIC_B, MAGIC_C, MAGIC_D };

  md5_64 (salt_pc_block, salt_pc_digest);

  salt_pc_digest[0] = byte_swap_32 (salt_pc_digest[0]);
  salt_pc_digest[1] = byte_swap_32 (salt_pc_digest[1]);
  salt_pc_digest[2] = byte_swap_32 (salt_pc_digest[2]);
  salt_pc_digest[3] = byte_swap_32 (salt_pc_digest[3]);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_buf, salt_len);

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  bin_to_hex_lower (salt_pc_digest[0], salt_buf_pc_ptr +  0);
  bin_to_hex_lower (salt_pc_digest[1], salt_buf_pc_ptr +  8);
  bin_to_hex_lower (salt_pc_digest[2], salt_buf_pc_ptr + 16);
  bin_to_hex_lower (salt_pc_digest[3], salt_buf_pc_ptr + 24);

  salt->salt_len = 32; // changed, was salt_len before -- was a bug? 32 should be correct

  return (PARSER_OK);
}

int sha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_100) || (input_len > DISPLAY_LEN_MAX_100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1axcrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13300) || (input_len > DISPLAY_LEN_MAX_13300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_AXCRYPT_SHA1, input_buf, 13)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  input_buf += 14;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = 0;

  return (PARSER_OK);
}

int sha1s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_110H) || (input_len > DISPLAY_LEN_MAX_110H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_110) || (input_len > DISPLAY_LEN_MAX_110)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pstoken_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13500) || (input_len > DISPLAY_LEN_MAX_13500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pstoken_t *pstoken = (pstoken_t *) hash_buf->esalt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  if (salt_len == UINT_MAX || salt_len % 2 != 0) return (PARSER_SALT_LENGTH);

  u8 *pstoken_ptr = (u8 *) pstoken->salt_buf;

  for (uint i = 0, j = 0; i < salt_len; i += 2, j += 1)
  {
    pstoken_ptr[j] = hex_to_u8 ((const u8 *) &salt_buf[i]);
  }

  pstoken->salt_len = salt_len / 2;

  /* some fake salt for the sorting mechanisms */

  salt->salt_buf[0] = pstoken->salt_buf[0];
  salt->salt_buf[1] = pstoken->salt_buf[1];
  salt->salt_buf[2] = pstoken->salt_buf[2];
  salt->salt_buf[3] = pstoken->salt_buf[3];
  salt->salt_buf[4] = pstoken->salt_buf[4];
  salt->salt_buf[5] = pstoken->salt_buf[5];
  salt->salt_buf[6] = pstoken->salt_buf[6];
  salt->salt_buf[7] = pstoken->salt_buf[7];

  salt->salt_len = 32;

  /* we need to check if we can precompute some of the data --
     this is possible since the scheme is badly designed */

  pstoken->pc_digest[0] = SHA1M_A;
  pstoken->pc_digest[1] = SHA1M_B;
  pstoken->pc_digest[2] = SHA1M_C;
  pstoken->pc_digest[3] = SHA1M_D;
  pstoken->pc_digest[4] = SHA1M_E;

  pstoken->pc_offset = 0;

  for (int i = 0; i < (int) pstoken->salt_len - 63; i += 64)
  {
    uint w[16];

    w[ 0] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  0]);
    w[ 1] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  1]);
    w[ 2] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  2]);
    w[ 3] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  3]);
    w[ 4] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  4]);
    w[ 5] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  5]);
    w[ 6] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  6]);
    w[ 7] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  7]);
    w[ 8] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  8]);
    w[ 9] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  9]);
    w[10] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 10]);
    w[11] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 11]);
    w[12] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 12]);
    w[13] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 13]);
    w[14] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 14]);
    w[15] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 15]);

    sha1_64 (w, pstoken->pc_digest);

    pstoken->pc_offset += 16;
  }

  return (PARSER_OK);
}

int sha1b64_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_101) || (input_len > DISPLAY_LEN_MAX_101)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA1B64, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) input_buf + 5, input_len - 5, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1b64s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_111) || (input_len > DISPLAY_LEN_MAX_111)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SSHA1B64_lower, input_buf, 6) && memcmp (SIGNATURE_SSHA1B64_upper, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  int tmp_len = base64_decode (base64_to_int, (const u8 *) input_buf + 6, input_len - 6, tmp_buf);

  if (tmp_len < 20) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 20);

  int salt_len = tmp_len - 20;

  if (salt_len < 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, tmp_buf + 20, salt->salt_len);

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    char *ptr = (char *) salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2000_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_131) || (input_len > DISPLAY_LEN_MAX_131)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8 + 40;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2005_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_132) || (input_len > DISPLAY_LEN_MAX_132)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2012_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1731) || (input_len > DISPLAY_LEN_MAX_1731)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL2012, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 8;

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int oracleh_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_3100H) || (input_len > DISPLAY_LEN_MAX_3100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_3100) || (input_len > DISPLAY_LEN_MAX_3100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 16 - 1;

  char *salt_buf = input_buf + 16 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oracles_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_112) || (input_len > DISPLAY_LEN_MAX_112)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oraclet_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12300) || (input_len > DISPLAY_LEN_MAX_12300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hash_pos = input_buf;

  digest[ 0] = hex_to_u32 ((const u8 *) &hash_pos[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &hash_pos[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &hash_pos[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &hash_pos[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &hash_pos[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &hash_pos[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &hash_pos[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &hash_pos[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &hash_pos[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &hash_pos[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &hash_pos[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &hash_pos[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &hash_pos[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &hash_pos[104]);
  digest[14] = hex_to_u32 ((const u8 *) &hash_pos[112]);
  digest[15] = hex_to_u32 ((const u8 *) &hash_pos[120]);

  char *salt_pos = input_buf + 128;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

  salt->salt_iter = ROUNDS_ORACLET - 1;
  salt->salt_len  = 16;

  return (PARSER_OK);
}

int sha256_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1400) || (input_len > DISPLAY_LEN_MAX_1400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha256s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1410H) || (input_len > DISPLAY_LEN_MAX_1410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1410) || (input_len > DISPLAY_LEN_MAX_1410)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha384_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10800) || (input_len > DISPLAY_LEN_MAX_10800)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = 0;
  digest[7] = 0;

  digest[0] -= SHA384M_A;
  digest[1] -= SHA384M_B;
  digest[2] -= SHA384M_C;
  digest[3] -= SHA384M_D;
  digest[4] -= SHA384M_E;
  digest[5] -= SHA384M_F;
  digest[6] -= 0;
  digest[7] -= 0;

  return (PARSER_OK);
}

int sha512_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1700) || (input_len > DISPLAY_LEN_MAX_1700)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int sha512s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1710H) || (input_len > DISPLAY_LEN_MAX_1710H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1710) || (input_len > DISPLAY_LEN_MAX_1710)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  if (input_buf[128] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 128 - 1;

  char *salt_buf = input_buf + 128 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha512crypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp (SIGNATURE_SHA512CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi (salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA512CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1800) || (input_len > DISPLAY_LEN_MAX_1800 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha512crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int keccak_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5000) || (input_len > DISPLAY_LEN_MAX_5000)) return (PARSER_GLOBAL_LENGTH);

  if (input_len % 16) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  uint keccak_mdlen = input_len / 2;

  for (uint i = 0; i < keccak_mdlen / 8; i++)
  {
    digest[i] = hex_to_u64 ((const u8 *) &input_buf[i * 16]);

    digest[i] = byte_swap_64 (digest[i]);
  }

  salt->keccak_mdlen = keccak_mdlen;

  return (PARSER_OK);
}

int ikepsk_md5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5300) || (input_len > DISPLAY_LEN_MAX_5300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *) hash_buf->esalt;

  /**
   * Parse that strange long line
   */

  char *in_off[9];

  size_t in_len[9] = { 0 };

  in_off[0] = strtok (input_buf, ":");

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen (in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = strtok (NULL, ":");

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen (in_off[i]);
  }

  char *ptr = (char *) ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (char *) ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
   * Store to database
   */

  ptr = in_off[8];

  digest[0] = hex_to_u32 ((const u8 *) &ptr[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &ptr[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &ptr[16]);
  digest[3] = hex_to_u32 ((const u8 *) &ptr[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ikepsk_sha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5400) || (input_len > DISPLAY_LEN_MAX_5400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *) hash_buf->esalt;

  /**
   * Parse that strange long line
   */

  char *in_off[9];

  size_t in_len[9] = { 0 };

  in_off[0] = strtok (input_buf, ":");

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen (in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = strtok (NULL, ":");

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen (in_off[i]);
  }

  char *ptr = (char *) ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (char *) ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
   * Store to database
   */

  ptr = in_off[8];

  digest[0] = hex_to_u32 ((const u8 *) &ptr[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &ptr[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &ptr[16]);
  digest[3] = hex_to_u32 ((const u8 *) &ptr[24]);
  digest[4] = hex_to_u32 ((const u8 *) &ptr[32]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ripemd160_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6000) || (input_len > DISPLAY_LEN_MAX_6000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int whirlpool_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6100) || (input_len > DISPLAY_LEN_MAX_6100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[ 0] = hex_to_u32 ((const u8 *) &input_buf[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &input_buf[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &input_buf[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &input_buf[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &input_buf[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &input_buf[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &input_buf[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &input_buf[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &input_buf[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &input_buf[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &input_buf[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &input_buf[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &input_buf[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &input_buf[104]);
  digest[14] = hex_to_u32 ((const u8 *) &input_buf[112]);
  digest[15] = hex_to_u32 ((const u8 *) &input_buf[120]);

  return (PARSER_OK);
}

int androidpin_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_5800) || (input_len > DISPLAY_LEN_MAX_5800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_ANDROIDPIN - 1;

  return (PARSER_OK);
}

int truecrypt_parse_hash_1k (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("TrueCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_TC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_1K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int truecrypt_parse_hash_2k (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("TrueCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_TC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_2K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_200000 (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("VeraCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_200000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_500000 (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("VeraCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_500000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_327661 (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("VeraCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_327661 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_655331 (char *input_buf, uint input_len, hash_t *hash_buf)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0)
  {
    log_error ("VeraCrypt container not specified");

    exit (-1);
  }

  FILE *fp = fopen (input_buf, "rb");

  if (fp == NULL)
  {
    log_error ("%s: %s", input_buf, strerror (errno));

    exit (-1);
  }

  char buf[512] = { 0 };

  int n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != 512) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_655331 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int md5aix_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6300) || (input_len > DISPLAY_LEN_MAX_6300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MD5AIX, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 8) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  salt->salt_iter = 1000;

  hash_pos++;

  md5crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int sha1aix_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6700) || (input_len > DISPLAY_LEN_MAX_6700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA1AIX, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 7;

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi (salt_iter);

  salt->salt_iter = (1 << atoi (salt_iter)) - 1;

  hash_pos++;

  sha1aix_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int sha256aix_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6400) || (input_len > DISPLAY_LEN_MAX_6400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA256AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 9;

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi (salt_iter);

  salt->salt_iter = (1 << atoi (salt_iter)) - 1;

  hash_pos++;

  sha256aix_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int sha512aix_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6500) || (input_len > DISPLAY_LEN_MAX_6500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 9;

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoi (salt_iter);

  salt->salt_iter = (1 << atoi (salt_iter)) - 1;

  hash_pos++;

  sha512aix_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int agilekey_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6600) || (input_len > DISPLAY_LEN_MAX_6600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  agilekey_t *agilekey = (agilekey_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *iterations_pos = input_buf;

  char *saltbuf_pos = strchr (iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint iterations_len = saltbuf_pos - iterations_pos;

  if (iterations_len > 6) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *cipherbuf_pos = strchr (saltbuf_pos, ':');

  if (cipherbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = cipherbuf_pos - saltbuf_pos;

  if (saltbuf_len != 16) return (PARSER_SALT_LENGTH);

  uint cipherbuf_len = input_len - iterations_len - 1 - saltbuf_len - 1;

  if (cipherbuf_len != 2080) return (PARSER_HASH_LENGTH);

  cipherbuf_pos++;

  /**
   * pbkdf2 iterations
   */

  salt->salt_iter = atoi (iterations_pos) - 1;

  /**
   * handle salt encoding
   */

  char *saltbuf_ptr = (char *) salt->salt_buf;

  for (uint i = 0; i < saltbuf_len; i += 2)
  {
    const char p0 = saltbuf_pos[i + 0];
    const char p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  salt->salt_len = saltbuf_len / 2;

  /**
   * handle cipher encoding
   */

  uint *tmp = (uint *) mymalloc (32);

  char *cipherbuf_ptr = (char *) tmp;

  for (uint i = 2016; i < cipherbuf_len; i += 2)
  {
    const char p0 = cipherbuf_pos[i + 0];
    const char p1 = cipherbuf_pos[i + 1];

    *cipherbuf_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  // iv   is stored at salt_buf 4 (length 16)
  // data is stored at salt_buf 8 (length 16)

  salt->salt_buf[ 4] = byte_swap_32 (tmp[0]);
  salt->salt_buf[ 5] = byte_swap_32 (tmp[1]);
  salt->salt_buf[ 6] = byte_swap_32 (tmp[2]);
  salt->salt_buf[ 7] = byte_swap_32 (tmp[3]);

  salt->salt_buf[ 8] = byte_swap_32 (tmp[4]);
  salt->salt_buf[ 9] = byte_swap_32 (tmp[5]);
  salt->salt_buf[10] = byte_swap_32 (tmp[6]);
  salt->salt_buf[11] = byte_swap_32 (tmp[7]);

  free (tmp);

  for (uint i = 0, j = 0; i < 1040; i += 1, j += 2)
  {
    const char p0 = cipherbuf_pos[j + 0];
    const char p1 = cipherbuf_pos[j + 1];

    agilekey->cipher[i] = hex_convert (p1) << 0
                        | hex_convert (p0) << 4;
  }

  /**
   * digest buf
   */

  digest[0] = 0x10101010;
  digest[1] = 0x10101010;
  digest[2] = 0x10101010;
  digest[3] = 0x10101010;

  return (PARSER_OK);
}

int lastpass_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6800) || (input_len > DISPLAY_LEN_MAX_6800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *hashbuf_pos = input_buf;

  char *iterations_pos = strchr (hashbuf_pos, ':');

  if (iterations_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint hash_len = iterations_pos - hashbuf_pos;

  if ((hash_len != 32) && (hash_len != 64)) return (PARSER_HASH_LENGTH);

  iterations_pos++;

  char *saltbuf_pos = strchr (iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint iterations_len = saltbuf_pos - iterations_pos;

  saltbuf_pos++;

  uint salt_len = input_len - hash_len - 1 - iterations_len - 1;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, saltbuf_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = atoi (iterations_pos) - 1;

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);

  return (PARSER_OK);
}

int gost_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_6900) || (input_len > DISPLAY_LEN_MAX_6900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int sha256crypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp (SIGNATURE_SHA256CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 3;

  uint iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoi (salt_pos - iterations_len);

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA256CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_7400) || (input_len > DISPLAY_LEN_MAX_7400 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha256crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int sha512osx_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  uint max_len = DISPLAY_LEN_MAX_7100 + (2 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7100) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512OSX, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  char *iter_pos = input_buf + 4;

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  uint salt_len = hash_pos - salt_pos - 1;

  if ((salt_len % 2) != 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len / 2;

  pbkdf2_sha512->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  pbkdf2_sha512->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  pbkdf2_sha512->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  pbkdf2_sha512->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);
  pbkdf2_sha512->salt_buf[4] = hex_to_u32 ((const u8 *) &salt_pos[32]);
  pbkdf2_sha512->salt_buf[5] = hex_to_u32 ((const u8 *) &salt_pos[40]);
  pbkdf2_sha512->salt_buf[6] = hex_to_u32 ((const u8 *) &salt_pos[48]);
  pbkdf2_sha512->salt_buf[7] = hex_to_u32 ((const u8 *) &salt_pos[56]);

  pbkdf2_sha512->salt_buf[0] = byte_swap_32 (pbkdf2_sha512->salt_buf[0]);
  pbkdf2_sha512->salt_buf[1] = byte_swap_32 (pbkdf2_sha512->salt_buf[1]);
  pbkdf2_sha512->salt_buf[2] = byte_swap_32 (pbkdf2_sha512->salt_buf[2]);
  pbkdf2_sha512->salt_buf[3] = byte_swap_32 (pbkdf2_sha512->salt_buf[3]);
  pbkdf2_sha512->salt_buf[4] = byte_swap_32 (pbkdf2_sha512->salt_buf[4]);
  pbkdf2_sha512->salt_buf[5] = byte_swap_32 (pbkdf2_sha512->salt_buf[5]);
  pbkdf2_sha512->salt_buf[6] = byte_swap_32 (pbkdf2_sha512->salt_buf[6]);
  pbkdf2_sha512->salt_buf[7] = byte_swap_32 (pbkdf2_sha512->salt_buf[7]);
  pbkdf2_sha512->salt_buf[8] = 0x01000000;
  pbkdf2_sha512->salt_buf[9] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_iter = atoi (iter_pos) - 1;

  return (PARSER_OK);
}

int episerver4_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1441) || (input_len > DISPLAY_LEN_MAX_1441)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_EPISERVER4, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 14;

  char *hash_pos = strchr (salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint salt_len = hash_pos - salt_pos - 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) hash_pos, 43, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha512grub_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  uint max_len = DISPLAY_LEN_MAX_7200 + (8 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7200) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512GRUB, input_buf, 19)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  char *iter_pos = input_buf + 19;

  char *salt_pos = strchr (iter_pos, '.');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '.');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  uint salt_len = hash_pos - salt_pos - 1;

  salt_len /= 2;

  char *salt_buf_ptr = (char *) pbkdf2_sha512->salt_buf;

  uint i;

  for (i = 0; i < salt_len; i++)
  {
    salt_buf_ptr[i] = hex_to_u8 ((const u8 *) &salt_pos[i * 2]);
  }

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_len = salt_len;

  salt->salt_iter = atoi (iter_pos) - 1;

  return (PARSER_OK);
}

int sha512b64s_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1711) || (input_len > DISPLAY_LEN_MAX_1711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512B64S, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  int tmp_len = base64_decode (base64_to_int, (const u8 *) input_buf + 9, input_len - 9, tmp_buf);

  if (tmp_len < 64) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  int salt_len = tmp_len - 64;

  if (salt_len < 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, tmp_buf + 64, salt->salt_len);

  if (data.opts_type & OPTS_TYPE_ST_ADD80)
  {
    char *ptr = (char *) salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int hmacmd5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_50H) || (input_len > DISPLAY_LEN_MAX_50H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_50) || (input_len > DISPLAY_LEN_MAX_50)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_150H) || (input_len > DISPLAY_LEN_MAX_150H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_150) || (input_len > DISPLAY_LEN_MAX_150)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha256_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1450H) || (input_len > DISPLAY_LEN_MAX_1450H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1450) || (input_len > DISPLAY_LEN_MAX_1450)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha512_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (data.opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1750H) || (input_len > DISPLAY_LEN_MAX_1750H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1750) || (input_len > DISPLAY_LEN_MAX_1750)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  if (input_buf[128] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 128 - 1;

  char *salt_buf = input_buf + 128 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int krb5pa_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7500) || (input_len > DISPLAY_LEN_MAX_7500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KRB5PA, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5pa_t *krb5pa = (krb5pa_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *user_pos = input_buf + 10 + 1;

  char *realm_pos = strchr (user_pos, '$');

  if (realm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint user_len = realm_pos - user_pos;

  if (user_len >= 64) return (PARSER_SALT_LENGTH);

  realm_pos++;

  char *salt_pos = strchr (realm_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint realm_len = salt_pos - realm_pos;

  if (realm_len >= 64) return (PARSER_SALT_LENGTH);

  salt_pos++;

  char *data_pos = strchr (salt_pos, '$');

  if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = data_pos - salt_pos;

  if (salt_len >= 128) return (PARSER_SALT_LENGTH);

  data_pos++;

  uint data_len = input_len - 10 - 1 - user_len - 1 - realm_len - 1 - salt_len - 1;

  if (data_len != ((36 + 16) * 2)) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  memcpy (krb5pa->user,  user_pos,  user_len);
  memcpy (krb5pa->realm, realm_pos, realm_len);
  memcpy (krb5pa->salt,  salt_pos,  salt_len);

  char *timestamp_ptr = (char *) krb5pa->timestamp;

  for (uint i = 0; i < (36 * 2); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *timestamp_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  char *checksum_ptr = (char *) krb5pa->checksum;

  for (uint i = (36 * 2); i < ((36 + 16) * 2); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

  /**
   * copy some data to generic buffers to make sorting happy
   */

  salt->salt_buf[0] = krb5pa->timestamp[0];
  salt->salt_buf[1] = krb5pa->timestamp[1];
  salt->salt_buf[2] = krb5pa->timestamp[2];
  salt->salt_buf[3] = krb5pa->timestamp[3];
  salt->salt_buf[4] = krb5pa->timestamp[4];
  salt->salt_buf[5] = krb5pa->timestamp[5];
  salt->salt_buf[6] = krb5pa->timestamp[6];
  salt->salt_buf[7] = krb5pa->timestamp[7];
  salt->salt_buf[8] = krb5pa->timestamp[8];

  salt->salt_len = 36;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = krb5pa->checksum[3];

  return (PARSER_OK);
}

int sapb_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7700) || (input_len > DISPLAY_LEN_MAX_7700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *salt_pos = input_buf;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  uint hash_len = input_len - 1 - salt_len;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  /**
   * valid some data
   */

  uint user_len = 0;

  for (uint i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
   * copy data
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  return (PARSER_OK);
}

int sapg_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7800) || (input_len > DISPLAY_LEN_MAX_7800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *salt_pos = input_buf;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  uint hash_len = input_len - 1 - salt_len;

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  /**
   * valid some data
   */

  uint user_len = 0;

  for (uint i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  // this is kinda buggy. if the username is in utf the length can be up to length 12*3
  // so far nobody complained so we stay with this because it helps in optimization
  // final string can have a max size of 32 (password) + (10 * 5) = lengthMagicArray + 12 (max salt) + 1 (the 0x80)

  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
   * copy data
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  return (PARSER_OK);
}

int drupal7_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7900) || (input_len > DISPLAY_LEN_MAX_7900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DRUPAL7, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 3;

  uint salt_iter = 1 << itoa64_to_int (iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy ((char *) salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  char *salt_pos = iter_pos + 1;

  uint salt_len = 8;

  memcpy ((char *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char *hash_pos = salt_pos + salt_len;

  drupal7_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  // ugly hack start

  char *tmp = (char *) salt->salt_buf_pc;

  tmp[0] = hash_pos[42];

  // ugly hack end

  digest[ 0] = byte_swap_64 (digest[ 0]);
  digest[ 1] = byte_swap_64 (digest[ 1]);
  digest[ 2] = byte_swap_64 (digest[ 2]);
  digest[ 3] = byte_swap_64 (digest[ 3]);
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;

  return (PARSER_OK);
}

int sybasease_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8000) || (input_len > DISPLAY_LEN_MAX_8000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SYBASEASE, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  uint salt_len = 16;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  char *hash_pos = input_buf + 6 + 16;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  return (PARSER_OK);
}

int mysql323_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_200) || (input_len > DISPLAY_LEN_MAX_200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rakp_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7300) || (input_len > DISPLAY_LEN_MAX_7300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rakp_t *rakp = (rakp_t *) hash_buf->esalt;

  char *saltbuf_pos = input_buf;

  char *hashbuf_pos = strchr (saltbuf_pos, ':');

  if (hashbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = hashbuf_pos - saltbuf_pos;

  if (saltbuf_len <  64) return (PARSER_SALT_LENGTH);
  if (saltbuf_len > 512) return (PARSER_SALT_LENGTH);

  if (saltbuf_len & 1) return (PARSER_SALT_LENGTH); // muss gerade sein wegen hex

  hashbuf_pos++;

  uint hashbuf_len = input_len - saltbuf_len - 1;

  if (hashbuf_len != 40) return (PARSER_HASH_LENGTH);

  char *salt_ptr = (char *) saltbuf_pos;
  char *rakp_ptr = (char *) rakp->salt_buf;

  uint i;
  uint j;

  for (i = 0, j = 0; i < saltbuf_len; i += 2, j += 1)
  {
    rakp_ptr[j] = hex_to_u8 ((const u8 *) &salt_ptr[i]);
  }

  rakp_ptr[j] = 0x80;

  rakp->salt_len = j;

  for (i = 0; i < 64; i++)
  {
    rakp->salt_buf[i] = byte_swap_32 (rakp->salt_buf[i]);
  }

  salt->salt_buf[0] = rakp->salt_buf[0];
  salt->salt_buf[1] = rakp->salt_buf[1];
  salt->salt_buf[2] = rakp->salt_buf[2];
  salt->salt_buf[3] = rakp->salt_buf[3];
  salt->salt_buf[4] = rakp->salt_buf[4];
  salt->salt_buf[5] = rakp->salt_buf[5];
  salt->salt_buf[6] = rakp->salt_buf[6];
  salt->salt_buf[7] = rakp->salt_buf[7];

  salt->salt_len = 32; // muss min. 32 haben

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hashbuf_pos[32]);

  return (PARSER_OK);
}

int netscaler_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8100) || (input_len > DISPLAY_LEN_MAX_8100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (memcmp (SIGNATURE_NETSCALER, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  char *salt_pos = input_buf + 1;

  memcpy (salt->salt_buf, salt_pos, 8);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_len = 8;

  char *hash_pos = salt_pos + 8;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int chap_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_4800) || (input_len > DISPLAY_LEN_MAX_4800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *salt_buf_ptr = input_buf + 32 + 1;

  u32 *salt_buf = salt->salt_buf;

  salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf_ptr[ 0]);
  salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf_ptr[ 8]);
  salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf_ptr[16]);
  salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf_ptr[24]);

  salt_buf[0] = byte_swap_32 (salt_buf[0]);
  salt_buf[1] = byte_swap_32 (salt_buf[1]);
  salt_buf[2] = byte_swap_32 (salt_buf[2]);
  salt_buf[3] = byte_swap_32 (salt_buf[3]);

  salt->salt_len = 16 + 1;

  if (input_buf[65] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *idbyte_buf_ptr = input_buf + 32 + 1 + 32 + 1;

  salt_buf[4] = hex_to_u8 ((const u8 *) &idbyte_buf_ptr[0]) & 0xff;

  return (PARSER_OK);
}

int cloudkey_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8200) || (input_len > DISPLAY_LEN_MAX_8200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  cloudkey_t *cloudkey = (cloudkey_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *hashbuf_pos = input_buf;

  char *saltbuf_pos = strchr (hashbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint hashbuf_len = saltbuf_pos - hashbuf_pos;

  if (hashbuf_len != 64) return (PARSER_HASH_LENGTH);

  saltbuf_pos++;

  char *iteration_pos = strchr (saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  char *databuf_pos = strchr (iteration_pos, ':');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint iteration_len = databuf_pos - iteration_pos;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 8) return (PARSER_SALT_ITERATION);

  const uint databuf_len = input_len - hashbuf_len - 1 - saltbuf_len - 1 - iteration_len - 1;

  if (databuf_len <    1) return (PARSER_SALT_LENGTH);
  if (databuf_len > 2048) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  // digest

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hashbuf_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hashbuf_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hashbuf_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hashbuf_pos[56]);

  // salt

  char *saltbuf_ptr = (char *) salt->salt_buf;

  for (uint i = 0; i < saltbuf_len; i += 2)
  {
    const char p0 = saltbuf_pos[i + 0];
    const char p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  salt->salt_buf[4] = 0x01000000;
  salt->salt_buf[5] = 0x80;

  salt->salt_len = saltbuf_len / 2;

  // iteration

  salt->salt_iter = atoi (iteration_pos) - 1;

  // data

  char *databuf_ptr = (char *) cloudkey->data_buf;

  for (uint i = 0; i < databuf_len; i += 2)
  {
    const char p0 = databuf_pos[i + 0];
    const char p1 = databuf_pos[i + 1];

    *databuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  *databuf_ptr++ = 0x80;

  for (uint i = 0; i < 512; i++)
  {
    cloudkey->data_buf[i] = byte_swap_32 (cloudkey->data_buf[i]);
  }

  cloudkey->data_len = databuf_len / 2;

  return (PARSER_OK);
}

int nsec3_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8300) || (input_len > DISPLAY_LEN_MAX_8300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *hashbuf_pos = input_buf;

  char *domainbuf_pos = strchr (hashbuf_pos, ':');

  if (domainbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint hashbuf_len = domainbuf_pos - hashbuf_pos;

  if (hashbuf_len != 32) return (PARSER_HASH_LENGTH);

  domainbuf_pos++;

  if (domainbuf_pos[0] != '.') return (PARSER_SALT_VALUE);

  char *saltbuf_pos = strchr (domainbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint domainbuf_len = saltbuf_pos - domainbuf_pos;

  if (domainbuf_len >= 32) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *iteration_pos = strchr (saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len >= 28) return (PARSER_SALT_LENGTH); // 28 = 32 - 4; 4 = length

  if ((domainbuf_len + saltbuf_len) >= 48) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  const uint iteration_len = input_len - hashbuf_len - 1 - domainbuf_len - 1 - saltbuf_len - 1;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 5) return (PARSER_SALT_ITERATION);

  // ok, the plan for this algorithm is the following:
  // we have 2 salts here, the domain-name and a random salt
  // while both are used in the initial transformation,
  // only the random salt is used in the following iterations
  // so we create two buffer, one that includes domain-name (stored into salt_buf_pc[])
  // and one that includes only the real salt (stored into salt_buf[]).
  // the domain-name length is put into array position 7 of salt_buf_pc[] since there is not salt_pc_len

  u8 tmp_buf[100] = { 0 };

  base32_decode (itoa32_to_int, (const u8 *) hashbuf_pos, 32, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // domain

  char *salt_buf_pc_ptr = (char *) salt->salt_buf_pc;

  memcpy (salt_buf_pc_ptr, domainbuf_pos, domainbuf_len);

  char *len_ptr = NULL;

  for (uint i = 0; i < domainbuf_len; i++)
  {
    if (salt_buf_pc_ptr[i] == '.')
    {
      len_ptr = &salt_buf_pc_ptr[i];

      *len_ptr = 0;
    }
    else
    {
      *len_ptr += 1;
    }
  }

  salt->salt_buf_pc[7] = domainbuf_len;

  // "real" salt

  char *salt_buf_ptr = (char *) salt->salt_buf;

  const uint salt_len = parse_and_store_salt (salt_buf_ptr, saltbuf_pos, saltbuf_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  // iteration

  salt->salt_iter = atoi (iteration_pos);

  return (PARSER_OK);
}

int wbb3_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8400) || (input_len > DISPLAY_LEN_MAX_8400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int racf_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  const u8 ascii_to_ebcdic[] =
  {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
    0x40, 0x4f, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0x4a, 0xe0, 0x5a, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x6a, 0xd0, 0xa1, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
    0x9f, 0xa0, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  };

  if ((input_len < DISPLAY_LEN_MIN_8500) || (input_len > DISPLAY_LEN_MAX_8500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RACF, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 6 + 1;

  char *digest_pos = strchr (salt_pos, '*');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  uint hash_len = input_len - 1 - salt_len - 1 - 6;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  digest_pos++;

  char *salt_buf_ptr    = (char *) salt->salt_buf;
  char *salt_buf_pc_ptr = (char *) salt->salt_buf_pc;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  for (uint i = 0; i < salt_len; i++)
  {
    salt_buf_pc_ptr[i] = ascii_to_ebcdic[(int) salt_buf_ptr[i]];
  }
  for (uint i = salt_len; i < 8; i++)
  {
    salt_buf_pc_ptr[i] = 0x40;
  }

  uint tt;

  IP (salt->salt_buf_pc[0], salt->salt_buf_pc[1], tt);

  salt->salt_buf_pc[0] = rotl32 (salt->salt_buf_pc[0], 3u);
  salt->salt_buf_pc[1] = rotl32 (salt->salt_buf_pc[1], 3u);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  IP (digest[0], digest[1], tt);

  digest[0] = rotr32 (digest[0], 29);
  digest[1] = rotr32 (digest[1], 29);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int lotus5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8600) || (input_len > DISPLAY_LEN_MAX_8600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int lotus6_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8700) || (input_len > DISPLAY_LEN_MAX_8700)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'G') || (input_buf[21] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, (const u8 *) input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  memcpy (salt->salt_buf, tmp_buf, 5);

  salt->salt_len = 5;

  memcpy (digest, tmp_buf + 5, 9);

  // yes, only 9 byte are needed to crack, but 10 to display

  salt->salt_buf_pc[7] = input_buf[20];

  return (PARSER_OK);
}

int lotus8_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9100) || (input_len > DISPLAY_LEN_MAX_9100)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'H') || (input_buf[DISPLAY_LEN_MAX_9100 - 1] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, (const u8 *) input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  // salt

  memcpy (salt->salt_buf, tmp_buf, 16);

  salt->salt_len = 16; // Attention: in theory we have 2 salt_len, one for the -m 8700 part (len: 8), 2nd for the 9100 part (len: 16)

  // iteration

  char tmp_iter_buf[11] = { 0 };

  memcpy (tmp_iter_buf, tmp_buf + 16, 10);

  tmp_iter_buf[10] = 0;

  salt->salt_iter = atoi (tmp_iter_buf);

  if (salt->salt_iter < 1) // well, the limit hopefully is much higher
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter--; // first round in init

  // 2 additional bytes for display only

  salt->salt_buf_pc[0] = tmp_buf[26];
  salt->salt_buf_pc[1] = tmp_buf[27];

  // digest

  memcpy (digest, tmp_buf + 28, 8);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int hmailserver_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_1421) || (input_len > DISPLAY_LEN_MAX_1421)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf_pos = input_buf;

  char *hash_buf_pos = salt_buf_pos + 6;

  digest[0] = hex_to_u32 ((const u8 *) &hash_buf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_buf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_buf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_buf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_buf_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_buf_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_buf_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_buf_pos[56]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  const uint salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf_pos, 6);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int phps_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_2612) || (input_len > DISPLAY_LEN_MAX_2612)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (memcmp (SIGNATURE_PHPS, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 6;

  char *digest_buf = strchr (salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  digest[0] = hex_to_u32 ((const u8 *) &digest_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int mediawiki_b_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_3711) || (input_len > DISPLAY_LEN_MAX_3711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MEDIAWIKI_B, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_buf = input_buf + 3;

  char *digest_buf = strchr (salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len] = 0x2d;

  salt->salt_len = salt_len + 1;

  digest[0] = hex_to_u32 ((const u8 *) &digest_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int peoplesoft_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_133) || (input_len > DISPLAY_LEN_MAX_133)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) input_buf, input_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  salt->salt_buf[0] = 0x80;

  salt->salt_len = 0;

  return (PARSER_OK);
}

int skype_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_23) || (input_len > DISPLAY_LEN_MAX_23)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  /*
   * add static "salt" part
   */

  memcpy (salt_buf_ptr + salt_len, "\nskyper\n", 8);

  salt_len += 8;

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int androidfde_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8800) || (input_len > DISPLAY_LEN_MAX_8800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ANDROIDFDE, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  androidfde_t *androidfde = (androidfde_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *saltlen_pos = input_buf + 1 + 3 + 1;

  char *saltbuf_pos = strchr (saltlen_pos, '$');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltlen_len = saltbuf_pos - saltlen_pos;

  if (saltlen_len != 2) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  char *keylen_pos = strchr (saltbuf_pos, '$');

  if (keylen_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint saltbuf_len = keylen_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  keylen_pos++;

  char *keybuf_pos = strchr (keylen_pos, '$');

  if (keybuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint keylen_len = keybuf_pos - keylen_pos;

  if (keylen_len != 2) return (PARSER_SALT_LENGTH);

  keybuf_pos++;

  char *databuf_pos = strchr (keybuf_pos, '$');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint keybuf_len = databuf_pos - keybuf_pos;

  if (keybuf_len != 32) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  uint data_len = input_len - 1 - 3 - 1 - saltlen_len - 1 - saltbuf_len - 1 - keylen_len - 1 - keybuf_len - 1;

  if (data_len != 3072) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  digest[0] = hex_to_u32 ((const u8 *) &keybuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &keybuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &keybuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &keybuf_pos[24]);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &saltbuf_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &saltbuf_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &saltbuf_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &saltbuf_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_ANDROIDFDE - 1;

  for (uint i = 0, j = 0; i < 3072; i += 8, j += 1)
  {
    androidfde->data[j] = hex_to_u32 ((const u8 *) &databuf_pos[i]);
  }

  return (PARSER_OK);
}

int scrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_8900) || (input_len > DISPLAY_LEN_MAX_8900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SCRYPT, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  // first is the N salt parameter

  char *N_pos = input_buf + 6;

  if (N_pos[0] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  N_pos++;

  salt->scrypt_N = atoi (N_pos);

  // r

  char *r_pos = strchr (N_pos, ':');

  if (r_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  r_pos++;

  salt->scrypt_r = atoi (r_pos);

  // p

  char *p_pos = strchr (r_pos, ':');

  if (p_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  p_pos++;

  salt->scrypt_p = atoi (p_pos);

  // salt

  char *saltbuf_pos = strchr (p_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  saltbuf_pos++;

  char *hash_pos = strchr (saltbuf_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  // base64 decode

  int salt_len_base64 = hash_pos - saltbuf_pos;

  if (salt_len_base64 > 45) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[33] = { 0 };

  int tmp_len = base64_decode (base64_to_int, (const u8 *) saltbuf_pos, salt_len_base64, tmp_buf);

  char *salt_buf_ptr = (char *) salt->salt_buf;

  memcpy (salt_buf_ptr, tmp_buf, tmp_len);

  salt->salt_len  = tmp_len;
  salt->salt_iter = 1;

  // digest - base64 decode

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = input_len - (hash_pos - input_buf);

  if (tmp_len != 44) return (PARSER_GLOBAL_LENGTH);

  base64_decode (base64_to_int, (const u8 *) hash_pos, tmp_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  return (PARSER_OK);
}

int juniper_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_501) || (input_len > DISPLAY_LEN_MAX_501)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char decrypted[76] = { 0 }; // iv + hash

  juniper_decrypt_hash (input_buf, decrypted);

  char *md5crypt_hash = decrypted + 12;

  if (memcmp (md5crypt_hash, "$1$danastre$", 12)) return (PARSER_SALT_VALUE);

  salt->salt_iter = ROUNDS_MD5CRYPT;

  char *salt_pos = md5crypt_hash + 3;

  char *hash_pos = strchr (salt_pos, '$'); // or simply salt_pos + 8

  salt->salt_len = hash_pos - salt_pos;    // should be 8

  memcpy ((char *) salt->salt_buf, salt_pos, salt->salt_len);

  hash_pos++;

  md5crypt_decode ((unsigned char *) digest, (unsigned char *) hash_pos);

  return (PARSER_OK);
}

int cisco8_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9200) || (input_len > DISPLAY_LEN_MAX_9200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CISCO8, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // first is *raw* salt

  char *salt_pos = input_buf + 3;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  hash_pos++;

  char *salt_buf_ptr = (char *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, 14);

  salt_buf_ptr[17] = 0x01;
  salt_buf_ptr[18] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];

  salt->salt_len  = salt_len;
  salt->salt_iter = ROUNDS_CISCO8 - 1;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode (itoa64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int cisco9_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9300) || (input_len > DISPLAY_LEN_MAX_9300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CISCO9, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  // first is *raw* salt

  char *salt_pos = input_buf + 3;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;
  hash_pos++;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);
  salt_buf_ptr[salt_len] = 0;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode (itoa64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  // fixed:
  salt->scrypt_N  = 16384;
  salt->scrypt_r  = 1;
  salt->scrypt_p  = 1;
  salt->salt_iter = 1;

  return (PARSER_OK);
}

int office2007_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9400) || (input_len > DISPLAY_LEN_MAX_9400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2007, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2007_t *office2007 = (office2007_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 8 + 1;

  char *verifierHashSize_pos = strchr (version_pos, '*');

  if (verifierHashSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = verifierHashSize_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  verifierHashSize_pos++;

  char *keySize_pos = strchr (verifierHashSize_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 verifierHashSize_len = keySize_pos - verifierHashSize_pos;

  if (verifierHashSize_len != 2) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr (keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr (saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - verifierHashSize_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  const uint version = atoi (version_pos);

  if (version != 2007) return (PARSER_SALT_VALUE);

  const uint verifierHashSize = atoi (verifierHashSize_pos);

  if (verifierHashSize != 20) return (PARSER_SALT_VALUE);

  const uint keySize = atoi (keySize_pos);

  if ((keySize != 128) && (keySize != 256)) return (PARSER_SALT_VALUE);

  office2007->keySize = keySize;

  const uint saltSize = atoi (saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_OFFICE2007;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  /**
   * esalt
   */

  office2007->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2007->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2007->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2007->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2007->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2007->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2007->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2007->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2007->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  /**
   * digest
   */

  digest[0] = office2007->encryptedVerifierHash[0];
  digest[1] = office2007->encryptedVerifierHash[1];
  digest[2] = office2007->encryptedVerifierHash[2];
  digest[3] = office2007->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2010_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9500) || (input_len > DISPLAY_LEN_MAX_9500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2010, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2010_t *office2010 = (office2010_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 8 + 1;

  char *spinCount_pos = strchr (version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  spinCount_pos++;

  char *keySize_pos = strchr (spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  if (spinCount_len != 6) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr (keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr (saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  const uint version = atoi (version_pos);

  if (version != 2010) return (PARSER_SALT_VALUE);

  const uint spinCount = atoi (spinCount_pos);

  if (spinCount != 100000) return (PARSER_SALT_VALUE);

  const uint keySize = atoi (keySize_pos);

  if (keySize != 128) return (PARSER_SALT_VALUE);

  const uint saltSize = atoi (saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  /**
   * esalt
   */

  office2010->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2010->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2010->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2010->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2010->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2010->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2010->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2010->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2010->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);
  office2010->encryptedVerifierHash[5] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[40]);
  office2010->encryptedVerifierHash[6] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[48]);
  office2010->encryptedVerifierHash[7] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[56]);

  /**
   * digest
   */

  digest[0] = office2010->encryptedVerifierHash[0];
  digest[1] = office2010->encryptedVerifierHash[1];
  digest[2] = office2010->encryptedVerifierHash[2];
  digest[3] = office2010->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2013_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9600) || (input_len > DISPLAY_LEN_MAX_9600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2013, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2013_t *office2013 = (office2013_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 8 + 1;

  char *spinCount_pos = strchr (version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  if (version_len != 4) return (PARSER_SALT_LENGTH);

  spinCount_pos++;

  char *keySize_pos = strchr (spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  if (spinCount_len != 6) return (PARSER_SALT_LENGTH);

  keySize_pos++;

  char *saltSize_pos = strchr (keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  if (keySize_len != 3) return (PARSER_SALT_LENGTH);

  saltSize_pos++;

  char *osalt_pos = strchr (saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  if (saltSize_len != 2) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  const uint version = atoi (version_pos);

  if (version != 2013) return (PARSER_SALT_VALUE);

  const uint spinCount = atoi (spinCount_pos);

  if (spinCount != 100000) return (PARSER_SALT_VALUE);

  const uint keySize = atoi (keySize_pos);

  if (keySize != 256) return (PARSER_SALT_VALUE);

  const uint saltSize = atoi (saltSize_pos);

  if (saltSize != 16) return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  /**
   * esalt
   */

  office2013->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2013->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2013->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2013->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2013->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2013->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2013->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2013->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2013->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);
  office2013->encryptedVerifierHash[5] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[40]);
  office2013->encryptedVerifierHash[6] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[48]);
  office2013->encryptedVerifierHash[7] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[56]);

  /**
   * digest
   */

  digest[0] = office2013->encryptedVerifierHash[0];
  digest[1] = office2013->encryptedVerifierHash[1];
  digest[2] = office2013->encryptedVerifierHash[2];
  digest[3] = office2013->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9700) || (input_len > DISPLAY_LEN_MAX_9700)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr (version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice01->version = version;

  oldoffice01->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  oldoffice01->encryptedVerifier[0] = byte_swap_32 (oldoffice01->encryptedVerifier[0]);
  oldoffice01->encryptedVerifier[1] = byte_swap_32 (oldoffice01->encryptedVerifier[1]);
  oldoffice01->encryptedVerifier[2] = byte_swap_32 (oldoffice01->encryptedVerifier[2]);
  oldoffice01->encryptedVerifier[3] = byte_swap_32 (oldoffice01->encryptedVerifier[3]);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);

  oldoffice01->encryptedVerifierHash[0] = byte_swap_32 (oldoffice01->encryptedVerifierHash[0]);
  oldoffice01->encryptedVerifierHash[1] = byte_swap_32 (oldoffice01->encryptedVerifierHash[1]);
  oldoffice01->encryptedVerifierHash[2] = byte_swap_32 (oldoffice01->encryptedVerifierHash[2]);
  oldoffice01->encryptedVerifierHash[3] = byte_swap_32 (oldoffice01->encryptedVerifierHash[3]);

  /**
   * salt
   */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice01->encryptedVerifierHash[0];
  digest[1] = oldoffice01->encryptedVerifierHash[1];
  digest[2] = oldoffice01->encryptedVerifierHash[2];
  digest[3] = oldoffice01->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01cm1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  return oldoffice01_parse_hash (input_buf, input_len, hash_buf);
}

int oldoffice01cm2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9720) || (input_len > DISPLAY_LEN_MAX_9720)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr (version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  char *rc4key_pos = strchr (encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice01->version = version;

  oldoffice01->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  oldoffice01->encryptedVerifier[0] = byte_swap_32 (oldoffice01->encryptedVerifier[0]);
  oldoffice01->encryptedVerifier[1] = byte_swap_32 (oldoffice01->encryptedVerifier[1]);
  oldoffice01->encryptedVerifier[2] = byte_swap_32 (oldoffice01->encryptedVerifier[2]);
  oldoffice01->encryptedVerifier[3] = byte_swap_32 (oldoffice01->encryptedVerifier[3]);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);

  oldoffice01->encryptedVerifierHash[0] = byte_swap_32 (oldoffice01->encryptedVerifierHash[0]);
  oldoffice01->encryptedVerifierHash[1] = byte_swap_32 (oldoffice01->encryptedVerifierHash[1]);
  oldoffice01->encryptedVerifierHash[2] = byte_swap_32 (oldoffice01->encryptedVerifierHash[2]);
  oldoffice01->encryptedVerifierHash[3] = byte_swap_32 (oldoffice01->encryptedVerifierHash[3]);

  oldoffice01->rc4key[1] = 0;
  oldoffice01->rc4key[0] = 0;

  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  oldoffice01->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  oldoffice01->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  oldoffice01->rc4key[0] = byte_swap_32 (oldoffice01->rc4key[0]);
  oldoffice01->rc4key[1] = byte_swap_32 (oldoffice01->rc4key[1]);

  /**
   * salt
   */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice01->rc4key[0];
  digest[1] = oldoffice01->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int oldoffice34_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9800) || (input_len > DISPLAY_LEN_MAX_9800)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE4, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr (version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice34->version = version;

  oldoffice34->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  oldoffice34->encryptedVerifier[0] = byte_swap_32 (oldoffice34->encryptedVerifier[0]);
  oldoffice34->encryptedVerifier[1] = byte_swap_32 (oldoffice34->encryptedVerifier[1]);
  oldoffice34->encryptedVerifier[2] = byte_swap_32 (oldoffice34->encryptedVerifier[2]);
  oldoffice34->encryptedVerifier[3] = byte_swap_32 (oldoffice34->encryptedVerifier[3]);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  oldoffice34->encryptedVerifierHash[0] = byte_swap_32 (oldoffice34->encryptedVerifierHash[0]);
  oldoffice34->encryptedVerifierHash[1] = byte_swap_32 (oldoffice34->encryptedVerifierHash[1]);
  oldoffice34->encryptedVerifierHash[2] = byte_swap_32 (oldoffice34->encryptedVerifierHash[2]);
  oldoffice34->encryptedVerifierHash[3] = byte_swap_32 (oldoffice34->encryptedVerifierHash[3]);
  oldoffice34->encryptedVerifierHash[4] = byte_swap_32 (oldoffice34->encryptedVerifierHash[4]);

  /**
   * salt
   */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice34->encryptedVerifierHash[0];
  digest[1] = oldoffice34->encryptedVerifierHash[1];
  digest[2] = oldoffice34->encryptedVerifierHash[2];
  digest[3] = oldoffice34->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice34cm1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if (memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  return oldoffice34_parse_hash (input_buf, input_len, hash_buf);
}

int oldoffice34cm2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9820) || (input_len > DISPLAY_LEN_MAX_9820)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos = input_buf + 11;

  char *osalt_pos = strchr (version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  char *encryptedVerifier_pos = strchr (osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  char *encryptedVerifierHash_pos = strchr (encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  char *rc4key_pos = strchr (encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  const uint version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice34->version = version;

  oldoffice34->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  oldoffice34->encryptedVerifier[0] = byte_swap_32 (oldoffice34->encryptedVerifier[0]);
  oldoffice34->encryptedVerifier[1] = byte_swap_32 (oldoffice34->encryptedVerifier[1]);
  oldoffice34->encryptedVerifier[2] = byte_swap_32 (oldoffice34->encryptedVerifier[2]);
  oldoffice34->encryptedVerifier[3] = byte_swap_32 (oldoffice34->encryptedVerifier[3]);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  oldoffice34->encryptedVerifierHash[0] = byte_swap_32 (oldoffice34->encryptedVerifierHash[0]);
  oldoffice34->encryptedVerifierHash[1] = byte_swap_32 (oldoffice34->encryptedVerifierHash[1]);
  oldoffice34->encryptedVerifierHash[2] = byte_swap_32 (oldoffice34->encryptedVerifierHash[2]);
  oldoffice34->encryptedVerifierHash[3] = byte_swap_32 (oldoffice34->encryptedVerifierHash[3]);
  oldoffice34->encryptedVerifierHash[4] = byte_swap_32 (oldoffice34->encryptedVerifierHash[4]);

  oldoffice34->rc4key[1] = 0;
  oldoffice34->rc4key[0] = 0;

  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  oldoffice34->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  oldoffice34->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  oldoffice34->rc4key[0] = byte_swap_32 (oldoffice34->rc4key[0]);
  oldoffice34->rc4key[1] = byte_swap_32 (oldoffice34->rc4key[1]);

  /**
   * salt
   */

  salt->salt_len = 16;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice34->rc4key[0];
  digest[1] = oldoffice34->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int radmin2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_9900) || (input_len > DISPLAY_LEN_MAX_9900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int djangosha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_124) || (input_len > DISPLAY_LEN_MAX_124)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_DJANGOSHA1, input_buf, 5)) && (memcmp (SIGNATURE_DJANGOSHA1, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *signature_pos = input_buf;

  char *salt_pos = strchr (signature_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 signature_len = salt_pos - signature_pos;

  if (signature_len != 4) return (PARSER_SIGNATURE_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - signature_len - 1 - salt_len - 1;

  if (hash_len != 40) return (PARSER_SALT_LENGTH);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int djangopbkdf2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10000) || (input_len > DISPLAY_LEN_MAX_10000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DJANGOPBKDF2, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *iter_pos = input_buf + 14;

  const int iter = atoi (iter_pos);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  char *salt_pos = strchr (iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const uint salt_len = hash_pos - salt_pos;

  hash_pos++;

  char *salt_buf_ptr = (char *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len  = salt_len;

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 44) return (PARSER_HASH_LENGTH);

  base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int siphash_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10100) || (input_len > DISPLAY_LEN_MAX_10100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  if (input_buf[16] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[18] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[20] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char iter_c = input_buf[17];
  char iter_d = input_buf[19];

  // atm only defaults, let's see if there's more request
  if (iter_c != '2') return (PARSER_SALT_ITERATION);
  if (iter_d != '4') return (PARSER_SALT_ITERATION);

  char *salt_buf = input_buf + 16 + 1 + 1 + 1 + 1 + 1;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int crammd5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10200) || (input_len > DISPLAY_LEN_MAX_10200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CRAM_MD5, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  cram_md5_t *cram_md5 = (cram_md5_t *) hash_buf->esalt;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 10;

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = hash_pos - salt_pos;

  hash_pos++;

  uint hash_len = input_len - 10 - salt_len - 1;

  // base64 decode salt

  if (salt_len > 133) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[100] = { 0 };

  salt_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, tmp_buf);

  if (salt_len > 55) return (PARSER_SALT_LENGTH);

  tmp_buf[salt_len] = 0x80;

  memcpy (&salt->salt_buf, tmp_buf, salt_len + 1);

  salt->salt_len = salt_len;

  // base64 decode hash

  if (hash_len > 133) return (PARSER_HASH_LENGTH);

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (hash_len < 32 + 1) return (PARSER_SALT_LENGTH);

  uint user_len = hash_len - 32;

  const u8 *tmp_hash = tmp_buf + user_len;

  user_len--; // skip the trailing space

  digest[0] = hex_to_u32 (&tmp_hash[ 0]);
  digest[1] = hex_to_u32 (&tmp_hash[ 8]);
  digest[2] = hex_to_u32 (&tmp_hash[16]);
  digest[3] = hex_to_u32 (&tmp_hash[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // store username for host only (output hash if cracked)

  memset (cram_md5->user, 0, sizeof (cram_md5->user));
  memcpy (cram_md5->user, tmp_buf, user_len);

  return (PARSER_OK);
}

int saph_sha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10300) || (input_len > DISPLAY_LEN_MAX_10300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SAPH_SHA1, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *iter_pos = input_buf + 10;

  u32 iter = atoi (iter_pos);

  if (iter < 1)
  {
    return (PARSER_SALT_ITERATION);
  }

  iter--; // first iteration is special

  salt->salt_iter = iter;

  char *base64_pos = strchr (iter_pos, '}');

  if (base64_pos == NULL)
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }

  base64_pos++;

  // base64 decode salt

  u32 base64_len = input_len - (base64_pos - input_buf);

  u8 tmp_buf[100] = { 0 };

  u32 decoded_len = base64_decode (base64_to_int, (const u8 *) base64_pos, base64_len, tmp_buf);

  if (decoded_len < 24)
  {
    return (PARSER_SALT_LENGTH);
  }

  // copy the salt

  uint salt_len = decoded_len - 20;

  if (salt_len <  4) return (PARSER_SALT_LENGTH);
  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy (&salt->salt_buf, tmp_buf + 20, salt_len);

  salt->salt_len = salt_len;

  // set digest

  u32 *digest_ptr = (u32*) tmp_buf;

  digest[0] = byte_swap_32 (digest_ptr[0]);
  digest[1] = byte_swap_32 (digest_ptr[1]);
  digest[2] = byte_swap_32 (digest_ptr[2]);
  digest[3] = byte_swap_32 (digest_ptr[3]);
  digest[4] = byte_swap_32 (digest_ptr[4]);

  return (PARSER_OK);
}

int redmine_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_7600) || (input_len > DISPLAY_LEN_MAX_7600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  if (input_buf[40] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 40 - 1;

  char *salt_buf = input_buf + 40 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pdf11_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10400) || (input_len > DISPLAY_LEN_MAX_10400)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PDF, input_buf, 5)) && (memcmp (SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr (V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr (R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr (bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr (P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr (enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr (id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr (id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr (u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr (u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr (o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi (V_pos);
  const int R = atoi (R_pos);
  const int P = atoi (P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi (enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi (id_len_pos);
  const int u_len  = atoi (u_len_pos);
  const int o_len  = atoi (o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi (bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);
  pdf->id_len    = id_len;

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  pdf->id_buf[0] = byte_swap_32 (pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32 (pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32 (pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32 (pdf->id_buf[3]);

  pdf->u_buf[0]  = byte_swap_32 (pdf->u_buf[0]);
  pdf->u_buf[1]  = byte_swap_32 (pdf->u_buf[1]);
  pdf->u_buf[2]  = byte_swap_32 (pdf->u_buf[2]);
  pdf->u_buf[3]  = byte_swap_32 (pdf->u_buf[3]);
  pdf->u_buf[4]  = byte_swap_32 (pdf->u_buf[4]);
  pdf->u_buf[5]  = byte_swap_32 (pdf->u_buf[5]);
  pdf->u_buf[6]  = byte_swap_32 (pdf->u_buf[6]);
  pdf->u_buf[7]  = byte_swap_32 (pdf->u_buf[7]);

  pdf->o_buf[0]  = byte_swap_32 (pdf->o_buf[0]);
  pdf->o_buf[1]  = byte_swap_32 (pdf->o_buf[1]);
  pdf->o_buf[2]  = byte_swap_32 (pdf->o_buf[2]);
  pdf->o_buf[3]  = byte_swap_32 (pdf->o_buf[3]);
  pdf->o_buf[4]  = byte_swap_32 (pdf->o_buf[4]);
  pdf->o_buf[5]  = byte_swap_32 (pdf->o_buf[5]);
  pdf->o_buf[6]  = byte_swap_32 (pdf->o_buf[6]);
  pdf->o_buf[7]  = byte_swap_32 (pdf->o_buf[7]);

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_len    = pdf->id_len;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];

  return (PARSER_OK);
}

int pdf11cm1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  return pdf11_parse_hash (input_buf, input_len, hash_buf);
}

int pdf11cm2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10420) || (input_len > DISPLAY_LEN_MAX_10420)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PDF, input_buf, 5)) && (memcmp (SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr (V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr (R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr (bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr (P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr (enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr (id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr (id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr (u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr (u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr (o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  char *rc4key_pos = strchr (o_buf_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_buf_len = rc4key_pos - o_buf_pos;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1 - o_buf_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi (V_pos);
  const int R = atoi (R_pos);
  const int P = atoi (P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi (enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi (id_len_pos);
  const int u_len  = atoi (u_len_pos);
  const int o_len  = atoi (o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi (bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);
  pdf->id_len    = id_len;

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  pdf->id_buf[0] = byte_swap_32 (pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32 (pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32 (pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32 (pdf->id_buf[3]);

  pdf->u_buf[0]  = byte_swap_32 (pdf->u_buf[0]);
  pdf->u_buf[1]  = byte_swap_32 (pdf->u_buf[1]);
  pdf->u_buf[2]  = byte_swap_32 (pdf->u_buf[2]);
  pdf->u_buf[3]  = byte_swap_32 (pdf->u_buf[3]);
  pdf->u_buf[4]  = byte_swap_32 (pdf->u_buf[4]);
  pdf->u_buf[5]  = byte_swap_32 (pdf->u_buf[5]);
  pdf->u_buf[6]  = byte_swap_32 (pdf->u_buf[6]);
  pdf->u_buf[7]  = byte_swap_32 (pdf->u_buf[7]);

  pdf->o_buf[0]  = byte_swap_32 (pdf->o_buf[0]);
  pdf->o_buf[1]  = byte_swap_32 (pdf->o_buf[1]);
  pdf->o_buf[2]  = byte_swap_32 (pdf->o_buf[2]);
  pdf->o_buf[3]  = byte_swap_32 (pdf->o_buf[3]);
  pdf->o_buf[4]  = byte_swap_32 (pdf->o_buf[4]);
  pdf->o_buf[5]  = byte_swap_32 (pdf->o_buf[5]);
  pdf->o_buf[6]  = byte_swap_32 (pdf->o_buf[6]);
  pdf->o_buf[7]  = byte_swap_32 (pdf->o_buf[7]);

  pdf->rc4key[1] = 0;
  pdf->rc4key[0] = 0;

  pdf->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  pdf->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  pdf->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  pdf->rc4key[0] = byte_swap_32 (pdf->rc4key[0]);
  pdf->rc4key[1] = byte_swap_32 (pdf->rc4key[1]);

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len    = pdf->id_len + 16;

  digest[0] = pdf->rc4key[0];
  digest[1] = pdf->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf14_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10500) || (input_len > DISPLAY_LEN_MAX_10500)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PDF, input_buf, 5)) && (memcmp (SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr (V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr (R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr (bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr (P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr (enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr (id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr (id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if ((id_buf_len != 32) && (id_buf_len != 64)) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  char *u_buf_pos = strchr (u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr (u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  char *o_buf_pos = strchr (o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi (V_pos);
  const int R = atoi (R_pos);
  const int P = atoi (P_pos);

  int vr_ok = 0;

  if ((V == 2) && (R == 3)) vr_ok = 1;
  if ((V == 4) && (R == 4)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int id_len = atoi (id_len_pos);
  const int u_len  = atoi (u_len_pos);
  const int o_len  = atoi (o_len_pos);

  if ((id_len != 16) && (id_len != 32)) return (PARSER_SALT_VALUE);

  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi (bits_pos);

  if (bits != 128) return (PARSER_SALT_VALUE);

  int enc_md = 1;

  if (R >= 4)
  {
    enc_md = atoi (enc_md_pos);
  }

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);

  if (id_len == 32)
  {
    pdf->id_buf[4] = hex_to_u32 ((const u8 *) &id_buf_pos[32]);
    pdf->id_buf[5] = hex_to_u32 ((const u8 *) &id_buf_pos[40]);
    pdf->id_buf[6] = hex_to_u32 ((const u8 *) &id_buf_pos[48]);
    pdf->id_buf[7] = hex_to_u32 ((const u8 *) &id_buf_pos[56]);
  }

  pdf->id_len = id_len;

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  pdf->id_buf[0] = byte_swap_32 (pdf->id_buf[0]);
  pdf->id_buf[1] = byte_swap_32 (pdf->id_buf[1]);
  pdf->id_buf[2] = byte_swap_32 (pdf->id_buf[2]);
  pdf->id_buf[3] = byte_swap_32 (pdf->id_buf[3]);

  if (id_len == 32)
  {
    pdf->id_buf[4] = byte_swap_32 (pdf->id_buf[4]);
    pdf->id_buf[5] = byte_swap_32 (pdf->id_buf[5]);
    pdf->id_buf[6] = byte_swap_32 (pdf->id_buf[6]);
    pdf->id_buf[7] = byte_swap_32 (pdf->id_buf[7]);
  }

  pdf->u_buf[0]  = byte_swap_32 (pdf->u_buf[0]);
  pdf->u_buf[1]  = byte_swap_32 (pdf->u_buf[1]);
  pdf->u_buf[2]  = byte_swap_32 (pdf->u_buf[2]);
  pdf->u_buf[3]  = byte_swap_32 (pdf->u_buf[3]);
  pdf->u_buf[4]  = byte_swap_32 (pdf->u_buf[4]);
  pdf->u_buf[5]  = byte_swap_32 (pdf->u_buf[5]);
  pdf->u_buf[6]  = byte_swap_32 (pdf->u_buf[6]);
  pdf->u_buf[7]  = byte_swap_32 (pdf->u_buf[7]);

  pdf->o_buf[0]  = byte_swap_32 (pdf->o_buf[0]);
  pdf->o_buf[1]  = byte_swap_32 (pdf->o_buf[1]);
  pdf->o_buf[2]  = byte_swap_32 (pdf->o_buf[2]);
  pdf->o_buf[3]  = byte_swap_32 (pdf->o_buf[3]);
  pdf->o_buf[4]  = byte_swap_32 (pdf->o_buf[4]);
  pdf->o_buf[5]  = byte_swap_32 (pdf->o_buf[5]);
  pdf->o_buf[6]  = byte_swap_32 (pdf->o_buf[6]);
  pdf->o_buf[7]  = byte_swap_32 (pdf->o_buf[7]);

  // precompute rc4 data for later use

  uint padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  // md5

  uint salt_pc_block[32] = { 0 };

  char *salt_pc_ptr = (char *) salt_pc_block;

  memcpy (salt_pc_ptr, padding, 32);
  memcpy (salt_pc_ptr + 32, pdf->id_buf, pdf->id_len);

  uint salt_pc_digest[4] = { 0 };

  md5_complete_no_limit (salt_pc_digest, salt_pc_block, 32 + pdf->id_len);

  pdf->rc4data[0] = salt_pc_digest[0];
  pdf->rc4data[1] = salt_pc_digest[1];

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len    = pdf->id_len + 16;

  salt->salt_iter   = ROUNDS_PDF14;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf17l3_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  int ret = pdf17l8_parse_hash (input_buf, input_len, hash_buf);

  if (ret != PARSER_OK)
  {
    return ret;
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  salt->salt_buf[2] = 0x80;

  return (PARSER_OK);
}

int pdf17l8_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10600) || (input_len > DISPLAY_LEN_MAX_10600)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PDF, input_buf, 5)) && (memcmp (SIGNATURE_PDF, input_buf, 5))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *V_pos = input_buf + 5;

  char *R_pos = strchr (V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  char *bits_pos = strchr (R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  char *P_pos = strchr (bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  char *enc_md_pos = strchr (P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  char *id_len_pos = strchr (enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  char *id_buf_pos = strchr (id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  char *u_len_pos = strchr (id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  u_len_pos++;

  char *u_buf_pos = strchr (u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  char *o_len_pos = strchr (u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  o_len_pos++;

  char *o_buf_pos = strchr (o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  char *last = strchr (o_buf_pos, '*');

  if (last == NULL) last = input_buf + input_len;

  u32 o_buf_len = last - o_buf_pos;

  // validate data

  const int V = atoi (V_pos);
  const int R = atoi (R_pos);

  int vr_ok = 0;

  if ((V == 5) && (R == 5)) vr_ok = 1;
  if ((V == 5) && (R == 6)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int bits = atoi (bits_pos);

  if (bits != 256) return (PARSER_SALT_VALUE);

  int enc_md = atoi (enc_md_pos);

  if (enc_md != 1) return (PARSER_SALT_VALUE);

  const uint id_len = atoi (id_len_pos);
  const uint u_len  = atoi (u_len_pos);
  const uint o_len  = atoi (o_len_pos);

  if (V_len      > 6) return (PARSER_SALT_LENGTH);
  if (R_len      > 6) return (PARSER_SALT_LENGTH);
  if (P_len      > 6) return (PARSER_SALT_LENGTH);
  if (id_len_len > 6) return (PARSER_SALT_LENGTH);
  if (u_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (o_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (bits_len   > 6) return (PARSER_SALT_LENGTH);
  if (enc_md_len > 6) return (PARSER_SALT_LENGTH);

  if ((id_len * 2) != id_buf_len) return (PARSER_SALT_VALUE);
  if ((u_len  * 2) != u_buf_len)  return (PARSER_SALT_VALUE);
  if ((o_len  * 2) != o_buf_len)  return (PARSER_SALT_VALUE);

  // copy data to esalt

  if (u_len < 40) return (PARSER_SALT_VALUE);

  for (int i = 0, j = 0; i < 8 + 2; i += 1, j += 8)
  {
    pdf->u_buf[i] = hex_to_u32 ((const u8 *) &u_buf_pos[j]);
  }

  salt->salt_buf[0] = pdf->u_buf[8];
  salt->salt_buf[1] = pdf->u_buf[9];

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_PDF17L8;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];
  digest[4] = pdf->u_buf[4];
  digest[5] = pdf->u_buf[5];
  digest[6] = pdf->u_buf[6];
  digest[7] = pdf->u_buf[7];

  return (PARSER_OK);
}

int pbkdf2_sha256_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_10900) || (input_len > DISPLAY_LEN_MAX_10900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA256, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  char *iter_pos = input_buf + 7;

  u32 iter = atoi (iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr (iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *) pbkdf2_sha256->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int prestashop_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11000) || (input_len > DISPLAY_LEN_MAX_11000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (input_buf[32] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 32 - 1;

  char *salt_buf = input_buf + 32 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_auth_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11100) || (input_len > DISPLAY_LEN_MAX_11100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_POSTGRESQL_AUTH, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *user_pos = input_buf + 10;

  char *salt_pos = strchr (user_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, '*');

  hash_pos++;

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  uint user_len = salt_pos - user_pos - 1;

  uint salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 8) return (PARSER_SALT_LENGTH);

  /*
   * store digest
   */

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /*
   * store salt
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  // first 4 bytes are the "challenge"

  salt_buf_ptr[0] = hex_to_u8 ((const u8 *) &salt_pos[0]);
  salt_buf_ptr[1] = hex_to_u8 ((const u8 *) &salt_pos[2]);
  salt_buf_ptr[2] = hex_to_u8 ((const u8 *) &salt_pos[4]);
  salt_buf_ptr[3] = hex_to_u8 ((const u8 *) &salt_pos[6]);

  // append the user name

  user_len = parse_and_store_salt (salt_buf_ptr + 4, user_pos, user_len);

  salt->salt_len = 4 + user_len;

  return (PARSER_OK);
}

int mysql_auth_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11200) || (input_len > DISPLAY_LEN_MAX_11200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MYSQL_AUTH, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  char *salt_pos = input_buf + 9;

  char *hash_pos = strchr (salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  uint hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  uint salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 40) return (PARSER_SALT_LENGTH);

  /*
   * store digest
   */

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  /*
   * store salt
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int bitcoin_wallet_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11300) || (input_len > DISPLAY_LEN_MAX_11300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_BITCOIN_WALLET, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  bitcoin_wallet_t *bitcoin_wallet = (bitcoin_wallet_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *cry_master_len_pos = input_buf + 9;

  char *cry_master_buf_pos = strchr (cry_master_len_pos, '$');

  if (cry_master_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_len_len = cry_master_buf_pos - cry_master_len_pos;

  cry_master_buf_pos++;

  char *cry_salt_len_pos = strchr (cry_master_buf_pos, '$');

  if (cry_salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_buf_len = cry_salt_len_pos - cry_master_buf_pos;

  cry_salt_len_pos++;

  char *cry_salt_buf_pos = strchr (cry_salt_len_pos, '$');

  if (cry_salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_len_len = cry_salt_buf_pos - cry_salt_len_pos;

  cry_salt_buf_pos++;

  char *cry_rounds_pos = strchr (cry_salt_buf_pos, '$');

  if (cry_rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_buf_len = cry_rounds_pos - cry_salt_buf_pos;

  cry_rounds_pos++;

  char *ckey_len_pos = strchr (cry_rounds_pos, '$');

  if (ckey_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_rounds_len = ckey_len_pos - cry_rounds_pos;

  ckey_len_pos++;

  char *ckey_buf_pos = strchr (ckey_len_pos, '$');

  if (ckey_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_len_len = ckey_buf_pos - ckey_len_pos;

  ckey_buf_pos++;

  char *public_key_len_pos = strchr (ckey_buf_pos, '$');

  if (public_key_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_buf_len = public_key_len_pos - ckey_buf_pos;

  public_key_len_pos++;

  char *public_key_buf_pos = strchr (public_key_len_pos, '$');

  if (public_key_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 public_key_len_len = public_key_buf_pos - public_key_len_pos;

  public_key_buf_pos++;

  u32 public_key_buf_len = input_len - 1 - 7 - 1 - cry_master_len_len - 1 - cry_master_buf_len - 1 - cry_salt_len_len - 1 - cry_salt_buf_len - 1 - cry_rounds_len - 1 - ckey_len_len - 1 - ckey_buf_len - 1 - public_key_len_len - 1;

  const uint cry_master_len = atoi (cry_master_len_pos);
  const uint cry_salt_len   = atoi (cry_salt_len_pos);
  const uint ckey_len       = atoi (ckey_len_pos);
  const uint public_key_len = atoi (public_key_len_pos);

  if (cry_master_buf_len != cry_master_len) return (PARSER_SALT_VALUE);
  if (cry_salt_buf_len   != cry_salt_len)   return (PARSER_SALT_VALUE);
  if (ckey_buf_len       != ckey_len)       return (PARSER_SALT_VALUE);
  if (public_key_buf_len != public_key_len) return (PARSER_SALT_VALUE);

  for (uint i = 0, j = 0; j < cry_master_len; i += 1, j += 8)
  {
    bitcoin_wallet->cry_master_buf[i] = hex_to_u32 ((const u8 *) &cry_master_buf_pos[j]);

    bitcoin_wallet->cry_master_buf[i] = byte_swap_32 (bitcoin_wallet->cry_master_buf[i]);
  }

  for (uint i = 0, j = 0; j < ckey_len; i += 1, j += 8)
  {
    bitcoin_wallet->ckey_buf[i] = hex_to_u32 ((const u8 *) &ckey_buf_pos[j]);

    bitcoin_wallet->ckey_buf[i] = byte_swap_32 (bitcoin_wallet->ckey_buf[i]);
  }

  for (uint i = 0, j = 0; j < public_key_len; i += 1, j += 8)
  {
    bitcoin_wallet->public_key_buf[i] = hex_to_u32 ((const u8 *) &public_key_buf_pos[j]);

    bitcoin_wallet->public_key_buf[i] = byte_swap_32 (bitcoin_wallet->public_key_buf[i]);
  }

  bitcoin_wallet->cry_master_len = cry_master_len / 2;
  bitcoin_wallet->ckey_len       = ckey_len / 2;
  bitcoin_wallet->public_key_len = public_key_len / 2;

  /*
   * store digest (should be unique enought, hopefully)
   */

  digest[0] = bitcoin_wallet->cry_master_buf[0];
  digest[1] = bitcoin_wallet->cry_master_buf[1];
  digest[2] = bitcoin_wallet->cry_master_buf[2];
  digest[3] = bitcoin_wallet->cry_master_buf[3];

  /*
   * store salt
   */

  if (cry_rounds_len >= 7) return (PARSER_SALT_VALUE);

  const uint cry_rounds = atoi (cry_rounds_pos);

  salt->salt_iter = cry_rounds - 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  const uint salt_len = parse_and_store_salt (salt_buf_ptr, cry_salt_buf_pos, cry_salt_buf_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sip_auth_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11400) || (input_len > DISPLAY_LEN_MAX_11400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SIP_AUTH, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  sip_t *sip = (sip_t *) hash_buf->esalt;

  // work with a temporary copy of input_buf (s.t. we can manipulate it directly)

  char *temp_input_buf = (char *) mymalloc (input_len + 1);

  memcpy (temp_input_buf, input_buf, input_len);

  // URI_server:

  char *URI_server_pos = temp_input_buf + 6;

  char *URI_client_pos = strchr (URI_server_pos, '*');

  if (URI_client_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_client_pos[0] = 0;
  URI_client_pos++;

  uint URI_server_len = strlen (URI_server_pos);

  if (URI_server_len > 512)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_client:

  char *user_pos = strchr (URI_client_pos, '*');

  if (user_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  user_pos[0] = 0;
  user_pos++;

  uint URI_client_len = strlen (URI_client_pos);

  if (URI_client_len > 512)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // user:

  char *realm_pos = strchr (user_pos, '*');

  if (realm_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  realm_pos[0] = 0;
  realm_pos++;

  uint user_len = strlen (user_pos);

  if (user_len > 116)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // realm:

  char *method_pos = strchr (realm_pos, '*');

  if (method_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  method_pos[0] = 0;
  method_pos++;

  uint realm_len = strlen (realm_pos);

  if (realm_len > 116)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // method:

  char *URI_prefix_pos = strchr (method_pos, '*');

  if (URI_prefix_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_prefix_pos[0] = 0;
  URI_prefix_pos++;

  uint method_len = strlen (method_pos);

  if (method_len > 246)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_prefix:

  char *URI_resource_pos = strchr (URI_prefix_pos, '*');

  if (URI_resource_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_resource_pos[0] = 0;
  URI_resource_pos++;

  uint URI_prefix_len = strlen (URI_prefix_pos);

  if (URI_prefix_len > 245)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_resource:

  char *URI_suffix_pos = strchr (URI_resource_pos, '*');

  if (URI_suffix_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  URI_suffix_pos[0] = 0;
  URI_suffix_pos++;

  uint URI_resource_len = strlen (URI_resource_pos);

  if (URI_resource_len < 1 || URI_resource_len > 246)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // URI_suffix:

  char *nonce_pos = strchr (URI_suffix_pos, '*');

  if (nonce_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_pos[0] = 0;
  nonce_pos++;

  uint URI_suffix_len = strlen (URI_suffix_pos);

  if (URI_suffix_len > 245)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce:

  char *nonce_client_pos = strchr (nonce_pos, '*');

  if (nonce_client_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_client_pos[0] = 0;
  nonce_client_pos++;

  uint nonce_len = strlen (nonce_pos);

  if (nonce_len < 1 || nonce_len > 50)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce_client:

  char *nonce_count_pos = strchr (nonce_client_pos, '*');

  if (nonce_count_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  nonce_count_pos[0] = 0;
  nonce_count_pos++;

  uint nonce_client_len = strlen (nonce_client_pos);

  if (nonce_client_len > 50)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // nonce_count:

  char *qop_pos = strchr (nonce_count_pos, '*');

  if (qop_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  qop_pos[0] = 0;
  qop_pos++;

  uint nonce_count_len = strlen (nonce_count_pos);

  if (nonce_count_len > 50)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // qop:

  char *directive_pos = strchr (qop_pos, '*');

  if (directive_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  directive_pos[0] = 0;
  directive_pos++;

  uint qop_len = strlen (qop_pos);

  if (qop_len > 50)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  // directive

  char *digest_pos = strchr (directive_pos, '*');

  if (digest_pos == NULL)
  {
    myfree (temp_input_buf);

    return (PARSER_SEPARATOR_UNMATCHED);
  }

  digest_pos[0] = 0;
  digest_pos++;

  uint directive_len = strlen (directive_pos);

  if (directive_len != 3)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  if (memcmp (directive_pos, "MD5", 3))
  {
    log_info ("ERROR: Only the MD5 directive is currently supported\n");

    myfree (temp_input_buf);

    return (PARSER_SIP_AUTH_DIRECTIVE);
  }

  /*
   * first (pre-)compute: HA2 = md5 ($method . ":" . $uri)
   */

  uint md5_len = 0;

  uint md5_max_len = 4 * 64;

  uint md5_remaining_len = md5_max_len;

  uint tmp_md5_buf[64] = { 0 };

  char *tmp_md5_ptr = (char *) tmp_md5_buf;

  snprintf (tmp_md5_ptr, md5_remaining_len, "%s:", method_pos);

  md5_len     += method_len + 1;
  tmp_md5_ptr += method_len + 1;

  if (URI_prefix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf (tmp_md5_ptr, md5_remaining_len + 1, "%s:", URI_prefix_pos);

    md5_len     += URI_prefix_len + 1;
    tmp_md5_ptr += URI_prefix_len + 1;
  }

  md5_remaining_len = md5_max_len - md5_len;

  snprintf (tmp_md5_ptr, md5_remaining_len + 1, "%s", URI_resource_pos);

  md5_len     += URI_resource_len;
  tmp_md5_ptr += URI_resource_len;

  if (URI_suffix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf (tmp_md5_ptr, md5_remaining_len + 1, ":%s", URI_suffix_pos);

    md5_len += 1 + URI_suffix_len;
  }

  uint tmp_digest[4] = { 0 };

  md5_complete_no_limit (tmp_digest, tmp_md5_buf, md5_len);

  tmp_digest[0] = byte_swap_32 (tmp_digest[0]);
  tmp_digest[1] = byte_swap_32 (tmp_digest[1]);
  tmp_digest[2] = byte_swap_32 (tmp_digest[2]);
  tmp_digest[3] = byte_swap_32 (tmp_digest[3]);

  /*
   * esalt
   */

  char *esalt_buf_ptr = (char *) sip->esalt_buf;

  uint esalt_len = 0;

  uint max_esalt_len = sizeof (sip->esalt_buf); // 151 = (64 + 64 + 55) - 32, where 32 is the hexadecimal MD5 HA1 hash

  // there are 2 possibilities for the esalt:

  if ((strcmp (qop_pos, "auth") == 0) || (strcmp (qop_pos, "auth-int") == 0))
  {
    esalt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

    if (esalt_len > max_esalt_len)
    {
      myfree (temp_input_buf);

      return (PARSER_SALT_LENGTH);
    }

    snprintf (esalt_buf_ptr, max_esalt_len, ":%s:%s:%s:%s:%08x%08x%08x%08x",
      nonce_pos,
      nonce_count_pos,
      nonce_client_pos,
      qop_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }
  else
  {
    esalt_len = 1 + nonce_len + 1 + 32;

    if (esalt_len > max_esalt_len)
    {
      myfree (temp_input_buf);

      return (PARSER_SALT_LENGTH);
    }

    snprintf (esalt_buf_ptr, max_esalt_len, ":%s:%08x%08x%08x%08x",
      nonce_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }

  // add 0x80 to esalt

  esalt_buf_ptr[esalt_len] = 0x80;

  sip->esalt_len = esalt_len;

  /*
   * actual salt
   */

  char *sip_salt_ptr = (char *) sip->salt_buf;

  uint salt_len = user_len + 1 + realm_len + 1;

  uint max_salt_len = 119;

  if (salt_len > max_salt_len)
  {
    myfree (temp_input_buf);

    return (PARSER_SALT_LENGTH);
  }

  snprintf (sip_salt_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  sip->salt_len = salt_len;

  /*
   * fake salt (for sorting)
   */

  char *salt_buf_ptr = (char *) salt->salt_buf;

  max_salt_len = 55;

  uint fake_salt_len = salt_len;

  if (fake_salt_len > max_salt_len)
  {
    fake_salt_len = max_salt_len;
  }

  snprintf (salt_buf_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  salt->salt_len = fake_salt_len;

  /*
   * digest
   */

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  myfree (temp_input_buf);

  return (PARSER_OK);
}

int crc32_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11500) || (input_len > DISPLAY_LEN_MAX_11500)) return (PARSER_GLOBAL_LENGTH);

  if (input_buf[8] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // digest

  char *digest_pos = input_buf;

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  // salt

  char *salt_buf = input_buf + 8 + 1;

  uint salt_len = 8;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int seven_zip_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11600) || (input_len > DISPLAY_LEN_MAX_11600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SEVEN_ZIP, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  seven_zip_t *seven_zip = (seven_zip_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *p_buf_pos = input_buf + 4;

  char *NumCyclesPower_pos = strchr (p_buf_pos, '$');

  if (NumCyclesPower_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 p_buf_len = NumCyclesPower_pos - p_buf_pos;

  NumCyclesPower_pos++;

  char *salt_len_pos = strchr (NumCyclesPower_pos, '$');

  if (salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 NumCyclesPower_len = salt_len_pos - NumCyclesPower_pos;

  salt_len_pos++;

  char *salt_buf_pos = strchr (salt_len_pos, '$');

  if (salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len_len = salt_buf_pos - salt_len_pos;

  salt_buf_pos++;

  char *iv_len_pos = strchr (salt_buf_pos, '$');

  if (iv_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_buf_len = iv_len_pos - salt_buf_pos;

  iv_len_pos++;

  char *iv_buf_pos = strchr (iv_len_pos, '$');

  if (iv_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_len_len = iv_buf_pos - iv_len_pos;

  iv_buf_pos++;

  char *crc_buf_pos = strchr (iv_buf_pos, '$');

  if (crc_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_buf_len = crc_buf_pos - iv_buf_pos;

  crc_buf_pos++;

  char *data_len_pos = strchr (crc_buf_pos, '$');

  if (data_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 crc_buf_len = data_len_pos - crc_buf_pos;

  data_len_pos++;

  char *unpack_size_pos = strchr (data_len_pos, '$');

  if (unpack_size_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = unpack_size_pos - data_len_pos;

  unpack_size_pos++;

  char *data_buf_pos = strchr (unpack_size_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 unpack_size_len = data_buf_pos - unpack_size_pos;

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 2 - 1 - p_buf_len - 1 - NumCyclesPower_len - 1 - salt_len_len - 1 - salt_buf_len - 1 - iv_len_len - 1 - iv_buf_len - 1 - crc_buf_len - 1 - data_len_len - 1 - unpack_size_len - 1;

  const uint iter         = atoi (NumCyclesPower_pos);
  const uint crc          = atoi (crc_buf_pos);
  const uint p_buf        = atoi (p_buf_pos);
  const uint salt_len     = atoi (salt_len_pos);
  const uint iv_len       = atoi (iv_len_pos);
  const uint unpack_size  = atoi (unpack_size_pos);
  const uint data_len     = atoi (data_len_pos);

  /**
   * verify some data
   */

  if (p_buf     != 0) return (PARSER_SALT_VALUE);
  if (salt_len  != 0) return (PARSER_SALT_VALUE);

  if ((data_len * 2) != data_buf_len) return (PARSER_SALT_VALUE);

  if (data_len > 384) return (PARSER_SALT_VALUE);

  if (unpack_size > data_len) return (PARSER_SALT_VALUE);

  /**
   * store data
   */

  seven_zip->iv_buf[0] = hex_to_u32 ((const u8 *) &iv_buf_pos[ 0]);
  seven_zip->iv_buf[1] = hex_to_u32 ((const u8 *) &iv_buf_pos[ 8]);
  seven_zip->iv_buf[2] = hex_to_u32 ((const u8 *) &iv_buf_pos[16]);
  seven_zip->iv_buf[3] = hex_to_u32 ((const u8 *) &iv_buf_pos[24]);

  seven_zip->iv_len = iv_len;

  memcpy (seven_zip->salt_buf, salt_buf_pos, salt_buf_len); // we just need that for later ascii_digest()

  seven_zip->salt_len = 0;

  seven_zip->crc = crc;

  for (uint i = 0, j = 0; j < data_buf_len; i += 1, j += 8)
  {
    seven_zip->data_buf[i] = hex_to_u32 ((const u8 *) &data_buf_pos[j]);

    seven_zip->data_buf[i] = byte_swap_32 (seven_zip->data_buf[i]);
  }

  seven_zip->data_len = data_len;

  seven_zip->unpack_size = unpack_size;

  // real salt

  salt->salt_buf[0] = seven_zip->data_buf[0];
  salt->salt_buf[1] = seven_zip->data_buf[1];
  salt->salt_buf[2] = seven_zip->data_buf[2];
  salt->salt_buf[3] = seven_zip->data_buf[3];

  salt->salt_len = 16;

  salt->salt_sign[0] = iter;

  salt->salt_iter = 1 << iter;

  /**
   * digest
   */

  digest[0] = crc;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int gost2012sbog_256_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11700) || (input_len > DISPLAY_LEN_MAX_11700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int gost2012sbog_512_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11800) || (input_len > DISPLAY_LEN_MAX_11800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[ 0] = hex_to_u32 ((const u8 *) &input_buf[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &input_buf[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &input_buf[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &input_buf[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &input_buf[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &input_buf[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &input_buf[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &input_buf[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &input_buf[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &input_buf[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &input_buf[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &input_buf[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &input_buf[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &input_buf[104]);
  digest[14] = hex_to_u32 ((const u8 *) &input_buf[112]);
  digest[15] = hex_to_u32 ((const u8 *) &input_buf[120]);

  digest[ 0] = byte_swap_32 (digest[ 0]);
  digest[ 1] = byte_swap_32 (digest[ 1]);
  digest[ 2] = byte_swap_32 (digest[ 2]);
  digest[ 3] = byte_swap_32 (digest[ 3]);
  digest[ 4] = byte_swap_32 (digest[ 4]);
  digest[ 5] = byte_swap_32 (digest[ 5]);
  digest[ 6] = byte_swap_32 (digest[ 6]);
  digest[ 7] = byte_swap_32 (digest[ 7]);
  digest[ 8] = byte_swap_32 (digest[ 8]);
  digest[ 9] = byte_swap_32 (digest[ 9]);
  digest[10] = byte_swap_32 (digest[10]);
  digest[11] = byte_swap_32 (digest[11]);
  digest[12] = byte_swap_32 (digest[12]);
  digest[13] = byte_swap_32 (digest[13]);
  digest[14] = byte_swap_32 (digest[14]);
  digest[15] = byte_swap_32 (digest[15]);

  return (PARSER_OK);
}

int pbkdf2_md5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_11900) || (input_len > DISPLAY_LEN_MAX_11900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_MD5, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_md5_t *pbkdf2_md5 = (pbkdf2_md5_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  char *iter_pos = input_buf + 4;

  u32 iter = atoi (iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr (iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *) pbkdf2_md5->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_md5->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_md5->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_md5->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_md5->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha1_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12000) || (input_len > DISPLAY_LEN_MAX_12000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA1, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha1_t *pbkdf2_sha1 = (pbkdf2_sha1_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  char *iter_pos = input_buf + 5;

  u32 iter = atoi (iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr (iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *) pbkdf2_sha1->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha1->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha1->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha1->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha1->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha512_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12100) || (input_len > DISPLAY_LEN_MAX_12100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA512, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  char *iter_pos = input_buf + 7;

  u32 iter = atoi (iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  char *salt_pos = strchr (iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  char *hash_pos = strchr (salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  char *salt_buf_ptr = (char *) pbkdf2_sha512->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int ecryptfs_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12200) || (input_len > DISPLAY_LEN_MAX_12200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ECRYPTFS, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  uint *digest = (uint *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *salt_pos = input_buf + 10 + 2 + 2; // skip over "0$" and "1$"

  char *hash_pos = strchr (salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 10 - 2 - 2 - salt_len - 1;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  // decode hash

  digest[ 0] = hex_to_u32 ((const u8 *) &hash_pos[0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &hash_pos[8]);
  digest[ 2] = 0;
  digest[ 3] = 0;
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;
  digest[ 8] = 0;
  digest[ 9] = 0;
  digest[10] = 0;
  digest[11] = 0;
  digest[12] = 0;
  digest[13] = 0;
  digest[14] = 0;
  digest[15] = 0;

  // decode salt

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[8]);

  salt->salt_iter = ROUNDS_ECRYPTFS;
  salt->salt_len  = 8;

  return (PARSER_OK);
}

int bsdicrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12400) || (input_len > DISPLAY_LEN_MAX_12400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_BSDICRYPT, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  unsigned char c19 = itoa64_to_int (input_buf[19]);

  if (c19 & 3) return (PARSER_HASH_VALUE);

  salt_t *salt = hash_buf->salt;

  u32 *digest = (u32 *) hash_buf->digest;

  // iteration count

  salt->salt_iter = itoa64_to_int (input_buf[1])
                  | itoa64_to_int (input_buf[2]) <<  6
                  | itoa64_to_int (input_buf[3]) << 12
                  | itoa64_to_int (input_buf[4]) << 18;

  // set salt

  salt->salt_buf[0] = itoa64_to_int (input_buf[5])
                    | itoa64_to_int (input_buf[6]) <<  6
                    | itoa64_to_int (input_buf[7]) << 12
                    | itoa64_to_int (input_buf[8]) << 18;

  salt->salt_len = 4;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf + 9, 11, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  uint tt;

  IP (digest[0], digest[1], tt);

  digest[0] = rotr32 (digest[0], 31);
  digest[1] = rotr32 (digest[1], 31);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar3hp_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12500) || (input_len > DISPLAY_LEN_MAX_12500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RAR3, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *type_pos = input_buf + 6 + 1;

  char *salt_pos = strchr (type_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 type_len = salt_pos - type_pos;

  if (type_len != 1) return (PARSER_SALT_LENGTH);

  salt_pos++;

  char *crypted_pos = strchr (salt_pos, '*');

  if (crypted_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = crypted_pos - salt_pos;

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  crypted_pos++;

  u32 crypted_len = input_len - 6 - 1 - type_len - 1 - salt_len - 1;

  if (crypted_len != 32) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[8]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &crypted_pos[ 0]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &crypted_pos[ 8]);
  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &crypted_pos[16]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &crypted_pos[24]);

  salt->salt_len  = 24;
  salt->salt_iter = ROUNDS_RAR3;

  // there's no hash for rar3. the data which is in crypted_pos is some encrypted data and
  // if it matches the value \xc4\x3d\x7b\x00\x40\x07\x00 after decrypt we know that we successfully cracked it.

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar5_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13000) || (input_len > DISPLAY_LEN_MAX_13000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RAR5, input_buf, 1 + 4 + 1)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rar5_t *rar5 = (rar5_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *param0_pos = input_buf + 1 + 4 + 1;

  char *param1_pos = strchr (param0_pos, '$');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  char *param2_pos = strchr (param1_pos, '$');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  char *param3_pos = strchr (param2_pos, '$');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  char *param4_pos = strchr (param3_pos, '$');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  char *param5_pos = strchr (param4_pos, '$');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  u32 param5_len = input_len - 1 - 4 - 1 - param0_len - 1 - param1_len - 1 - param2_len - 1 - param3_len - 1 - param4_len - 1;

  char *salt_buf = param1_pos;
  char *iv       = param3_pos;
  char *pswcheck = param5_pos;

  const uint salt_len     = atoi (param0_pos);
  const uint iterations   = atoi (param2_pos);
  const uint pswcheck_len = atoi (param4_pos);

  /**
   * verify some data
   */

  if (param1_len   != 32) return (PARSER_SALT_VALUE);
  if (param3_len   != 32) return (PARSER_SALT_VALUE);
  if (param5_len   != 16) return (PARSER_SALT_VALUE);

  if (salt_len     != 16) return (PARSER_SALT_VALUE);
  if (iterations   ==  0) return (PARSER_SALT_VALUE);
  if (pswcheck_len !=  8) return (PARSER_SALT_VALUE);

  /**
   * store data
   */

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

  rar5->iv[0] = hex_to_u32 ((const u8 *) &iv[ 0]);
  rar5->iv[1] = hex_to_u32 ((const u8 *) &iv[ 8]);
  rar5->iv[2] = hex_to_u32 ((const u8 *) &iv[16]);
  rar5->iv[3] = hex_to_u32 ((const u8 *) &iv[24]);

  salt->salt_len = 16;

  salt->salt_sign[0] = iterations;

  salt->salt_iter = ((1 << iterations) + 32) - 1;

  /**
   * digest buf
   */

  digest[0] = hex_to_u32 ((const u8 *) &pswcheck[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &pswcheck[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int krb5tgs_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13100) || (input_len > DISPLAY_LEN_MAX_13100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KRB5TGS, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5tgs_t *krb5tgs = (krb5tgs_t *) hash_buf->esalt;

  /**
   * parse line
   */

  /* Skip '$' */
  char *account_pos = input_buf + 11 + 1;

  char *data_pos;

  uint data_len;

  if (account_pos[0] == '*')
  {
    account_pos++;

    data_pos = strchr (account_pos, '*');

    /* Skip '*' */
    data_pos++;

    if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    uint account_len = data_pos - account_pos + 1;

    if (account_len >= 512) return (PARSER_SALT_LENGTH);

    /* Skip '$' */
    data_pos++;

    data_len = input_len - 11 - 1 - account_len - 2;

    memcpy (krb5tgs->account_info, account_pos - 1, account_len);
  }
  else
  {
    /* assume $krb5tgs$23$checksum$edata2 */
    data_pos = account_pos;

    memcpy (krb5tgs->account_info, "**", 3);

    data_len = input_len - 11 - 1 - 1;
  }

  if (data_len < ((16 + 32) * 2)) return (PARSER_SALT_LENGTH);

  char *checksum_ptr = (char *) krb5tgs->checksum;

  for (uint i = 0; i < 16 * 2; i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  char *edata_ptr = (char *) krb5tgs->edata2;

  krb5tgs->edata2_len = (data_len - 32) / 2 ;

  /* skip '$' */
  for (uint i = 16 * 2 + 1; i < (krb5tgs->edata2_len * 2) + (16 * 2 + 1); i += 2)
  {
    const char p0 = data_pos[i + 0];
    const char p1 = data_pos[i + 1];
    *edata_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

 /* this is needed for hmac_md5 */
  *edata_ptr++ = 0x80;

  salt->salt_buf[0] = krb5tgs->checksum[0];
  salt->salt_buf[1] = krb5tgs->checksum[1];
  salt->salt_buf[2] = krb5tgs->checksum[2];
  salt->salt_buf[3] = krb5tgs->checksum[3];

  salt->salt_len = 32;

  digest[0] = krb5tgs->checksum[0];
  digest[1] = krb5tgs->checksum[1];
  digest[2] = krb5tgs->checksum[2];
  digest[3] = krb5tgs->checksum[3];

  return (PARSER_OK);
}

int axcrypt_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13200) || (input_len > DISPLAY_LEN_MAX_13200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_AXCRYPT, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  /* Skip '*' */
  char *wrapping_rounds_pos = input_buf + 11 + 1;

  char *salt_pos;

  char *wrapped_key_pos;

  char *data_pos;

  salt->salt_iter = atoi (wrapping_rounds_pos);

  salt_pos = strchr (wrapping_rounds_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint wrapping_rounds_len = salt_pos - wrapping_rounds_pos;

  /* Skip '*' */
  salt_pos++;

  data_pos = salt_pos;

  wrapped_key_pos = strchr (salt_pos, '*');

  if (wrapped_key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = wrapped_key_pos - salt_pos;

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  /* Skip '*' */
  wrapped_key_pos++;

  uint wrapped_key_len = input_len - 11 - 1 - wrapping_rounds_len - 1 - salt_len - 1;

  if (wrapped_key_len != 48) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &data_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &data_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &data_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &data_pos[24]);

  data_pos += 33;

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &data_pos[ 0]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &data_pos[ 8]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &data_pos[16]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &data_pos[24]);
  salt->salt_buf[8] = hex_to_u32 ((const u8 *) &data_pos[32]);
  salt->salt_buf[9] = hex_to_u32 ((const u8 *) &data_pos[40]);

  salt->salt_len = 40;

  digest[0] = salt->salt_buf[0];
  digest[1] = salt->salt_buf[1];
  digest[2] = salt->salt_buf[2];
  digest[3] = salt->salt_buf[3];

  return (PARSER_OK);
}

int keepass_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13400) || (input_len > DISPLAY_LEN_MAX_13400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KEEPASS, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  keepass_t *keepass = (keepass_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *version_pos;

  char *rounds_pos;

  char *algorithm_pos;

  char *final_random_seed_pos;
  u32   final_random_seed_len;

  char *transf_random_seed_pos;
  u32   transf_random_seed_len;

  char *enc_iv_pos;
  u32   enc_iv_len;

   /* default is no keyfile provided */
   char *keyfile_len_pos;
   u32   keyfile_len = 0;
   u32   is_keyfile_present = 0;
   char *keyfile_inline_pos;
   char *keyfile_pos;

  /* specific to version 1 */
  char *contents_len_pos;
  u32   contents_len;
  char *contents_pos;

  /* specific to version 2 */
  char *expected_bytes_pos;
  u32   expected_bytes_len;

  char *contents_hash_pos;
  u32   contents_hash_len;

  version_pos = input_buf + 8 + 1 + 1;

  keepass->version = atoi (version_pos);

  rounds_pos = strchr (version_pos, '*');

  if (rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  rounds_pos++;

  salt->salt_iter = (atoi (rounds_pos));

  algorithm_pos = strchr (rounds_pos, '*');

  if (algorithm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  algorithm_pos++;

  keepass->algorithm = atoi (algorithm_pos);

  final_random_seed_pos = strchr (algorithm_pos, '*');

  if (final_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_pos++;

  keepass->final_random_seed[0] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 0]);
  keepass->final_random_seed[1] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 8]);
  keepass->final_random_seed[2] = hex_to_u32 ((const u8 *) &final_random_seed_pos[16]);
  keepass->final_random_seed[3] = hex_to_u32 ((const u8 *) &final_random_seed_pos[24]);

  if (keepass->version == 2)
  {
    keepass->final_random_seed[4] = hex_to_u32 ((const u8 *) &final_random_seed_pos[32]);
    keepass->final_random_seed[5] = hex_to_u32 ((const u8 *) &final_random_seed_pos[40]);
    keepass->final_random_seed[6] = hex_to_u32 ((const u8 *) &final_random_seed_pos[48]);
    keepass->final_random_seed[7] = hex_to_u32 ((const u8 *) &final_random_seed_pos[56]);
  }

  transf_random_seed_pos = strchr (final_random_seed_pos, '*');

  if (transf_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_len = transf_random_seed_pos - final_random_seed_pos;

  if (keepass->version == 1 && final_random_seed_len != 32) return (PARSER_SALT_LENGTH);
  if (keepass->version == 2 && final_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  transf_random_seed_pos++;

  keepass->transf_random_seed[0] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 0]);
  keepass->transf_random_seed[1] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 8]);
  keepass->transf_random_seed[2] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[16]);
  keepass->transf_random_seed[3] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[24]);
  keepass->transf_random_seed[4] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[32]);
  keepass->transf_random_seed[5] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[40]);
  keepass->transf_random_seed[6] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[48]);
  keepass->transf_random_seed[7] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[56]);

  enc_iv_pos = strchr (transf_random_seed_pos, '*');

  if (enc_iv_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  transf_random_seed_len = enc_iv_pos - transf_random_seed_pos;

  if (transf_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  enc_iv_pos++;

  keepass->enc_iv[0] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 0]);
  keepass->enc_iv[1] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 8]);
  keepass->enc_iv[2] = hex_to_u32 ((const u8 *) &enc_iv_pos[16]);
  keepass->enc_iv[3] = hex_to_u32 ((const u8 *) &enc_iv_pos[24]);

  if (keepass->version == 1)
  {
    contents_hash_pos = strchr (enc_iv_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = contents_hash_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    /* get length of contents following */
    char *inline_flag_pos = strchr (contents_hash_pos, '*');

    if (inline_flag_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_hash_len = inline_flag_pos - contents_hash_pos;

    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);

    inline_flag_pos++;

    u32 inline_flag = atoi (inline_flag_pos);

    if (inline_flag != 1) return (PARSER_SALT_LENGTH);

    contents_len_pos = strchr (inline_flag_pos, '*');

    if (contents_len_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_len_pos++;

    contents_len = atoi (contents_len_pos);

    if (contents_len > 50000) return (PARSER_SALT_LENGTH);

    contents_pos = strchr (contents_len_pos, '*');

    if (contents_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_pos++;

    u32 i;

    keepass->contents_len = contents_len;

    contents_len = contents_len / 4;

    keyfile_inline_pos = strchr (contents_pos, '*');

    u32 real_contents_len;

    if (keyfile_inline_pos == NULL)
      real_contents_len = input_len - (contents_pos - input_buf);
    else
    {
      real_contents_len = keyfile_inline_pos - contents_pos;
      keyfile_inline_pos++;
      is_keyfile_present = 1;
    }

    if (real_contents_len != keepass->contents_len * 2) return (PARSER_SALT_LENGTH);

    for (i = 0; i < contents_len; i++)
      keepass->contents[i] = hex_to_u32 ((const u8 *) &contents_pos[i * 8]);
  }
  else if (keepass->version == 2)
  {
    expected_bytes_pos = strchr (enc_iv_pos, '*');

    if (expected_bytes_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = expected_bytes_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    expected_bytes_pos++;

    keepass->expected_bytes[0] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 0]);
    keepass->expected_bytes[1] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 8]);
    keepass->expected_bytes[2] = hex_to_u32 ((const u8 *) &expected_bytes_pos[16]);
    keepass->expected_bytes[3] = hex_to_u32 ((const u8 *) &expected_bytes_pos[24]);
    keepass->expected_bytes[4] = hex_to_u32 ((const u8 *) &expected_bytes_pos[32]);
    keepass->expected_bytes[5] = hex_to_u32 ((const u8 *) &expected_bytes_pos[40]);
    keepass->expected_bytes[6] = hex_to_u32 ((const u8 *) &expected_bytes_pos[48]);
    keepass->expected_bytes[7] = hex_to_u32 ((const u8 *) &expected_bytes_pos[56]);

    contents_hash_pos = strchr (expected_bytes_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    expected_bytes_len = contents_hash_pos - expected_bytes_pos;

    if (expected_bytes_len != 64) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    keyfile_inline_pos = strchr (contents_hash_pos, '*');

    if (keyfile_inline_pos == NULL)
      contents_hash_len = input_len - (int) (contents_hash_pos - input_buf);
    else
    {
      contents_hash_len = keyfile_inline_pos - contents_hash_pos;
      keyfile_inline_pos++;
      is_keyfile_present = 1;
    }
    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);
  }

  if (is_keyfile_present != 0)
  {
    keyfile_len_pos = strchr (keyfile_inline_pos, '*');

    keyfile_len_pos++;

    keyfile_len = atoi (keyfile_len_pos);

    keepass->keyfile_len = keyfile_len;

    if (keyfile_len != 64) return (PARSER_SALT_LENGTH);

    keyfile_pos = strchr (keyfile_len_pos, '*');

    if (keyfile_pos == NULL) return (PARSER_SALT_LENGTH);

    keyfile_pos++;

    u32 real_keyfile_len = input_len - (keyfile_pos - input_buf);

    if (real_keyfile_len != 64) return (PARSER_SALT_LENGTH);

    keepass->keyfile[0] = hex_to_u32 ((const u8 *) &keyfile_pos[ 0]);
    keepass->keyfile[1] = hex_to_u32 ((const u8 *) &keyfile_pos[ 8]);
    keepass->keyfile[2] = hex_to_u32 ((const u8 *) &keyfile_pos[16]);
    keepass->keyfile[3] = hex_to_u32 ((const u8 *) &keyfile_pos[24]);
    keepass->keyfile[4] = hex_to_u32 ((const u8 *) &keyfile_pos[32]);
    keepass->keyfile[5] = hex_to_u32 ((const u8 *) &keyfile_pos[40]);
    keepass->keyfile[6] = hex_to_u32 ((const u8 *) &keyfile_pos[48]);
    keepass->keyfile[7] = hex_to_u32 ((const u8 *) &keyfile_pos[56]);
  }

  digest[0] = keepass->enc_iv[0];
  digest[1] = keepass->enc_iv[1];
  digest[2] = keepass->enc_iv[2];
  digest[3] = keepass->enc_iv[3];

  salt->salt_buf[0] = keepass->transf_random_seed[0];
  salt->salt_buf[1] = keepass->transf_random_seed[1];
  salt->salt_buf[2] = keepass->transf_random_seed[2];
  salt->salt_buf[3] = keepass->transf_random_seed[3];
  salt->salt_buf[4] = keepass->transf_random_seed[4];
  salt->salt_buf[5] = keepass->transf_random_seed[5];
  salt->salt_buf[6] = keepass->transf_random_seed[6];
  salt->salt_buf[7] = keepass->transf_random_seed[7];

  return (PARSER_OK);
}

int cf10_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12600) || (input_len > DISPLAY_LEN_MAX_12600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  uint salt_len = input_len - 64 - 1;

  char *salt_buf = input_buf + 64 + 1;

  char *salt_buf_ptr = (char *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  /**
   * we can precompute the first sha256 transform
   */

  uint w[16] = { 0 };

  w[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  w[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  w[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  w[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  w[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  w[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  w[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  w[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  w[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  w[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  w[10] = byte_swap_32 (salt->salt_buf[10]);
  w[11] = byte_swap_32 (salt->salt_buf[11]);
  w[12] = byte_swap_32 (salt->salt_buf[12]);
  w[13] = byte_swap_32 (salt->salt_buf[13]);
  w[14] = byte_swap_32 (salt->salt_buf[14]);
  w[15] = byte_swap_32 (salt->salt_buf[15]);

  uint pc256[8] = { SHA256M_A, SHA256M_B, SHA256M_C, SHA256M_D, SHA256M_E, SHA256M_F, SHA256M_G, SHA256M_H };

  sha256_64 (w, pc256);

  salt->salt_buf_pc[0] = pc256[0];
  salt->salt_buf_pc[1] = pc256[1];
  salt->salt_buf_pc[2] = pc256[2];
  salt->salt_buf_pc[3] = pc256[3];
  salt->salt_buf_pc[4] = pc256[4];
  salt->salt_buf_pc[5] = pc256[5];
  salt->salt_buf_pc[6] = pc256[6];
  salt->salt_buf_pc[7] = pc256[7];

  digest[0] -= pc256[0];
  digest[1] -= pc256[1];
  digest[2] -= pc256[2];
  digest[3] -= pc256[3];
  digest[4] -= pc256[4];
  digest[5] -= pc256[5];
  digest[6] -= pc256[6];
  digest[7] -= pc256[7];

  return (PARSER_OK);
}

int mywallet_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12700) || (input_len > DISPLAY_LEN_MAX_12700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MYWALLET, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *data_len_pos = input_buf + 1 + 10 + 1;

  char *data_buf_pos = strchr (data_len_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = data_buf_pos - data_len_pos;

  if (data_len_len < 1) return (PARSER_SALT_LENGTH);
  if (data_len_len > 5) return (PARSER_SALT_LENGTH);

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 10 - 1 - data_len_len - 1;

  if (data_buf_len < 64) return (PARSER_HASH_LENGTH);

  if (data_buf_len % 16) return (PARSER_HASH_LENGTH);

  u32 data_len = atoi (data_len_pos);

  if ((data_len * 2) != data_buf_len) return (PARSER_HASH_LENGTH);

  /**
   * salt
   */

  char *salt_pos = data_buf_pos;

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &salt_pos[32]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &salt_pos[40]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &salt_pos[48]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &salt_pos[56]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  salt->salt_iter = 10 - 1;

  /**
   * digest buf
   */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int ms_drsr_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12800) || (input_len > DISPLAY_LEN_MAX_12800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MS_DRSR, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *salt_pos = input_buf + 11 + 1;

  char *iter_pos = strchr (salt_pos, ',');

  if (iter_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = iter_pos - salt_pos;

  if (salt_len != 20) return (PARSER_SALT_LENGTH);

  iter_pos++;

  char *hash_pos = strchr (iter_pos, ',');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_len = hash_pos - iter_pos;

  if (iter_len > 5) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 11 - 1 - salt_len - 1 - iter_len - 1;

  if (hash_len != 64) return (PARSER_HASH_LENGTH);

  /**
   * salt
   */

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]) & 0xffff0000;
  salt->salt_buf[3] = 0x00018000;

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_len = salt_len / 2;

  salt->salt_iter = atoi (iter_pos) - 1;

  /**
   * digest buf
   */

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  return (PARSER_OK);
}

int androidfde_samsung_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_12900) || (input_len > DISPLAY_LEN_MAX_12900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  char *hash_pos  = input_buf + 64;
  char *salt1_pos = input_buf + 128;
  char *salt2_pos = input_buf;

  /**
   * salt
   */

  salt->salt_buf[ 0] = hex_to_u32 ((const u8 *) &salt1_pos[ 0]);
  salt->salt_buf[ 1] = hex_to_u32 ((const u8 *) &salt1_pos[ 8]);
  salt->salt_buf[ 2] = hex_to_u32 ((const u8 *) &salt1_pos[16]);
  salt->salt_buf[ 3] = hex_to_u32 ((const u8 *) &salt1_pos[24]);

  salt->salt_buf[ 4] = hex_to_u32 ((const u8 *) &salt2_pos[ 0]);
  salt->salt_buf[ 5] = hex_to_u32 ((const u8 *) &salt2_pos[ 8]);
  salt->salt_buf[ 6] = hex_to_u32 ((const u8 *) &salt2_pos[16]);
  salt->salt_buf[ 7] = hex_to_u32 ((const u8 *) &salt2_pos[24]);

  salt->salt_buf[ 8] = hex_to_u32 ((const u8 *) &salt2_pos[32]);
  salt->salt_buf[ 9] = hex_to_u32 ((const u8 *) &salt2_pos[40]);
  salt->salt_buf[10] = hex_to_u32 ((const u8 *) &salt2_pos[48]);
  salt->salt_buf[11] = hex_to_u32 ((const u8 *) &salt2_pos[56]);

  salt->salt_len = 48;

  salt->salt_iter = ROUNDS_ANDROIDFDE_SAMSUNG - 1;

  /**
   * digest buf
   */

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  return (PARSER_OK);
}

int zip2_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13600) || (input_len > DISPLAY_LEN_MAX_13600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ZIP2_START, input_buf                , 6)) return (PARSER_SIGNATURE_UNMATCHED);
  if (memcmp (SIGNATURE_ZIP2_STOP , input_buf + input_len - 7, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  zip2_t *zip2 = (zip2_t *) hash_buf->esalt;

  /**
   * parse line
   */

  char *param0_pos = input_buf + 6 + 1;

  char *param1_pos = strchr (param0_pos, '*');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  char *param2_pos = strchr (param1_pos, '*');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  char *param3_pos = strchr (param2_pos, '*');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  char *param4_pos = strchr (param3_pos, '*');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  char *param5_pos = strchr (param4_pos, '*');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  char *param6_pos = strchr (param5_pos, '*');

  if (param6_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param5_len = param6_pos - param5_pos;

  param6_pos++;

  char *param7_pos = strchr (param6_pos, '*');

  if (param7_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param6_len = param7_pos - param6_pos;

  param7_pos++;

  char *param8_pos = strchr (param7_pos, '*');

  if (param8_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param7_len = param8_pos - param7_pos;

  param8_pos++;

  const uint type  = atoi (param0_pos);
  const uint mode  = atoi (param1_pos);
  const uint magic = atoi (param2_pos);

  char *salt_buf = param3_pos;

  uint verify_bytes; sscanf (param4_pos, "%4x*", &verify_bytes);

  const uint compress_length = atoi (param5_pos);

  char *data_buf = param6_pos;
  char *auth     = param7_pos;

  /**
   * verify some data
   */

  if (param0_len != 1) return (PARSER_SALT_VALUE);

  if (param1_len != 1) return (PARSER_SALT_VALUE);

  if (param2_len != 1) return (PARSER_SALT_VALUE);

  if ((param3_len != 16) && (param3_len != 24) && (param3_len != 32)) return (PARSER_SALT_VALUE);

  if (param4_len >= 5) return (PARSER_SALT_VALUE);

  if (param5_len >= 5) return (PARSER_SALT_VALUE);

  if (param6_len >= 8192) return (PARSER_SALT_VALUE);

  if (param6_len & 1) return (PARSER_SALT_VALUE);

  if (param7_len != 20) return (PARSER_SALT_VALUE);

  if (type != 0) return (PARSER_SALT_VALUE);

  if ((mode != 1) && (mode != 2) && (mode != 3)) return (PARSER_SALT_VALUE);

  if (magic != 0) return (PARSER_SALT_VALUE);

  if (verify_bytes >= 0x10000) return (PARSER_SALT_VALUE);

  /**
   * store data
   */

  zip2->type  = type;
  zip2->mode  = mode;
  zip2->magic = magic;

  if (mode == 1)
  {
    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = 0;
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 8;
  }
  else if (mode == 2)
  {
    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 12;
  }
  else if (mode == 3)
  {
    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
    zip2->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

    zip2->salt_len = 16;
  }

  zip2->salt_buf[0] = byte_swap_32 (zip2->salt_buf[0]);
  zip2->salt_buf[1] = byte_swap_32 (zip2->salt_buf[1]);
  zip2->salt_buf[2] = byte_swap_32 (zip2->salt_buf[2]);
  zip2->salt_buf[3] = byte_swap_32 (zip2->salt_buf[3]);

  zip2->verify_bytes = verify_bytes;

  zip2->compress_length = compress_length;

  char *data_buf_ptr = (char *) zip2->data_buf;

  for (uint i = 0; i < param6_len; i += 2)
  {
    const char p0 = data_buf[i + 0];
    const char p1 = data_buf[i + 1];

    *data_buf_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;

    zip2->data_len++;
  }

  *data_buf_ptr = 0x80;

  char *auth_ptr = (char *) zip2->auth_buf;

  for (uint i = 0; i < param7_len; i += 2)
  {
    const char p0 = auth[i + 0];
    const char p1 = auth[i + 1];

    *auth_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;

    zip2->auth_len++;
  }

  /**
   * salt buf (fake)
   */

  salt->salt_buf[0] = zip2->salt_buf[0];
  salt->salt_buf[1] = zip2->salt_buf[1];
  salt->salt_buf[2] = zip2->salt_buf[2];
  salt->salt_buf[3] = zip2->salt_buf[3];
  salt->salt_buf[4] = zip2->data_buf[0];
  salt->salt_buf[5] = zip2->data_buf[1];
  salt->salt_buf[6] = zip2->data_buf[2];
  salt->salt_buf[7] = zip2->data_buf[3];

  salt->salt_len = 32;

  salt->salt_iter = ROUNDS_ZIP2 - 1;

  /**
   * digest buf (fake)
   */

  digest[0] = zip2->auth_buf[0];
  digest[1] = zip2->auth_buf[1];
  digest[2] = zip2->auth_buf[2];
  digest[3] = zip2->auth_buf[3];

  return (PARSER_OK);
}

int win8phone_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf)
{
  if ((input_len < DISPLAY_LEN_MIN_13800) || (input_len > DISPLAY_LEN_MAX_13800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  win8phone_t *esalt = hash_buf->esalt;

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  if (input_buf[64] != data.separator) return (PARSER_SEPARATOR_UNMATCHED);

  char *salt_buf_ptr = input_buf + 64 + 1;

  u32 *salt_buf = esalt->salt_buf;

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    salt_buf[i] = hex_to_u32 ((const u8 *) &salt_buf_ptr[j]);
  }

  salt->salt_buf[0] = salt_buf[0];
  salt->salt_buf[1] = salt_buf[1];
  salt->salt_buf[2] = salt_buf[2];
  salt->salt_buf[3] = salt_buf[3];
  salt->salt_buf[4] = salt_buf[4];
  salt->salt_buf[5] = salt_buf[5];
  salt->salt_buf[6] = salt_buf[6];
  salt->salt_buf[7] = salt_buf[7];

  salt->salt_len = 64;

  return (PARSER_OK);
}

/**
 * parallel running threads
 */

#ifdef WIN

BOOL WINAPI sigHandler_default (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      /*
       * special case see: https://stackoverflow.com/questions/3640633/c-setconsolectrlhandler-routine-issue/5610042#5610042
       * if the user interacts w/ the user-interface (GUI/cmd), we need to do the finalization job within this signal handler
       * function otherwise it is too late (e.g. after returning from this function)
       */

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

BOOL WINAPI sigHandler_benchmark (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

void hc_signal (BOOL WINAPI (callback) (DWORD))
{
  if (callback == NULL)
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, FALSE);
  }
  else
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, TRUE);
  }
}

#else

void sigHandler_default (int sig)
{
  myabort ();

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit ();

  signal (sig, NULL);
}

void hc_signal (void (callback) (int))
{
  if (callback == NULL) callback = SIG_DFL;

  signal (SIGINT,  callback);
  signal (SIGTERM, callback);
  signal (SIGABRT, callback);
}

#endif

void status_display ();

void *thread_keypress (void *p)
{
  uint quiet = data.quiet;

  tty_break();

  while (data.shutdown_outer == 0)
  {
    int ch = tty_getchar();

    if (ch == -1) break;

    if (ch ==  0) continue;

    //https://github.com/hashcat/hashcat/issues/302
    //#ifdef _POSIX
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_lock (mux_display);

    log_info ("");

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        log_info ("");

        status_display ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'b':

        log_info ("");

        bypass ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'p':

        log_info ("");

        SuspendThreads ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'r':

        log_info ("");

        ResumeThreads ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'c':

        log_info ("");

        stop_at_checkpoint ();

        log_info ("");

        if (quiet == 0) fprintf (stdout, "%s", PROMPT);
        if (quiet == 0) fflush (stdout);

        break;

      case 'q':

        log_info ("");

        myabort ();

        break;
    }

    //https://github.com/hashcat/hashcat/issues/302
    //#ifdef _POSIX
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_unlock (mux_display);
  }

  tty_fix();

  return (p);
}

/**
 * rules common
 */

bool class_num (const u8 c)
{
  return ((c >= '0') && (c <= '9'));
}

bool class_lower (const u8 c)
{
  return ((c >= 'a') && (c <= 'z'));
}

bool class_upper (const u8 c)
{
  return ((c >= 'A') && (c <= 'Z'));
}

bool class_alpha (const u8 c)
{
  return (class_lower (c) || class_upper (c));
}

int conv_ctoi (const u8 c)
{
  if (class_num (c))
  {
    return c - '0';
  }
  else if (class_upper (c))
  {
    return c - 'A' + 10;
  }

  return -1;
}

int conv_itoc (const u8 c)
{
  if (c < 10)
  {
    return c + '0';
  }
  else if (c < 37)
  {
    return c + 'A' - 10;
  }

  return -1;
}

/**
 * device rules
 */

#define INCR_POS           if (++rule_pos == rule_len) return (-1)
#define SET_NAME(rule,val) (rule)->cmds[rule_cnt]  = ((val) & 0xff) <<  0
#define SET_P0(rule,val)   INCR_POS; (rule)->cmds[rule_cnt] |= ((val) & 0xff) <<  8
#define SET_P1(rule,val)   INCR_POS; (rule)->cmds[rule_cnt] |= ((val) & 0xff) << 16
#define MAX_KERNEL_RULES   255
#define GET_NAME(rule)     rule_cmd = (((rule)->cmds[rule_cnt] >>  0) & 0xff)
#define GET_P0(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1(rule)       INCR_POS; rule_buf[rule_pos] = (((rule)->cmds[rule_cnt] >> 16) & 0xff)

#define SET_P0_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) <<  8
#define SET_P1_CONV(rule,val)  INCR_POS; (rule)->cmds[rule_cnt] |= ((conv_ctoi (val)) & 0xff) << 16
#define GET_P0_CONV(rule)      INCR_POS; rule_buf[rule_pos] = conv_itoc (((rule)->cmds[rule_cnt] >>  8) & 0xff)
#define GET_P1_CONV(rule)      INCR_POS; rule_buf[rule_pos] = conv_itoc (((rule)->cmds[rule_cnt] >> 16) & 0xff)

int cpu_rule_to_kernel_rule (char *rule_buf, uint rule_len, kernel_rule_t *rule)
{
  uint rule_pos;
  uint rule_cnt;

  for (rule_pos = 0, rule_cnt = 0; rule_pos < rule_len && rule_cnt < MAX_KERNEL_RULES; rule_pos++, rule_cnt++)
  {
    switch (rule_buf[rule_pos])
    {
      case ' ':
        rule_cnt--;
        break;

      case RULE_OP_MANGLE_NOOP:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_LREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_UREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TREST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REVERSE:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REFLECT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_APPEND:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_PREPEND:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_OMIT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_INSERT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1      (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1      (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE:
        SET_NAME (rule, rule_buf[rule_pos]);
        SET_P0   (rule, rule_buf[rule_pos]);
        SET_P1   (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        return (-1);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        return (-1);
        break;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        SET_P1_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        SET_NAME    (rule, rule_buf[rule_pos]);
        SET_P0_CONV (rule, rule_buf[rule_pos]);
        break;

      case RULE_OP_MANGLE_TITLE:
        SET_NAME (rule, rule_buf[rule_pos]);
        break;

      default:
        return (-1);
        break;
    }
  }

  if (rule_pos < rule_len) return (-1);

  return (0);
}

int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule)
{
  uint rule_cnt;
  uint rule_pos;
  uint rule_len = HCBUFSIZ - 1; // maximum possible len

  char rule_cmd;

  for (rule_cnt = 0, rule_pos = 0; rule_pos < rule_len && rule_cnt < MAX_KERNEL_RULES; rule_pos++, rule_cnt++)
  {
    GET_NAME (rule);

    if (rule_cnt > 0) rule_buf[rule_pos++] = ' ';

    switch (rule_cmd)
    {
      case RULE_OP_MANGLE_NOOP:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_LREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_UREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_TREST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REVERSE:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REFLECT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_APPEND:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case RULE_OP_MANGLE_PREPEND:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_OMIT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_INSERT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1      (rule);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1      (rule);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0 (rule);
        GET_P1 (rule);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        return (-1);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        return (-1);
        break;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        GET_P1_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        rule_buf[rule_pos] = rule_cmd;
        GET_P0_CONV (rule);
        break;

      case RULE_OP_MANGLE_TITLE:
        rule_buf[rule_pos] = rule_cmd;
        break;

      case 0:
        return rule_pos - 1;
        break;

      default:
        return (-1);
        break;
    }
  }

  if (rule_cnt > 0)
  {
    return rule_pos;
  }

  return (-1);
}

/**
 * CPU rules : this is from hashcat sources, cpu based rules
 */

#define NEXT_RULEPOS(rp)      if (++(rp) == rule_len) return (RULE_RC_SYNTAX_ERROR)
#define NEXT_RPTOI(r,rp,up)   if (((up) = conv_ctoi ((r)[(rp)])) == -1) return (RULE_RC_SYNTAX_ERROR)

#define MANGLE_TOGGLE_AT(a,p) if (class_alpha ((a)[(p)])) (a)[(p)] ^= 0x20
#define MANGLE_LOWER_AT(a,p)  if (class_upper ((a)[(p)])) (a)[(p)] ^= 0x20
#define MANGLE_UPPER_AT(a,p)  if (class_lower ((a)[(p)])) (a)[(p)] ^= 0x20

/* #define MANGLE_SWITCH(a,l,r)  { char c = (l); arr[(r)] = arr[(l)]; arr[(l)] = c; } */
/* #define MANGLE_SWITCH(a,l,r)  { char c = (l); (a)[(r)] = (a)[(l)]; (a)[(l)] = c; } */
#define MANGLE_SWITCH(a,l,r)  { char c = (a)[(r)]; (a)[(r)] = (a)[(l)]; (a)[(l)] = c; }

int mangle_lrest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_LOWER_AT (arr, pos);

  return (arr_len);
}

int mangle_urest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_UPPER_AT (arr, pos);

  return (arr_len);
}

int mangle_trest (char arr[BLOCK_SIZE], int arr_len)
{
  int pos;

  for (pos = 0; pos < arr_len; pos++) MANGLE_TOGGLE_AT (arr, pos);

  return (arr_len);
}

int mangle_reverse (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0; l < arr_len; l++)
  {
    r = arr_len - 1 - l;

    if (l >= r) break;

    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_double (char arr[BLOCK_SIZE], int arr_len)
{
  if ((arr_len * 2) >= BLOCK_SIZE) return (arr_len);

  memcpy (&arr[arr_len], arr, (size_t) arr_len);

  return (arr_len * 2);
}

int mangle_double_times (char arr[BLOCK_SIZE], int arr_len, int times)
{
  if (((arr_len * times) + arr_len) >= BLOCK_SIZE) return (arr_len);

  int orig_len = arr_len;

  int i;

  for (i = 0; i < times; i++)
  {
    memcpy (&arr[arr_len], arr, orig_len);

    arr_len += orig_len;
  }

  return (arr_len);
}

int mangle_reflect (char arr[BLOCK_SIZE], int arr_len)
{
  if ((arr_len * 2) >= BLOCK_SIZE) return (arr_len);

  mangle_double (arr, arr_len);

  mangle_reverse (arr + arr_len, arr_len);

  return (arr_len * 2);
}

int mangle_rotate_left (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0, r = arr_len - 1; r > 0; r--)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_rotate_right (char arr[BLOCK_SIZE], int arr_len)
{
  int l;
  int r;

  for (l = 0, r = arr_len - 1; l < r; l++)
  {
    MANGLE_SWITCH (arr, l, r);
  }

  return (arr_len);
}

int mangle_append (char arr[BLOCK_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  arr[arr_len] = c;

  return (arr_len + 1);
}

int mangle_prepend (char arr[BLOCK_SIZE], int arr_len, char c)
{
  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[0] = c;

  return (arr_len + 1);
}

int mangle_delete_at (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = upos; arr_pos < arr_len - 1; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + 1];
  }

  return (arr_len - 1);
}

int mangle_extract (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return (arr_len);

  if ((upos + ulen) > arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = 0; arr_pos < ulen; arr_pos++)
  {
    arr[arr_pos] = arr[upos + arr_pos];
  }

  return (ulen);
}

int mangle_omit (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if (upos >= arr_len) return (arr_len);

  if ((upos + ulen) >= arr_len) return (arr_len);

  int arr_pos;

  for (arr_pos = upos; arr_pos < arr_len - ulen; arr_pos++)
  {
    arr[arr_pos] = arr[arr_pos + ulen];
  }

  return (arr_len - ulen);
}

int mangle_insert (char arr[BLOCK_SIZE], int arr_len, int upos, char c)
{
  if (upos >= arr_len) return (arr_len);

  if ((arr_len + 1) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > upos - 1; arr_pos--)
  {
    arr[arr_pos + 1] = arr[arr_pos];
  }

  arr[upos] = c;

  return (arr_len + 1);
}

int mangle_insert_multi (char arr[BLOCK_SIZE], int arr_len, int arr_pos, char arr2[BLOCK_SIZE], int arr2_len, int arr2_pos, int arr2_cpy)
{
  if ((arr_len + arr2_cpy) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);

  if (arr_pos > arr_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_pos > arr2_len) return (RULE_RC_REJECT_ERROR);

  if ((arr2_pos + arr2_cpy) > arr2_len) return (RULE_RC_REJECT_ERROR);

  if (arr2_cpy < 1) return (RULE_RC_SYNTAX_ERROR);

  memcpy (arr2, arr2 + arr2_pos, arr2_len - arr2_pos);

  memcpy (arr2 + arr2_cpy, arr + arr_pos, arr_len - arr_pos);

  memcpy (arr + arr_pos, arr2, arr_len - arr_pos + arr2_cpy);

  return (arr_len + arr2_cpy);
}

int mangle_overstrike (char arr[BLOCK_SIZE], int arr_len, int upos, char c)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] = c;

  return (arr_len);
}

int mangle_truncate_at (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  memset (arr + upos, 0, arr_len - upos);

  return (upos);
}

int mangle_replace (char arr[BLOCK_SIZE], int arr_len, char oldc, char newc)
{
  int arr_pos;

  for (arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] != oldc) continue;

    arr[arr_pos] = newc;
  }

  return (arr_len);
}

int mangle_purgechar (char arr[BLOCK_SIZE], int arr_len, char c)
{
  int arr_pos;

  int ret_len;

  for (ret_len = 0, arr_pos = 0; arr_pos < arr_len; arr_pos++)
  {
    if (arr[arr_pos] == c) continue;

    arr[ret_len] = arr[arr_pos];

    ret_len++;
  }

  return (ret_len);
}

int mangle_dupeblock_prepend (char arr[BLOCK_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return (arr_len);

  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  char cs[100] = { 0 };

  memcpy (cs, arr, ulen);

  int i;

  for (i = 0; i < ulen; i++)
  {
    char c = cs[i];

    arr_len = mangle_insert (arr, arr_len, i, c);
  }

  return (arr_len);
}

int mangle_dupeblock_append (char arr[BLOCK_SIZE], int arr_len, int ulen)
{
  if (ulen > arr_len) return (arr_len);

  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  int upos = arr_len - ulen;

  int i;

  for (i = 0; i < ulen; i++)
  {
    char c = arr[upos + i];

    arr_len = mangle_append (arr, arr_len, c);
  }

  return (arr_len);
}

int mangle_dupechar_at (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen)
{
  if ( arr_len         ==  0) return (arr_len);
  if ((arr_len + ulen) >= BLOCK_SIZE) return (arr_len);

  char c = arr[upos];

  int i;

  for (i = 0; i < ulen; i++)
  {
    arr_len = mangle_insert (arr, arr_len, upos, c);
  }

  return (arr_len);
}

int mangle_dupechar (char arr[BLOCK_SIZE], int arr_len)
{
  if ( arr_len            ==  0) return (arr_len);
  if ((arr_len + arr_len) >= BLOCK_SIZE) return (arr_len);

  int arr_pos;

  for (arr_pos = arr_len - 1; arr_pos > -1; arr_pos--)
  {
    int new_pos = arr_pos * 2;

    arr[new_pos] = arr[arr_pos];

    arr[new_pos + 1] = arr[arr_pos];
  }

  return (arr_len * 2);
}

int mangle_switch_at_check (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2)
{
  if (upos  >= arr_len) return (arr_len);
  if (upos2 >= arr_len) return (arr_len);

  MANGLE_SWITCH (arr, upos, upos2);

  return (arr_len);
}

int mangle_switch_at (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2)
{
  MANGLE_SWITCH (arr, upos, upos2);

  return (arr_len);
}

int mangle_chr_shiftl (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] <<= 1;

  return (arr_len);
}

int mangle_chr_shiftr (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] >>= 1;

  return (arr_len);
}

int mangle_chr_incr (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] += 1;

  return (arr_len);
}

int mangle_chr_decr (char arr[BLOCK_SIZE], int arr_len, int upos)
{
  if (upos >= arr_len) return (arr_len);

  arr[upos] -= 1;

  return (arr_len);
}

int mangle_title (char arr[BLOCK_SIZE], int arr_len)
{
  int upper_next = 1;

  int pos;

  for (pos = 0; pos < arr_len; pos++)
  {
    if (arr[pos] == ' ')
    {
      upper_next = 1;

      continue;
    }

    if (upper_next)
    {
      upper_next = 0;

      MANGLE_UPPER_AT (arr, pos);
    }
    else
    {
      MANGLE_LOWER_AT (arr, pos);
    }
  }

  return (arr_len);
}

int generate_random_rule (char rule_buf[RP_RULE_BUFSIZ], u32 rp_gen_func_min, u32 rp_gen_func_max)
{
  u32 rp_gen_num = get_random_num (rp_gen_func_min, rp_gen_func_max);

  u32 j;

  u32 rule_pos = 0;

  for (j = 0; j < rp_gen_num; j++)
  {
    u32 r  = 0;
    u32 p1 = 0;
    u32 p2 = 0;
    u32 p3 = 0;

    switch ((char) get_random_num (0, 9))
    {
      case 0:
        r = get_random_num (0, sizeof (grp_op_nop));
        rule_buf[rule_pos++] = grp_op_nop[r];
        break;

      case 1:
        r = get_random_num (0, sizeof (grp_op_pos_p0));
        rule_buf[rule_pos++] = grp_op_pos_p0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 2:
        r = get_random_num (0, sizeof (grp_op_pos_p1));
        rule_buf[rule_pos++] = grp_op_pos_p1[r];
        p1 = get_random_num (1, 6);
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 3:
        r = get_random_num (0, sizeof (grp_op_chr));
        rule_buf[rule_pos++] = grp_op_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        break;

      case 4:
        r = get_random_num (0, sizeof (grp_op_chr_chr));
        rule_buf[rule_pos++] = grp_op_chr_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        p2 = get_random_num (0x20, 0x7e);
        while (p1 == p2)
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 5:
        r = get_random_num (0, sizeof (grp_op_pos_chr));
        rule_buf[rule_pos++] = grp_op_pos_chr[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 6:
        r = get_random_num (0, sizeof (grp_op_pos_pos0));
        rule_buf[rule_pos++] = grp_op_pos_pos0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;

      case 7:
        r = get_random_num (0, sizeof (grp_op_pos_pos1));
        rule_buf[rule_pos++] = grp_op_pos_pos1[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;

      case 8:
        r = get_random_num (0, sizeof (grp_op_pos1_pos2_pos3));
        rule_buf[rule_pos++] = grp_op_pos1_pos2_pos3[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p3 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p3];
        break;
    }
  }

  return (rule_pos);
}

int _old_apply_rule (char *rule, int rule_len, char in[BLOCK_SIZE], int in_len, char out[BLOCK_SIZE])
{
  char mem[BLOCK_SIZE] = { 0 };

  if (in == NULL) return (RULE_RC_REJECT_ERROR);

  if (out == NULL) return (RULE_RC_REJECT_ERROR);

  if (in_len < 1 || in_len > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);

  if (rule_len < 1) return (RULE_RC_REJECT_ERROR);

  int out_len = in_len;
  int mem_len = in_len;

  memcpy (out, in, out_len);

  int rule_pos;

  for (rule_pos = 0; rule_pos < rule_len; rule_pos++)
  {
    int upos, upos2;
    int ulen;

    switch (rule[rule_pos])
    {
      case ' ':
        break;

      case RULE_OP_MANGLE_NOOP:
        break;

      case RULE_OP_MANGLE_LREST:
        out_len = mangle_lrest (out, out_len);
        break;

      case RULE_OP_MANGLE_UREST:
        out_len = mangle_urest (out, out_len);
        break;

      case RULE_OP_MANGLE_LREST_UFIRST:
        out_len = mangle_lrest (out, out_len);
        if (out_len) MANGLE_UPPER_AT (out, 0);
        break;

      case RULE_OP_MANGLE_UREST_LFIRST:
        out_len = mangle_urest (out, out_len);
        if (out_len) MANGLE_LOWER_AT (out, 0);
        break;

      case RULE_OP_MANGLE_TREST:
        out_len = mangle_trest (out, out_len);
        break;

      case RULE_OP_MANGLE_TOGGLE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (upos < out_len) MANGLE_TOGGLE_AT (out, upos);
        break;

      case RULE_OP_MANGLE_REVERSE:
        out_len = mangle_reverse (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD:
        out_len = mangle_double (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEWORD_TIMES:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_double_times (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_REFLECT:
        out_len = mangle_reflect (out, out_len);
        break;

      case RULE_OP_MANGLE_ROTATE_LEFT:
        mangle_rotate_left (out, out_len);
        break;

      case RULE_OP_MANGLE_ROTATE_RIGHT:
        mangle_rotate_right (out, out_len);
        break;

      case RULE_OP_MANGLE_APPEND:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_append (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_PREPEND:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_prepend (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_DELETE_FIRST:
        out_len = mangle_delete_at (out, out_len, 0);
        break;

      case RULE_OP_MANGLE_DELETE_LAST:
        out_len = mangle_delete_at (out, out_len, (out_len) ? out_len - 1 : 0);
        break;

      case RULE_OP_MANGLE_DELETE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        out_len = mangle_delete_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_EXTRACT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_extract (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_OMIT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_omit (out, out_len, upos, ulen);
        break;

      case RULE_OP_MANGLE_INSERT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_insert (out, out_len, upos, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_OVERSTRIKE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_overstrike (out, out_len, upos, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_TRUNCATE_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        out_len = mangle_truncate_at (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE:
        NEXT_RULEPOS (rule_pos);
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_replace (out, out_len, rule[rule_pos - 1], rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_PURGECHAR:
        NEXT_RULEPOS (rule_pos);
        out_len = mangle_purgechar (out, out_len, rule[rule_pos]);
        break;

      case RULE_OP_MANGLE_TOGGLECASE_REC:
        /* todo */
        break;

      case RULE_OP_MANGLE_DUPECHAR_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, 0, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupechar_at (out, out_len, out_len - 1, ulen);
        break;

      case RULE_OP_MANGLE_DUPECHAR_ALL:
        out_len = mangle_dupechar (out, out_len);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupeblock_prepend (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_DUPEBLOCK_LAST:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        out_len = mangle_dupeblock_append (out, out_len, ulen);
        break;

      case RULE_OP_MANGLE_SWITCH_FIRST:
        if (out_len >= 2) mangle_switch_at (out, out_len, 0, 1);
        break;

      case RULE_OP_MANGLE_SWITCH_LAST:
        if (out_len >= 2) mangle_switch_at (out, out_len, out_len - 1, out_len - 2);
        break;

      case RULE_OP_MANGLE_SWITCH_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos2);
        out_len = mangle_switch_at_check (out, out_len, upos, upos2);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTL:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_shiftl (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_SHIFTR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_shiftr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_INCR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_incr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_CHR_DECR:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        mangle_chr_decr (out, out_len, upos);
        break;

      case RULE_OP_MANGLE_REPLACE_NP1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos >= 0) && ((upos + 1) < out_len)) mangle_overstrike (out, out_len, upos, out[upos + 1]);
        break;

      case RULE_OP_MANGLE_REPLACE_NM1:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos >= 1) && ((upos + 0) < out_len)) mangle_overstrike (out, out_len, upos, out[upos - 1]);
        break;

      case RULE_OP_MANGLE_TITLE:
        out_len = mangle_title (out, out_len);
        break;

      case RULE_OP_MANGLE_EXTRACT_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, ulen);
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos2);
        if ((out_len = mangle_insert_multi (out, out_len, upos2, mem, mem_len, upos, ulen)) < 1) return (out_len);
        break;

      case RULE_OP_MANGLE_APPEND_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        if ((out_len + mem_len) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);
        memcpy (out + out_len, mem, mem_len);
        out_len += mem_len;
        break;

      case RULE_OP_MANGLE_PREPEND_MEMORY:
        if (mem_len < 1) return (RULE_RC_REJECT_ERROR);
        if ((mem_len + out_len) > BLOCK_SIZE) return (RULE_RC_REJECT_ERROR);
        memcpy (mem + mem_len, out, out_len);
        out_len += mem_len;
        memcpy (out, mem, out_len);
        break;

      case RULE_OP_MEMORIZE_WORD:
        memcpy (mem, out, out_len);
        mem_len = out_len;
        break;

      case RULE_OP_REJECT_LESS:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (out_len > upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_GREATER:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if (out_len < upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (strchr (out, rule[rule_pos]) != NULL) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_NOT_CONTAIN:
        NEXT_RULEPOS (rule_pos);
        if (strchr (out, rule[rule_pos]) == NULL) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_FIRST:
        NEXT_RULEPOS (rule_pos);
        if (out[0] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_LAST:
        NEXT_RULEPOS (rule_pos);
        if (out[out_len - 1] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_EQUAL_AT:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos + 1) > out_len) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        if (out[upos] != rule[rule_pos]) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_CONTAINS:
        NEXT_RULEPOS (rule_pos);
        NEXT_RPTOI (rule, rule_pos, upos);
        if ((upos + 1) > out_len) return (RULE_RC_REJECT_ERROR);
        NEXT_RULEPOS (rule_pos);
        int c; int cnt; for (c = 0, cnt = 0; c < out_len; c++) if (out[c] == rule[rule_pos]) cnt++;
        if (cnt < upos) return (RULE_RC_REJECT_ERROR);
        break;

      case RULE_OP_REJECT_MEMORY:
        if ((out_len == mem_len) && (memcmp (out, mem, out_len) == 0)) return (RULE_RC_REJECT_ERROR);
        break;

      default:
        return (RULE_RC_SYNTAX_ERROR);
        break;
    }
  }

  memset (out + out_len, 0, BLOCK_SIZE - out_len);

  return (out_len);
}
