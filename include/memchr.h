/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MEMCHR_H
#define HC_MEMCHR_H

#include <string.h>

typedef size_t (*hc_memchr_t) (const u8 *ptr, int ch, size_t max_len);

HC_PLUGIN_API size_t hc_memchr_generic      (const u8 *ptr, int ch, size_t max_len);
HC_PLUGIN_API size_t hc_memchr_avx2         (const u8 *ptr, int ch, size_t max_len);
HC_PLUGIN_API size_t hc_memchr_avx512       (const u8 *ptr, int ch, size_t max_len);

HC_PLUGIN_API hc_memchr_t hc_memchr_get     (void);

// Where the next line ends inside a buffer, and how long it is once the line ending is off.
//
// Everything that reads lines out of a block wants exactly this and used to have its own copy: the
// wordlist feed walking an mmap, the stdin feed walking the blocks it read, and counting the lines of a
// file. One copy means one place decides how a line ends, and it is the place the memchr choice already
// lives.
//
// The return value is where the '\n' is, or max_len when there is none, which is what hc_memchr says
// and is what lets the caller tell a whole line from the unfinished tail of a block. The length written
// out is the line without its ending, so a file written on Windows and read anywhere else does not hand
// out candidates with a carriage return on them.
//
// A line is not copied and not terminated. Callers hold buffers they do not own, an mmap or a block
// another thread filled, and a reader that wrote into them could not be shared by all three.
//
// It lives in the header rather than in memchr.c because a feed is a shared object and a call into the
// hashcat library cannot be inlined away. Measured on the stdin feed, that call cost 13 percent: at a
// hundred million candidates a second there is no room for one that does this little.

static inline size_t hc_line_next (const u8 *buf, const size_t max_len, size_t *out_len)
{
  hc_memchr_t hc_memchr = hc_memchr_get ();

  const size_t step = hc_memchr (buf, '\n', max_len);

  size_t line_len = step;

  while ((line_len > 0) && (buf[line_len - 1] == '\r')) line_len--;

  *out_len = line_len;

  return step;
}

#endif // HC_MEMCHR_H
