/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "shared.h"
#include "parser.h"
#include "convert.h"
#include "keyboard_layout.h"

// One side of a mapping line. $HEX[..] is how a token that would otherwise be read as a comment, or
// that carries a tab, is written down. Returns the length, or -1 when it does not fit.

static int mapping_token (const u8 *buf, const int len, u8 *out, const int out_max)
{
  if (is_hexify (buf, (size_t) len) == true)
  {
    const int want = (len - 6) / 2;

    if (want > out_max) return -1;

    for (int i = 0; i < want; i++) out[i] = hex_to_u8 (&buf[5 + (i * 2)]);

    return want;
  }

  if (len > out_max) return -1;

  for (int i = 0; i < len; i++) out[i] = buf[i];

  return len;
}

static int sort_by_src_len (const void *p1, const void *p2)
{
  const keyboard_layout_mapping_t *k1 = (const keyboard_layout_mapping_t *) p1;
  const keyboard_layout_mapping_t *k2 = (const keyboard_layout_mapping_t *) p2;

  if (k1->src_len < k2->src_len) return 1;
  if (k1->src_len > k2->src_len) return -1;

  return 0;
}

bool initialize_keyboard_layout_mapping (const char *filename, keyboard_layout_mapping_t *keyboard_layout_mapping, int *keyboard_layout_mapping_cnt)
{
  HCFILE fp;

  if (hc_fopen (&fp, filename, "r") == false) return false;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  int maps_cnt = 0;

  while (!hc_feof (&fp))
  {
    const size_t line_len = fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

    if (line_len == 0) continue;

    // A mapping file is a table file: blank lines and comments are skipped, and a line that does not
    // hold exactly one tab is not a mapping and is skipped too. A file that turns out to hold no
    // mappings at all is refused below, which is what catches one whose tabs have been eaten by an
    // editor rather than letting it convert nothing and say nothing.
    //
    // The tabs are counted before the comment is considered, because '#' is a key on a German
    // keyboard and layouts/de.hckmap mapped it. Reading that line as a comment would drop a real
    // mapping out of a file somebody kept, and drop it silently.

    int tabs = 0;
    int at   = 0;

    for (size_t i = 0; i < line_len; i++)
    {
      if (line_buf[i] != 0x09) continue;

      tabs++;
      at = (int) i;
    }

    if (tabs != 1)
    {
      // Only now, where it cannot be a mapping anyway

      continue;
    }

    if ((line_buf[0] == '#') && (at != 0)) continue;

    u8 src[4];
    u8 dst[4];

    const int src_len = mapping_token ((const u8 *) line_buf, at, src, 4);
    const int dst_len = mapping_token ((const u8 *) &line_buf[at + 1], (int) line_len - at - 1, dst, 4);

    if (src_len < 1) continue;
    if (dst_len < 0) continue;

    // The array every caller passes holds 256 entries, and the check for a full one came after the
    // writes, so a mapping file with 257 lines filled element 256 before giving up.

    if (maps_cnt == 256)
    {
      hc_fclose (&fp);

      hcfree (line_buf);

      return false;
    }

    keyboard_layout_mapping[maps_cnt].src_char = 0;
    keyboard_layout_mapping[maps_cnt].dst_char = 0;

    memcpy (&keyboard_layout_mapping[maps_cnt].src_char, src, src_len);
    memcpy (&keyboard_layout_mapping[maps_cnt].dst_char, dst, dst_len);

    keyboard_layout_mapping[maps_cnt].src_len = src_len;
    keyboard_layout_mapping[maps_cnt].dst_len = dst_len;

    maps_cnt++;
  }

  *keyboard_layout_mapping_cnt = maps_cnt;

  hc_fclose (&fp);

  hcfree (line_buf);

  // Nothing was read. The file exists and every line of it was passed over, which means it is not in
  // this format, and converting nothing while saying nothing is the worst thing to do about it.

  if (maps_cnt == 0) return false;

  // we need to sort this by length to ensure the largest blocks come first in mapping

  qsort (keyboard_layout_mapping, maps_cnt, sizeof (keyboard_layout_mapping_t), sort_by_src_len);

  return true;
}

int find_keyboard_layout_map (const u32 search, const int search_len, const keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt)
{
  for (int idx = 0; idx < keyboard_layout_mapping_cnt; idx++)
  {
    const u32 src_char = s_keyboard_layout_mapping[idx].src_char;
    const int src_len  = s_keyboard_layout_mapping[idx].src_len;

    if (src_len == search_len)
    {
      const u32 mask = 0xffffffff >> ((4 - search_len) * 8);

      if ((src_char & mask) == (search & mask)) return idx;
    }
  }

  return -1;
}

int execute_keyboard_layout_mapping (u32 plain_buf[64], const int plain_len, const keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt)
{
  u32 out_buf[16] = { 0 };

  u8 *out_ptr = (u8 *) out_buf;

  int out_len = 0;

  u8 *plain_ptr = (u8 *) plain_buf;

  int plain_pos = 0;

  while (plain_pos < plain_len)
  {
    u32 src0 = 0;
    u32 src1 = 0;
    u32 src2 = 0;
    u32 src3 = 0;

    const int rem = MIN (plain_len - plain_pos, 4);

    if (rem > 0) src0 = plain_ptr[plain_pos + 0];
    if (rem > 1) src1 = plain_ptr[plain_pos + 1];
    if (rem > 2) src2 = plain_ptr[plain_pos + 2];
    if (rem > 3) src3 = plain_ptr[plain_pos + 3];

    const u32 src = (src0 <<  0)
                  | (src1 <<  8)
                  | (src2 << 16)
                  | (src3 << 24);

    int src_len;

    for (src_len = rem; src_len > 0; src_len--)
    {
      const int idx = find_keyboard_layout_map (src, src_len, s_keyboard_layout_mapping, keyboard_layout_mapping_cnt);

      if (idx == -1) continue;

      u32 dst_char = s_keyboard_layout_mapping[idx].dst_char;
      int dst_len  = s_keyboard_layout_mapping[idx].dst_len;

      // A mapping entry may be longer than the character it replaces, so the output grows, and the
      // only thing that ever leaves this function is the 64 bytes copied back at the end. Ending the
      // walk here keeps the writes inside out_buf and loses nothing that was ever returned.

      if ((out_len + dst_len) > (int) sizeof (out_buf))
      {
        plain_pos = plain_len;

        break;
      }

      switch (dst_len)
      {
        case 1:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          break;
        case 2:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          break;
        case 3:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          out_ptr[out_len++] = (dst_char >> 16) & 0xff;
          break;
        case 4:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          out_ptr[out_len++] = (dst_char >> 16) & 0xff;
          out_ptr[out_len++] = (dst_char >> 24) & 0xff;
          break;
      }

      plain_pos += src_len;

      break;
    }

    // not matched, keep original

    if (src_len == 0)
    {
      if ((out_len + 1) > (int) sizeof (out_buf)) break;

      out_ptr[out_len] = plain_ptr[plain_pos];

      out_len++;

      plain_pos++;
    }
  }

  plain_buf[ 0] = out_buf[ 0];
  plain_buf[ 1] = out_buf[ 1];
  plain_buf[ 2] = out_buf[ 2];
  plain_buf[ 3] = out_buf[ 3];
  plain_buf[ 4] = out_buf[ 4];
  plain_buf[ 5] = out_buf[ 5];
  plain_buf[ 6] = out_buf[ 6];
  plain_buf[ 7] = out_buf[ 7];
  plain_buf[ 8] = out_buf[ 8];
  plain_buf[ 9] = out_buf[ 9];
  plain_buf[10] = out_buf[10];
  plain_buf[11] = out_buf[11];
  plain_buf[12] = out_buf[12];
  plain_buf[13] = out_buf[13];
  plain_buf[14] = out_buf[14];
  plain_buf[15] = out_buf[15];

  return out_len;
}
