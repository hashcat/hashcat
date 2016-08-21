/**
* maskprocessor
*/

#include <shared.h>
#include <consts/hash_options.h>
#include <converter.h>
#include <logging.h>
#include <hc_global_data_t.h>
#include <hc_global.h>

void mp_css_to_uniq_tbl(uint css_cnt, cs_t *css, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    log_error("ERROR: Mask length is too long");

    exit(-1);
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

void mp_add_cs_buf(uint *in_buf, size_t in_len, cs_t *css, int css_cnt)
{
  cs_t *cs = &css[css_cnt];

  size_t css_uniq_sz = CHARSIZ * sizeof(uint);

  uint *css_uniq = (uint *)mymalloc(css_uniq_sz);

  size_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    const uint u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    uint u = in_buf[i] & 0xff;

    if (data.opts_type & OPTS_TYPE_PT_UPPER) u = toupper(u);

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  myfree(css_uniq);
}

void mp_expand(char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, int mp_usr_offset, int interpret)
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
      case 'l': mp_add_cs_buf(mp_sys[0].cs_buf, mp_sys[0].cs_len, mp_usr, mp_usr_offset);
        break;
      case 'u': mp_add_cs_buf(mp_sys[1].cs_buf, mp_sys[1].cs_len, mp_usr, mp_usr_offset);
        break;
      case 'd': mp_add_cs_buf(mp_sys[2].cs_buf, mp_sys[2].cs_len, mp_usr, mp_usr_offset);
        break;
      case 's': mp_add_cs_buf(mp_sys[3].cs_buf, mp_sys[3].cs_len, mp_usr, mp_usr_offset);
        break;
      case 'a': mp_add_cs_buf(mp_sys[4].cs_buf, mp_sys[4].cs_len, mp_usr, mp_usr_offset);
        break;
      case 'b': mp_add_cs_buf(mp_sys[5].cs_buf, mp_sys[5].cs_len, mp_usr, mp_usr_offset);
        break;
      case '1': if (mp_usr[0].cs_len == 0) { log_error("ERROR: Custom-charset 1 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[0].cs_buf, mp_usr[0].cs_len, mp_usr, mp_usr_offset);
                break;
      case '2': if (mp_usr[1].cs_len == 0) { log_error("ERROR: Custom-charset 2 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[1].cs_buf, mp_usr[1].cs_len, mp_usr, mp_usr_offset);
                break;
      case '3': if (mp_usr[2].cs_len == 0) { log_error("ERROR: Custom-charset 3 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[2].cs_buf, mp_usr[2].cs_len, mp_usr, mp_usr_offset);
                break;
      case '4': if (mp_usr[3].cs_len == 0) { log_error("ERROR: Custom-charset 4 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[3].cs_buf, mp_usr[3].cs_len, mp_usr, mp_usr_offset);
                break;
      case '?': mp_add_cs_buf(&p0, 1, mp_usr, mp_usr_offset);
        break;
      default:  log_error("Syntax error: %s", in_buf);
        exit(-1);
      }
    }
    else
    {
      if (data.hex_charset)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          log_error("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

          exit(-1);
        }

        uint p1 = in_buf[in_pos] & 0xff;

        if ((is_valid_hex_char(p0) == 0) || (is_valid_hex_char(p1) == 0))
        {
          log_error("ERROR: Invalid hex character detected in mask %s", in_buf);

          exit(-1);
        }

        uint chr = 0;

        chr = hex_convert(p1) << 0;
        chr |= hex_convert(p0) << 4;

        mp_add_cs_buf(&chr, 1, mp_usr, mp_usr_offset);
      }
      else
      {
        uint chr = p0;

        mp_add_cs_buf(&chr, 1, mp_usr, mp_usr_offset);
      }
    }
  }
}

u64 mp_get_sum(uint css_cnt, cs_t *css)
{
  u64 sum = 1;

  for (uint css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    sum *= css[css_pos].cs_len;
  }

  return (sum);
}

cs_t *mp_gen_css(char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint *css_cnt)
{
  cs_t *css = (cs_t *)mycalloc(256, sizeof(cs_t));

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
      case 'l': mp_add_cs_buf(mp_sys[0].cs_buf, mp_sys[0].cs_len, css, css_pos);
        break;
      case 'u': mp_add_cs_buf(mp_sys[1].cs_buf, mp_sys[1].cs_len, css, css_pos);
        break;
      case 'd': mp_add_cs_buf(mp_sys[2].cs_buf, mp_sys[2].cs_len, css, css_pos);
        break;
      case 's': mp_add_cs_buf(mp_sys[3].cs_buf, mp_sys[3].cs_len, css, css_pos);
        break;
      case 'a': mp_add_cs_buf(mp_sys[4].cs_buf, mp_sys[4].cs_len, css, css_pos);
        break;
      case 'b': mp_add_cs_buf(mp_sys[5].cs_buf, mp_sys[5].cs_len, css, css_pos);
        break;
      case '1': if (mp_usr[0].cs_len == 0) { log_error("ERROR: Custom-charset 1 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[0].cs_buf, mp_usr[0].cs_len, css, css_pos);
                break;
      case '2': if (mp_usr[1].cs_len == 0) { log_error("ERROR: Custom-charset 2 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[1].cs_buf, mp_usr[1].cs_len, css, css_pos);
                break;
      case '3': if (mp_usr[2].cs_len == 0) { log_error("ERROR: Custom-charset 3 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[2].cs_buf, mp_usr[2].cs_len, css, css_pos);
                break;
      case '4': if (mp_usr[3].cs_len == 0) { log_error("ERROR: Custom-charset 4 is undefined\n"); exit(-1); }
                mp_add_cs_buf(mp_usr[3].cs_buf, mp_usr[3].cs_len, css, css_pos);
                break;
      case '?': mp_add_cs_buf(&chr, 1, css, css_pos);
        break;
      default:  log_error("ERROR: Syntax error: %s", mask_buf);
        exit(-1);
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
          log_error("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit(-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char(p0) == 0) || (is_valid_hex_char(p1) == 0))
        {
          log_error("ERROR: Invalid hex character detected in mask %s", mask_buf);

          exit(-1);
        }

        uint chr = 0;

        chr |= hex_convert(p1) << 0;
        chr |= hex_convert(p0) << 4;

        mp_add_cs_buf(&chr, 1, css, css_pos);
      }
      else
      {
        uint chr = p0;

        mp_add_cs_buf(&chr, 1, css, css_pos);
      }
    }
  }

  if (css_pos == 0)
  {
    log_error("ERROR: Invalid mask length (0)");

    exit(-1);
  }

  *css_cnt = css_pos;

  return (css);
}

void mp_exec(u64 val, char *buf, cs_t *css, int css_cnt)
{
  for (int i = 0; i < css_cnt; i++)
  {
    uint len = css[i].cs_len;
    u64 next = val / len;
    uint pos = val % len;
    buf[i] = (char)css[i].cs_buf[pos] & 0xff;
    val = next;
  }
}

void mp_cut_at(char *mask, uint max)
{
  uint i;
  uint j;
  uint mask_len = strlen(mask);

  for (i = 0, j = 0; i < mask_len && j < max; i++, j++)
  {
    if (mask[i] == '?') i++;
  }

  mask[i] = 0;
}

void mp_setup_sys(cs_t *mp_sys)
{
  uint pos;
  uint chr;
  uint donec[CHARSIZ] = { 0 };

  for (pos = 0, chr = 'a'; chr <= 'z'; chr++) {
    donec[chr] = 1;
    mp_sys[0].cs_buf[pos++] = chr;
    mp_sys[0].cs_len = pos;
  }

  for (pos = 0, chr = 'A'; chr <= 'Z'; chr++) {
    donec[chr] = 1;
    mp_sys[1].cs_buf[pos++] = chr;
    mp_sys[1].cs_len = pos;
  }

  for (pos = 0, chr = '0'; chr <= '9'; chr++) {
    donec[chr] = 1;
    mp_sys[2].cs_buf[pos++] = chr;
    mp_sys[2].cs_len = pos;
  }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) {
    if (donec[chr]) continue;
    mp_sys[3].cs_buf[pos++] = chr;
    mp_sys[3].cs_len = pos;
  }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) {
    mp_sys[4].cs_buf[pos++] = chr;
    mp_sys[4].cs_len = pos;
  }

  for (pos = 0, chr = 0x00; chr <= 0xff; chr++) {
    mp_sys[5].cs_buf[pos++] = chr;
    mp_sys[5].cs_len = pos;
  }
}

void mp_setup_usr(cs_t *mp_sys, cs_t *mp_usr, char *buf, uint index)
{
  FILE *fp = fopen(buf, "rb");

  if (fp == NULL || feof(fp)) // feof() in case if file is empty
  {
    mp_expand(buf, strlen(buf), mp_sys, mp_usr, index, 1);
  }
  else
  {
    char mp_file[1024] = { 0 };

    size_t len = fread(mp_file, 1, sizeof(mp_file) - 1, fp);

    fclose(fp);

    len = in_superchop(mp_file);

    if (len == 0)
    {
      log_info("WARNING: Charset file corrupted");

      mp_expand(buf, strlen(buf), mp_sys, mp_usr, index, 1);
    }
    else
    {
      mp_expand(mp_file, len, mp_sys, mp_usr, index, 0);
    }
  }
}

void mp_reset_usr(cs_t *mp_usr, uint index)
{
  mp_usr[index].cs_len = 0;

  memset(mp_usr[index].cs_buf, 0, sizeof(mp_usr[index].cs_buf));
}

char *mp_get_truncated_mask(char *mask_buf, size_t mask_len, uint len)
{
  char *new_mask_buf = (char *)mymalloc(256);

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
          log_error("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit(-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char(p0) == 0) || (is_valid_hex_char(p1) == 0))
        {
          log_error("ERROR: Invalid hex character detected in mask: %s", mask_buf);

          exit(-1);
        }

        new_mask_buf[mask_pos] = p1;
      }
    }
  }

  if (css_pos == len) return (new_mask_buf);

  myfree(new_mask_buf);

  return (NULL);
}
