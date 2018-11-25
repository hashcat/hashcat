DECLSPEC int find_keyboard_layout_map (const u32 search, const int search_len, __local keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt)
{
  for (int idx = 0; idx < keyboard_layout_mapping_cnt; idx++)
  {
    const u32 src_char = s_keyboard_layout_mapping_buf[idx].src_char;
    const int src_len  = s_keyboard_layout_mapping_buf[idx].src_len;

    if (src_len == search_len)
    {
      const u32 mask = 0xffffffff >> ((4 - search_len) * 8);

      if ((src_char & mask) == (search & mask)) return idx;
    }
  }

  return -1;
}

DECLSPEC int keyboard_map (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const int pw_len, __local keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt)
{
  u32 out_buf[16] = { 0 };

  u8 *out_ptr = (u8 *) out_buf;

  int out_len = 0;

  // TC/VC passwords are limited to 64

  u32 w[16];

  w[ 0] = w0[0];
  w[ 1] = w0[1];
  w[ 2] = w0[2];
  w[ 3] = w0[3];
  w[ 4] = w1[0];
  w[ 5] = w1[1];
  w[ 6] = w1[2];
  w[ 7] = w1[3];
  w[ 8] = w2[0];
  w[ 9] = w2[1];
  w[10] = w2[2];
  w[11] = w2[3];
  w[12] = w3[0];
  w[13] = w3[1];
  w[14] = w3[2];
  w[15] = w3[3];

  u8 *w_ptr = (u8 *) w;

  int pw_pos = 0;

  while (pw_pos < pw_len)
  {
    u32 src0 = 0;
    u32 src1 = 0;
    u32 src2 = 0;
    u32 src3 = 0;

    #define MIN(a,b) (((a) < (b)) ? (a) : (b))

    const int rem = MIN (pw_len - pw_pos, 4);

    #undef MIN

    if (rem > 0) src0 = w_ptr[pw_pos + 0];
    if (rem > 1) src1 = w_ptr[pw_pos + 1];
    if (rem > 2) src2 = w_ptr[pw_pos + 2];
    if (rem > 3) src3 = w_ptr[pw_pos + 3];

    const u32 src = (src0 <<  0)
                  | (src1 <<  8)
                  | (src2 << 16)
                  | (src3 << 24);

    int src_len;

    for (src_len = rem; src_len > 0; src_len--)
    {
      const int idx = find_keyboard_layout_map (src, src_len, s_keyboard_layout_mapping_buf, keyboard_layout_mapping_cnt);

      if (idx == -1) continue;

      u32 dst_char = s_keyboard_layout_mapping_buf[idx].dst_char;
      int dst_len  = s_keyboard_layout_mapping_buf[idx].dst_len;

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

      pw_pos += src_len;

      break;
    }

    // not matched, keep original

    if (src_len == 0)
    {
      out_ptr[out_len] = w_ptr[pw_pos];

      out_len++;

      pw_pos++;
    }
  }

  w0[0] = out_buf[ 0];
  w0[1] = out_buf[ 1];
  w0[2] = out_buf[ 2];
  w0[3] = out_buf[ 3];
  w1[0] = out_buf[ 4];
  w1[1] = out_buf[ 5];
  w1[2] = out_buf[ 6];
  w1[3] = out_buf[ 7];
  w2[0] = out_buf[ 8];
  w2[1] = out_buf[ 9];
  w2[2] = out_buf[10];
  w2[3] = out_buf[11];
  w3[0] = out_buf[12];
  w3[1] = out_buf[13];
  w3[2] = out_buf[14];
  w3[3] = out_buf[15];

  return out_len;
}
