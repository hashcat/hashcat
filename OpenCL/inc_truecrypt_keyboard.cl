DECLSPEC void keyboard_map (u32 w[4], __local u32 *s_keyboard_layout)
{
  w[0] = (s_keyboard_layout[(w[0] >>  0) & 0xff] <<  0)
       | (s_keyboard_layout[(w[0] >>  8) & 0xff] <<  8)
       | (s_keyboard_layout[(w[0] >> 16) & 0xff] << 16)
       | (s_keyboard_layout[(w[0] >> 24) & 0xff] << 24);

  w[1] = (s_keyboard_layout[(w[1] >>  0) & 0xff] <<  0)
       | (s_keyboard_layout[(w[1] >>  8) & 0xff] <<  8)
       | (s_keyboard_layout[(w[1] >> 16) & 0xff] << 16)
       | (s_keyboard_layout[(w[1] >> 24) & 0xff] << 24);

  w[2] = (s_keyboard_layout[(w[2] >>  0) & 0xff] <<  0)
       | (s_keyboard_layout[(w[2] >>  8) & 0xff] <<  8)
       | (s_keyboard_layout[(w[2] >> 16) & 0xff] << 16)
       | (s_keyboard_layout[(w[2] >> 24) & 0xff] << 24);

  w[3] = (s_keyboard_layout[(w[3] >>  0) & 0xff] <<  0)
       | (s_keyboard_layout[(w[3] >>  8) & 0xff] <<  8)
       | (s_keyboard_layout[(w[3] >> 16) & 0xff] << 16)
       | (s_keyboard_layout[(w[3] >> 24) & 0xff] << 24);
}
