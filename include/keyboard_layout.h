/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _KEYBOARD_LAYOUT_H
#define _KEYBOARD_LAYOUT_H

bool initialize_keyboard_layout_mapping (const char *filename, keyboard_layout_mapping_t *keyboard_layout_mapping, int *keyboard_layout_mapping_cnt);
int  find_keyboard_layout_map (const u32 search, const int search_len, const keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt);
int  execute_keyboard_layout_mapping (u32 plain_buf[64], const int plain_len, const keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt);

#endif // _KEYBOARD_LAYOUT_H
