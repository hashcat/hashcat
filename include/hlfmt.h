#pragma once
#include "common.h"
#include "consts/hashcat_modes.h"

void hlfmt_hash_hashcat(char * line_buf, int line_len, char ** hashbuf_pos, int * hashbuf_len);

void hlfmt_user_hashcat(char * line_buf, int line_len, char ** userbuf_pos, int * userbuf_len);

int hlfmt_detect_pwdump(char * line_buf, int line_len);

void hlfmt_hash_pwdump(char * line_buf, int line_len, char ** hashbuf_pos, int * hashbuf_len);

void hlfmt_user_pwdump(char * line_buf, int line_len, char ** userbuf_pos, int * userbuf_len);

int hlfmt_detect_passwd(char * line_buf, int line_len);

void hlfmt_hash_passwd(char * line_buf, int line_len, char ** hashbuf_pos, int * hashbuf_len);

void hlfmt_user_passwd(char * line_buf, int line_len, char ** userbuf_pos, int * userbuf_len);

int hlfmt_detect_shadow(char * line_buf, int line_len);

void hlfmt_hash_shadow(char * line_buf, int line_len, char ** hashbuf_pos, int * hashbuf_len);

void hlfmt_user_shadow(char * line_buf, int line_len, char ** userbuf_pos, int * userbuf_len);

void hlfmt_hash(HLFMT hashfile_format, char * line_buf, int line_len, char ** hashbuf_pos, int * hashbuf_len);

void hlfmt_user(HLFMT hashfile_format, char * line_buf, int line_len, char ** userbuf_pos, int * userbuf_len);

char * strhlfmt(const HLFMT hashfile_format);

HLFMT hlfmt_detect(FILE * fp, uint max_check);
