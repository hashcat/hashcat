#pragma once
#include "common.h"
#include "shared.h"
void mp_css_to_uniq_tbl(uint css_cnt, cs_t *css, uint uniq_tbls[SP_PW_MAX][CHARSIZ]);
void mp_cut_at(char *mask, uint max);
void mp_exec(u64 val, char *buf, cs_t *css, int css_cnt);
cs_t *mp_gen_css(char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint *css_cnt);
u64 mp_get_sum(uint css_cnt, cs_t *css);
void mp_setup_sys(cs_t *mp_sys);
void mp_setup_usr(cs_t *mp_sys, cs_t *mp_usr, char *buf, uint index);
void mp_reset_usr(cs_t *mp_usr, uint index);
char *mp_get_truncated_mask(char *mask_buf, size_t mask_len, uint len);
