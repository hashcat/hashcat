/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _MPSP_H
#define _MPSP_H

#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define CHARSIZ       0x100

#define SP_HCSTAT     "hashcat.hcstat"
#define SP_PW_MIN     2
#define SP_PW_MAX     64
#define SP_ROOT_CNT   (SP_PW_MAX * CHARSIZ)
#define SP_MARKOV_CNT (SP_PW_MAX * CHARSIZ * CHARSIZ)

#define INCR_MASKS    1000

void  mp_css_split_cnt (const mask_ctx_t *mask_ctx, const hashconfig_t *hashconfig, const u32 css_cnt_orig, u32 css_cnt_rl[2]);
void  mp_css_append_salt (mask_ctx_t *mask_ctx, salt_t *salt_buf);
void  mp_css_unicode_expand (mask_ctx_t *mask_ctx);
int   mp_css_to_uniq_tbl (hashcat_ctx_t *hashcat_ctx, u32 css_cnt, cs_t *css, u32 uniq_tbls[SP_PW_MAX][CHARSIZ]);
void  mp_cut_at (char *mask, u32 max);
u32   mp_get_length (char *mask);
void  mp_exec (u64 val, char *buf, cs_t *css, int css_cnt);
u64   mp_get_sum (u32 css_cnt, cs_t *css);
void  mp_setup_sys (cs_t *mp_sys);
int   mp_setup_usr (hashcat_ctx_t *hashcat_ctx, cs_t *mp_sys, cs_t *mp_usr, char *buf, u32 index);
void  mp_reset_usr (cs_t *mp_usr, u32 index);

u64   sp_get_sum (u32 start, u32 stop, cs_t *root_css_buf);
void  sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 start, u32 stop);
int   sp_comp_val (const void *p1, const void *p2);
void  sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 threshold, u32 uniq_tbls[SP_PW_MAX][CHARSIZ]);
void  sp_stretch_markov (hcstat_table_t *in, hcstat_table_t *out);
void  sp_stretch_root (hcstat_table_t *in, hcstat_table_t *out);

int   mask_ctx_update_loop    (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_init           (hashcat_ctx_t *hashcat_ctx);
void  mask_ctx_destroy        (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_parse_maskfile (hashcat_ctx_t *hashcat_ctx);

#endif // _MPSP_H
