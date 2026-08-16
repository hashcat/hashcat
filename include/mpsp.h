/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MPSP_H
#define HC_MPSP_H

#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define CHARSIZ       0x100

#define SP_HCSTAT     "hashcat.hcstat2"
#define SP_VERSION    (0x6863737461740000 | 0x0002)
#define SP_PW_MIN     2
#define SP_PW_MAX     256
#define SP_ROOT_CNT   (SP_PW_MAX * CHARSIZ)
#define SP_MARKOV_CNT (SP_PW_MAX * CHARSIZ * CHARSIZ)
#define SP_FILESZ     (sizeof (u64) + sizeof (u64) + (sizeof (u64) * SP_ROOT_CNT) + (sizeof (u64) * SP_MARKOV_CNT))

#define INCR_MASKS    1000

bool  mask_has_marker (const char *mask, const char marker);
bool  mask_ends_with_marker (const char *mask, const char marker);
bool  mask_starts_with_marker (const char *mask, const char marker);
bool  mask_arg_ends_with_marker (const char *arg, const char marker);

u32   hybrid_amp_mask (hashcat_ctx_t *hashcat_ctx, const u64 off, char *mask_buf);
u32   hybrid_amp_rebuild (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param, const u32 il_pos, u8 *out_buf, const u8 *base_buf, const u32 base_len);
u32   hybrid_assemble (hashcat_ctx_t *hashcat_ctx, u8 *out_buf, const char *mask_buf, const u8 *base_buf, const u32 base_len, const u8 *word_buf, const u32 word_len);

u32   mp_get_length (const char *mask, const u32 opts_type);

void  sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 start, u32 stop);

int   mask_ctx_update_loop    (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_init           (hashcat_ctx_t *hashcat_ctx);
void  mask_ctx_destroy        (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_parse_maskfile (hashcat_ctx_t *hashcat_ctx);

#endif // HC_MPSP_H
