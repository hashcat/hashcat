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
// Put one candidate together out of a mask and the words its markers name. Exported because
// src/feeds/mask.c assembles the same candidate for a feed, and one implementation is what keeps a
// feed and the attack it replaces from disagreeing about what a candidate looks like.

HC_PLUGIN_API u32 hybrid_assemble (hashcat_ctx_t *hashcat_ctx, u8 *out_buf, const char *mask_buf, const u8 *base_buf, const u32 base_len, const u8 *word_buf, const u32 word_len);

u32   mp_get_length (const char *mask, const u32 opts_type);

// The one call that turns a position into a candidate, and the only part of the mask processor a
// plugin may reach. src/feeds/feed_mask.c is the mask processor offered as a feed, so that -a 3 can
// take rules without a second mask parser existing to disagree with this one.

HC_PLUGIN_API void sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 start, u32 stop);

// The charsets a mask allows, one entry per position, for a feed that selects candidates by a mask
// rather than producing them from one. css_buf has to hold 256 entries, which is the longest mask the
// processor takes, and css_max says so. See the comment on the definition for why a feed asks rather
// than parses.

HC_PLUGIN_API int mask_css_parse (hashcat_ctx_t *hashcat_ctx, const char *mask, cs_t *css_buf, const u32 css_max, u32 *css_cnt);

// Whether the mask is a feed's source rather than the device's own generator. That is -a 3 given
// rules, which user_options_alias_attack_mode () rewrites to -a 8 with the mask feed. The mask
// processor still does all of its work in that case, and the only thing it must not do is split the
// mask so that part of it is generated on the device.

HC_API mask_feed_kind_t mask_feed_kind (const user_options_t *user_options);

HC_API bool mask_is_feed (const user_options_t *user_options);

void  mask_ctx_lookup_report  (hashcat_ctx_t *hashcat_ctx);
void  combi_ctx_lookup_report (hashcat_ctx_t *hashcat_ctx);

int   mask_ctx_update_loop    (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_init           (hashcat_ctx_t *hashcat_ctx);
void  mask_ctx_destroy        (hashcat_ctx_t *hashcat_ctx);
int   mask_ctx_parse_maskfile (hashcat_ctx_t *hashcat_ctx);

#endif // HC_MPSP_H
