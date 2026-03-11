/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_LOOPBACK_H
#define HC_PCFG_LOOPBACK_H

void pcfg_loopback_write_pw        (hashcat_ctx_t *hashcat_ctx, const u8 *pw, const u32 pw_len);
int  pcfg_loopback_ctx_init        (hashcat_ctx_t *hashcat_ctx);
void pcfg_loopback_ctx_destroy     (hashcat_ctx_t *hashcat_ctx);
int  pcfg_loopback_run             (hashcat_ctx_t *hashcat_ctx);
int  pcfg_loopback_sanity_check    (hashcat_ctx_t *hashcat_ctx);

#endif // HC_PCFG_LOOPBACK_H
