/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DEBUGFILE_H
#define _DEBUGFILE_H

#include <stdio.h>

int  debugfile_init         (hashcat_ctx_t *hashcat_ctx);
void debugfile_destroy      (hashcat_ctx_t *hashcat_ctx);
void debugfile_write_append (hashcat_ctx_t *hashcat_ctx, const u8 *rule_buf, const u32 rule_len, const u8 *mod_plain_ptr, const u32 mod_plain_len, const u8 *orig_plain_ptr, const u32 orig_plain_len);

#endif // _DEBUGFILE_H
