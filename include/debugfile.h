/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DEBUGFILE_H
#define _DEBUGFILE_H

#include <stdio.h>

int  debugfile_init         (debugfile_ctx_t *debugfile_ctx, const user_options_t *user_options);
void debugfile_destroy      (debugfile_ctx_t *debugfile_ctx);
void debugfile_format_plain (debugfile_ctx_t *debugfile_ctx, const u8 *plain_ptr, const u32 plain_len);
void debugfile_write_append (debugfile_ctx_t *debugfile_ctx, const u8 *rule_buf, const u32 rule_len, const u8 *mod_plain_ptr, const u32 mod_plain_len, const u8 *orig_plain_ptr, const u32 orig_plain_len);

#endif // _DEBUGFILE_H
