/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _USER_OPTIONS_H
#define _USER_OPTIONS_H

#include <getopt.h>

int user_options_init (hashcat_ctx_t *hashcat_ctx);

void user_options_destroy (hashcat_ctx_t *hashcat_ctx);

int user_options_getopt (hashcat_ctx_t *hashcat_ctx, int argc, char **argv);

int user_options_sanity (hashcat_ctx_t *hashcat_ctx);

void user_options_session_auto (hashcat_ctx_t *hashcat_ctx);

void user_options_preprocess (hashcat_ctx_t *hashcat_ctx);

void user_options_postprocess (hashcat_ctx_t *hashcat_ctx);

void user_options_extra_init (hashcat_ctx_t *hashcat_ctx);

void user_options_extra_destroy (hashcat_ctx_t *hashcat_ctx);

u64 user_options_extra_amplifier (hashcat_ctx_t *hashcat_ctx);

void user_options_logger (hashcat_ctx_t *hashcat_ctx);

int user_options_check_files (hashcat_ctx_t *hashcat_ctx);

void user_options_info (hashcat_ctx_t *hashcat_ctx);

#endif // _USER_OPTIONS_H
