/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FEED_CTX_H
#define HC_FEED_CTX_H

#include "feed.h"

// How the core drives a feed. Nothing here is part of the plugin contract and no feed may call any
// of it: these functions read and write hashcat's own per instance bookkeeping, and calling one
// from a plugin thread would step on the state the calling thread is in the middle of.
//
// Keeping this out of the header a feed includes is what stops every feed from seeing all of it.
// The #error below is what turns "no feed includes this" from a sentence into a build failure, and
// HC_CORE_BUILD is on the core's compile line and on nothing else (src/Makefile:874).

#if !defined (HC_CORE_BUILD)
#error "feed_ctx.h is the core's own half of the feed subsystem. A feed includes feed.h."
#endif

// The oldest plugin interface hashcat still accepts, checked against the GENERIC_PLUGIN_VERSION a
// feed exports. It is the core's number and a feed neither reads it nor declares it.

#define GENERIC_PLUGIN_VERSION_REQ 720

#define HC_LOAD_FUNC_GENERIC(ptr, name, type)                                                \
do                                                                                           \
{                                                                                            \
  (ptr)->name = (type) hc_dlsym ((ptr)->lib, #name);                                         \
  if ((ptr)->name == NULL)                                                                   \
  {                                                                                          \
    event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, (ptr)->dynlib_filename); \
    return -1;                                                                               \
  }                                                                                          \
} while (0)

// Make one device current on the calling thread, and give it back. Called at the coarsest place on
// each thread that can reach a feed: once around the producer thread's whole life, once per device
// around thread_init () and thread_term (), and once around the stdin discard loop. thread_calc ()
// does its own at src/dispatch.c:1123 and predates this.
//
// bind returns false when the device could not be made current, which for a thread that is about to
// call a feed is the same kind of failure thread_calc () treats as fatal. Every successful bind is
// matched by exactly one unbind, error paths included, or the CUDA context stack of that thread is
// left one deep.

bool feed_device_bind      (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
void feed_device_unbind    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);

bool feed_device_bind_id   (hashcat_ctx_t *hashcat_ctx, const int device_id);
void feed_device_unbind_id (hashcat_ctx_t *hashcat_ctx, const int device_id);

int   generic_filename       (const folder_config_t *folder_config, const char *plugin_name, const char *prefix, char *out_buf, const size_t out_size);
char *generic_resolve        (const folder_config_t *folder_config, const char *plugin_name, bool *by_name);

int  generic_thread_next     (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int backend_device_idx, u8 *out_buf, const int out_size);
int  generic_thread_next_dev (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int backend_device_idx, u8 *out_buf, const int out_size, pcfg_cell_t *cell);
int  generic_thread_seek     (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const int backend_device_idx, const u64 offset);

int  generic_association_in_sync   (hashcat_ctx_t *hashcat_ctx, const generic_ctx_t *generic_ctx);

int  generic_ctx_base_round  (hashcat_ctx_t *hashcat_ctx, const char *path);
int  generic_ctx_base_discard (hashcat_ctx_t *hashcat_ctx, const int device_id, const u64 count);

int  generic_ctx_word_index  (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u8 *cand, const u32 cand_len, u64 *out_index, u64 *out_more, u64 *out_words);
int  generic_ctx_word_family (hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u8 *anchor, const u32 min_len, const u32 max_len, const bool backward, u64 *out_index, u64 *out_words);
const char *generic_ctx_segment_of (const hashcat_ctx_t *hashcat_ctx, const generic_role_t role, const u64 index);

int  generic_ctx_init        (hashcat_ctx_t *hashcat_ctx);
bool generic_ctx_described   (const hashcat_ctx_t *hashcat_ctx);
void generic_ctx_roles_swap  (hashcat_ctx_t *hashcat_ctx);
void generic_ctx_destroy     (hashcat_ctx_t *hashcat_ctx);

#endif // HC_FEED_CTX_H
