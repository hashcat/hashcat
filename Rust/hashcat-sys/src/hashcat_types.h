/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdint.h>

typedef uint32_t u32;
typedef void unit_t;
typedef void *hc_dynlib_t;
typedef void *RS_GET_INFO;
typedef void *RS_GLOBAL_INIT;
typedef void *RS_GLOBAL_TERM;
typedef void *RS_THREAD_INIT;
typedef void *RS_THREAD_TERM;
typedef void *RS_KERNEL_LOOP;
typedef void *RS_NEW_CONTEXT;
typedef void *RS_DROP_CONTEXT;

// Sync with:
// OpenCL/inc_types.h

typedef struct salt
{
    u32 salt_buf[64];
    u32 salt_buf_pc[64];

    u32 salt_len;
    u32 salt_len_pc;
    u32 salt_iter;
    u32 salt_iter2;
    u32 salt_dimy;
    u32 salt_sign[2];
    u32 salt_repeats;

    u32 orig_pos;

    u32 digests_cnt;
    u32 digests_done;

    u32 digests_offset;

    u32 scrypt_N;
    u32 scrypt_r;
    u32 scrypt_p;

} salt_t;

/// Generic IO struct containing buffers for an input (password) and an output (computed hash).
/// This struct should be in sync with the following files:
/// - `src/bridges/bridge_rust_generic_hash.c`
/// - `src/modules/module_74000.c`
/// - `OpenCL/m72000-pure.cl`
typedef struct
{
    // password candidate
    u32 pw_buf[64];
    // password length
    u32 pw_len;

    // output hashes
    u32 out_buf[32][64];
    // output hash lengths
    u32 out_len[32];
    u32 out_cnt;

} generic_io_tmp_t;

typedef struct
{
    u32 hash_buf[256];
    u32 hash_len;

    u32 salt_buf[256];
    u32 salt_len;

} generic_io_t;

/// Context of a bridge, including parameters and function pointers for the different steps.
/// This struct should be in sync with the definition in `src/bridges/bridge_rust_generic_hash.c`
typedef struct bridge_context
{
    unit_t *units_buf;
    int units_cnt;

    char *dynlib_filename;
    hc_dynlib_t lib;

    RS_GET_INFO get_info;
    RS_GLOBAL_INIT global_init;
    RS_GLOBAL_TERM global_term;
    RS_THREAD_INIT thread_init;
    RS_THREAD_TERM thread_term;
    RS_KERNEL_LOOP kernel_loop;
    RS_NEW_CONTEXT new_context;
    RS_DROP_CONTEXT drop_context;

    const char *bridge_parameter1;
    const char *bridge_parameter2;
    const char *bridge_parameter3;
    const char *bridge_parameter4;

} bridge_context_t;
