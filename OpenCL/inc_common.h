/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_COMMON_H
#define _INC_COMMON_H

/*
 * Prototype kernel function that fits all kernel macros
 *
 * There are four variables where major differences occur:
 *
 *   -  P2: Adress space of kernel_rules_t struct.
 *          If the kernel uses rules_buf, it will be stored in CONSTANT_AS.
 *          If it does not, cheaper GLOBAL_AS space is used.
 *
 *   -  P4: Innerloop word buffer:
 *          Most kernels use a bf_t structure in GLOBAL_AS address space (_BASIC).
 *          Some use u32x pointer to a vector in CONSTANT_AS address space (_VECTOR).
 *          A few use a specific bs_word_t struct (_BITSLICE).
 *
 *   -  P5: Type of the tmps structure with additional data, or void.
 *          Used with slow hash types (ATTACK_EXEC_OUTSIDE_KERNEL) only.
 *
 *   - P19: Type of the esalt_bufs structure with additional data, or void.
 */

#if defined IS_CUDA || defined IS_HIP
#define KERN_ATTR(p2,p4,p5,p6,p19)                                \
  MAYBE_UNUSED GLOBAL_AS       pw_t           *pws,               \
  MAYBE_UNUSED p2        const kernel_rule_t  *g_rules_buf,       \
  MAYBE_UNUSED GLOBAL_AS const pw_t           *combs_buf,         \
  MAYBE_UNUSED p4,                                                \
  MAYBE_UNUSED GLOBAL_AS p5                   *tmps,              \
  MAYBE_UNUSED GLOBAL_AS p6                   *hooks,             \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_a,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_b,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_c,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_d,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_a,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_b,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_c,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_d,  \
  MAYBE_UNUSED GLOBAL_AS       plain_t        *plains_buf,        \
  MAYBE_UNUSED GLOBAL_AS const digest_t       *digests_buf,       \
  MAYBE_UNUSED GLOBAL_AS       u32            *hashes_shown,      \
  MAYBE_UNUSED GLOBAL_AS const salt_t         *salt_bufs,         \
  MAYBE_UNUSED GLOBAL_AS const p19            *esalt_bufs,        \
  MAYBE_UNUSED GLOBAL_AS       u32            *d_return_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra0_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra1_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra2_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra3_buf,      \
  MAYBE_UNUSED GLOBAL_AS const kernel_param_t *kernel_param
#else
#define KERN_ATTR(p2,p4,p5,p6,p19)                                \
  MAYBE_UNUSED GLOBAL_AS       pw_t           *pws,               \
  MAYBE_UNUSED p2        const kernel_rule_t  *rules_buf,         \
  MAYBE_UNUSED GLOBAL_AS const pw_t           *combs_buf,         \
  MAYBE_UNUSED p4,                                                \
  MAYBE_UNUSED GLOBAL_AS p5                   *tmps,              \
  MAYBE_UNUSED GLOBAL_AS p6                   *hooks,             \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_a,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_b,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_c,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s1_d,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_a,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_b,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_c,  \
  MAYBE_UNUSED GLOBAL_AS const u32            *bitmaps_buf_s2_d,  \
  MAYBE_UNUSED GLOBAL_AS       plain_t        *plains_buf,        \
  MAYBE_UNUSED GLOBAL_AS const digest_t       *digests_buf,       \
  MAYBE_UNUSED GLOBAL_AS       u32            *hashes_shown,      \
  MAYBE_UNUSED GLOBAL_AS const salt_t         *salt_bufs,         \
  MAYBE_UNUSED GLOBAL_AS const p19            *esalt_bufs,        \
  MAYBE_UNUSED GLOBAL_AS       u32            *d_return_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra0_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra1_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra2_buf,      \
  MAYBE_UNUSED GLOBAL_AS       void           *d_extra3_buf,      \
  MAYBE_UNUSED GLOBAL_AS const kernel_param_t *kernel_param
#endif

/*
 * Shortcut macros for usage in the actual kernels
 *
 * Not all possible combinations are needed. E.g. all kernels that use rules
 * do not use the tmps pointer, all kernels that use a vector pointer in P4
 * do not use rules or tmps, etc.
 */

#if defined IS_CUDA || defined IS_HIP
#define _KERN_ATTR_BASIC()                 KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, void)
#define _KERN_ATTR_BITSLICE()              KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bs_word_t *g_words_buf_s, void, void, void)
#define _KERN_ATTR_ESALT(e)                KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, e)
#define _KERN_ATTR_RULES()                 KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, void)
#define _KERN_ATTR_RULES_ESALT(e)          KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, e)
#define _KERN_ATTR_TMPS(t)                 KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    void, void)
#define _KERN_ATTR_TMPS_ESALT(t,e)         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    void, e)
#define _KERN_ATTR_TMPS_HOOKS(t,h)         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    h,    void)
#define _KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e) KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    h,    e)
#define _KERN_ATTR_VECTOR()                KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const u32x      *g_words_buf_r, void, void, void)
#define _KERN_ATTR_VECTOR_ESALT(e)         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const u32x      *g_words_buf_r, void, void, e)
#else
#define _KERN_ATTR_BASIC()                 KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       void, void, void)
#define _KERN_ATTR_BITSLICE()              KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bs_word_t *words_buf_s,   void, void, void)
#define _KERN_ATTR_ESALT(e)                KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       void, void, e)
#define _KERN_ATTR_RULES()                 KERN_ATTR (CONSTANT_AS, GLOBAL_AS   const bf_t      *bfs_buf,       void, void, void)
#define _KERN_ATTR_RULES_ESALT(e)          KERN_ATTR (CONSTANT_AS, GLOBAL_AS   const bf_t      *bfs_buf,       void, void, e)
#define _KERN_ATTR_TMPS(t)                 KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    void, void)
#define _KERN_ATTR_TMPS_ESALT(t,e)         KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    void, e)
#define _KERN_ATTR_TMPS_HOOKS(t,h)         KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    h,    void)
#define _KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e) KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    h,    e)
#define _KERN_ATTR_VECTOR()                KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const u32x      *words_buf_r,   void, void, void)
#define _KERN_ATTR_VECTOR_ESALT(e)         KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const u32x      *words_buf_r,   void, void, e)
#endif

/*
 * with Metal we have additional parameters for the 'modifiers' (gid, lid, lsize, etc...)
 * they should not be declared in the host code
 * the compiler make the magic for us :)
 */

#if defined IS_METAL
#define KERN_ATTR_MAIN_PARAMS                       \
  uint hc_gid [[ thread_position_in_grid ]],        \
  uint hc_lid [[ thread_position_in_threadgroup ]], \
  uint hc_lsz [[ threads_per_threadgroup ]]
#endif // IS_METAL

/*
 * TM kernel function parameters
 */

#define _KERN_ATTR_TM              \
  GLOBAL_AS u32 *mod,              \
  GLOBAL_AS bs_word_t *words_buf_b

/*
 * Below are the macros to be used in the declarations of the KERNEL_FQ functions (pure and optimized kernels)
 * With Metal we need to add KERN_ATTR_MAIN_PARAMS
 * With CUDA, HIP and OpenCL there are no additional parameters other than those declared in the host code
 */

#if defined IS_METAL
#define KERN_ATTR_BASIC()                      _KERN_ATTR_BASIC(), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_BITSLICE()                   _KERN_ATTR_BITSLICE(), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_ESALT(e)                     _KERN_ATTR_ESALT(e), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_RULES()                      _KERN_ATTR_RULES(), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_RULES_ESALT(e)               _KERN_ATTR_RULES_ESALT(e), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_TMPS(t)                      _KERN_ATTR_TMPS(t), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_TMPS_ESALT(t,e)              _KERN_ATTR_TMPS_ESALT(t,e), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_TMPS_HOOKS(t,h)              _KERN_ATTR_TMPS_HOOKS(t,h), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e)      _KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_VECTOR()                     _KERN_ATTR_VECTOR(), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_VECTOR_ESALT(e)              _KERN_ATTR_VECTOR_ESALT(e), KERN_ATTR_MAIN_PARAMS
#define KERN_ATTR_TM                           _KERN_ATTR_TM, KERN_ATTR_MAIN_PARAMS
#else // CUDA, HIP and OpenCL
#define KERN_ATTR_BASIC()                      _KERN_ATTR_BASIC()
#define KERN_ATTR_BITSLICE()                   _KERN_ATTR_BITSLICE()
#define KERN_ATTR_ESALT(e)                     _KERN_ATTR_ESALT(e)
#define KERN_ATTR_RULES()                      _KERN_ATTR_RULES()
#define KERN_ATTR_RULES_ESALT(e)               _KERN_ATTR_RULES_ESALT(e)
#define KERN_ATTR_TMPS(t)                      _KERN_ATTR_TMPS(t)
#define KERN_ATTR_TMPS_ESALT(t,e)              _KERN_ATTR_TMPS_ESALT(t,e)
#define KERN_ATTR_TMPS_HOOKS(t,h)              _KERN_ATTR_TMPS_HOOKS(t,h)
#define KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e)      _KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e)
#define KERN_ATTR_VECTOR()                     _KERN_ATTR_VECTOR()
#define KERN_ATTR_VECTOR_ESALT(e)              _KERN_ATTR_VECTOR_ESALT(e)
#define KERN_ATTR_TM                           _KERN_ATTR_TM
#endif // IS_METAL

/*
 * Below are the macros to be used in the declarations of the DECLSPEC functions
 * that reuse the same parameters of KERNEL_FQ functions (-a3 optimized kernels)
 * They are shared with CUDA, HIP, Metal and OpenCL runtime
 * With these we can reuse 'modifier' (gid, lid, lsz, etc...) if we got it inside KERNEL functions
 */

#define KERN_ATTR_FUNC_PARAMS \
               const u64 gid, \
  MAYBE_UNUSED const u64 lid, \
  MAYBE_UNUSED const u64 lsz

#define KERN_ATTR_FUNC_BASIC()                 _KERN_ATTR_BASIC(), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_BITSLICE()              _KERN_ATTR_BITSLICE(), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_ESALT(e)                _KERN_ATTR_ESALT(e), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_RULES()                 _KERN_ATTR_RULES(), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_RULES_ESALT(e)          _KERN_ATTR_RULES_ESALT(e), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_TMPS(t)                 _KERN_ATTR_TMPS(t), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_TMPS_ESALT(t,e)         _KERN_ATTR_TMPS_ESALT(t,e), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_TMPS_HOOKS(t,h)         _KERN_ATTR_TMPS_HOOKS(t,h), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_TMPS_HOOKS_ESALT(t,h,e) _KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_VECTOR()                _KERN_ATTR_VECTOR(), KERN_ATTR_FUNC_PARAMS
#define KERN_ATTR_FUNC_VECTOR_ESALT(e)         _KERN_ATTR_VECTOR_ESALT(e), KERN_ATTR_FUNC_PARAMS

// union based packing

DECLSPEC u8 v8a_from_v32_S (const u32 v32);
DECLSPEC u8 v8b_from_v32_S (const u32 v32);
DECLSPEC u8 v8c_from_v32_S (const u32 v32);
DECLSPEC u8 v8d_from_v32_S (const u32 v32);

DECLSPEC u8 v8a_from_v64_S (const u64 v64);
DECLSPEC u8 v8b_from_v64_S (const u64 v64);
DECLSPEC u8 v8c_from_v64_S (const u64 v64);
DECLSPEC u8 v8d_from_v64_S (const u64 v64);
DECLSPEC u8 v8e_from_v64_S (const u64 v64);
DECLSPEC u8 v8f_from_v64_S (const u64 v64);
DECLSPEC u8 v8g_from_v64_S (const u64 v64);
DECLSPEC u8 v8h_from_v64_S (const u64 v64);

DECLSPEC u8x v8a_from_v64 (const u64x v64);
DECLSPEC u8x v8b_from_v64 (const u64x v64);
DECLSPEC u8x v8c_from_v64 (const u64x v64);
DECLSPEC u8x v8d_from_v64 (const u64x v64);
DECLSPEC u8x v8e_from_v64 (const u64x v64);
DECLSPEC u8x v8f_from_v64 (const u64x v64);
DECLSPEC u8x v8g_from_v64 (const u64x v64);
DECLSPEC u8x v8h_from_v64 (const u64x v64);

DECLSPEC u16 v16a_from_v32_S (const u32 v32);
DECLSPEC u16 v16b_from_v32_S (const u32 v32);

DECLSPEC u32 v32a_from_v64_S (const u64 v64);
DECLSPEC u32 v32b_from_v64_S (const u64 v64);

DECLSPEC u32 v32_from_v16ab_S (const u16 v16a, const u16 v16b);
DECLSPEC u64 v64_from_v32ab_S (const u32 v32a, const u32 v32b);

// inline asm packing

DECLSPEC u32x unpack_v8a_from_v32 (const u32x v32);
DECLSPEC u32x unpack_v8b_from_v32 (const u32x v32);
DECLSPEC u32x unpack_v8c_from_v32 (const u32x v32);
DECLSPEC u32x unpack_v8d_from_v32 (const u32x v32);

DECLSPEC u32 unpack_v8a_from_v32_S (const u32 v32);
DECLSPEC u32 unpack_v8b_from_v32_S (const u32 v32);
DECLSPEC u32 unpack_v8c_from_v32_S (const u32 v32);
DECLSPEC u32 unpack_v8d_from_v32_S (const u32 v32);

// opencl intern based packing

DECLSPEC u32x l32_from_64   (u64x a);
DECLSPEC u32x h32_from_64   (u64x a);
DECLSPEC u32  l32_from_64_S (u64  a);
DECLSPEC u32  h32_from_64_S (u64  a);

DECLSPEC u64x hl32_to_64   (const u32x a, const u32x b);
DECLSPEC u64  hl32_to_64_S (const u32  a, const u32  b);

// bit operations

DECLSPEC u32x hc_rotl32   (const u32x a, const int n);
DECLSPEC u32x hc_rotr32   (const u32x a, const int n);
DECLSPEC u32  hc_rotl32_S (const u32  a, const int n);
DECLSPEC u32  hc_rotr32_S (const u32  a, const int n);
DECLSPEC u64x hc_rotl64   (const u64x a, const int n);
DECLSPEC u64x hc_rotr64   (const u64x a, const int n);
DECLSPEC u64  hc_rotl64_S (const u64  a, const int n);
DECLSPEC u64  hc_rotr64_S (const u64  a, const int n);

DECLSPEC u32x hc_swap32   (const u32x v);
DECLSPEC u32  hc_swap32_S (const u32  v);
DECLSPEC u64x hc_swap64   (const u64x v);
DECLSPEC u64  hc_swap64_S (const u64  v);

// byte operations

DECLSPEC u32x hc_bytealign      (const u32x a, const u32x b, const int  c);
DECLSPEC u32  hc_bytealign_S    (const u32  a, const u32  b, const int  c);
DECLSPEC u32x hc_bytealign_be   (const u32x a, const u32x b, const int  c);
DECLSPEC u32  hc_bytealign_be_S (const u32  a, const u32  b, const int  c);
DECLSPEC u32x hc_byte_perm      (const u32x a, const u32x b, const int  c);
DECLSPEC u32  hc_byte_perm_S    (const u32  a, const u32  b, const int  c);

DECLSPEC u32x hc_add3           (const u32x a, const u32x b, const u32x c);
DECLSPEC u32  hc_add3_S         (const u32  a, const u32  b, const u32  c);
DECLSPEC u32x hc_bfe            (const u32x a, const u32x b, const u32x c);
DECLSPEC u32  hc_bfe_S          (const u32  a, const u32  b, const u32  c);
DECLSPEC u32x hc_lop_0x96       (const u32x a, const u32x b, const u32x c);
DECLSPEC u32  hc_lop_0x96_S     (const u32  a, const u32  b, const u32  c);

// legacy common code

DECLSPEC int ffz (const u32 v);

#ifdef KERNEL_STATIC
DECLSPEC int hash_comp (PRIVATE_AS const u32 *d1, GLOBAL_AS const u32 *d2);
DECLSPEC int find_hash (PRIVATE_AS const u32 *digest, const u32 digests_cnt, GLOBAL_AS const digest_t *digests_buf);
#endif

DECLSPEC int hc_enc_scan (PRIVATE_AS const u32 *buf, const int len);
DECLSPEC int hc_enc_scan_global (GLOBAL_AS const u32 *buf, const int len);
DECLSPEC void hc_enc_init (PRIVATE_AS hc_enc_t *hc_enc);
DECLSPEC int hc_enc_has_next (PRIVATE_AS hc_enc_t *hc_enc, const int sz);
DECLSPEC int hc_enc_next (PRIVATE_AS hc_enc_t *hc_enc, PRIVATE_AS const u32 *src_buf, const int src_len, const int src_sz, PRIVATE_AS u32 *dst_buf, const int dst_sz);
DECLSPEC int hc_enc_next_global (PRIVATE_AS hc_enc_t *hc_enc, GLOBAL_AS const u32 *src_buf, const int src_len, const int src_sz, PRIVATE_AS u32 *dst_buf, const int dst_sz);

DECLSPEC int pkcs_padding_bs8 (PRIVATE_AS const u32 *data_buf, const int data_len);
DECLSPEC int pkcs_padding_bs16 (PRIVATE_AS const u32 *data_buf, const int data_len);
DECLSPEC int asn1_detect (PRIVATE_AS const u32 *buf, const int len);
DECLSPEC u32 check_bitmap (GLOBAL_AS const u32 *bitmap, const u32 bitmap_mask, const u32 bitmap_shift, const u32 digest);
DECLSPEC u32 check (PRIVATE_AS const u32 *digest, GLOBAL_AS const u32 *bitmap_s1_a, GLOBAL_AS const u32 *bitmap_s1_b, GLOBAL_AS const u32 *bitmap_s1_c, GLOBAL_AS const u32 *bitmap_s1_d, GLOBAL_AS const u32 *bitmap_s2_a, GLOBAL_AS const u32 *bitmap_s2_b, GLOBAL_AS const u32 *bitmap_s2_c, GLOBAL_AS const u32 *bitmap_s2_d, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2);
DECLSPEC void mark_hash (GLOBAL_AS plain_t *plains_buf, GLOBAL_AS u32 *d_result, const u32 salt_pos, const u32 digests_cnt, const u32 digest_pos, const u32 hash_pos, const u64 gid, const u32 il_pos, const u32 extra1, const u32 extra2);
DECLSPEC int hc_count_char (PRIVATE_AS const u32 *buf, const int elems, const u32 c);
DECLSPEC float hc_get_entropy (PRIVATE_AS const u32 *buf, const int elems);
DECLSPEC int is_valid_hex_8 (const u8 v);
DECLSPEC int is_valid_hex_32 (const u32 v);
DECLSPEC int is_valid_base58_8 (const u8 v);
DECLSPEC int is_valid_base58_32 (const u32 v);
DECLSPEC int hc_find_keyboard_layout_map (const u32 search, const int search_len, LOCAL_AS keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt);
DECLSPEC int hc_execute_keyboard_layout_mapping (PRIVATE_AS u32 *w, const int pw_len, LOCAL_AS keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt);
DECLSPEC void make_utf16be (PRIVATE_AS const u32x *in, PRIVATE_AS u32x *out1, PRIVATE_AS u32x *out2);
DECLSPEC void make_utf16beN (PRIVATE_AS const u32x *in, PRIVATE_AS u32x *out1, PRIVATE_AS u32x *out2);
DECLSPEC void make_utf16beN_S (PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out1, PRIVATE_AS u32 *out2);
DECLSPEC void make_utf16le (PRIVATE_AS const u32x *in, PRIVATE_AS u32x *out1, PRIVATE_AS u32x *out2);
DECLSPEC void make_utf16leN (PRIVATE_AS const u32x *in, PRIVATE_AS u32x *out1, PRIVATE_AS u32x *out2);
DECLSPEC void undo_utf16be (PRIVATE_AS const u32x *in1, PRIVATE_AS const u32x *in2, PRIVATE_AS u32x *out);
DECLSPEC void undo_utf16le (PRIVATE_AS const u32x *in1, PRIVATE_AS const u32x *in2, PRIVATE_AS u32x *out);
DECLSPEC void set_mark_1x4 (PRIVATE_AS u32 *v, const u32 offset);
DECLSPEC void append_helper_1x4 (PRIVATE_AS u32x *r, const u32 v, PRIVATE_AS const u32 *m);
DECLSPEC void append_0x80_1x4 (PRIVATE_AS u32x *w0, const u32 offset);
DECLSPEC void append_0x80_2x4 (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, const u32 offset);
DECLSPEC void append_0x80_3x4 (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, const u32 offset);
DECLSPEC void append_0x80_4x4 (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32 offset);
DECLSPEC void append_0x80_8x4 (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const u32 offset);
DECLSPEC void append_0x80_1x16 (PRIVATE_AS u32x *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_le (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_le (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *c0, PRIVATE_AS u32x *c1, PRIVATE_AS u32x *c2, PRIVATE_AS u32x *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_be (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_be (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *c0, PRIVATE_AS u32x *c1, PRIVATE_AS u32x *c2, PRIVATE_AS u32x *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_le (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_le (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, PRIVATE_AS u32x *c0, PRIVATE_AS u32x *c1, PRIVATE_AS u32x *c2, PRIVATE_AS u32x *c3, PRIVATE_AS u32x *c4, PRIVATE_AS u32x *c5, PRIVATE_AS u32x *c6, PRIVATE_AS u32x *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_be (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_be (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, PRIVATE_AS u32x *c0, PRIVATE_AS u32x *c1, PRIVATE_AS u32x *c2, PRIVATE_AS u32x *c3, PRIVATE_AS u32x *c4, PRIVATE_AS u32x *c5, PRIVATE_AS u32x *c6, PRIVATE_AS u32x *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_le (PRIVATE_AS u32x *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_be (PRIVATE_AS u32x *w, const u32 offset);
DECLSPEC void truncate_block_4x4_le_S (PRIVATE_AS u32 *w0, const u32 len);
DECLSPEC void truncate_block_4x4_be_S (PRIVATE_AS u32 *w0, const u32 len);
DECLSPEC void truncate_block_16x4_le_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 len);
DECLSPEC void truncate_block_16x4_be_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 len);
DECLSPEC void set_mark_1x4_S (PRIVATE_AS u32 *v, const u32 offset);
DECLSPEC void append_helper_1x4_S (PRIVATE_AS u32 *r, const u32 v, PRIVATE_AS const u32 *m);
DECLSPEC void append_0x01_2x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, const u32 offset);
DECLSPEC void append_0x06_2x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, const u32 offset);
DECLSPEC void append_0x01_4x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset);
DECLSPEC void append_0x2d_4x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset);
DECLSPEC void append_0x80_1x4_S (PRIVATE_AS u32 *w0, const u32 offset);
DECLSPEC void append_0x80_2x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, const u32 offset);
DECLSPEC void append_0x80_3x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, const u32 offset);
DECLSPEC void append_0x80_4x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset);
DECLSPEC void append_0x80_8x4_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const u32 offset);
DECLSPEC void make_utf16be_S (PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out1, PRIVATE_AS u32 *out2);
DECLSPEC void make_utf16le_S (PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out1, PRIVATE_AS u32 *out2);
DECLSPEC void undo_utf16be_S (PRIVATE_AS const u32 *in1, PRIVATE_AS const u32 *in2, PRIVATE_AS u32 *out);
DECLSPEC void undo_utf16le_S (PRIVATE_AS const u32 *in1, PRIVATE_AS const u32 *in2, PRIVATE_AS u32 *out);
DECLSPEC void switch_buffer_by_offset_le_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_le_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *c0, PRIVATE_AS u32 *c1, PRIVATE_AS u32 *c2, PRIVATE_AS u32 *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_be_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_be_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *c0, PRIVATE_AS u32 *c1, PRIVATE_AS u32 *c2, PRIVATE_AS u32 *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_le_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_le_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, PRIVATE_AS u32 *c0, PRIVATE_AS u32 *c1, PRIVATE_AS u32 *c2, PRIVATE_AS u32 *c3, PRIVATE_AS u32 *c4, PRIVATE_AS u32 *c5, PRIVATE_AS u32 *c6, PRIVATE_AS u32 *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_be_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_be_S (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, PRIVATE_AS u32 *c0, PRIVATE_AS u32 *c1, PRIVATE_AS u32 *c2, PRIVATE_AS u32 *c3, PRIVATE_AS u32 *c4, PRIVATE_AS u32 *c5, PRIVATE_AS u32 *c6, PRIVATE_AS u32 *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_le_S (PRIVATE_AS u32 *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_be_S (PRIVATE_AS u32 *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_le_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32x offset);
DECLSPEC void switch_buffer_by_offset_8x4_le_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const u32x offset);
DECLSPEC void append_0x01_2x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, const u32x offset);
DECLSPEC void append_0x01_4x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32x offset);
DECLSPEC void append_0x06_2x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, const u32x offset);
DECLSPEC void append_0x80_2x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, const u32x offset);
DECLSPEC void append_0x80_4x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32x offset);
DECLSPEC void append_0x2d_4x4_VV (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const u32x offset);

#endif // _INC_COMMON_H
