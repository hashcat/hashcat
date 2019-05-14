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

#ifdef IS_CUDA
#define KERN_ATTR(p2,p4,p5,p6,p19)                              \
  MAYBE_UNUSED GLOBAL_AS       pw_t          *pws,              \
  MAYBE_UNUSED p2        const kernel_rule_t *g_rules_buf,      \
  MAYBE_UNUSED GLOBAL_AS const pw_t          *combs_buf,        \
  MAYBE_UNUSED p4,                                              \
  MAYBE_UNUSED GLOBAL_AS p5                  *tmps,             \
  MAYBE_UNUSED GLOBAL_AS p6                  *hooks,            \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_a, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_b, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_c, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_d, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_a, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_b, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_c, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_d, \
  MAYBE_UNUSED GLOBAL_AS       plain_t       *plains_buf,       \
  MAYBE_UNUSED GLOBAL_AS const digest_t      *digests_buf,      \
  MAYBE_UNUSED GLOBAL_AS       u32           *hashes_shown,     \
  MAYBE_UNUSED GLOBAL_AS const salt_t        *salt_bufs,        \
  MAYBE_UNUSED GLOBAL_AS const p19           *esalt_bufs,       \
  MAYBE_UNUSED GLOBAL_AS       u32           *d_return_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra0_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra1_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra2_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra3_buf,     \
  MAYBE_UNUSED           const u32            bitmap_mask,      \
  MAYBE_UNUSED           const u32            bitmap_shift1,    \
  MAYBE_UNUSED           const u32            bitmap_shift2,    \
  MAYBE_UNUSED           const u32            salt_pos,         \
  MAYBE_UNUSED           const u32            loop_pos,         \
  MAYBE_UNUSED           const u32            loop_cnt,         \
  MAYBE_UNUSED           const u32            il_cnt,           \
  MAYBE_UNUSED           const u32            digests_cnt,      \
  MAYBE_UNUSED           const u32            digests_offset,   \
  MAYBE_UNUSED           const u32            combs_mode,       \
  MAYBE_UNUSED           const u64            gid_max
#else
#define KERN_ATTR(p2,p4,p5,p6,p19)                              \
  MAYBE_UNUSED GLOBAL_AS       pw_t          *pws,              \
  MAYBE_UNUSED p2        const kernel_rule_t *rules_buf,        \
  MAYBE_UNUSED GLOBAL_AS const pw_t          *combs_buf,        \
  MAYBE_UNUSED p4,                                              \
  MAYBE_UNUSED GLOBAL_AS p5                  *tmps,             \
  MAYBE_UNUSED GLOBAL_AS p6                  *hooks,            \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_a, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_b, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_c, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s1_d, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_a, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_b, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_c, \
  MAYBE_UNUSED GLOBAL_AS const u32           *bitmaps_buf_s2_d, \
  MAYBE_UNUSED GLOBAL_AS       plain_t       *plains_buf,       \
  MAYBE_UNUSED GLOBAL_AS const digest_t      *digests_buf,      \
  MAYBE_UNUSED GLOBAL_AS       u32           *hashes_shown,     \
  MAYBE_UNUSED GLOBAL_AS const salt_t        *salt_bufs,        \
  MAYBE_UNUSED GLOBAL_AS const p19           *esalt_bufs,       \
  MAYBE_UNUSED GLOBAL_AS       u32           *d_return_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra0_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra1_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra2_buf,     \
  MAYBE_UNUSED GLOBAL_AS       void          *d_extra3_buf,     \
  MAYBE_UNUSED           const u32            bitmap_mask,      \
  MAYBE_UNUSED           const u32            bitmap_shift1,    \
  MAYBE_UNUSED           const u32            bitmap_shift2,    \
  MAYBE_UNUSED           const u32            salt_pos,         \
  MAYBE_UNUSED           const u32            loop_pos,         \
  MAYBE_UNUSED           const u32            loop_cnt,         \
  MAYBE_UNUSED           const u32            il_cnt,           \
  MAYBE_UNUSED           const u32            digests_cnt,      \
  MAYBE_UNUSED           const u32            digests_offset,   \
  MAYBE_UNUSED           const u32            combs_mode,       \
  MAYBE_UNUSED           const u64            gid_max
#endif
/*
 * Shortcut macros for usage in the actual kernels
 *
 * Not all possible combinations are needed. E.g. all kernels that use rules
 * do not use the tmps pointer, all kernels that use a vector pointer in P4
 * do not use rules or tmps, etc.
 */

#ifdef IS_CUDA
#define KERN_ATTR_BASIC()         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, void)
#define KERN_ATTR_BITSLICE()      KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bs_word_t *g_words_buf_s, void, void, void)
#define KERN_ATTR_ESALT(e)        KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, e)
#define KERN_ATTR_RULES()         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, void)
#define KERN_ATTR_RULES_ESALT(e)  KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     void, void, e)
#define KERN_ATTR_TMPS(t)         KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    void, void)
#define KERN_ATTR_TMPS_ESALT(t,e) KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    void, e)
#define KERN_ATTR_TMPS_HOOKS(t,h) KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const bf_t      *g_bfs_buf,     t,    h,    void)
#define KERN_ATTR_VECTOR()        KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const u32x      *g_words_buf_r, void, void, void)
#define KERN_ATTR_VECTOR_ESALT(e) KERN_ATTR (GLOBAL_AS,   GLOBAL_AS   const u32x      *g_words_buf_r, void, void, e)
#else
#define KERN_ATTR_BASIC()         KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       void, void, void)
#define KERN_ATTR_BITSLICE()      KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bs_word_t *words_buf_s,   void, void, void)
#define KERN_ATTR_ESALT(e)        KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       void, void, e)
#define KERN_ATTR_RULES()         KERN_ATTR (CONSTANT_AS, GLOBAL_AS   const bf_t      *bfs_buf,       void, void, void)
#define KERN_ATTR_RULES_ESALT(e)  KERN_ATTR (CONSTANT_AS, GLOBAL_AS   const bf_t      *bfs_buf,       void, void, e)
#define KERN_ATTR_TMPS(t)         KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    void, void)
#define KERN_ATTR_TMPS_ESALT(t,e) KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    void, e)
#define KERN_ATTR_TMPS_HOOKS(t,h) KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const bf_t      *bfs_buf,       t,    h,    void)
#define KERN_ATTR_VECTOR()        KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const u32x      *words_buf_r,   void, void, void)
#define KERN_ATTR_VECTOR_ESALT(e) KERN_ATTR (GLOBAL_AS,   CONSTANT_AS const u32x      *words_buf_r,   void, void, e)
#endif

// union based packing

DECLSPEC u8 v8a_from_v32_S   (const u32 v32);
DECLSPEC u8 v8b_from_v32_S   (const u32 v32);
DECLSPEC u8 v8c_from_v32_S   (const u32 v32);
DECLSPEC u8 v8d_from_v32_S   (const u32 v32);

DECLSPEC u16 v16a_from_v32_S (const u32 v32);
DECLSPEC u16 v16b_from_v32_S (const u32 v32);

DECLSPEC u32 v32a_from_v64_S (const u64 v64);
DECLSPEC u32 v32b_from_v64_S (const u64 v64);

DECLSPEC u32 v32_from_v16ab_S (const u16 v16a, const u16 v16b);
DECLSPEC u64 v64_from_v32ab_S (const u32 v32a, const u32 v32b);

// inline asm packing

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
DECLSPEC int hash_comp (const u32 *d1, GLOBAL_AS const u32 *d2);
DECLSPEC int find_hash (const u32 *digest, const u32 digests_cnt, GLOBAL_AS const digest_t *digests_buf);
#endif

DECLSPEC u32 check_bitmap (GLOBAL_AS const u32 *bitmap, const u32 bitmap_mask, const u32 bitmap_shift, const u32 digest);
DECLSPEC u32 check (const u32 *digest, GLOBAL_AS const u32 *bitmap_s1_a, GLOBAL_AS const u32 *bitmap_s1_b, GLOBAL_AS const u32 *bitmap_s1_c, GLOBAL_AS const u32 *bitmap_s1_d, GLOBAL_AS const u32 *bitmap_s2_a, GLOBAL_AS const u32 *bitmap_s2_b, GLOBAL_AS const u32 *bitmap_s2_c, GLOBAL_AS const u32 *bitmap_s2_d, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2);
DECLSPEC void mark_hash (GLOBAL_AS plain_t *plains_buf, GLOBAL_AS u32 *d_result, const u32 salt_pos, const u32 digests_cnt, const u32 digest_pos, const u32 hash_pos, const u64 gid, const u32 il_pos, const u32 extra1, const u32 extra2);
DECLSPEC int hc_count_char (const u32 *buf, const int elems, const u32 c);
DECLSPEC float hc_get_entropy (const u32 *buf, const int elems);
DECLSPEC int is_valid_hex_8 (const u8 v);
DECLSPEC int is_valid_hex_32 (const u32 v);
DECLSPEC int is_valid_base58_8 (const u8 v);
DECLSPEC int is_valid_base58_32 (const u32 v);
DECLSPEC int hc_find_keyboard_layout_map (const u32 search, const int search_len, LOCAL_AS keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt);
DECLSPEC int hc_execute_keyboard_layout_mapping (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const int pw_len, LOCAL_AS keyboard_layout_mapping_t *s_keyboard_layout_mapping_buf, const int keyboard_layout_mapping_cnt);
DECLSPEC void make_utf16be (const u32x *in, u32x *out1, u32x *out2);
DECLSPEC void make_utf16beN (const u32x *in, u32x *out1, u32x *out2);
DECLSPEC void make_utf16le (const u32x *in, u32x *out1, u32x *out2);
DECLSPEC void make_utf16leN (const u32x *in, u32x *out1, u32x *out2);
DECLSPEC void undo_utf16be (const u32x *in1, const u32x *in2, u32x *out);
DECLSPEC void undo_utf16le (const u32x *in1, const u32x *in2, u32x *out);
DECLSPEC void set_mark_1x4 (u32 *v, const u32 offset);
DECLSPEC void append_helper_1x4 (u32x *r, const u32 v, const u32 *m);
DECLSPEC void append_0x80_1x4 (u32x *w0, const u32 offset);
DECLSPEC void append_0x80_2x4 (u32x *w0, u32x *w1, const u32 offset);
DECLSPEC void append_0x80_3x4 (u32x *w0, u32x *w1, u32x *w2, const u32 offset);
DECLSPEC void append_0x80_4x4 (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32 offset);
DECLSPEC void append_0x80_8x4 (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const u32 offset);
DECLSPEC void append_0x80_1x16 (u32x *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_le (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_le (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *c0, u32x *c1, u32x *c2, u32x *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_be (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_be (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *c0, u32x *c1, u32x *c2, u32x *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_le (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_be (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_be (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, u32x *c0, u32x *c1, u32x *c2, u32x *c3, u32x *c4, u32x *c5, u32x *c6, u32x *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_le (u32x *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_be (u32x *w, const u32 offset);
DECLSPEC void truncate_block_4x4_le_S (u32 *w0, const u32 len);
DECLSPEC void truncate_block_4x4_be_S (u32 *w0, const u32 len);
DECLSPEC void truncate_block_16x4_le_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 len);
DECLSPEC void truncate_block_16x4_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 len);
DECLSPEC void set_mark_1x4_S (u32 *v, const u32 offset);
DECLSPEC void append_helper_1x4_S (u32 *r, const u32 v, const u32 *m);
DECLSPEC void append_0x01_2x4_S (u32 *w0, u32 *w1, const u32 offset);
DECLSPEC void append_0x06_2x4_S (u32 *w0, u32 *w1, const u32 offset);
DECLSPEC void append_0x01_4x4_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset);
DECLSPEC void append_0x80_1x4_S (u32 *w0, const u32 offset);
DECLSPEC void append_0x80_2x4_S (u32 *w0, u32 *w1, const u32 offset);
DECLSPEC void append_0x80_3x4_S (u32 *w0, u32 *w1, u32 *w2, const u32 offset);
DECLSPEC void append_0x80_4x4_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset);
DECLSPEC void append_0x80_8x4_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const u32 offset);
DECLSPEC void make_utf16be_S (const u32 *in, u32 *out1, u32 *out2);
DECLSPEC void make_utf16le_S (const u32 *in, u32 *out1, u32 *out2);
DECLSPEC void undo_utf16be_S (const u32 *in1, const u32 *in2, u32 *out);
DECLSPEC void undo_utf16le_S (const u32 *in1, const u32 *in2, u32 *out);
DECLSPEC void switch_buffer_by_offset_le_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_le_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *c0, u32 *c1, u32 *c2, u32 *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_carry_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *c0, u32 *c1, u32 *c2, u32 *c3, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_le_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_8x4_carry_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, u32 *c0, u32 *c1, u32 *c2, u32 *c3, u32 *c4, u32 *c5, u32 *c6, u32 *c7, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_le_S (u32 *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_1x64_be_S (u32 *w, const u32 offset);
DECLSPEC void switch_buffer_by_offset_le_VV (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32x offset);
DECLSPEC void switch_buffer_by_offset_8x4_le_VV (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const u32x offset);
DECLSPEC void append_0x01_2x4_VV (u32x *w0, u32x *w1, const u32x offset);
DECLSPEC void append_0x01_4x4_VV (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32x offset);
DECLSPEC void append_0x06_2x4_VV (u32x *w0, u32x *w1, const u32x offset);
DECLSPEC void append_0x80_2x4_VV (u32x *w0, u32x *w1, const u32x offset);
DECLSPEC void append_0x80_4x4_VV (u32x *w0, u32x *w1, u32x *w2, u32x *w3, const u32x offset);
DECLSPEC void gpu_decompress_entry (GLOBAL_AS pw_idx_t *pws_idx, GLOBAL_AS u32 *pws_comp, pw_t *pw, const u64 gid);

#endif
