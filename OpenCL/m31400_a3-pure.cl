/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.h)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.h)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

DECLSPEC void shift_buffer_by_offset(PRIVATE_AS u32 *w0, const u32 offset)
{
    const int offset_switch = offset / 4;

#if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
    switch (offset_switch)
    {
    case 0:
        w0[3] = hc_bytealign_be_S(w0[2], w0[3], offset);
        w0[2] = hc_bytealign_be_S(w0[1], w0[2], offset);
        w0[1] = hc_bytealign_be_S(w0[0], w0[1], offset);
        w0[0] = hc_bytealign_be_S(0, w0[0], offset);
        break;

    case 1:
        w0[3] = hc_bytealign_be_S(w0[1], w0[2], offset);
        w0[2] = hc_bytealign_be_S(w0[0], w0[1], offset);
        w0[1] = hc_bytealign_be_S(0, w0[0], offset);
        w0[0] = 0;
        break;

    case 2:
        w0[3] = hc_bytealign_be_S(w0[0], w0[1], offset);
        w0[2] = hc_bytealign_be_S(0, w0[0], offset);
        w0[1] = 0;
        w0[0] = 0;
        break;

    case 3:
        w0[3] = hc_bytealign_be_S(0, w0[0], offset);
        w0[2] = 0;
        w0[1] = 0;
        w0[0] = 0;
        break;

    default:
        w0[3] = 0;
        w0[2] = 0;
        w0[1] = 0;
        w0[0] = 0;
        break;
    }
#endif

#if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

#if defined IS_NV
    const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;
#endif

#if (defined IS_AMD || defined IS_HIP)
    const int selector = l32_from_64_S(0x0706050403020100UL >> ((offset & 3) * 8));
#endif

    switch (offset_switch)
    {
    case 0:
        w0[3] = hc_byte_perm_S(w0[3], w0[2], selector);
        w0[2] = hc_byte_perm_S(w0[2], w0[1], selector);
        w0[1] = hc_byte_perm_S(w0[1], w0[0], selector);
        w0[0] = hc_byte_perm_S(w0[0], 0, selector);
        break;

    case 1:
        w0[3] = hc_byte_perm_S(w0[2], w0[1], selector);
        w0[2] = hc_byte_perm_S(w0[1], w0[0], selector);
        w0[1] = hc_byte_perm_S(w0[0], 0, selector);
        w0[0] = 0;
        break;

    case 2:
        w0[3] = hc_byte_perm_S(w0[1], w0[0], selector);
        w0[2] = hc_byte_perm_S(w0[0], 0, selector);
        w0[1] = 0;
        w0[0] = 0;
        break;

    case 3:
        w0[3] = hc_byte_perm_S(w0[0], 0, selector);
        w0[2] = 0;
        w0[1] = 0;
        w0[0] = 0;
        break;

    default:
        w0[3] = 0;
        w0[2] = 0;
        w0[1] = 0;
        w0[0] = 0;
        break;
    }
#endif
}

DECLSPEC void aes256_scrt_format(PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32 *pw, const int pw_len, PRIVATE_AS u32 *hash, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
    AES256_set_encrypt_key(aes_ks, hash, s_te0, s_te1, s_te2, s_te3);

    shift_buffer_by_offset(hash, pw_len + 4);

    hash[0] = hc_swap32(pw_len);
    hash[1] |= hc_swap32(pw[0]);
    hash[2] |= hc_swap32(pw[1]);
    hash[3] |= hc_swap32(pw[2]);

    AES256_encrypt(aes_ks, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}
DECLSPEC void aes256_scrt_format_VV(PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32x *w, const int pw_len, PRIVATE_AS u32x *hash, PRIVATE_AS u32x *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
#if VECT_SIZE == 1
    aes256_scrt_format(aes_ks, w, pw_len, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif

#if VECT_SIZE >= 2
    aes256_scrt_format(aes_ks, w.s0, pw_len.s0, hash.s0, out.s0, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s1, pw_len.s1, hash.s1, out.s1, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif

#if VECT_SIZE >= 4
    aes256_scrt_format(aes_ks, w.s2, pw_len.s2, hash.s2, out.s2, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s3, pw_len.s3, hash.s3, out.s3, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif

#if VECT_SIZE >= 8
    aes256_scrt_format(aes_ks, w.s5, pw_len.s5, hash.s5, out.s5, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s6, pw_len.s6, hash.s6, out.s6, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s7, pw_len.s7, hash.s7, out.s7, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s8, pw_len.s8, hash.s8, out.s8, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif

#if VECT_SIZE >= 16
    aes256_scrt_format(aes_ks, w.s9, pw_len.s9, hash.s9, out.s9, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s10, pw_len.s10, hash.s10, out.s10, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s11, pw_len.s11, hash.s11, out.s11, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s12, pw_len.s12, hash.s12, out.s12, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s13, pw_len.s13, hash.s13, out.s13, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s15, pw_len.s15, hash.s15, out.s15, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s16, pw_len.s16, hash.s16, out.s16, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes256_scrt_format(aes_ks, w.s17, pw_len.s17, hash.s17, out.s17, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif
}

KERNEL_FQ void m31400_mxx(KERN_ATTR_VECTOR())
{
    /**
     * modifier
     */

    const u64 lid = get_local_id(0);
    const u64 gid = get_global_id(0);
    const u64 lsz = get_local_size(0);

    /**
     * aes shared
     */

#ifdef REAL_SHM

    LOCAL_VK u32 s_te0[256];
    LOCAL_VK u32 s_te1[256];
    LOCAL_VK u32 s_te2[256];
    LOCAL_VK u32 s_te3[256];
    LOCAL_VK u32 s_te4[256];

    for (u32 i = lid; i < 256; i += lsz)
    {
        s_te0[i] = te0[i];
        s_te1[i] = te1[i];
        s_te2[i] = te2[i];
        s_te3[i] = te3[i];
        s_te4[i] = te4[i];
    }

    SYNC_THREADS();

#else

    CONSTANT_AS u32a *s_te0 = te0;
    CONSTANT_AS u32a *s_te1 = te1;
    CONSTANT_AS u32a *s_te2 = te2;
    CONSTANT_AS u32a *s_te3 = te3;
    CONSTANT_AS u32a *s_te4 = te4;

#endif

    if (gid >= GID_CNT)
        return;

    /**
     * base
     */

    const u32 pw_len = pws[gid].pw_len;

    u32x w[64] = {0};

    for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
    {
        w[idx] = pws[gid].i[idx];
    }

    u32 aes_ks[60];

    /**
     * loop
     */

    u32x w0l = w[0];

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
        const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

        const u32x w0 = w0l | w0r;

        w[0] = w0;

        sha256_ctx_vector_t ctx;

        sha256_init_vector(&ctx);

        sha256_update_vector_swap(&ctx, w, pw_len);

        sha256_final_vector(&ctx);

        u32x out[4] = {0};

        aes256_scrt_format_VV(aes_ks, w, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

        const u32x r0 = out[DGST_R0];
        const u32x r1 = out[DGST_R1];
        const u32x r2 = out[DGST_R2];
        const u32x r3 = out[DGST_R3];

        COMPARE_M_SIMD(r0, r1, r2, r3);
    }
}

KERNEL_FQ void m31400_sxx(KERN_ATTR_VECTOR())
{
    /**
     * modifier
     */

    const u64 lid = get_local_id(0);
    const u64 gid = get_global_id(0);
    const u64 lsz = get_local_size(0);

    /**
     * aes shared
     */

#ifdef REAL_SHM

    LOCAL_VK u32 s_te0[256];
    LOCAL_VK u32 s_te1[256];
    LOCAL_VK u32 s_te2[256];
    LOCAL_VK u32 s_te3[256];
    LOCAL_VK u32 s_te4[256];

    for (u32 i = lid; i < 256; i += lsz)
    {
        s_te0[i] = te0[i];
        s_te1[i] = te1[i];
        s_te2[i] = te2[i];
        s_te3[i] = te3[i];
        s_te4[i] = te4[i];
    }

    SYNC_THREADS();

#else

    CONSTANT_AS u32a *s_te0 = te0;
    CONSTANT_AS u32a *s_te1 = te1;
    CONSTANT_AS u32a *s_te2 = te2;
    CONSTANT_AS u32a *s_te3 = te3;
    CONSTANT_AS u32a *s_te4 = te4;

#endif

    if (gid >= GID_CNT)
        return;
    /**
     * digest
     */

    const u32 search[4] =
        {
            digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
            digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
            digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
            digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]};

    /**
     * base
     */

    const u32 pw_len = pws[gid].pw_len;

    u32x w[64] = {0};

    for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
    {
        w[idx] = pws[gid].i[idx];
    }

    /**
     * loop
     */

    u32 aes_ks[60];
    u32x w0l = w[0];

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
        const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

        const u32x w0 = w0l | w0r;

        w[0] = w0;

        sha256_ctx_vector_t ctx;

        sha256_init_vector(&ctx);

        sha256_update_vector_swap(&ctx, w, pw_len);

        sha256_final_vector(&ctx);

        u32x out[4] = {0};

        aes256_scrt_format_VV(aes_ks, w, pw_len, ctx.h, out, s_te0, s_te1, s_te2, s_te3, s_te4);

        const u32x r0 = out[DGST_R0];
        const u32x r1 = out[DGST_R1];
        const u32x r2 = out[DGST_R2];
        const u32x r3 = out[DGST_R3];

        COMPARE_S_SIMD(r0, r1, r2, r3);
    }
}
