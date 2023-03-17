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

DECLSPEC void aes256_scrt_format(PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32 *pw, PRIVATE_AS u32 pw_len, PRIVATE_AS u32 *hash, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
    AES256_set_encrypt_key(aes_ks, hash, s_te0, s_te1, s_te2, s_te3);

    shift_buffer_by_offset(hash, pw_len + 4);

    hash[0] = hc_swap32_S(pw_len);
    hash[1] |= hc_swap32_S(pw[0]);
    hash[2] |= hc_swap32_S(pw[1]);
    hash[3] |= hc_swap32_S(pw[2]);

    AES256_encrypt(aes_ks, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}
DECLSPEC void aes256_scrt_format_VV(PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32x *w, PRIVATE_AS u32x pw_len, PRIVATE_AS u32x *hash, PRIVATE_AS u32x *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
#if VECT_SIZE == 1
    aes256_scrt_format(aes_ks, w, pw_len, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
#endif

#if VECT_SIZE >= 2

    u32 tmp_w[4];
    u32 tmp_hash[4];
    u32 tmp_out[4];
    u32 tmp_pw_len;

    //s0
    tmp_w[0] = w[0].s0;
    tmp_w[1] = w[1].s0;
    tmp_w[2] = w[2].s0;
    tmp_w[3] = w[3].s0;

    tmp_hash[0] = hash[0].s0;
    tmp_hash[1] = hash[1].s0;
    tmp_hash[2] = hash[2].s0;
    tmp_hash[3] = hash[3].s0;

    tmp_pw_len = pw_len.s0;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, hash.s0, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s0 = tmp_out[0];
    out[1].s0 = tmp_out[1];
    out[2].s0 = tmp_out[2];
    out[3].s0 = tmp_out[3];


    //s1
    tmp_w[0] = w[0].s1;
    tmp_w[1] = w[1].s1;
    tmp_w[2] = w[2].s1;
    tmp_w[3] = w[3].s1;

    tmp_hash[0] = hash[0].s1;
    tmp_hash[1] = hash[1].s1;
    tmp_hash[2] = hash[2].s1;
    tmp_hash[3] = hash[3].s1;

    tmp_pw_len = pw_len.s1;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, hash.s1, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s1 = tmp_out[0];
    out[1].s1 = tmp_out[1];
    out[2].s1 = tmp_out[2];
    out[3].s1 = tmp_out[3];


#endif

#if VECT_SIZE >= 4
    //s2
    tmp_w[0] = w[0].s2;
    tmp_w[1] = w[1].s2;
    tmp_w[2] = w[2].s2;
    tmp_w[3] = w[3].s2;

    tmp_hash[0] = hash[0].s2;
    tmp_hash[1] = hash[1].s2;
    tmp_hash[2] = hash[2].s2;
    tmp_hash[3] = hash[3].s2;

    tmp_pw_len = pw_len.s2;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s2 = tmp_out[0];
    out[1].s2 = tmp_out[1];
    out[2].s2 = tmp_out[2];
    out[3].s2 = tmp_out[3];


    //s3
    tmp_w[0] = w[0].s3;
    tmp_w[1] = w[1].s3;
    tmp_w[2] = w[2].s3;
    tmp_w[3] = w[3].s3;

    tmp_hash[0] = hash[0].s3;
    tmp_hash[1] = hash[1].s3;
    tmp_hash[2] = hash[2].s3;
    tmp_hash[3] = hash[3].s3;

    tmp_pw_len = pw_len.s3;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s3 = tmp_out[0];
    out[1].s3 = tmp_out[1];
    out[2].s3 = tmp_out[2];
    out[3].s3 = tmp_out[3];


#endif

#if VECT_SIZE >= 8
    //s4
    tmp_w[0] = w[0].s4;
    tmp_w[1] = w[1].s4;
    tmp_w[2] = w[2].s4;
    tmp_w[3] = w[3].s4;

    tmp_hash[0] = hash[0].s4;
    tmp_hash[1] = hash[1].s4;
    tmp_hash[2] = hash[2].s4;
    tmp_hash[3] = hash[3].s4;

    tmp_pw_len = pw_len.s4;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s4 = tmp_out[0];
    out[1].s4 = tmp_out[1];
    out[2].s4 = tmp_out[2];
    out[3].s4 = tmp_out[3];


    //s5
    tmp_w[0] = w[0].s5;
    tmp_w[1] = w[1].s5;
    tmp_w[2] = w[2].s5;
    tmp_w[3] = w[3].s5;

    tmp_hash[0] = hash[0].s5;
    tmp_hash[1] = hash[1].s5;
    tmp_hash[2] = hash[2].s5;
    tmp_hash[3] = hash[3].s5;

    tmp_pw_len = pw_len.s5;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s5 = tmp_out[0];
    out[1].s5 = tmp_out[1];
    out[2].s5 = tmp_out[2];
    out[3].s5 = tmp_out[3];


    //s6
    tmp_w[0] = w[0].s6;
    tmp_w[1] = w[1].s6;
    tmp_w[2] = w[2].s6;
    tmp_w[3] = w[3].s6;

    tmp_hash[0] = hash[0].s6;
    tmp_hash[1] = hash[1].s6;
    tmp_hash[2] = hash[2].s6;
    tmp_hash[3] = hash[3].s6;

    tmp_pw_len = pw_len.s6;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s6 = tmp_out[0];
    out[1].s6 = tmp_out[1];
    out[2].s6 = tmp_out[2];
    out[3].s6 = tmp_out[3];


    //s7
    tmp_w[0] = w[0].s7;
    tmp_w[1] = w[1].s7;
    tmp_w[2] = w[2].s7;
    tmp_w[3] = w[3].s7;

    tmp_hash[0] = hash[0].s7;
    tmp_hash[1] = hash[1].s7;
    tmp_hash[2] = hash[2].s7;
    tmp_hash[3] = hash[3].s7;

    tmp_pw_len = pw_len.s7;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s7 = tmp_out[0];
    out[1].s7 = tmp_out[1];
    out[2].s7 = tmp_out[2];
    out[3].s7 = tmp_out[3];

#endif

#if VECT_SIZE >= 16

    //s8
    tmp_w[0] = w[0].s8;
    tmp_w[1] = w[1].s8;
    tmp_w[2] = w[2].s8;
    tmp_w[3] = w[3].s8;

    tmp_hash[0] = hash[0].s8;
    tmp_hash[1] = hash[1].s8;
    tmp_hash[2] = hash[2].s8;
    tmp_hash[3] = hash[3].s8;

    tmp_pw_len = pw_len.s8;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s8 = tmp_out[0];
    out[1].s8 = tmp_out[1];
    out[2].s8 = tmp_out[2];
    out[3].s8 = tmp_out[3];


    //s9
    tmp_w[0] = w[0].s9;
    tmp_w[1] = w[1].s9;
    tmp_w[2] = w[2].s9;
    tmp_w[3] = w[3].s9;


    tmp_hash[0] = hash[0].s9;
    tmp_hash[1] = hash[1].s9;
    tmp_hash[2] = hash[2].s9;
    tmp_hash[3] = hash[3].s9;

    tmp_pw_len = pw_len.s9;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s9 = tmp_out[0];
    out[1].s9 = tmp_out[1];
    out[2].s9 = tmp_out[2];
    out[3].s9 = tmp_out[3];


    //s10
    tmp_w[0] = w[0].s10;
    tmp_w[1] = w[1].s10;
    tmp_w[2] = w[2].s10;
    tmp_w[3] = w[3].s10;


    tmp_hash[0] = hash[0].s10;
    tmp_hash[1] = hash[1].s10;
    tmp_hash[2] = hash[2].s10;
    tmp_hash[3] = hash[3].s10;

    tmp_pw_len = pw_len.s10;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s10 = tmp_out[0];
    out[1].s10 = tmp_out[1];
    out[2].s10 = tmp_out[2];
    out[3].s10 = tmp_out[3];


    //s11
    tmp_w[0] = w[0].s11;
    tmp_w[1] = w[1].s11;
    tmp_w[2] = w[2].s11;
    tmp_w[3] = w[3].s11;


    tmp_hash[0] = hash[0].s11;
    tmp_hash[1] = hash[1].s11;
    tmp_hash[2] = hash[2].s11;
    tmp_hash[3] = hash[3].s11;

    tmp_pw_len = pw_len.s11;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s11 = tmp_out[0];
    out[1].s11 = tmp_out[1];
    out[2].s11 = tmp_out[2];
    out[3].s11 = tmp_out[3];


    //s12
    tmp_w[0] = w[0].s12;
    tmp_w[1] = w[1].s12;
    tmp_w[2] = w[2].s12;
    tmp_w[3] = w[3].s12;


    tmp_hash[0] = hash[0].s12;
    tmp_hash[1] = hash[1].s12;
    tmp_hash[2] = hash[2].s12;
    tmp_hash[3] = hash[3].s12;

    tmp_pw_len = pw_len.s12;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s12 = tmp_out[0];
    out[1].s12 = tmp_out[1];
    out[2].s12 = tmp_out[2];
    out[3].s12 = tmp_out[3];


    //s13
    tmp_w[0] = w[0].s13;
    tmp_w[1] = w[1].s13;
    tmp_w[2] = w[2].s13;
    tmp_w[3] = w[3].s13;


    tmp_hash[0] = hash[0].s13;
    tmp_hash[1] = hash[1].s13;
    tmp_hash[2] = hash[2].s13;
    tmp_hash[3] = hash[3].s13;

    tmp_pw_len = pw_len.s13;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s13 = tmp_out[0];
    out[1].s13 = tmp_out[1];
    out[2].s13 = tmp_out[2];
    out[3].s13 = tmp_out[3];

     //s14
    tmp_w[0] = w[0].s14;
    tmp_w[1] = w[1].s14;
    tmp_w[2] = w[2].s14;
    tmp_w[3] = w[3].s14;

    tmp_hash[0] = hash[0].s14;
    tmp_hash[1] = hash[1].s14;
    tmp_hash[2] = hash[2].s14;
    tmp_hash[3] = hash[3].s14;


    tmp_pw_len = pw_len.s14;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s14 = tmp_out[0];
    out[1].s14 = tmp_out[1];
    out[2].s14 = tmp_out[2];
    out[3].s14 = tmp_out[3];


    //s15
    tmp_w[0] = w[0].s15;
    tmp_w[1] = w[1].s15;
    tmp_w[2] = w[2].s15;
    tmp_w[3] = w[3].s15;


    tmp_hash[0] = hash[0].s15;
    tmp_hash[1] = hash[1].s15;
    tmp_hash[2] = hash[2].s15;
    tmp_hash[3] = hash[3].s15;

    tmp_pw_len = pw_len.s15;

    aes256_scrt_format(aes_ks, tmp_w, tmp_pw_len, tmp_hash, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

    out[0].s15 = tmp_out[0];
    out[1].s15 = tmp_out[1];
    out[2].s15 = tmp_out[2];
    out[3].s15 = tmp_out[3];


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
