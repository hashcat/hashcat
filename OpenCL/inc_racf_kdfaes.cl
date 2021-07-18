#if VECT_SIZE != 1
  #error "The implementation of the RACF-KDFAES algorithm is currently not vectorized. Please set VECTOR_SIZE to 1 via the --opencl-vector-width parameter or via an entry in the hashcat.hctune file. If you want to vectorize the code instead, this probably only requires replacing a lot of u32's by u32x .
#endif

#include "m08500_a0-pure.cl"
#include "inc_cipher_aes.cl"
#include "inc_hash_sha256.cl"

DECLSPEC void hmac_sha256_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0]; digest[1] = ipad[1]; digest[2] = ipad[2]; digest[3] = ipad[3];
  digest[4] = ipad[4]; digest[5] = ipad[5]; digest[6] = ipad[6]; digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0]; w0[1] = digest[1]; w0[2] = digest[2]; w0[3] = digest[3];
  w1[0] = digest[4]; w1[1] = digest[5]; w1[2] = digest[6]; w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0; w2[2] = 0; w2[3] = 0; w3[0] = 0; w3[1] = 0; w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0]; digest[1] = opad[1]; digest[2] = opad[2]; digest[3] = opad[3];
  digest[4] = opad[4]; digest[5] = opad[5]; digest[6] = opad[6]; digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

#define HMAC_IPAD_MASK (0x36363636)
#define HMAC_OPAD_MASK (0x5c5c5c5c)
#define SHA256_END_OF_INPUT (0x80000000)

#define HMAC_SHA256_ITERATIONS 5000 
#define ACCUMULATOR_SIZE 8

#define IP_INV(l, r, tt)              \
{                                     \
  PERM_OP(r, l, tt,  1, 0x55555555); PERM_OP(l, r, tt,  8, 0x00ff00ff); PERM_OP(r, l, tt,  2, 0x33333333); PERM_OP(l, r, tt, 16, 0x0000ffff); PERM_OP(r, l, tt,  4, 0x0f0f0f0f);  \
}

DECLSPEC void racf_kdfaes_des(u32 *username, u32 *password, u32 *output, LOCAL_AS u32 (*s_SPtrans)[64], LOCAL_AS u32 (*s_skb)[64])
{
  u32 key[2], Kc[16], Kd[16], temp_output[2], tt, data[2];
  transform_racf_key (password[0], password[1], key);
  const u32 c = key[0];
  const u32 d = key[1];
  _des_crypt_keysetup (c, d, Kc, Kd, s_skb);
  data[0] = username[0];
  data[1] = username[1];
  IP(data[0], data[1], tt);
  data[0] = hc_rotl32_S(data[0], 3u);
  data[1] = hc_rotl32_S(data[1], 3u);
  
  _des_crypt_encrypt (temp_output, data, Kc, Kd, s_SPtrans);
  temp_output[0] = hc_rotl32_S(temp_output[0], 29u);
  temp_output[1] = hc_rotl32_S(temp_output[1], 29u);
  IP_INV(temp_output[0], temp_output[1], tt);
  
  output[0] = hc_swap32_S(temp_output[0]);
  output[1] = hc_swap32_S(temp_output[1]);
}

#define COPY_4(from, to, from_idx, to_idx) \
  to[to_idx + 0] = from[from_idx + 0];     \
  to[to_idx + 1] = from[from_idx + 1];     \
  to[to_idx + 2] = from[from_idx + 2];     \
  to[to_idx + 3] = from[from_idx + 3];     
#define COPY_8(from, to, from_idx, to_idx) \
  to[to_idx + 0] = from[from_idx + 0];     \
  to[to_idx + 1] = from[from_idx + 1];     \
  to[to_idx + 2] = from[from_idx + 2];     \
  to[to_idx + 3] = from[from_idx + 3];     \
  to[to_idx + 4] = from[from_idx + 4];     \
  to[to_idx + 5] = from[from_idx + 5];     \
  to[to_idx + 6] = from[from_idx + 6];     \
  to[to_idx + 7] = from[from_idx + 7];     
#define SET_2(arr, start_idx, value)       \
  arr[start_idx + 0] = value;              \
  arr[start_idx + 1] = value;
#define SET_3(arr, start_idx, value)       \
  arr[start_idx + 0] = value;              \
  arr[start_idx + 1] = value;              \
  arr[start_idx + 2] = value;
#define SET_4(arr, start_idx, value)       \
  arr[start_idx + 0] = value;              \
  arr[start_idx + 1] = value;              \
  arr[start_idx + 2] = value;              \
  arr[start_idx + 3] = value;
#define HMAC_SHA256_FINALIZE_OPAD(precomputed_opad, ipad_out, sha256_ctx, output)              \
  COPY_4(ipad_out, sha256_ctx->w0, 0, 0);                                                      \
  COPY_4(ipad_out, sha256_ctx->w1, 4, 0);                                                      \
  sha256_ctx->w2[0] = SHA256_END_OF_INPUT;                                                     \
  SET_3(sha256_ctx->w2, 1, 0);                                                                 \
  SET_3(sha256_ctx->w3, 0, 0);                                                                 \
  sha256_ctx->w3[3] = (64 + 32) * 8;                                                           \
  COPY_8(precomputed_opad, output, 0, 0);                                                      \
  sha256_transform(sha256_ctx->w0, sha256_ctx->w1, sha256_ctx->w2, sha256_ctx->w3, output);
  
DECLSPEC void sha256_init_h(u32 h[8])
{
  h[0] = SHA256M_A; h[1] = SHA256M_B; h[2] = SHA256M_C; h[3] = SHA256M_D;
  h[4] = SHA256M_E; h[5] = SHA256M_F; h[6] = SHA256M_G; h[7] = SHA256M_H;
}

DECLSPEC void _sha256_hmac_init_8(const u32 *key, sha256_ctx_t * sha256_ctx, u32 *ipad_buf, u32 *opad_buf)
{
  sha256_ctx->w0[0] = key[0] ^ HMAC_IPAD_MASK;
  sha256_ctx->w0[1] = key[1] ^ HMAC_IPAD_MASK;
  sha256_ctx->w0[2] = HMAC_IPAD_MASK;
  sha256_ctx->w0[3] = HMAC_IPAD_MASK;
  SET_4(sha256_ctx->w1, 0, HMAC_IPAD_MASK);
  SET_4(sha256_ctx->w2, 0, HMAC_IPAD_MASK);
  SET_4(sha256_ctx->w3, 0, HMAC_IPAD_MASK);
  sha256_init_h(ipad_buf);
  sha256_transform(sha256_ctx->w0, sha256_ctx->w1, sha256_ctx->w2, sha256_ctx->w3, ipad_buf);

  sha256_ctx->w0[0] = key[0] ^ HMAC_OPAD_MASK;
  sha256_ctx->w0[1] = key[1] ^ HMAC_OPAD_MASK;
  sha256_ctx->w0[2] = HMAC_OPAD_MASK;
  sha256_ctx->w0[3] = HMAC_OPAD_MASK;
  SET_4(sha256_ctx->w1, 0, HMAC_OPAD_MASK);
  SET_4(sha256_ctx->w2, 0, HMAC_OPAD_MASK);
  SET_4(sha256_ctx->w3, 0, HMAC_OPAD_MASK);
  sha256_init_h(opad_buf);
  sha256_transform(sha256_ctx->w0, sha256_ctx->w1, sha256_ctx->w2, sha256_ctx->w3, opad_buf);
}

DECLSPEC void _experimental_sha256_hmac_init_short_4(const u32 * key, const u32 key_length, sha256_ctx_t * sha256_ctx, u32 *ipad_buf, u32 *opad_buf)
{
  // optimization: we don't call sha256_init_h and sha256_transform on sha256_ctx->h at all
  // (which would be the sane thing to do), but instead use ipad_buf and opad_buf directly.
  // This way, we save the effort of copying from sha256_ctx->h to ipad_buf/opad_buf.
  
  #pragma unroll
  for (int j = 0; j < 4; j++) {
    u32 key_length_divided_by_4 = key_length >> 2;
    sha256_ctx->w0[j] = (key_length_divided_by_4 > (j +  0)) ? key[j +  0] ^ HMAC_IPAD_MASK : HMAC_IPAD_MASK;
    sha256_ctx->w1[j] = (key_length_divided_by_4 > (j +  4)) ? key[j +  4] ^ HMAC_IPAD_MASK : HMAC_IPAD_MASK;
    sha256_ctx->w2[j] = (key_length_divided_by_4 > (j +  8)) ? key[j +  8] ^ HMAC_IPAD_MASK : HMAC_IPAD_MASK;
    sha256_ctx->w3[j] = (key_length_divided_by_4 > (j + 12)) ? key[j + 12] ^ HMAC_IPAD_MASK : HMAC_IPAD_MASK;
  }
  sha256_init_h(ipad_buf);
  sha256_transform(sha256_ctx->w0, sha256_ctx->w1, sha256_ctx->w2, sha256_ctx->w3, ipad_buf);
  
  #pragma unroll
  for (int j = 0; j < 4; j++) {
    u32 key_length_divided_by_4 = key_length >> 2;
    sha256_ctx->w0[j] = (key_length_divided_by_4 > (j +  0)) ? key[j +  0] ^ HMAC_OPAD_MASK : HMAC_OPAD_MASK;
    sha256_ctx->w1[j] = (key_length_divided_by_4 > (j +  4)) ? key[j +  4] ^ HMAC_OPAD_MASK : HMAC_OPAD_MASK;
    sha256_ctx->w2[j] = (key_length_divided_by_4 > (j +  8)) ? key[j +  8] ^ HMAC_OPAD_MASK : HMAC_OPAD_MASK;
    sha256_ctx->w3[j] = (key_length_divided_by_4 > (j + 12)) ? key[j + 12] ^ HMAC_OPAD_MASK : HMAC_OPAD_MASK;
  }
  sha256_init_h(opad_buf);
  sha256_transform(sha256_ctx->w0, sha256_ctx->w1, sha256_ctx->w2, sha256_ctx->w3, opad_buf);
}

DECLSPEC void _experimental_pbkdf2_hmac_sha256_loop(u32 *precomputed_ipad, u32 *precomputed_opad, u32 iterations, u32 *output, u32 *intermediate_output)
{
  u32 h_buffer1[8], h_buffer2[8];
  const u32 w2[4] = { SHA256_END_OF_INPUT, 0, 0, 0 };
  const u32 w3[4] = { 0, 0, 0, (64 + 32) * 8 };
  u32 *source0 = &(output[0]);
  u32 *source1 = &(output[4]);
  
  #pragma unroll
  for (int i = 1; i < iterations; i++)
  {
    COPY_8(precomputed_ipad, h_buffer1, 0, 0);
    sha256_transform(source0, source1, w2, w3, h_buffer1);
    
    COPY_8(precomputed_opad, h_buffer2, 0, 0);
    sha256_transform(h_buffer1, &(h_buffer1[4]), w2, w3, h_buffer2);
    
    #pragma unroll
    for (int j = 0; j < 8; j++) output[j] ^= h_buffer2[j];
    
    // extremely weird IBM-specific twist
    if (intermediate_output != 0 && i == iterations - 2) {COPY_8(h_buffer2, intermediate_output, 0, 0);}
    
    source0 = &(h_buffer2[0]);
    source1 = &(h_buffer2[4]);
  }
}

DECLSPEC void _hashcat_pbkdf2_hmac_sha256_loop(u32 *precomputed_ipad, u32 *precomputed_opad, u32 iterations, u32 *output, u32 * intermediate_output)
{
  u32x dgst[8], out[8], w0[4], w1[4], w2[4], w3[4];
  COPY_8(output, dgst, 0, 0);
  COPY_8(output, out , 0, 0);

  #pragma unroll
  for (u32 j = 1; j < iterations; j++)
  {
    w0[0] = dgst[0]; w0[1] = dgst[1]; w0[2] = dgst[2]; w0[3] = dgst[3]; w1[0] = dgst[4]; w1[1] = dgst[5]; w1[2] = dgst[6]; w1[3] = dgst[7];
    w2[0] = 0x80000000;
    w2[1] = 0; w2[2] = 0; w2[3] = 0; w3[0] = 0; w3[1] = 0; w3[2] = 0;
    w3[3] = (64 + 32) * 8;

    hmac_sha256_run_V (w0, w1, w2, w3, precomputed_ipad, precomputed_opad, dgst);
    
    if (j == iterations - 2 && intermediate_output != 0) {COPY_8(dgst, intermediate_output, 0, 0);}

    out[0] ^= dgst[0]; out[1] ^= dgst[1]; out[2] ^= dgst[2]; out[3] ^= dgst[3]; out[4] ^= dgst[4]; out[5] ^= dgst[5]; out[6] ^= dgst[6]; out[7] ^= dgst[7];
  }
  COPY_8(out, output, 0, 0);  
}

DECLSPEC void _experimental_racf_pbkdf2_hmac_sha256(const u32 * key, const u32 key_length,u32 * salt, const u32 salt_length,const u32 iterations, u32 *output, u32 *intermediate_output)
{
  u32 precomputed_ipad[8], precomputed_opad[8];
  sha256_ctx_t sha256_ctx;
   
  // STEP 1: precompute HMAC_SHA256(key, data= ... ), short key always
  _experimental_sha256_hmac_init_short_4(key, key_length, &sha256_ctx, precomputed_ipad, precomputed_opad);

  // STEP 2: iteration 0: compute HMAC_SHA256(key, salt || PBKDF2_round)
  COPY_8(precomputed_ipad, sha256_ctx.h, 0, 0); // reuse precomputed ipad
  sha256_ctx.len = 64;
  
  // STEP 2.1: finalize ipad.
  salt[salt_length / 4] = 1;
  for (int j = 0; j < 4; j++)
  {
    sha256_ctx.w0[j] = 0; sha256_ctx.w1[j] = 0;
    sha256_ctx.w2[j] = 0; sha256_ctx.w3[j] = 0;
  }
  sha256_update(&sha256_ctx, salt, salt_length + 4);
  salt[salt_length / 4] = 0;
  sha256_final(&sha256_ctx);
  
  // STEP 2.2: finalize opad
  COPY_4(sha256_ctx.h, sha256_ctx.w0, 0, 0);
  COPY_4(sha256_ctx.h, sha256_ctx.w1, 4, 0);
  sha256_ctx.w2[0] = SHA256_END_OF_INPUT;
  sha256_ctx.w2[1] = sha256_ctx.w2[2] = sha256_ctx.w2[3] = 0;
  sha256_ctx.w3[0] = sha256_ctx.w3[1] = sha256_ctx.w3[2] = 0;
  sha256_ctx.w3[3] = (64 + 32) * 8;
  COPY_8(precomputed_opad, output, 0, 0);
  sha256_transform(sha256_ctx.w0, sha256_ctx.w1, sha256_ctx.w2, sha256_ctx.w3, output);
  
  // output now contains the output of the first round of PBKDF2-HMAC-SHA256.
  // STEP 3: later iterations: hash(key, result of previous round)
  _experimental_pbkdf2_hmac_sha256_loop(precomputed_ipad, precomputed_opad, iterations, output, intermediate_output);
  //_hashcat_pbkdf2_hmac_sha256_loop(precomputed_ipad, precomputed_opad, iterations, output, intermediate_output);
}

DECLSPEC void pbkdf2_hmac_sha256_32(u32 *input0, u32 *input1, u32 *salt0, u32 *salt1, const u32 iterations, u32 *out0, u32 *out1)
{
  u32 input2[4] = {0}, input3[4] = {0}, last_result0[4], last_result1[4], output[8];
  
  // precompute the HMAC state after feeding the password into HMAC
  // this can be reused several times.
  sha256_hmac_ctx_t sha256_hmac_ctx_precomputed;
  sha256_hmac_init_64(&sha256_hmac_ctx_precomputed, input0, input1, input2, input3);
  sha256_hmac_ctx_t hmac_ctx = sha256_hmac_ctx_precomputed;
   
  input2[0] = 1;
  sha256_hmac_update_64(&hmac_ctx, salt0, salt1, input2, input3, 36);
  input2[0] = 0;
  sha256_hmac_final(&hmac_ctx);
  
  #pragma unroll
  for (int i = 0; i < 4; i++)
  {
    out0        [i] = hmac_ctx.opad.h[i];
    last_result0[i] = hmac_ctx.opad.h[i];
    out1        [i] = hmac_ctx.opad.h[i + 4];
    last_result1[i] = hmac_ctx.opad.h[i + 4];
  }
  
  // later iterations: hash password || last_result
  u32 * precomputed_ipad = hmac_ctx.ipad.h;
  u32 * precomputed_opad = hmac_ctx.opad.h;

  _experimental_pbkdf2_hmac_sha256_loop(precomputed_ipad, precomputed_opad, iterations, output, 0);
  //_hashcat_pbkdf2_hmac_sha256_loop(precomputed_ipad, precomputed_opad, iterations, output, 0);
  COPY_4(output, out0, 0, 0);
  COPY_4(output, out1, 4, 0);
}

DECLSPEC void racf_kdfaes_middle(u32 *key, u32 *salt, u32 *output)
{  
  u32 salt_buffer[13] = {0}, result[8], salt_length = 20, precomputed_ipad[8], precomputed_opad[8], results_buffer[ACCUMULATOR_SIZE][8];
  sha256_ctx_t sha256_ctx;
  COPY_4(salt, salt_buffer, 0, 0);
  salt_buffer[4] = ACCUMULATOR_SIZE;
  _sha256_hmac_init_8(key, &sha256_ctx, precomputed_ipad, precomputed_opad);
    
  // First pass: initialize accumulator contents
  for (int i = 0; i < ACCUMULATOR_SIZE; i++)
  {
    _experimental_racf_pbkdf2_hmac_sha256(key, 8, salt_buffer, salt_length, HMAC_SHA256_ITERATIONS, results_buffer[i], salt_buffer);
    salt_length = 48;
    COPY_8(results_buffer[i], salt_buffer, 0, 4);
  }

  // Bridge between first and second pass over the accumulator
  COPY_8(results_buffer[ACCUMULATOR_SIZE - 1], result, 0, 0);
  
  // Second pass: mix accumulator contents
  #pragma unroll
  for (int i = 0; i < ACCUMULATOR_SIZE; i++)
  {
    u32 index = result[7] & (ACCUMULATOR_SIZE-1);
    pbkdf2_hmac_sha256_32(&(result[0]), &(result[4]), &(results_buffer[index][0]), &(results_buffer[index][4]), 1, &(result[0]), &(result[4]));
    COPY_8(result, results_buffer[i], 0, 0);
  }
  
  // final stage: hash over entire accumulator.
  for (int j = 0; j < 8; j++) results_buffer[ACCUMULATOR_SIZE - 1][j] = 0;
  _experimental_racf_pbkdf2_hmac_sha256(result, 32, &(results_buffer[0][0]), 32 * (ACCUMULATOR_SIZE - 1), HMAC_SHA256_ITERATIONS, output, 0);
}

DECLSPEC void racf_kdfaes_aes_256(u32 *key, u32 *input, u32 *output
  // the aes implementation wants these buffers if REAL_SHM is defined.
  #ifdef REAL_SHM
    , LOCAL_AS u32 s_te0[256], LOCAL_AS u32 s_te1[256], LOCAL_AS u32 s_te2[256], LOCAL_AS u32 s_te3[256], LOCAL_AS u32 s_te4[256]
  #endif
)
{
  #ifndef REAL_SHM
    CONSTANT_AS u32 *s_te0 = te0; CONSTANT_AS u32 *s_te1 = te1; CONSTANT_AS u32 *s_te2 = te2; CONSTANT_AS u32 *s_te3 = te3; CONSTANT_AS u32 *s_te4 = te4;
  #endif

  #define KEYLEN 60
  u32 ks[KEYLEN];
  AES256_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);
  aes256_encrypt (ks, input, output, s_te0, s_te1, s_te2, s_te3, s_te4);
}

/**
 * implementation of the entire KDFAES algorithm employed by RACF.
 * The arguments s_SPtrans, s_skb (and possibly s_te0 through s_te4) must be initialized
 * before calling this function.
 */
DECLSPEC void racf_kdfaes(u32 *username, u32 *salt, u32 *password, u32 *output, LOCAL_AS u32 (*s_SPtrans)[64], LOCAL_AS u32 (*s_skb)[64]
  #ifdef REAL_SHM
    , LOCAL_AS u32 s_te0[256], LOCAL_AS u32 s_te1[256], LOCAL_AS u32 s_te2[256], LOCAL_AS u32 s_te3[256], LOCAL_AS u32 s_te4[256]
  #endif
)
{
    /* DES */
    
    u32 des_output[2];
    racf_kdfaes_des(username, password, des_output, s_SPtrans, s_skb);
    
    /* PBKDF2-HMAC-SHA256 */

    u32 aes_key[8];
    u32 salt_buf[4];
    for (int i = 0; i < 4; i++) salt_buf[i] = hc_swap32_S(salt[i]);
    racf_kdfaes_middle(des_output, salt_buf, aes_key);
   
    /* AES */
    racf_kdfaes_aes_256(aes_key, username, output 
    #ifdef REAL_SHM
        , s_te0, s_te1, s_te2, s_te3, s_te4
    #endif
    );
}

DECLSPEC void initialize_local_buffers(LOCAL_AS u32 (*s_SPtrans)[64], LOCAL_AS u32 (*s_skb)[64]
  #ifdef REAL_SHM
    , LOCAL_AS u32 s_te0[256], LOCAL_AS u32 s_te1[256], LOCAL_AS u32 s_te2[256], LOCAL_AS u32 s_te3[256], LOCAL_AS u32 s_te4[256]
  #endif
)
{
  const u32 lid = get_local_id(0);
  const u32 lsz = get_local_size(0);
  
  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i]; s_SPtrans[1][i] = c_SPtrans[1][i]; s_SPtrans[2][i] = c_SPtrans[2][i]; s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i]; s_SPtrans[5][i] = c_SPtrans[5][i]; s_SPtrans[6][i] = c_SPtrans[6][i]; s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i]; s_skb[1][i] = c_skb[1][i]; s_skb[2][i] = c_skb[2][i]; s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i]; s_skb[5][i] = c_skb[5][i]; s_skb[6][i] = c_skb[6][i]; s_skb[7][i] = c_skb[7][i];
  }

  #ifdef REAL_SHM
  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i]; s_te1[i] = te1[i]; s_te2[i] = te2[i]; s_te3[i] = te3[i]; s_te4[i] = te4[i];
  }
  #endif
  
  SYNC_THREADS ();
}
