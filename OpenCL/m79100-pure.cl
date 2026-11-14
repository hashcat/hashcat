/**
 * SubWallet (polkadot-js keyring) - m79100-pure.cl
 *
 *   key = scrypt(password, salt32, N, r, p, 32)
 *   mac = Poly1305(XSalsa20block0(key, nonce24), ct)   [NaCl secretbox]
 *
 * The scrypt pipeline (PBKDF2 -> BlockMix -> ROMix -> PBKDF2) is the stock
 * hashcat implementation from inc_hash_scrypt.cl (same as m08900); the
 * final secretbox verify (tweetnacl port) is cloned from Phantom's
 * m90011-pure.cl with the tag split out of the authenticated range.
 *
 * License: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// MUST match module_79100.c field-for-field
typedef struct subwallet_scrypt
{
  u32 nonce[6];         // 24 bytes
  u32 ciphertext[128];  // ct only (tag rides in the digest), up to 512 bytes
  u32 ciphertext_len;

} subwallet_scrypt_t;

#define FOR(i,n) for (i = 0;i < n;++i)

CONSTANT_VK u8 sigma[16] = {  101, 120, 112,  97, 110, 100,  32,  51,  50,  45,98, 121, 116, 101,  32, 107};

DECLSPEC u32 L32(u32 x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

DECLSPEC u32 ld32(const u8 *x)
{
  u32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

DECLSPEC u32 ld32_c(CONSTANT_AS const u8 *x)
{
  u32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}


DECLSPEC void st32(u8 *x,u32 u)
{
  int i;
  FOR(i,4) { x[i] = u; u >>= 8; }
}

CONSTANT_VK u32 minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

DECLSPEC void add1305(u32 *h,const u32 *c)
{
  u32 j,u = 0;
  FOR(j,17)
{
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

DECLSPEC void core(u8 *out,const u8 *in,const u8 *k,CONSTANT_AS const u8 *c,int h)
{
  u32 w[16],x[16],y[16],t[4];
  int i,j,m;

  FOR(i,4)
{
    x[5*i] = ld32_c(c+4*i);
    x[1+i] = ld32(k+4*i);
    x[6+i] = ld32(in+4*i);
    x[11+i] = ld32(k+16+4*i);
  }

  FOR(i,16) y[i] = x[i];

  FOR(i,20)
{
    FOR(j,4)
{
      FOR(m,4) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1],13);
      t[0] ^= L32(t[3]+t[2],18);
      FOR(m,4) w[4*j+(j+m)%4] = t[m];
    }
    FOR(m,16) x[m] = w[m];
  }

  if (h)
{
    FOR(i,16) x[i] += y[i];
    FOR(i,4)
{
      x[5*i] -= ld32_c(c+4*i);
      x[6+i] -= ld32(in+4*i);
    }
    FOR(i,4)
{
      st32(out+4*i,x[5*i]);
      st32(out+16+4*i,x[6+i]);
    }
  }
else
    FOR(i,16) st32(out + 4 * i,x[i] + y[i]);
}

DECLSPEC int crypto_core_salsa20(u8 *out,const u8 *in,const u8 *k,CONSTANT_AS const u8 *c)
{
  core(out,in,k,c,0);
  return 0;
}

DECLSPEC int crypto_core_hsalsa20(u8 *out,const u8 *in,const u8 *k,CONSTANT_AS const u8 *c)
{
  core(out,in,k,c,1);
  return 0;
}


DECLSPEC int crypto_stream_salsa20_xor(u8 *c,const u8 *m,u64 b,const u8 *n,const u8 *k)
{
  u8 z[16],x[64];
  u32 u,i;
  if (!b) return 0;
  FOR(i,16) z[i] = 0;
  FOR(i,8) z[i] = n[i];
  while (b >= 64)
{
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,64) c[i] = (m?m[i]:0) ^ x[i];
    u = 1;
    for (i = 8;i < 16;++i)
{
      u += (u32) z[i];
      z[i] = u;
      u >>= 8;
    }
    b -= 64;
    c += 64;
    if (m) m += 64;
  }
  if (b)
{
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,b) c[i] = (m?m[i]:0) ^ x[i];
  }
  return 0;
}

DECLSPEC int crypto_stream_salsa20(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  return crypto_stream_salsa20_xor(c,0,d,n,k);
}

DECLSPEC int crypto_stream(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  u8 s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,d,n+16,s);
}

DECLSPEC int crypto_onetimeauth(u8 *out,const u8 *m,u64 n,const u8 *k)
{
  u32 s,i,j,u,x[17],r[17],h[17],c[17],g[17];

  FOR(j,17) r[j]=h[j]=0;
  FOR(j,16) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0)
{
    FOR(j,17) c[j] = 0;
    for (j = 0;(j < 16) && (j < n);++j) c[j] = m[j];
    c[j] = 1;
    m += j; n -= j;
    add1305(h,c);
    FOR(i,17)
{
      x[i] = 0;
      FOR(j,17) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }
    FOR(i,17) h[i] = x[i];
    u = 0;
    FOR(j,16)
{
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >> 2);
    FOR(j,16)
{
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  FOR(j,17) g[j] = h[j];

  u32 minusp_priv[17];

  FOR(j,17) minusp_priv[j] = minusp[j];

  add1305(h,minusp_priv);
  s = -(h[16] >> 7);
  FOR(j,17) h[j] ^= s & (g[j] ^ h[j]);

  FOR(j,16) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  FOR(j,16) out[j] = h[j];
  return 0;
}

KERNEL_FQ KERNEL_FA void m79100_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, subwallet_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m79100_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m79100_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m79100_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, subwallet_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // final scrypt PBKDF2: 32-byte key (out words are stored pre-swapped,
  // i.e. (u8*)out reads as the raw derived key on LE)

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

  // NaCl secretbox verify: poly key = first 32 bytes of XSalsa20 stream

  GLOBAL_AS const subwallet_scrypt_t *esalt = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u8 nonce[24];

  for (int i = 0; i < 6; i++) ((PRIVATE_AS u32 *) nonce)[i] = esalt->nonce[i];

  u8 salsa_key[32];

  crypto_stream (salsa_key, 32, nonce, (u8 *) out);

  const u32 ct_len   = esalt->ciphertext_len;
  const u32 ct_words = (ct_len + 3) / 4;

  u8 ct[512];

  for (u32 i = 0; i < ct_words; i++) ((PRIVATE_AS u32 *) ct)[i] = esalt->ciphertext[i];

  u32 T[4] = { 0, 0, 0, 0 };

  // $subwallet$ stores the ct WITHOUT the prepended tag (tag rides in its
  // own line field / the digest), so authenticate from offset 0 - unlike
  // $phantom$'s box, which skips the first 16 bytes.
  crypto_onetimeauth ((u8 *) T, ct, ct_len, salsa_key);

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
