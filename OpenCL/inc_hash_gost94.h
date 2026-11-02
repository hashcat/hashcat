/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_GOST94_H
#define INC_HASH_GOST94_H

#define _round(k1,k2,tbl)                    \
{                                            \
  u32x t;                                    \
  t = (k1) + r;                              \
  l ^= BOX (((t >>  0) & 0xff), 0, tbl) ^    \
       BOX (((t >>  8) & 0xff), 1, tbl) ^    \
       BOX (((t >> 16) & 0xff), 2, tbl) ^    \
       BOX (((t >> 24) & 0xff), 3, tbl);     \
  t = (k2) + l;                              \
  r ^= BOX (((t >>  0) & 0xff), 0, tbl) ^    \
       BOX (((t >>  8) & 0xff), 1, tbl) ^    \
       BOX (((t >> 16) & 0xff), 2, tbl) ^    \
       BOX (((t >> 24) & 0xff), 3, tbl);     \
}

#define R(k,h,s,i,t)       \
{                          \
  u32x r;                  \
  u32x l;                  \
  r = h[i + 0];            \
  l = h[i + 1];            \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[0], k[1], t);  \
  _round (k[2], k[3], t);  \
  _round (k[4], k[5], t);  \
  _round (k[6], k[7], t);  \
  _round (k[7], k[6], t);  \
  _round (k[5], k[4], t);  \
  _round (k[3], k[2], t);  \
  _round (k[1], k[0], t);  \
  s[i + 0] = l;            \
  s[i + 1] = r;            \
}

#define X(w,u,v)      \
  w[0] = u[0] ^ v[0]; \
  w[1] = u[1] ^ v[1]; \
  w[2] = u[2] ^ v[2]; \
  w[3] = u[3] ^ v[3]; \
  w[4] = u[4] ^ v[4]; \
  w[5] = u[5] ^ v[5]; \
  w[6] = u[6] ^ v[6]; \
  w[7] = u[7] ^ v[7];

#define P(k,w)                        \
  k[0] = ((w[0] & 0x000000ff) <<  0)  \
       | ((w[2] & 0x000000ff) <<  8)  \
       | ((w[4] & 0x000000ff) << 16)  \
       | ((w[6] & 0x000000ff) << 24); \
  k[1] = ((w[0] & 0x0000ff00) >>  8)  \
       | ((w[2] & 0x0000ff00) >>  0)  \
       | ((w[4] & 0x0000ff00) <<  8)  \
       | ((w[6] & 0x0000ff00) << 16); \
  k[2] = ((w[0] & 0x00ff0000) >> 16)  \
       | ((w[2] & 0x00ff0000) >>  8)  \
       | ((w[4] & 0x00ff0000) <<  0)  \
       | ((w[6] & 0x00ff0000) <<  8); \
  k[3] = ((w[0] & 0xff000000) >> 24)  \
       | ((w[2] & 0xff000000) >> 16)  \
       | ((w[4] & 0xff000000) >>  8)  \
       | ((w[6] & 0xff000000) >>  0); \
  k[4] = ((w[1] & 0x000000ff) <<  0)  \
       | ((w[3] & 0x000000ff) <<  8)  \
       | ((w[5] & 0x000000ff) << 16)  \
       | ((w[7] & 0x000000ff) << 24); \
  k[5] = ((w[1] & 0x0000ff00) >>  8)  \
       | ((w[3] & 0x0000ff00) >>  0)  \
       | ((w[5] & 0x0000ff00) <<  8)  \
       | ((w[7] & 0x0000ff00) << 16); \
  k[6] = ((w[1] & 0x00ff0000) >> 16)  \
       | ((w[3] & 0x00ff0000) >>  8)  \
       | ((w[5] & 0x00ff0000) <<  0)  \
       | ((w[7] & 0x00ff0000) <<  8); \
  k[7] = ((w[1] & 0xff000000) >> 24)  \
       | ((w[3] & 0xff000000) >> 16)  \
       | ((w[5] & 0xff000000) >>  8)  \
       | ((w[7] & 0xff000000) >>  0);

#define A(x)        \
{                   \
  u32x l;           \
  u32x r;           \
  l = x[0] ^ x[2];  \
  r = x[1] ^ x[3];  \
  x[0] = x[2];      \
  x[1] = x[3];      \
  x[2] = x[4];      \
  x[3] = x[5];      \
  x[4] = x[6];      \
  x[5] = x[7];      \
  x[6] = l;         \
  x[7] = r;         \
}

#define AA(x)       \
{                   \
  u32x l;           \
  u32x r;           \
  l    = x[0];      \
  r    = x[2];      \
  x[0] = x[4];      \
  x[2] = x[6];      \
  x[4] = l ^ r;     \
  x[6] = x[0] ^ r;  \
  l    = x[1];      \
  r    = x[3];      \
  x[1] = x[5];      \
  x[3] = x[7];      \
  x[5] = l ^ r;     \
  x[7] = x[1] ^ r;  \
}

#define C(x)          \
  x[0] ^= 0xff00ff00; \
  x[1] ^= 0xff00ff00; \
  x[2] ^= 0x00ff00ff; \
  x[3] ^= 0x00ff00ff; \
  x[4] ^= 0x00ffff00; \
  x[5] ^= 0xff0000ff; \
  x[6] ^= 0x000000ff; \
  x[7] ^= 0xff00ffff;

#define SHIFT12(u,m,s)              \
  u[0] = m[0] ^ s[6];               \
  u[1] = m[1] ^ s[7];               \
  u[2] = m[2] ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[0] & 0x0000ffff) \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[7] & 0xffff0000) \
              ^ (s[7] >> 16);       \
  u[3] = m[3] ^ (s[0] & 0x0000ffff) \
              ^ (s[0] << 16)        \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] << 16)        \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[4] = m[4] ^ (s[0] & 0xffff0000) \
              ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[1] & 0xffff0000) \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[5] = m[5] ^ (s[0] << 16)        \
              ^ (s[0] >> 16)        \
              ^ (s[0] & 0xffff0000) \
              ^ (s[1] & 0x0000ffff) \
              ^ s[2]                \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0xffff0000) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);       \
  u[6] = m[6] ^ s[0]                \
              ^ (s[1] >> 16)        \
              ^ (s[2] << 16)        \
              ^ s[3]                \
              ^ (s[3] >> 16)        \
              ^ (s[4] << 16)        \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[5] >> 16)        \
              ^ s[6]                \
              ^ (s[6] << 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] << 16);       \
  u[7] = m[7] ^ (s[0] & 0xffff0000) \
              ^ (s[0] << 16)        \
              ^ (s[1] & 0x0000ffff) \
              ^ (s[1] << 16)        \
              ^ (s[2] >> 16)        \
              ^ (s[3] << 16)        \
              ^ s[4]                \
              ^ (s[4] >> 16)        \
              ^ (s[5] << 16)        \
              ^ (s[5] >> 16)        \
              ^ (s[6] >> 16)        \
              ^ (s[7] & 0x0000ffff) \
              ^ (s[7] << 16)        \
              ^ (s[7] >> 16);

#define SHIFT16(h,v,u)              \
  v[0] = h[0] ^ (u[1] << 16)        \
              ^ (u[0] >> 16);       \
  v[1] = h[1] ^ (u[2] << 16)        \
              ^ (u[1] >> 16);       \
  v[2] = h[2] ^ (u[3] << 16)        \
              ^ (u[2] >> 16);       \
  v[3] = h[3] ^ (u[4] << 16)        \
              ^ (u[3] >> 16);       \
  v[4] = h[4] ^ (u[5] << 16)        \
              ^ (u[4] >> 16);       \
  v[5] = h[5] ^ (u[6] << 16)        \
              ^ (u[5] >> 16);       \
  v[6] = h[6] ^ (u[7] << 16)        \
              ^ (u[6] >> 16);       \
  v[7] = h[7] ^ (u[0] & 0xffff0000) \
              ^ (u[0] << 16)        \
              ^ (u[7] >> 16)        \
              ^ (u[1] & 0xffff0000) \
              ^ (u[1] << 16)        \
              ^ (u[6] << 16)        \
              ^ (u[7] & 0xffff0000);

#define SHIFT61(h,v)          \
  h[0] = (v[0] & 0xffff0000)  \
       ^ (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16)         \
       ^ (v[7] & 0x0000ffff); \
  h[1] = (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] & 0x0000ffff)  \
       ^ v[2]                 \
       ^ (v[2] >> 16)         \
       ^ (v[3] << 16)         \
       ^ (v[4] >> 16)         \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ v[6]                 \
       ^ (v[7] & 0xffff0000)  \
       ^ (v[7] >> 16);        \
  h[2] = (v[0] & 0x0000ffff)  \
       ^ (v[0] << 16)         \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[6]                 \
       ^ (v[6] >> 16)         \
       ^ (v[7] & 0x0000ffff)  \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16);        \
  h[3] = (v[0] << 16)         \
       ^ (v[0] >> 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[1] >> 16)         \
       ^ (v[2] << 16)         \
       ^ (v[2] >> 16)         \
       ^ v[2]                 \
       ^ (v[3] << 16)         \
       ^ (v[4] >> 16)         \
       ^ v[4]                 \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ (v[7] & 0x0000ffff)  \
       ^ (v[7] >> 16);        \
  h[4] = (v[0] >> 16)         \
       ^ (v[1] << 16)         \
       ^ v[1]                 \
       ^ (v[2] >> 16)         \
       ^ v[2]                 \
       ^ (v[3] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16);        \
  h[5] = (v[0] << 16)         \
       ^ (v[0] & 0xffff0000)  \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[1] & 0xffff0000)  \
       ^ (v[2] << 16)         \
       ^ v[2]                 \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ (v[4] >> 16)         \
       ^ v[4]                 \
       ^ (v[5] << 16)         \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ v[6]                 \
       ^ (v[7] << 16)         \
       ^ (v[7] >> 16)         \
       ^ (v[7] & 0xffff0000); \
  h[6] = v[0]                 \
       ^ v[2]                 \
       ^ (v[2] >> 16)         \
       ^ v[3]                 \
       ^ (v[3] << 16)         \
       ^ v[4]                 \
       ^ (v[4] >> 16)         \
       ^ (v[5] << 16)         \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ v[6]                 \
       ^ (v[7] << 16)         \
       ^ v[7];                \
  h[7] = v[0]                 \
       ^ (v[0] >> 16)         \
       ^ (v[1] << 16)         \
       ^ (v[1] >> 16)         \
       ^ (v[2] << 16)         \
       ^ (v[3] >> 16)         \
       ^ v[3]                 \
       ^ (v[4] << 16)         \
       ^ v[4]                 \
       ^ (v[5] >> 16)         \
       ^ v[5]                 \
       ^ (v[6] << 16)         \
       ^ (v[6] >> 16)         \
       ^ (v[7] << 16)         \
       ^ v[7];

#define PASS0(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 0, t);      \
  A (u);                  \
  AA (v);                 \
}

#define PASS2(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 2, t);      \
  A (u);                  \
  C (u);                  \
  AA (v);                 \
}

#define PASS4(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 4, t);      \
  A (u);                  \
  AA (v);                 \
}

#define PASS6(h,s,u,v,t)  \
{                         \
  u32x k[8];              \
  u32x w[8];              \
  X (w, u, v);            \
  P (k, w);               \
  R (k, h, s, 6, t);      \
}

// The functions below hash messages of any length in 32-byte blocks. Each block is stored as 8
// little endian words, with its first byte in the lowest position, as for MD5. The c_tables
// table contains the S-box of the test parameter set used by mode 6900. The c_tables_cryptopro
// table contains the S-box of the CryptoPro parameter set. After gost94_final (), the digest
// is h in the same layout.

typedef struct gost94_ctx
{
  u32 h[8];
  u32 s[8];
  u32 m[8];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  SHM_TYPE u32a (*s_tables)[256];

} gost94_ctx_t;

typedef struct gost94_ctx_vector
{
  u32x h[8];
  u32x s[8];
  u32x m[8];

  int pos;
  int len;

  SHM_TYPE u32a (*s_tables)[256];

} gost94_ctx_vector_t;

DECLSPEC void gost94_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, SHM_TYPE u32a (*s_tables)[256]);
DECLSPEC void gost94_init (PRIVATE_AS gost94_ctx_t *ctx, SHM_TYPE u32a (*s_tables)[256]);
DECLSPEC void gost94_block (PRIVATE_AS gost94_ctx_t *ctx);
DECLSPEC void gost94_absorb (PRIVATE_AS gost94_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void gost94_update (PRIVATE_AS gost94_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void gost94_update_utf16le (PRIVATE_AS gost94_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void gost94_update_global (PRIVATE_AS gost94_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void gost94_update_global_utf16le (PRIVATE_AS gost94_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void gost94_final (PRIVATE_AS gost94_ctx_t *ctx);

DECLSPEC void gost94_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, SHM_TYPE u32a (*s_tables)[256]);
DECLSPEC void gost94_init_vector (PRIVATE_AS gost94_ctx_vector_t *ctx, SHM_TYPE u32a (*s_tables)[256]);
DECLSPEC void gost94_block_vector (PRIVATE_AS gost94_ctx_vector_t *ctx);
DECLSPEC void gost94_absorb_vector (PRIVATE_AS gost94_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void gost94_update_vector (PRIVATE_AS gost94_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void gost94_update_vector_utf16le (PRIVATE_AS gost94_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void gost94_final_vector (PRIVATE_AS gost94_ctx_vector_t *ctx);

#endif // INC_HASH_GOST94_H
