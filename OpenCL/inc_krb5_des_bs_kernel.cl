/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The -a 3 kernels of the Kerberos 5 DES modes. Only the first word of a candidate changes inside
// the mask loop, so the string-to-key runs on 32 candidates at once as bit slices, the way m14000
// runs a single DES, and so does the one decryption each mode needs before it can reject. What a
// slice leaves over is a handful of candidates in a billion, and those are run through the scalar
// string-to-key and the mode's full check again. That check is the only place a hash is marked, so
// the slices decide which candidates are looked at and nothing else.
//
// A kernel defines these before it includes this file:
//
// KRB5_DES_BS_KERNEL_TM   the names of the three kernels
// KRB5_DES_BS_KERNEL_MXX
// KRB5_DES_BS_KERNEL_SXX
// KRB5_DES_BS_PREPARE     statements that run once for a base word and leave salt_buf and salt_len
//                         behind, along with anything the other hooks read
// KRB5_DES_BS_CIPHER      defined by a mode that decrypts a block to test a candidate. PREPARE then
//                         also leaves ct0 and ct1, the two words of that block, and iv0 and iv1, the
//                         block CBC chains it with.
// KRB5_DES_BS_HITS(B)     the candidates of a slice that are worth the full check, as a mask. B is
//                         the decrypted block, or the key itself for a mode that has no cipher.
// KRB5_DES_BS_VERIFY      the full check of one candidate. It has key and il_pos, and marks the hash.
//
// A mode whose two kernels differ defines KRB5_DES_BS_PREPARE_M and KRB5_DES_BS_PREPARE_S in place
// of KRB5_DES_BS_PREPARE, and likewise for KRB5_DES_BS_VERIFY. In place of KRB5_DES_BS_HITS it
// defines KRB5_DES_BS_TEST_M(B,need) and KRB5_DES_BS_TEST_S(B,need), statements that OR the
// candidates worth the full check into need.

#ifndef KRB5_DES_BS_PREPARE_M
#define KRB5_DES_BS_PREPARE_M KRB5_DES_BS_PREPARE
#define KRB5_DES_BS_PREPARE_S KRB5_DES_BS_PREPARE
#endif

#ifndef KRB5_DES_BS_TEST_M
#define KRB5_DES_BS_TEST_M(B,need) need |= KRB5_DES_BS_HITS (B);
#define KRB5_DES_BS_TEST_S(B,need) need |= KRB5_DES_BS_HITS (B);
#endif

#ifndef KRB5_DES_BS_VERIFY_M
#define KRB5_DES_BS_VERIFY_M KRB5_DES_BS_VERIFY
#define KRB5_DES_BS_VERIFY_S KRB5_DES_BS_VERIFY
#endif

// A candidate that is left over waits in a queue until there are enough of them to check in one
// go, because the threads of a group only check together when they all have one to check.

#define KRB5_DES_BS_QUEUE 64

// A slice costs what it costs however many of its 32 candidates the mask fills. Below this many it
// is cheaper to give each of them the full check, and that is all a mask does whose first characters
// are fixed: it leaves a base word one candidate, or a handful.

#define KRB5_DES_BS_MIN 8

KERNEL_FQ KERNEL_FA void KRB5_DES_BS_KERNEL_TM (KERN_ATTR_TM)
{
  const u64 gid = get_global_id (0);

  const u32 block = gid / 32;
  const u32 slice = gid % 32;

  const u32 w0 = mod[gid];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 32; i++)
  {
    hc_atomic_or (&words_buf_b[block].b[i], (((w0 >> i) & 1) << slice));
  }
}

KERNEL_FQ KERNEL_FA void KRB5_DES_BS_KERNEL_MXX (KERN_ATTR_BITSLICE ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 pw[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = pws[gid].i[idx];
  }

  KRB5_DES_BS_PREPARE_M

  // the password and the salt are joined and folded once, without the bits the mask varies

  u32 w[64];

  const u32 blocks = krb5_des_build_buf_fit (pw, pw_len, salt_buf, salt_len, w);

  u32 fold[2];

  krb5_des_fold (w, blocks, fold);

  const u32 w0l = w[0];
  const u32 w1  = w[1];

  const u32 w0m = (pw_len < 4) ? ((1u << (pw_len * 8)) - 1) : 0xffffffff;

  /**
   * loop
   */

  u32 queue[KRB5_DES_BS_QUEUE];

  u32 queued = 0;

  u32 il_base = 0;

  while (1)
  {
    // slices, for as long as the queue has room for every candidate of the next one

    while ((il_base < IL_CNT) && (queued <= (KRB5_DES_BS_QUEUE - 32)))
    {
      // the table always holds 1024 candidates, the mask may have fewer

      const u32 left = IL_CNT - il_base;

      if (left < KRB5_DES_BS_MIN)
      {
        for (u32 i = 0; i < left; i++)
        {
          queue[queued] = il_base + i;

          queued++;
        }

        il_base += 32;

        continue;
      }

      u32 V[32];

      KRB5_DES_BS_LOAD_V (V, words_buf_s[il_base / 32].b, w0m);

      // the fan-folded key, which is also the IV of the CBC-MAC

      u32 K[56];

      KRB5_DES_BS_KEY (K, V, fold[0], fold[1]);

      u32 P[8];

      KRB5_DES_BS_PARITY (P, K);

      u32 need = KRB5_DES_BS_WEAK_KEY (K);

      // the CBC-MAC over the password and the salt

      u32 D[64];

      KRB5_DES_BS_LOAD_FIRST (D, K, P, V, w0l, w1);

      krb5_des_bs_encrypt (K, D);

      for (u32 i = 1; i < blocks; i++)
      {
        KRB5_DES_BS_CHAIN_IP (D, w[(i * 2) + 0], w[(i * 2) + 1]);

        krb5_des_bs_encrypt (K, D);
      }

      // what it leaves is the key, short of its parity bits and of the weak key correction

      u32 B[64];

      KRB5_DES_BS_FP (B, D);

      need |= KRB5_DES_BS_WEAK_BLOCK (B);

      #ifdef KRB5_DES_BS_CIPHER

      u32 K2[56];

      KRB5_DES_BS_KEY_OF (K2, B);

      KRB5_DES_BS_LOAD_IP (D, ct0, ct1);

      krb5_des_bs_decrypt (K2, D);

      KRB5_DES_BS_FP (B, D);

      KRB5_DES_BS_XOR (B, iv0, iv1);

      #endif

      KRB5_DES_BS_TEST_M (B, need)

      if (left < 32) need &= (1u << left) - 1;

      while (need != 0)
      {
        const u32 lane = (u32) ffz (~need);

        need &= need - 1;

        queue[queued] = il_base + lane;

        queued++;
      }

      il_base += 32;
    }

    // the full check of what the slices left over

    for (u32 i = 0; i < queued; i++)
    {
      const u32 il_pos = queue[i];

      const u32 w0r = KRB5_DES_BS_UNSLICE (words_buf_s[il_pos / 32].b, il_pos % 32) & w0m;

      w[0] = w0l | w0r;

      u32 f[2];

      f[0] = fold[0] ^ (w0r & 0x7f7f7f7f);
      f[1] = fold[1];

      u32 key[2];

      krb5_des_string_to_key_folded (w, blocks, f, key, s_SPtrans, s_skb);

      KRB5_DES_BS_VERIFY_M
    }

    queued = 0;

    if (il_base >= IL_CNT) break;
  }
}

KERNEL_FQ KERNEL_FA void KRB5_DES_BS_KERNEL_SXX (KERN_ATTR_BITSLICE ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 pw[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = pws[gid].i[idx];
  }

  KRB5_DES_BS_PREPARE_S

  // the password and the salt are joined and folded once, without the bits the mask varies

  u32 w[64];

  const u32 blocks = krb5_des_build_buf_fit (pw, pw_len, salt_buf, salt_len, w);

  u32 fold[2];

  krb5_des_fold (w, blocks, fold);

  const u32 w0l = w[0];
  const u32 w1  = w[1];

  const u32 w0m = (pw_len < 4) ? ((1u << (pw_len * 8)) - 1) : 0xffffffff;

  /**
   * loop
   */

  u32 queue[KRB5_DES_BS_QUEUE];

  u32 queued = 0;

  u32 il_base = 0;

  while (1)
  {
    // slices, for as long as the queue has room for every candidate of the next one

    while ((il_base < IL_CNT) && (queued <= (KRB5_DES_BS_QUEUE - 32)))
    {
      // the table always holds 1024 candidates, the mask may have fewer

      const u32 left = IL_CNT - il_base;

      if (left < KRB5_DES_BS_MIN)
      {
        for (u32 i = 0; i < left; i++)
        {
          queue[queued] = il_base + i;

          queued++;
        }

        il_base += 32;

        continue;
      }

      u32 V[32];

      KRB5_DES_BS_LOAD_V (V, words_buf_s[il_base / 32].b, w0m);

      // the fan-folded key, which is also the IV of the CBC-MAC

      u32 K[56];

      KRB5_DES_BS_KEY (K, V, fold[0], fold[1]);

      u32 P[8];

      KRB5_DES_BS_PARITY (P, K);

      u32 need = KRB5_DES_BS_WEAK_KEY (K);

      // the CBC-MAC over the password and the salt

      u32 D[64];

      KRB5_DES_BS_LOAD_FIRST (D, K, P, V, w0l, w1);

      krb5_des_bs_encrypt (K, D);

      for (u32 i = 1; i < blocks; i++)
      {
        KRB5_DES_BS_CHAIN_IP (D, w[(i * 2) + 0], w[(i * 2) + 1]);

        krb5_des_bs_encrypt (K, D);
      }

      // what it leaves is the key, short of its parity bits and of the weak key correction

      u32 B[64];

      KRB5_DES_BS_FP (B, D);

      need |= KRB5_DES_BS_WEAK_BLOCK (B);

      #ifdef KRB5_DES_BS_CIPHER

      u32 K2[56];

      KRB5_DES_BS_KEY_OF (K2, B);

      KRB5_DES_BS_LOAD_IP (D, ct0, ct1);

      krb5_des_bs_decrypt (K2, D);

      KRB5_DES_BS_FP (B, D);

      KRB5_DES_BS_XOR (B, iv0, iv1);

      #endif

      KRB5_DES_BS_TEST_S (B, need)

      if (left < 32) need &= (1u << left) - 1;

      while (need != 0)
      {
        const u32 lane = (u32) ffz (~need);

        need &= need - 1;

        queue[queued] = il_base + lane;

        queued++;
      }

      il_base += 32;
    }

    // the full check of what the slices left over

    for (u32 i = 0; i < queued; i++)
    {
      const u32 il_pos = queue[i];

      const u32 w0r = KRB5_DES_BS_UNSLICE (words_buf_s[il_pos / 32].b, il_pos % 32) & w0m;

      w[0] = w0l | w0r;

      u32 f[2];

      f[0] = fold[0] ^ (w0r & 0x7f7f7f7f);
      f[1] = fold[1];

      u32 key[2];

      krb5_des_string_to_key_folded (w, blocks, f, key, s_SPtrans, s_skb);

      KRB5_DES_BS_VERIFY_S
    }

    queued = 0;

    if (il_base >= IL_CNT) break;
  }
}

#undef KRB5_DES_BS_MIN
#undef KRB5_DES_BS_QUEUE
