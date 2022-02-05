/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_md5.cl"
#include "inc_ecc_secp256k1.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_ripemd160.cl"
#include "inc_hash_base58.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct btcprv_tmp
{
  u32 status;
  u32 prv_key_bin[10];
  u32 prv_key_len;
} btcprv_tmp_t;

KERNEL_FQ void m28500_init (KERN_ATTR_TMPS (btcprv_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  const u64 lid = get_local_id (0);

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  /**
   * prepare
   */
  // check if enough space to work - it should be exactly 52 chars (but maybe +-1 char)
  if (pw_len > 52) return;
  char b58[52]={0};
  // copy password to b58
  size_t b58sz = pw_len;
  char * pass = (char*) (pws[gid].i); 
  int i;
  for (i=0; i < b58sz ; i++)
  {
    b58[i] = pass[i];
  }
  // convert password from b58 to bin
  u8 bin[52];
  size_t binsz = 52;

  if (pw_len==51)
  {
    bool res = b58dec_51((u32*)bin,(char*)b58);
    if (res)
      binsz = 37;
  }
  else if (pw_len==52)
  {
    bool res = b58dec_52((u32*)bin,(char*)b58);
    if (res){
      binsz = 38;
      if (bin[33] != 1)  // not valid compressed address indicator
      {
        tmps[gid].status = 0; // already error
        return;
      }  
    }
  }

  // store binary prv key in tmps
  if ((binsz < 39)&&(binsz > 36)) // should be 37 or 38 bytes in WIF format
  {
    tmps[gid].status = 1;   // ready to verify 
    tmps[gid].prv_key_len = binsz;
    u32 * bin32 = (u32*) bin;
    u8 * ppkey = (u8 *) tmps[gid].prv_key_bin;
    for (i=0; i<binsz; i++)
      // if (binsz==37)
        ppkey[i] = bin[i];
      // else
      //   ppkey[i] = bin[52-binsz+i];
  }
  else
  {
    tmps[gid].status = 0; // already error
  }
}

KERNEL_FQ void m28500_loop (KERN_ATTR_TMPS (btcprv_tmp_t))
{
  /**
   * base
   */
  const u64 gid = get_global_id (0);

  // status should 1 to go further, otherwise skip this key
  if (tmps[gid].status != 1) return;
  /**
   * init
   */

  const u32 binsz = tmps[gid].prv_key_len;
  u8 bin[200];
  u32 * bin32 = (u32*) bin;
  int i;
  for (i=0; i<10; i++)
    bin32[i] = tmps[gid].prv_key_bin[i];

  /**
   * digest
   */


  /**
   * loop
   */
  // verify sha25(sha256(bin[0..binsz-4]))
  // real work is done in b58check where sha256 is run twice
  u8 * pbin=bin;
  int res = b58check(pbin,binsz);

  if (res < 0)
    tmps[gid].status = 0;  // already error
  else
  {
    // corrct address decoded from base58
    // store it - only prv key 32 octetes [1..32]
    pbin = (u8 *) tmps[gid].prv_key_bin;
    for (i=1; i<33; i++){
      pbin[32 - i] = bin[i];
    }
    tmps[gid].status = 2;
  }

}

KERNEL_FQ void m28500_comp (KERN_ATTR_TMPS (btcprv_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (tmps[gid].status != 2) return; // only when it is 2 we have correct prv key

  const u64 lid = get_local_id (0);

  secp256k1_t precomputed_G;
  set_precomputed_basepoint_g(&precomputed_G);
  u32 x[8];
  u32 y[8];
  u32 * prv_key=(u32*)tmps[gid].prv_key_bin;
  u32 i=0;
  u32 j=7;
  // convert: pub_key = G * prv_key
  #if defined IS_OPENCL
    GLOBAL_AS static u32 preG[SECP256K1_PRE_COMPUTED_XY_SIZE];
    for (i=0;i<SECP256K1_PRE_COMPUTED_XY_SIZE;i++)
    {
      preG[i]=((u32*)&precomputed_G)[i];
    }
    point_mul_xy(x,y,prv_key,&preG);
  #else
    point_mul_xy(x,y,prv_key,&precomputed_G);
  #endif

  // merge to public key
  u32 pub_key[33] = {0}; // 8 + 8 + 1 for type but used only 65 octets
  u32 pub_key_len = 65;
  if (tmps[gid].prv_key_len==37){  // uncompressed key
    pub_key[16] = ((y[0] << 24));
    pub_key[15] = ((y[0] >> 8) | (y[1] << 24));
    pub_key[14] = ((y[1] >> 8) | (y[2] << 24));
    pub_key[13] = ((y[2] >> 8) | (y[3] << 24));
    pub_key[12] = ((y[3] >> 8) | (y[4] << 24));
    pub_key[11] = ((y[4] >> 8) | (y[5] << 24));
    pub_key[10] = ((y[5] >> 8) | (y[6] << 24));
    pub_key[9] = ((y[6] >> 8) | (y[7] << 24));
  }
  pub_key[8] = ((y[7] >> 8) | (x[0] << 24));
  pub_key[7] = ((x[0] >> 8) | (x[1] << 24));
  pub_key[6] = ((x[1] >> 8) | (x[2] << 24));
  pub_key[5] = ((x[2] >> 8) | (x[3] << 24));
  pub_key[4] = ((x[3] >> 8) | (x[4] << 24));
  pub_key[3] = ((x[4] >> 8) | (x[5] << 24));
  pub_key[2] = ((x[5] >> 8) | (x[6] << 24));
  pub_key[1] = ((x[6] >> 8) | (x[7] << 24));
  pub_key[0] = (0x04000000  | (x[7] >> 8));
  if (tmps[gid].prv_key_len==38){  // compressed key - modify pub_key
    const u32 type = 0x02 | (y[0] & 1); // (note: 0b10 | 0b01 = 0x03)
    pub_key[0] = ((type << 24)  | (x[7] >> 8));
    pub_key[8] = (x[0] << 24);
    pub_key_len = 33;
  }
  // calculate HASH160 for pub key
  sha256_ctx_t ctx;
  ripemd160_ctx_t rctx;

  sha256_init (&ctx);

  sha256_update (&ctx, pub_key, pub_key_len);

  sha256_final (&ctx);

  // memcpy((char*)shash,(char*)ctx.h,32);
  u32 shash[16]={0};
  for (i=0;i<8;i++)
  {
    shash[i]=ctx.h[i];
  }

  // now let's do RIPEMD-160 on the sha246sum

  ripemd160_init (&rctx);

  ripemd160_update_swap (&rctx, shash, 32);

  ripemd160_final (&rctx);

  // now hash160 of public key is stored

  /**
   * digest
   */
  // manual check as we don't expect big number of digest to check 
  // it makes no sense to put long list of public addresses
  // to one private key patern
  bool found;
  for (i=0; i<DIGESTS_CNT; i++)
  {
    u8 * dig = (u8 *) digests_buf[i].digest_buf;
    u8 * ph = (u8*) rctx.h;
    found = true;
    for (j=0; found && j<20; j++)
    {
      if (dig[j]!=ph[j]) found=false;
    }
    if (found)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, i, i, gid, 0, 0, 0);
    }
  }
}
