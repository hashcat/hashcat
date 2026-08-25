/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_pcfg.h"

DECLSPEC u32 pcfg_pool_byte (GLOBAL_AS const u32 *pool, const u32 off)
{
  GLOBAL_AS const u8 *pb = (GLOBAL_AS const u8 *) pool;

  const u32 b = pb[off];

  return b;
}

DECLSPEC void pcfg_put_byte (PRIVATE_AS u32 *w, const u32 off, const u32 b)
{
  PRIVATE_AS u8 *wb = (PRIVATE_AS u8 *) w;

  wb[off] = (u8) b;
}

DECLSPEC u32 pcfg_get_byte (PRIVATE_AS const u32 *w, const u32 off)
{
  PRIVATE_AS const u8 *wb = (PRIVATE_AS const u8 *) w;

  const u32 b = wb[off];

  return b;
}

DECLSPEC u32 pcfg_ent_off (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, const u32 j, const u32 n)
{
  #if PCFG_DEV_VARLEN

  const u32 off = pool[cell->slots[j].pool_off + n];

  return off;

  #else

  const u32 off = cell->slots[j].pool_off + (n * PCFG_SLOT_ENT_LEN (cell->slots[j].packed));

  return off;

  #endif
}

DECLSPEC u32 pcfg_ent_len (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, const u32 j, const u32 n)
{
  #if PCFG_DEV_VARLEN

  const u32 len = pool[cell->slots[j].pool_off + n + 1] - pool[cell->slots[j].pool_off + n];

  return len;

  #else

  const u32 len = PCFG_SLOT_ENT_LEN (cell->slots[j].packed);

  return len;

  #endif
}

DECLSPEC void pcfg_case_slot (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS const u32 *digit, PRIVATE_AS u32 *w, const u32 j)
{
  const u32 packed = cell->slots[j].packed;

  const u32 from = PCFG_SLOT_FROM (packed);

  const u32 dj = PCFG_ODO_DIGIT (digit[j]);
  const u32 df = PCFG_ODO_DIGIT (digit[from]);

  const u32 mask_len = pcfg_ent_len (cell, pool, j,    dj);
  const u32 tok_len  = pcfg_ent_len (cell, pool, from, df);

  const u32 mask_src = pcfg_ent_off (cell, pool, j, dj);

  #if PCFG_DEV_VARLEN

  const u32 dst_off = PCFG_ODO_POS (digit[from]);
  const u32 up_src  = pcfg_ent_off (cell, pool, from, df) + cell->slots[j].digit;

  #else

  const u32 dst_off = PCFG_SLOT_DST_OFF (packed);
  const u32 up_src  = cell->slots[j].digit + (df * tok_len);

  #endif

  u32 ci = 0;
  u32 at = 0;

  while ((at < tok_len) && (ci < mask_len))
  {
    if (pcfg_pool_byte (pool, mask_src + ci) == 'U')
    {
      pcfg_put_byte (w, dst_off + at, pcfg_pool_byte (pool, up_src + at));
    }

    at++;

    while (at < tok_len)
    {
      if ((pcfg_get_byte (w, dst_off + at) & 0xc0) != 0x80) break;

      if (pcfg_pool_byte (pool, mask_src + ci) == 'U')
      {
        pcfg_put_byte (w, dst_off + at, pcfg_pool_byte (pool, up_src + at));
      }

      at++;
    }

    ci++;
  }
}

DECLSPEC bool pcfg_odo_seed (LOCAL_AS const pcfg_cell_t *cell, const u32 il_pos, LOCAL_AS u32 *digit)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  u32 carry = il_pos;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    if (radix == 0) return false;

    if (carry < radix)
    {
      digit[j] = carry;

      carry = 0;
    }
    else
    {
      digit[j] = carry % radix;

      carry = carry / radix;
    }
  }

  #if PCFG_DEV_VARLEN

  if (slot_cnt > 0) digit[0] = PCFG_ODO_PACK (digit[0], PCFG_SLOT_DST_OFF (cell->slots[0].packed));

  #endif

  if (carry != 0) return false;

  return true;
}

DECLSPEC int pcfg_odo_next (LOCAL_AS const pcfg_cell_t *cell, LOCAL_AS u32 *digit)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    #if PCFG_DEV_VARLEN
    const u32 t = PCFG_ODO_DIGIT (digit[j]) + 1;
    #else
    const u32 t = digit[j] + 1;
    #endif

    if (t == radix)
    {
      digit[j] = 0;

      continue;
    }

    #if PCFG_DEV_VARLEN
    digit[j] = PCFG_ODO_PACK (t, PCFG_ODO_POS (digit[j]));
    #else
    digit[j] = t;
    #endif

    return (int) PCFG_SLOT_FROM (cell->slots[j].packed);
  }

  return -1;
}

DECLSPEC u32 pcfg_write_from (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w, const u32 from)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  #if PCFG_DEV_VARLEN

  u32 pos = PCFG_ODO_POS (digit[from]);

  #endif

  for (u32 j = from; j < slot_cnt; j++)
  {
    const u32 packed = cell->slots[j].packed;

    const u32 kind = PCFG_SLOT_KIND (packed);

    if (kind == PCFG_SLOT_KIND_BYTES)
    {
      #if PCFG_DEV_VARLEN

      const u32 d = PCFG_ODO_DIGIT (digit[j]);

      digit[j] = PCFG_ODO_PACK (d, pos);

      const u32 src     = pcfg_ent_off (cell, pool, j, d);
      const u32 ent_len = pcfg_ent_len (cell, pool, j, d);
      const u32 dst_off = pos;

      pos += ent_len;

      #else

      const u32 ent_len = PCFG_SLOT_ENT_LEN (packed);
      const u32 dst_off = PCFG_SLOT_DST_OFF (packed);

      const u32 src = cell->slots[j].pool_off + (digit[j] * ent_len);

      #endif

      for (u32 k = 0; k < ent_len; k++)
      {
        pcfg_put_byte (w, dst_off + k, pcfg_pool_byte (pool, src + k));
      }
    }
    else
    {
      pcfg_case_slot (cell, pool, digit, w, j);
    }
  }

  #if PCFG_DEV_VARLEN
  return pos;
  #else
  return 0;
  #endif
}

DECLSPEC u32 pcfg_write (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w)
{
  const u32 len = pcfg_write_from (cell, pool, digit, w, 0);

  return len;
}
