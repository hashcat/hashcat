/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PCFG_H
#define INC_PCFG_H

DECLSPEC u32  pcfg_pool_byte (GLOBAL_AS const u32 *pool, const u32 off);
DECLSPEC u32  pcfg_get_byte  (PRIVATE_AS const u32 *w, const u32 off);
DECLSPEC void pcfg_put_byte  (PRIVATE_AS u32 *w, const u32 off, const u32 b);

DECLSPEC void pcfg_case_slot (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS const u32 *digit, PRIVATE_AS u32 *w, const u32 j);

DECLSPEC u32  pcfg_ent_off    (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, const u32 j, const u32 n);
DECLSPEC u32  pcfg_ent_len    (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, const u32 j, const u32 n);

DECLSPEC bool pcfg_odo_seed   (LOCAL_AS const pcfg_cell_t *cell, const u32 il_pos, LOCAL_AS u32 *digit);
DECLSPEC int  pcfg_odo_next   (LOCAL_AS const pcfg_cell_t *cell, LOCAL_AS u32 *digit);
DECLSPEC u32  pcfg_write      (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w);
DECLSPEC u32  pcfg_write_from (LOCAL_AS const pcfg_cell_t *cell, GLOBAL_AS const u32 *pool, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w, const u32 from);

#endif
