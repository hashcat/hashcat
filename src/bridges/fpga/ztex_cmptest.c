/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"

#include "fpga/hcfpga.h"
#include "fpga/ztex_tool_ctx.h"
#include "fpga/hcfpga_bcrypt_ref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PKT_WORD_LIST   0x01
#define PKT_WORD_GEN    0x02
#define PKT_CMP_CONFIG  0x03

#define EK_WORDS  18

#define CMP_REC   32

#define POS_MAX   16

#define PW_MAX    72

static const u8 WORD_GEN_PASS_BY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0xbb };

static void pw_to_ek (const u8 *pw, const u32 len, const u32 cyclen, u32 *ek)
{
  u32 idx = 0;

  for (u32 w = 0; w < EK_WORDS; w++)
  {
    u32 val = 0;

    for (u32 k = 0; k < 4; k++)
    {
      const u8 c = (idx < len) ? pw[idx] : 0;

      val = (val << 8) | c;

      idx++;

      if (idx >= cyclen) idx = 0;
    }

    ek[w] = val;
  }
}

static void make_pw (const u32 c, const u32 len, u8 *pw)
{
  u32 v = c + 0x01000000u;

  for (u32 i = 0; i < len; i++)
  {
    pw[i] = (u8) ('a' + (v % 26));

    v /= 26;
  }

  pw[len] = 0;
}

int main (int argc, char **argv)
{
  const char *dir = (argc > 1) ? argv[1] : ".";

  hashcat_ctx_t *hashcat_ctx = ztex_tool_ctx (dir);

  const u32 cost = (argc > 2) ? (u32) atoi (argv[2]) : 5;

  const u32 cands = (argc > 3) ? (u32) atoi (argv[3]) : 900;

  const u32 wordlen = (argc > 4) ? (u32) atoi (argv[4]) : 8;

  if (wordlen > PW_MAX)
  {
    printf ("word length %u is longer than the %u bytes bcrypt takes\n", wordlen, PW_MAX);
    printf ("usage: %s [dir] [cost] [candidates] [word length] [reps]\n", argv[0]);

    return 1;
  }

  const u32 reps = (argc > 5) ? (u32) atoi (argv[5]) : 1;

  const fpga_transport_t *transport = &fpga_transport_ztex115y;

  fpga_dev_t devs[FPGA_MAX_DEVICES];

  fpga_status_t status = FPGA_STATUS_OK;

  const int cnt = transport->enumerate (hashcat_ctx, devs, FPGA_MAX_DEVICES, &status);

  if (cnt <= 0)
  {
    printf ("no ZTEX found (status %d)\n", (int) status);

    return 1;
  }

  fpga_dev_t *dev = &devs[0];

  dev->transport = transport;

  if (transport->program (hashcat_ctx, dev, "bcrypt") != FPGA_STATUS_OK)
  {
    printf ("program failed\n");

    return 1;
  }

  if (transport->identify (dev) != FPGA_STATUS_OK)
  {
    printf ("identify failed\n");

    return 1;
  }

  if (transport->session_open (dev) == false)
  {
    printf ("session_open failed\n");

    return 1;
  }

  const u32 salt_buf[4] = { 0x0123abcd, 0x89ab4567, 0xfedc7654, 0x76543210 };

  const u32 iter = 1u << cost;

  const u32 want[POS_MAX] = { 0, 1, 61, 122, 123, 124, 125, 200, 496, 899 };

  u32 pos[POS_MAX];

  u32 pos_cnt = 0;

  for (u32 i = 0; i < 10; i++)
  {
    if (want[i] >= cands) continue;

    pos[pos_cnt] = want[i];

    pos_cnt++;
  }

  printf ("cost %u (%u rounds), %u candidates of %u chars, %u planted positions\n\n", cost, iter, cands, wordlen, pos_cnt);

  const u32 pad = (getenv ("ZTEX_PADHASHES") != NULL) ? (u32) atoi (getenv ("ZTEX_PADHASHES")) : 0;

  const u32 nbin = (pos_cnt * 4) + pad;

  u8 *cfg = (u8 *) hcmalloc (64 + (nbin * 4));

  u32 off = 0;

  for (u32 i = 0; i < 4; i++)
  {
    memcpy (&cfg[off], &salt_buf[i], 4);

    off += 4;
  }

  cfg[off++] = (u8) 'a';

  cfg[off++] = (u8) (iter >>  0);
  cfg[off++] = (u8) (iter >>  8);
  cfg[off++] = (u8) (iter >> 16);
  cfg[off++] = (u8) (iter >> 24);

  cfg[off++] = (u8) (nbin >> 0);
  cfg[off++] = (u8) (nbin >> 8);

  for (u32 p = 0; p < pos_cnt; p++)
  {
    u8 pw[80];

    make_pw (pos[p], wordlen, pw);

    for (u32 cyc = 0; cyc < 2; cyc++)
    {
      u32 ek[EK_WORDS];

      pw_to_ek (pw, wordlen, (cyc == 0) ? wordlen : (wordlen + 1), ek);

      u32 gold[6];

      hcfpga_bcrypt_canary (ek, salt_buf, (int) iter, gold);

      cfg[off + 0] = (u8) (gold[0] >>  0);
      cfg[off + 1] = (u8) (gold[0] >>  8);
      cfg[off + 2] = (u8) (gold[0] >> 16);
      cfg[off + 3] = (u8) (gold[0] >> 24);

      off += 4;

      cfg[off + 0] = (u8) (gold[0] >> 24);
      cfg[off + 1] = (u8) (gold[0] >> 16);
      cfg[off + 2] = (u8) (gold[0] >>  8);
      cfg[off + 3] = (u8) (gold[0] >>  0);

      off += 4;
    }
  }

  for (u32 i = 0; i < pad; i++)
  {
    cfg[off + 0] = (u8) (i >>  0);
    cfg[off + 1] = (u8) (i >>  8);
    cfg[off + 2] = 0xde;
    cfg[off + 3] = 0xad;

    off += 4;
  }

  cfg[off++] = 0xcc;

  if (transport->control (dev, PKT_CMP_CONFIG, cfg, off) == false)
  {
    printf ("cmp_config failed\n");

    return 1;
  }

  if (transport->control (dev, PKT_WORD_GEN, WORD_GEN_PASS_BY, sizeof (WORD_GEN_PASS_BY)) == false)
  {
    printf ("word_gen failed\n");

    return 1;
  }

  const u32 word_bytes = wordlen + 1;

  u8 *out = (u8 *) hcmalloc ((u64) cands * word_bytes);

  for (u32 c = 0; c < cands; c++)
  {
    make_pw (c, wordlen, &out[c * word_bytes]);
  }

  bool seen[POS_MAX];

  for (u32 i = 0; i < POS_MAX; i++) seen[i] = false;

  u32 matches = 0;

  u32 processed = 0;

  const u64 t0 = fpga_now_ns ();

  for (u32 rep = 0; rep < reps; rep++)
  {

  if (transport->batch_begin (dev, (u64) cands * word_bytes, 0, CMP_REC, 0) == false)
  {
    printf ("batch_begin failed\n");

    return 1;
  }

  if (transport->batch_send (dev, out, (u64) cands * word_bytes) == false)
  {
    printf ("batch_send failed\n");

    transport->batch_end (dev);

    return 1;
  }

  const u64 deadline_ns = fpga_now_ns () + (30ull * 1000000000ull);

  while (fpga_now_ns () < deadline_ns)
  {
    u64 bytes = 0;

    const u8 *rx = (const u8 *) transport->batch_recv (dev, &bytes, 5);

    if (rx != NULL)
    {
      for (u64 o = 0; o < bytes; o += CMP_REC)
      {
        const u8 *r = &rx[o];

        const u32 word_id  = (u32) r[0] | ((u32) r[1] << 8);
        const u32 hash_num = (u32) r[6] | ((u32) r[7] << 8);

        const u32 p   = hash_num / 4;
        const u32 cyc = (hash_num / 2) % 2;
        const u32 bo  = hash_num % 2;

        const bool right = ((p < pos_cnt) && (word_id == pos[p])) ? true : false;

        if (right == true) seen[p] = true;

        matches++;

        printf ("  match word_id %-5u hash_num %-3u -> position %-5u cycle %s  byte order %s   %s\n",
          word_id, hash_num, (p < pos_cnt) ? pos[p] : 0,
          (cyc == 0) ? "len   " : "len+1 ",
          (bo == 0) ? "LE" : "BE",
          (right == true) ? "OK" : "<-- WRONG CANDIDATE");
      }
    }

    if (transport->batch_done != NULL)
    {
      if (transport->batch_done (dev, &processed) == true) break;
    }
  }

  transport->batch_end (dev);

  if (rep + 1 < reps)
  {
    if (transport->control (dev, PKT_WORD_GEN, WORD_GEN_PASS_BY, sizeof (WORD_GEN_PASS_BY)) == false) return 1;
  }

  }

  const double ms = (double) (fpga_now_ns () - t0) / 1.0e6;

  u32 found = 0;

  for (u32 p = 0; p < pos_cnt; p++)
  {
    if (seen[p] == true) found++;
  }

  printf ("\n%u matches, %u of %u planted positions found, %u processed, %u reps in %.2f ms (%.0f H/s sustained)\n",
    matches, found, pos_cnt, processed, reps, ms, (double) cands * reps / (ms / 1000.0));

  transport->session_close (dev);

  for (int i = 0; i < cnt; i++) transport->close (&devs[i]);

  printf ("\n%s\n", (found == pos_cnt) ? "PASS" : "FAIL");

  const int rc = (found == pos_cnt) ? 0 : 1;

  return rc;
}
