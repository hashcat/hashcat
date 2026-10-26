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
#include <math.h>
#include <pthread.h>

#define PKT_WORD_LIST   0x01
#define PKT_WORD_GEN    0x02
#define PKT_CMP_CONFIG  0x03

#define EK_WORDS  18
#define EK_BYTES  (EK_WORDS * 4)

#define RESULT_BYTES       24
#define RESULT_REC         (2 + 4 + 2 + RESULT_BYTES)
#define RESULT_DIGEST_OFF  8

#define CMP_MAX  512

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

static u32 ek_no_nul (const u32 val)
{
  u32 out = val;

  for (u32 k = 0; k < 4; k++)
  {
    const u32 shift = 8 * k;

    if (((out >> shift) & 0xff) == 0) out |= (0x01u << shift);
  }

  return out;
}

static void put_be32 (u8 *dst, const u32 val)
{
  dst[0] = (u8) (val >> 24);
  dst[1] = (u8) (val >> 16);
  dst[2] = (u8) (val >>  8);
  dst[3] = (u8) (val >>  0);
}

static u32 get_le32 (const u8 *src)
{
  const u32 val = (u32) src[0] | ((u32) src[1] << 8) | ((u32) src[2] << 16) | ((u32) src[3] << 24);

  return val;
}

static bool send_cmp_config (fpga_dev_t *dev, const u32 *salt_buf, const u32 cost, const char subtype, const u32 *gold, const u32 cands)
{
  u8 *msg = (u8 *) hcmalloc (32 + (cands * 4));

  if (msg == NULL) return false;

  u32 off = 0;

  for (u32 i = 0; i < 4; i++)
  {
    memcpy (&msg[off], &salt_buf[i], 4);

    off += 4;
  }

  msg[off++] = (u8) subtype;

  msg[off++] = (u8) (cost >>  0);
  msg[off++] = (u8) (cost >>  8);
  msg[off++] = (u8) (cost >> 16);
  msg[off++] = (u8) (cost >> 24);

  const u16 num_hashes = (u16) cands;

  msg[off++] = (u8) (num_hashes >> 0);
  msg[off++] = (u8) (num_hashes >> 8);

  for (u32 c = 0; c < cands; c++)
  {
    const u32 g0 = gold[c * 6];

    msg[off + 0] = (u8) (g0 >>  0);
    msg[off + 1] = (u8) (g0 >>  8);
    msg[off + 2] = (u8) (g0 >> 16);
    msg[off + 3] = (u8) (g0 >> 24);

    off += 4;
  }

  msg[off++] = 0xcc;

  const bool ok = dev->transport->control (dev, PKT_CMP_CONFIG, msg, off);

  hcfree (msg);

  return ok;
}

typedef struct
{
  const fpga_transport_t *transport;

  fpga_dev_t *dev;

  int  idx;

  u32  cost;
  u32  cands;
  u32  iter;

  const u32 *salt_buf;

  u32  recv;
  u32  bad;

  bool ok;

} unit_job_t;

static void *run_unit (void *arg)
{
  unit_job_t *j = (unit_job_t *) arg;

  fpga_dev_t *dev = j->dev;

  const fpga_transport_t *transport = j->transport;

  j->ok = false;

  const u32 cands = j->cands;

  const char *wl = getenv ("ZTEX_WORDLEN");

  const u32 wordlen = (wl != NULL) ? (u32) atoi (wl) : 0;

  const u32 word_bytes = (wordlen > 0) ? (wordlen + 1) : EK_BYTES;

  const u64 send_bytes = (u64) cands * word_bytes;

  u8 *out = (u8 *) hcmalloc (send_bytes);

  u32 *ek = (u32 *) hcmalloc ((size_t) cands * EK_WORDS * 4);

  for (u32 c = 0; c < cands; c++)
  {
    for (u32 w = 0; w < EK_WORDS; w++)
    {
      const u32 raw = 0x41424344u + ((u32) (j->idx + 1) * 0x11111111u) + (c * 0x01010101u) + (w * 0x00010203u);

      const u32 val = (getenv ("ZTEX_NONUL") != NULL) ? ek_no_nul (raw) : raw;

      ek[(c * EK_WORDS) + w] = val;

      if (wordlen == 0) put_be32 (&out[(c * EK_BYTES) + (w * 4)], val);
    }

    if (wordlen == 0) continue;

    u32 v = c + ((u32) (j->idx + 1) * 0x01000000u);

    u8 *pw = &out[c * word_bytes];

    for (u32 i = 0; i < wordlen; i++)
    {
      pw[i] = (u8) ('a' + (v % 26));

      v /= 26;
    }

    pw[wordlen] = 0;

    const u32 cyclen = (getenv ("ZTEX_KEYNUL") != NULL) ? (wordlen + 1) : wordlen;

    pw_to_ek (pw, wordlen, cyclen, &ek[c * EK_WORDS]);
  }

  u32 *gold = (u32 *) hcmalloc ((size_t) cands * 6 * 4);

  for (u32 c = 0; c < cands; c++)
  {
    hcfpga_bcrypt_canary (&ek[c * EK_WORDS], j->salt_buf, (int) j->iter, &gold[c * 6]);
  }

  if (send_cmp_config (dev, j->salt_buf, j->iter, 'a', gold, cands) == false)
  {
    printf ("unit %d: cmp_config failed\n", j->idx);

    hcfree (gold); hcfree (out); hcfree (ek);

    return NULL;
  }

  if (transport->control (dev, PKT_WORD_GEN, WORD_GEN_PASS_BY, sizeof (WORD_GEN_PASS_BY)) == false)
  {
    printf ("unit %d: word_gen failed\n", j->idx);

    hcfree (gold); hcfree (out); hcfree (ek);

    return NULL;
  }

  if (transport->batch_begin (dev, send_bytes, 0, RESULT_REC, 0) == false)
  {
    printf ("unit %d: batch_begin failed\n", j->idx);

    hcfree (gold); hcfree (out); hcfree (ek);

    return NULL;
  }

  if (transport->batch_send (dev, out, send_bytes) == false)
  {
    printf ("unit %d: batch_send failed\n", j->idx);

    transport->batch_end (dev);

    hcfree (gold); hcfree (out); hcfree (ek);

    return NULL;
  }

  bool *got = (bool *) hccalloc (cands, sizeof (bool));

  const double encryptions = (double) (1u << j->cost) * 1064.0;

  const double wave_s = (encryptions * 18.0) / ((double) dev->ident.clk_mhz * 1.0e6);

  const double waves = ceil ((double) cands / (double) dev->ident.cores);

  const u64 budget_s = 5ull + (u64) (8.0 * waves * wave_s);

  const u64 deadline_ns = fpga_now_ns () + (budget_s * 1000000000ull);

  while (j->recv < cands)
  {
    if (fpga_now_ns () > deadline_ns) break;

    u64 bytes = 0;

    const u8 *rx = (const u8 *) transport->batch_recv (dev, &bytes, 5);

    if (rx == NULL) continue;

    for (u64 off = 0; off < bytes; off += RESULT_REC)
    {
      const u8 *r = &rx[off];

      const u32 word_id = (u32) r[0] | ((u32) r[1] << 8);

      if (word_id >= cands) continue;

      if (got[word_id] == true) continue;

      got[word_id] = true;

      const u32 *want = &gold[word_id * 6];

      bool mismatch = false;

      for (u32 k = 0; k < 6; k++)
      {
        if (get_le32 (&r[RESULT_DIGEST_OFF + (k * 4)]) != want[k]) mismatch = true;
      }

      if (mismatch == true)
      {
        if (j->bad == 0)
        {
          printf ("unit %d: word_id %u MISMATCH\n  device ", j->idx, word_id);

          for (u32 k = 0; k < 6; k++) printf ("%08x", get_le32 (&r[RESULT_DIGEST_OFF + (k * 4)]));

          printf ("\n  host   ");

          for (u32 k = 0; k < 6; k++) printf ("%08x", want[k]);

          printf ("\n");

          int matched = -1;

          for (u32 c = 0; c < cands; c++)
          {
            const u32 *other = &gold[c * 6];

            bool same = true;

            for (u32 k = 0; k < 6; k++)
            {
              if (get_le32 (&r[RESULT_DIGEST_OFF + (k * 4)]) != other[k]) same = false;
            }

            if (same == true) { matched = (int) c; break; }
          }

          if (matched >= 0) printf ("  -> it is candidate %d's digest, delivered under id %u\n", matched, word_id);
          else              printf ("  -> matches NO candidate in this batch, so the key itself was wrong\n");

          if (matched < 0)
          {
            u32 alt[EK_WORDS];

            const char *names[10] = { "last BYTE zeroed", "last WORD zeroed", "last two words zeroed",
                                      "all zeroes", "stream shifted one byte EARLY",
                                      "stream shifted one byte LATE",
                                      "seen as 68 bytes and CYCLED", "seen as 69 bytes and CYCLED",
                                      "seen as 70 bytes and CYCLED", "seen as 71 bytes and CYCLED" };

            for (u32 v = 0; v < 10; v++)
            {
              memcpy (alt, &ek[word_id * EK_WORDS], EK_WORDS * 4);

              if (v == 0) alt[17] &= 0xffffff00u;
              if (v == 1) alt[17]  = 0;
              if (v == 2) { alt[17] = 0; alt[16] = 0; }
              if (v == 3) memset (alt, 0, sizeof (alt));

              if (v >= 4)
              {
                u8 wire[EK_BYTES + 2];

                for (u32 w = 0; w < EK_WORDS; w++) put_be32 (&wire[w * 4], ek[(word_id * EK_WORDS) + w]);

                wire[EK_BYTES + 0] = 0;
                wire[EK_BYTES + 1] = 0;

                u8 shifted[EK_BYTES];

                if (v == 4) memcpy (shifted, &wire[1], EK_BYTES);
                else { shifted[0] = 0; memcpy (&shifted[1], wire, EK_BYTES - 1); }

                for (u32 w = 0; w < EK_WORDS; w++)
                {
                  alt[w] = ((u32) shifted[w * 4] << 24) | ((u32) shifted[(w * 4) + 1] << 16)
                         | ((u32) shifted[(w * 4) + 2] << 8) | (u32) shifted[(w * 4) + 3];
                }
              }

              if (v >= 6)
              {
                const u32 seen = 68 + (v - 6);

                u8 wire[EK_BYTES];

                for (u32 w = 0; w < EK_WORDS; w++) put_be32 (&wire[w * 4], ek[(word_id * EK_WORDS) + w]);

                u8 cyc[EK_BYTES];

                for (u32 b = 0; b < EK_BYTES; b++) cyc[b] = wire[b % seen];

                for (u32 w = 0; w < EK_WORDS; w++)
                {
                  alt[w] = ((u32) cyc[w * 4] << 24) | ((u32) cyc[(w * 4) + 1] << 16)
                         | ((u32) cyc[(w * 4) + 2] << 8) | (u32) cyc[(w * 4) + 3];
                }
              }

              u32 g2[6];

              hcfpga_bcrypt_canary (alt, j->salt_buf, (int) j->iter, g2);

              bool same = true;

              for (u32 k = 0; k < 6; k++)
              {
                if (get_le32 (&r[RESULT_DIGEST_OFF + (k * 4)]) != g2[k]) same = false;
              }

              if (same == true) printf ("  -> the device computed it with the %s\n", names[v]);
            }
          }
        }

        j->bad++;
      }

      j->recv++;
    }
  }

  transport->batch_end (dev);

  hcfree (got); hcfree (gold); hcfree (out); hcfree (ek);

  j->ok = ((j->recv == cands) && (j->bad == 0)) ? true : false;

  return NULL;
}

int main (int argc, char **argv)
{
  const char *dir = (argc > 1) ? argv[1] : ".";

  hashcat_ctx_t *hashcat_ctx = ztex_tool_ctx (dir);

  const u32 cost = (argc > 2) ? (u32) atoi (argv[2]) : 5;

  const u32 cands = (argc > 3) ? (u32) atoi (argv[3]) : 64;

  if (cands > CMP_MAX)
  {
    printf ("at most %u candidates per unit: the device's comparator holds one binary per candidate\n", CMP_MAX);

    return 1;
  }

  const int mode = (argc > 4) ? atoi (argv[4]) : 0;

  const int max_units = (argc > 5) ? atoi (argv[5]) : FPGA_MAX_DEVICES;

  const bool threaded = (mode == 1) ? true : false;

  const bool isolated = (mode == 2) ? true : false;

  const fpga_transport_t *transport = &fpga_transport_ztex115y;

  fpga_dev_t devs[FPGA_MAX_DEVICES];

  fpga_status_t status = FPGA_STATUS_OK;

  const int cnt = transport->enumerate (hashcat_ctx, devs, FPGA_MAX_DEVICES, &status);

  if (cnt == 0)
  {
    printf ("no ZTEX found (status %d)\n", (int) status);

    return 1;
  }

  const u32 salt_buf[4] = { 0x0123abcd, 0x89ab4567, 0xfedc7654, 0x76543210 };

  const u32 iter = 1u << cost;

  printf ("units %d, cost %u (%u rounds), %u candidates per unit\n\n", cnt, cost, iter, cands);

  int ready = 0;

  unit_job_t jobs[FPGA_MAX_DEVICES];

  for (int u = 0; u < cnt; u++)
  {
    if (u >= max_units) break;

    fpga_dev_t *dev = &devs[u];

    dev->transport = transport;

    if (transport->program (hashcat_ctx, dev, "bcrypt") != FPGA_STATUS_OK)
    {
      printf ("unit %d: program failed\n", u);

      continue;
    }

    if (transport->identify (dev) != FPGA_STATUS_OK)
    {
      printf ("unit %d: identify failed\n", u);

      continue;
    }

    memset (&jobs[ready], 0, sizeof (unit_job_t));

    jobs[ready].transport = transport;
    jobs[ready].dev       = dev;
    jobs[ready].idx       = u;
    jobs[ready].cost      = cost;
    jobs[ready].cands     = cands;
    jobs[ready].iter      = iter;
    jobs[ready].salt_buf  = salt_buf;

    ready++;

    if (isolated == true)
    {
      if (transport->session_open (dev) == false)
      {
        printf ("unit %d: session_open failed\n", u);

        jobs[ready - 1].ok = false;
      }
      else
      {
        run_unit (&jobs[ready - 1]);
      }

      transport->session_close (dev);
    }
  }

  for (int i = 0; i < ready; i++)
  {
    if (isolated == true) break;

    if (transport->session_open (jobs[i].dev) == false)
    {
      printf ("unit %d: session_open failed\n", jobs[i].idx);

      jobs[i].ok = false;
    }
  }

  printf ("%d unit(s) ready, mode %s\n\n", ready,
    (threaded == true) ? "CONCURRENT" : ((isolated == true) ? "ISOLATED (one session at a time)" : "sequential, all sessions open"));

  const u64 t0 = fpga_now_ns ();

  if (isolated == true)
  {
  }
  else if (threaded == true)
  {
    pthread_t tid[FPGA_MAX_DEVICES];

    for (int i = 0; i < ready; i++) pthread_create (&tid[i], NULL, run_unit, &jobs[i]);

    for (int i = 0; i < ready; i++) pthread_join (tid[i], NULL);
  }
  else
  {
    for (int i = 0; i < ready; i++) run_unit (&jobs[i]);
  }

  const double elapsed = (double) (fpga_now_ns () - t0) / 1.0e9;

  int failed = 0;

  u32 total = 0;

  for (int i = 0; i < ready; i++)
  {
    printf ("unit %d: %u/%u results, %u bad %s\n", jobs[i].idx, jobs[i].recv, cands, jobs[i].bad,
      (jobs[i].ok == true) ? "OK" : "<-- FAIL");

    if (jobs[i].ok == false) failed++;

    total += jobs[i].recv;
  }

  const int wanted = MIN (cnt, max_units);

  if (ready != wanted) failed++;

  printf ("\n%.2f s, %u results, %.0f H/s aggregate\n", elapsed, total, (double) total / elapsed);

  if (isolated == false)
  {
    for (int i = 0; i < ready; i++) transport->session_close (jobs[i].dev);
  }

  for (int i = 0; i < cnt; i++) transport->close (&devs[i]);

  printf ("\n%s\n", (failed == 0) ? "PASS" : "FAIL");

  return (failed == 0) ? 0 : 1;
}
