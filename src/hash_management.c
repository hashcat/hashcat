/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "tuningdb.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "thread.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "terminal.h"
#include "status.h"
#include "rp_kernel_on_cpu.h"
#include "hash_management.h"

extern hc_global_data_t data;

extern hc_thread_mutex_t mux_display;

int sort_by_digest_p0p1 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  const uint dgst_pos0 = data.hashconfig->dgst_pos0;
  const uint dgst_pos1 = data.hashconfig->dgst_pos1;
  const uint dgst_pos2 = data.hashconfig->dgst_pos2;
  const uint dgst_pos3 = data.hashconfig->dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return  1;
  if (d1[dgst_pos3] < d2[dgst_pos3]) return -1;
  if (d1[dgst_pos2] > d2[dgst_pos2]) return  1;
  if (d1[dgst_pos2] < d2[dgst_pos2]) return -1;
  if (d1[dgst_pos1] > d2[dgst_pos1]) return  1;
  if (d1[dgst_pos1] < d2[dgst_pos1]) return -1;
  if (d1[dgst_pos0] > d2[dgst_pos0]) return  1;
  if (d1[dgst_pos0] < d2[dgst_pos0]) return -1;

  return 0;
}

int sort_by_salt (const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *) v1;
  const salt_t *s2 = (const salt_t *) v2;

  const int res1 = s1->salt_len - s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = s1->salt_iter - s2->salt_iter;

  if (res2 != 0) return (res2);

  uint n;

  n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return  1;
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  n = 8;

  while (n--)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return  1;
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}

int sort_by_hash (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  if (data.hashconfig->is_salted)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2);
}

int sort_by_hash_no_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2);
}

void save_hash ()
{
  hashconfig_t *hashconfig  = data.hashconfig;
  void         *digests_buf = data.digests_buf;
  salt_t       *salts_buf   = data.salts_buf;
  void         *esalts_buf  = data.esalts_buf;
  hashinfo_t  **hash_info   = data.hash_info;
  char         *hashfile    = data.hashfile;

  char new_hashfile[256] = { 0 };
  char old_hashfile[256] = { 0 };

  snprintf (new_hashfile, 255, "%s.new", hashfile);
  snprintf (old_hashfile, 255, "%s.old", hashfile);

  unlink (new_hashfile);

  char separator = hashconfig->separator;

  FILE *fp = fopen (new_hashfile, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s", new_hashfile, strerror (errno));

    exit (-1);
  }

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    if (data.salts_shown[salt_pos] == 1) continue;

    salt_t *salt_buf = &data.salts_buf[salt_pos];

    for (uint digest_pos = 0; digest_pos < salt_buf->digests_cnt; digest_pos++)
    {
      uint idx = salt_buf->digests_offset + digest_pos;

      if (data.digests_shown[idx] == 1) continue;

      if (hashconfig->hash_mode != 2500)
      {
        if (data.username == 1)
        {
          user_t *user = data.hash_info[idx]->user;

          uint i;

          for (i = 0; i < user->user_len; i++) fputc (user->user_name[i], fp);

          fputc (separator, fp);
        }

        char out_buf[HCBUFSIZ_LARGE]; // scratch buffer

        out_buf[0] = 0;

        ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf, hash_info, hashfile);

        fputs (out_buf, fp);

        fputc ('\n', fp);
      }
      else
      {
        hccap_t hccap;

        to_hccap_t (&hccap, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf);

        fwrite (&hccap, sizeof (hccap_t), 1, fp);
      }
    }
  }

  fflush (fp);

  fclose (fp);

  unlink (old_hashfile);

  if (rename (hashfile, old_hashfile) != 0)
  {
    log_error ("ERROR: Rename file '%s' to '%s': %s", hashfile, old_hashfile, strerror (errno));

    exit (-1);
  }

  unlink (hashfile);

  if (rename (new_hashfile, hashfile) != 0)
  {
    log_error ("ERROR: Rename file '%s' to '%s': %s", new_hashfile, hashfile, strerror (errno));

    exit (-1);
  }

  unlink (old_hashfile);
}

void check_hash (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, plain_t *plain)
{
  debugfile_ctx_t *debugfile_ctx = data.debugfile_ctx;
  loopback_ctx_t  *loopback_ctx  = data.loopback_ctx;
  outfile_ctx_t   *outfile_ctx   = data.outfile_ctx;
  potfile_ctx_t   *potfile_ctx   = data.potfile_ctx;

  uint quiet = data.quiet;

  // debugfile

  u8  debug_rule_buf[BLOCK_SIZE] = { 0 };
  u32 debug_rule_len  = 0; // -1 error

  u8  debug_plain_ptr[BLOCK_SIZE] = { 0 };
  u32 debug_plain_len = 0;

  // hash

  char out_buf[HCBUFSIZ_LARGE] = { 0 };

  const u32 salt_pos    = plain->salt_pos;
  const u32 digest_pos  = plain->digest_pos;  // relative
  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

  hashconfig_t *hashconfig  = data.hashconfig;
  void         *digests_buf = data.digests_buf;
  salt_t       *salts_buf   = data.salts_buf;
  void         *esalts_buf  = data.esalts_buf;
  hashinfo_t  **hash_info   = data.hash_info;
  char         *hashfile    = data.hashfile;

  ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf, hash_info, hashfile);

  // plain

  u64 crackpos = device_param->words_off;

  uint plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  unsigned int plain_len = 0;

  if (data.attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    const uint off = device_param->innerloop_pos + il_pos;

    const uint debug_mode = debugfile_ctx->mode;

    if (debug_mode > 0)
    {
      debug_rule_len = 0;

      // save rule
      if ((debug_mode == 1) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset (debug_rule_buf, 0, sizeof (debug_rule_buf));

        debug_rule_len = kernel_rule_to_cpu_rule ((char *) debug_rule_buf, &data.kernel_rules_buf[off]);
      }

      // save plain
      if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset (debug_plain_ptr, 0, sizeof (debug_plain_ptr));

        memcpy (debug_plain_ptr, plain_ptr, plain_len);

        debug_plain_len = plain_len;
      }
    }

    plain_len = apply_rules (data.kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], plain_len);

    crackpos += gidvid;
    crackpos *= data.kernel_rules_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (plain_len > data.pw_max) plain_len = data.pw_max;
  }
  else if (data.attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
    uint  comb_len =          device_param->combs_buf[il_pos].pw_len;

    if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      memcpy (plain_ptr + plain_len, comb_buf, comb_len);
    }
    else
    {
      memmove (plain_ptr + comb_len, plain_ptr, plain_len);

      memcpy (plain_ptr, comb_buf, comb_len);
    }

    plain_len += comb_len;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  else if (data.attack_mode == ATTACK_MODE_BF)
  {
    u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
    u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

    uint l_start = device_param->kernel_params_mp_l_buf32[5];
    uint r_start = device_param->kernel_params_mp_r_buf32[5];

    uint l_stop = device_param->kernel_params_mp_l_buf32[4];
    uint r_stop = device_param->kernel_params_mp_r_buf32[4];

    sp_exec (l_off, (char *) plain_ptr + l_start, data.root_css_buf, data.markov_css_buf, l_start, l_start + l_stop);
    sp_exec (r_off, (char *) plain_ptr + r_start, data.root_css_buf, data.markov_css_buf, r_start, r_start + r_stop);

    plain_len = data.css_cnt;

    crackpos += gidvid;
    crackpos *= data.bfs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop  = device_param->kernel_params_mp_buf32[4];

    sp_exec (off, (char *) plain_ptr + plain_len, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop  = device_param->kernel_params_mp_buf32[4];

    memmove (plain_ptr + stop, plain_ptr, plain_len);

    sp_exec (off, (char *) plain_ptr, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }

  if (data.attack_mode == ATTACK_MODE_BF)
  {
    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE) // lots of optimizations can happen here
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          plain_len = plain_len - data.salts_buf[0].salt_len;
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        for (uint i = 0, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
    }
  }

  // no need for locking, we're in a mutex protected function

  potfile_write_append (potfile_ctx, out_buf, plain_ptr, plain_len);

  // outfile, can be either to file or stdout
  // if an error occurs opening the file, send to stdout as fallback
  // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs


  outfile_write_open (outfile_ctx);

  if (outfile_ctx->filename == NULL) if (quiet == 0) clear_prompt ();

  outfile_write (outfile_ctx, out_buf, plain_ptr, plain_len, crackpos, NULL, 0, hashconfig);

  outfile_write_close (outfile_ctx);

  if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
  {
    if ((opencl_ctx->devices_status != STATUS_CRACKED) && (data.status != 1))
    {
      if (outfile_ctx->filename == NULL) if (quiet == 0) send_prompt ();
    }
  }

  // if enabled, update also the loopback file


  if (loopback_ctx->fp != NULL)
  {
    loopback_write_append (loopback_ctx, plain_ptr, plain_len);
  }

  // if enabled, update also the (rule) debug file

  if (debugfile_ctx->fp != NULL)
  {
    // the next check implies that:
    // - (data.attack_mode == ATTACK_MODE_STRAIGHT)
    // - debug_mode > 0

    if ((debug_plain_len > 0) || (debug_rule_len > 0))
    {
      debugfile_write_append (debugfile_ctx, debug_rule_buf, debug_rule_len, debug_plain_ptr, debug_plain_len, plain_ptr, plain_len);
    }
  }
}

int check_cracked (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint salt_pos, hashconfig_t *hashconfig)
{
  salt_t *salt_buf = &data.salts_buf[salt_pos];

  u32 num_cracked;

  cl_int CL_err;

  CL_err = hc_clEnqueueReadBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  if (num_cracked)
  {
    // display hack (for weak hashes etc, it could be that there is still something to clear on the current line)

    log_info_nn ("");

    plain_t *cracked = (plain_t *) mycalloc (num_cracked, sizeof (plain_t));

    CL_err = hc_clEnqueueReadBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_plain_bufs, CL_TRUE, 0, num_cracked * sizeof (plain_t), cracked, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    uint cpt_cracked = 0;

    hc_thread_mutex_lock (mux_display);

    for (uint i = 0; i < num_cracked; i++)
    {
      const uint hash_pos = cracked[i].hash_pos;

      if (data.digests_shown[hash_pos] == 1) continue;

      if ((hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) == 0)
      {
        data.digests_shown[hash_pos] = 1;

        data.digests_done++;

        cpt_cracked++;

        salt_buf->digests_done++;

        if (salt_buf->digests_done == salt_buf->digests_cnt)
        {
          data.salts_shown[salt_pos] = 1;

          data.salts_done++;
        }
      }

      if (data.salts_done == data.salts_cnt) opencl_ctx->devices_status = STATUS_CRACKED;

      check_hash (opencl_ctx, device_param, &cracked[i]);
    }

    hc_thread_mutex_unlock (mux_display);

    myfree (cracked);

    if (cpt_cracked > 0)
    {
      hc_thread_mutex_lock (mux_display);

      data.cpt_buf[data.cpt_pos].timestamp = time (NULL);
      data.cpt_buf[data.cpt_pos].cracked   = cpt_cracked;

      data.cpt_pos++;

      data.cpt_total += cpt_cracked;

      if (data.cpt_pos == CPT_BUF) data.cpt_pos = 0;

      hc_thread_mutex_unlock (mux_display);
    }

    if (hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK)
    {
      // we need to reset cracked state on the device
      // otherwise host thinks again and again the hash was cracked
      // and returns invalid password each time

      memset (data.digests_shown_tmp, 0, salt_buf->digests_cnt * sizeof (uint));

      CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_digests_shown, CL_TRUE, salt_buf->digests_offset * sizeof (uint), salt_buf->digests_cnt * sizeof (uint), &data.digests_shown_tmp[salt_buf->digests_offset], 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    num_cracked = 0;

    CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  return 0;
}
