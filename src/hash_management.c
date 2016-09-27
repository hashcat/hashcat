/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "logfile.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "filehandling.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "terminal.h"
#include "status.h"
#include "rp.h"
#include "rp_cpu.h"
#include "rp_kernel_on_cpu.h"
#include "hlfmt.h"

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

void save_hash (const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  char *hashfile = hashes->hashfile;

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

  for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    if (hashes->salts_shown[salt_pos] == 1) continue;

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    for (uint digest_pos = 0; digest_pos < salt_buf->digests_cnt; digest_pos++)
    {
      uint idx = salt_buf->digests_offset + digest_pos;

      if (hashes->digests_shown[idx] == 1) continue;

      if (hashconfig->hash_mode != 2500)
      {
        if (user_options->username == 1)
        {
          user_t *user = hashes->hash_info[idx]->user;

          uint i;

          for (i = 0; i < user->user_len; i++) fputc (user->user_name[i], fp);

          fputc (separator, fp);
        }

        char out_buf[HCBUFSIZ_LARGE]; // scratch buffer

        out_buf[0] = 0;

        ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, hashes);

        fputs (out_buf, fp);

        fputc ('\n', fp);
      }
      else
      {
        hccap_t hccap;

        to_hccap_t (&hccap, salt_pos, digest_pos, hashconfig, hashes);

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

void check_hash (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, plain_t *plain)
{
  debugfile_ctx_t *debugfile_ctx = data.debugfile_ctx;
  loopback_ctx_t  *loopback_ctx  = data.loopback_ctx;
  outfile_ctx_t   *outfile_ctx   = data.outfile_ctx;
  potfile_ctx_t   *potfile_ctx   = data.potfile_ctx;
  mask_ctx_t      *mask_ctx      = data.mask_ctx;

  hashconfig_t *hashconfig  = data.hashconfig;
  hashes_t     *hashes      = data.hashes;

  const u32 salt_pos    = plain->salt_pos;
  const u32 digest_pos  = plain->digest_pos;  // relative
  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

  const uint quiet = user_options->quiet;

  // debugfile

  u8  debug_rule_buf[BLOCK_SIZE] = { 0 };
  u32 debug_rule_len  = 0; // -1 error

  u8  debug_plain_ptr[BLOCK_SIZE] = { 0 };
  u32 debug_plain_len = 0;

  // hash

  char out_buf[HCBUFSIZ_LARGE] = { 0 };

  ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, hashes);

  // plain

  u64 crackpos = device_param->words_off;

  uint plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  unsigned int plain_len = 0;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
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

        debug_rule_len = kernel_rule_to_cpu_rule ((char *) debug_rule_buf, &straight_ctx->kernel_rules_buf[off]);
      }

      // save plain
      if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset (debug_plain_ptr, 0, sizeof (debug_plain_ptr));

        memcpy (debug_plain_ptr, plain_ptr, plain_len);

        debug_plain_len = plain_len;
      }
    }

    plain_len = apply_rules (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], plain_len);

    crackpos += gidvid;
    crackpos *= straight_ctx->kernel_rules_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (plain_len > data.pw_max) plain_len = data.pw_max;
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
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
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
    u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

    uint l_start = device_param->kernel_params_mp_l_buf32[5];
    uint r_start = device_param->kernel_params_mp_r_buf32[5];

    uint l_stop = device_param->kernel_params_mp_l_buf32[4];
    uint r_stop = device_param->kernel_params_mp_r_buf32[4];

    sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
    sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

    plain_len = mask_ctx->css_cnt;

    crackpos += gidvid;
    crackpos *= mask_ctx->bfs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
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

    sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
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

    sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE) // lots of optimizations can happen here
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          plain_len = plain_len - hashes->salts_buf[0].salt_len;
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

  if (outfile_ctx->filename == NULL) if (quiet == false) clear_prompt ();

  outfile_write (outfile_ctx, out_buf, plain_ptr, plain_len, crackpos, NULL, 0, hashconfig);

  outfile_write_close (outfile_ctx);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if ((opencl_ctx->devices_status != STATUS_CRACKED) && (user_options->status != true))
    {
      if (outfile_ctx->filename == NULL) if (quiet == false) send_prompt ();
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
    // - (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    // - debug_mode > 0

    if ((debug_plain_len > 0) || (debug_rule_len > 0))
    {
      debugfile_write_append (debugfile_ctx, debug_rule_buf, debug_rule_len, debug_plain_ptr, debug_plain_len, plain_ptr, plain_len);
    }
  }
}

int check_cracked (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, hashconfig_t *hashconfig, hashes_t *hashes, const uint salt_pos)
{
  salt_t *salt_buf = &hashes->salts_buf[salt_pos];

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

      if (hashes->digests_shown[hash_pos] == 1) continue;

      if ((hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) == 0)
      {
        hashes->digests_shown[hash_pos] = 1;

        hashes->digests_done++;

        cpt_cracked++;

        salt_buf->digests_done++;

        if (salt_buf->digests_done == salt_buf->digests_cnt)
        {
          hashes->salts_shown[salt_pos] = 1;

          hashes->salts_done++;
        }
      }

      if (hashes->salts_done == hashes->salts_cnt) mycracked (opencl_ctx);

      check_hash (opencl_ctx, device_param, user_options, user_options_extra, straight_ctx, &cracked[i]);
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

      memset (hashes->digests_shown_tmp, 0, salt_buf->digests_cnt * sizeof (uint));

      CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_digests_shown, CL_TRUE, salt_buf->digests_offset * sizeof (uint), salt_buf->digests_cnt * sizeof (uint), &hashes->digests_shown_tmp[salt_buf->digests_offset], 0, NULL, NULL);

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

int hashes_init_stage1 (hashes_t *hashes, const hashconfig_t *hashconfig, potfile_ctx_t *potfile_ctx, outfile_ctx_t *outfile_ctx, user_options_t *user_options, char *hash_or_file)
{
  /**
   * load hashes, part I: find input mode, count hashes
   */

  uint hashlist_mode   = 0;
  uint hashlist_format = HLFMT_HASHCAT;

  uint hashes_avail = 0;

  if ((user_options->benchmark == false) && (user_options->stdout_flag == false))
  {
    struct stat f;

    hashlist_mode = (stat (hash_or_file, &f) == 0) ? HL_MODE_FILE : HL_MODE_ARG;

    if ((hashconfig->hash_mode == 2500) ||
        (hashconfig->hash_mode == 5200) ||
        ((hashconfig->hash_mode >=  6200) && (hashconfig->hash_mode <=  6299)) ||
        ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799)) ||
        (hashconfig->hash_mode == 9000))
    {
      hashlist_mode = HL_MODE_ARG;

      char *hashfile = hash_or_file;

      hashes->hashfile = hashfile;
    }

    if (hashlist_mode == HL_MODE_ARG)
    {
      if (hashconfig->hash_mode == 2500)
      {
        struct stat st;

        if (stat (hashes->hashfile, &st) == -1)
        {
          log_error ("ERROR: %s: %s", hashes->hashfile, strerror (errno));

          return -1;
        }

        hashes_avail = st.st_size / sizeof (hccap_t);
      }
      else
      {
        hashes_avail = 1;
      }
    }
    else if (hashlist_mode == HL_MODE_FILE)
    {
      char *hashfile = hash_or_file;

      hashes->hashfile = hashfile;

      FILE *fp = NULL;

      if ((fp = fopen (hashfile, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", hashfile, strerror (errno));

        return -1;
      }

      if (user_options->quiet == false) log_info_nn ("Counting lines in %s", hashfile);

      hashes_avail = count_lines (fp);

      rewind (fp);

      if (hashes_avail == 0)
      {
        log_error ("ERROR: hashfile is empty or corrupt");

        fclose (fp);

        return -1;
      }

      hashlist_format = hlfmt_detect (fp, 100, hashconfig); // 100 = max numbers to "scan". could be hashes_avail, too

      if ((user_options->remove == 1) && (hashlist_format != HLFMT_HASHCAT))
      {
        log_error ("ERROR: remove not supported in native hashfile-format mode");

        fclose (fp);

        return -1;
      }

      fclose (fp);
    }
  }
  else
  {
    hashlist_mode = HL_MODE_ARG;

    hashes_avail = 1;
  }

  if (hashconfig->hash_mode == 3000) hashes_avail *= 2;

  hashes->hashlist_mode   = hashlist_mode;
  hashes->hashlist_format = hashlist_format;

  /**
   * load hashes, part II: allocate required memory, set pointers
   */

  hash_t *hashes_buf  = NULL;
  void   *digests_buf = NULL;
  salt_t *salts_buf   = NULL;
  void   *esalts_buf  = NULL;

  hashes_buf = (hash_t *) mycalloc (hashes_avail, sizeof (hash_t));

  digests_buf = (void *) mycalloc (hashes_avail, hashconfig->dgst_size);

  if ((user_options->username && (user_options->remove || user_options->show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
  {
    u32 hash_pos;

    for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
    {
      hashinfo_t *hash_info = (hashinfo_t *) mymalloc (sizeof (hashinfo_t));

      hashes_buf[hash_pos].hash_info = hash_info;

      if (user_options->username && (user_options->remove || user_options->show || user_options->left))
      {
        hash_info->user = (user_t*) mymalloc (sizeof (user_t));
      }

      if (user_options->benchmark)
      {
        hash_info->orighash = (char *) mymalloc (256);
      }
    }
  }

  if (hashconfig->is_salted)
  {
    salts_buf = (salt_t *) mycalloc (hashes_avail, sizeof (salt_t));

    if (hashconfig->esalt_size)
    {
      esalts_buf = (void *) mycalloc (hashes_avail, hashconfig->esalt_size);
    }
  }
  else
  {
    salts_buf = (salt_t *) mycalloc (1, sizeof (salt_t));
  }

  for (uint hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
  {
    hashes_buf[hash_pos].digest = ((char *) digests_buf) + (hash_pos * hashconfig->dgst_size);

    if (hashconfig->is_salted)
    {
      hashes_buf[hash_pos].salt = &salts_buf[hash_pos];

      if (hashconfig->esalt_size)
      {
        hashes_buf[hash_pos].esalt = ((char *) esalts_buf) + (hash_pos * hashconfig->esalt_size);
      }
    }
    else
    {
      hashes_buf[hash_pos].salt = &salts_buf[0];
    }
  }

  hashes->hashes_buf  = hashes_buf;
  hashes->digests_buf = digests_buf;
  hashes->salts_buf   = salts_buf;
  hashes->esalts_buf  = esalts_buf;

  /**
   * load hashes, part III: parse hashes or generate them if benchmark
   */

  uint hashes_cnt = 0;

  if (user_options->benchmark == true)
  {
    hashconfig_benchmark_defaults ((hashconfig_t *) hashconfig, hashes_buf[0].salt, hashes_buf[0].esalt);

    hashes->hashfile = "-";

    hashes_cnt = 1;
  }
  else if (user_options->keyspace == true)
  {
  }
  else if (user_options->stdout_flag == true)
  {
  }
  else if (user_options->opencl_info == true)
  {
  }
  else
  {
    if (hashes_avail == 0)
    {
      // ???
    }
    else if (hashlist_mode == HL_MODE_ARG)
    {
      char *input_buf = hash_or_file;

      uint input_len = strlen (input_buf);

      char *hash_buf = NULL;
      int   hash_len = 0;

      hlfmt_hash (hashlist_format, input_buf, input_len, &hash_buf, &hash_len, hashconfig, user_options);

      bool hash_fmt_error = 0;

      if (hash_len < 1)     hash_fmt_error = 1;
      if (hash_buf == NULL) hash_fmt_error = 1;

      if (hash_fmt_error)
      {
        log_info ("WARNING: Failed to parse hashes using the '%s' format", strhlfmt (hashlist_format));
      }
      else
      {
        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = mystrdup (hash_buf);
        }

        if (hashconfig->is_salted)
        {
          memset (hashes_buf[0].salt, 0, sizeof (salt_t));
        }

        int parser_status = PARSER_OK;

        if (hashconfig->hash_mode == 2500)
        {
          if (hash_len == 0)
          {
            log_error ("ERROR: hccap file not specified");

            return -1;
          }

          hashlist_mode = HL_MODE_FILE;

          hashes->hashlist_mode = hashlist_mode;

          FILE *fp = fopen (hash_buf, "rb");

          if (fp == NULL)
          {
            log_error ("ERROR: %s: %s", hash_buf, strerror (errno));

            return -1;
          }

          if (hashes_avail < 1)
          {
            log_error ("ERROR: hccap file is empty or corrupt");

            fclose (fp);

            return -1;
          }

          uint hccap_size = sizeof (hccap_t);

          char *in = (char *) mymalloc (hccap_size);

          while (!feof (fp))
          {
            int n = fread (in, hccap_size, 1, fp);

            if (n != 1)
            {
              if (hashes_cnt < 1) parser_status = PARSER_HCCAP_FILE_SIZE;

              break;
            }

            parser_status = hashconfig->parse_func (in, hccap_size, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status != PARSER_OK)
            {
              log_info ("WARNING: Hash '%s': %s", hash_buf, strparser (parser_status));

              continue;
            }

            // hack: append MAC1 and MAC2 s.t. in --show and --left the line matches with the .pot file format (i.e. ESSID:MAC1:MAC2)

            if ((user_options->show == true) || (user_options->left == true))
            {
              salt_t *tmp_salt = hashes_buf[hashes_cnt].salt;

              char *salt_ptr = (char *) tmp_salt->salt_buf;

              int cur_pos = tmp_salt->salt_len;
              int rem_len = sizeof (hashes_buf[hashes_cnt].salt->salt_buf) - cur_pos;

              wpa_t *wpa = (wpa_t *) hashes_buf[hashes_cnt].esalt;

              // do the appending task

              snprintf (salt_ptr + cur_pos,
                        rem_len,
                        ":%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x",
                        wpa->orig_mac1[0],
                        wpa->orig_mac1[1],
                        wpa->orig_mac1[2],
                        wpa->orig_mac1[3],
                        wpa->orig_mac1[4],
                        wpa->orig_mac1[5],
                        wpa->orig_mac2[0],
                        wpa->orig_mac2[1],
                        wpa->orig_mac2[2],
                        wpa->orig_mac2[3],
                        wpa->orig_mac2[4],
                        wpa->orig_mac2[5]);

              // memset () the remaining part of the salt

              cur_pos = tmp_salt->salt_len + 1 + 12 + 1 + 12;
              rem_len = sizeof (hashes_buf[hashes_cnt].salt->salt_buf) - cur_pos;

              if (rem_len > 0) memset (salt_ptr + cur_pos, 0, rem_len);

              tmp_salt->salt_len += 1 + 12 + 1 + 12;
            }

            if (user_options->show == true) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, (char *) hashes_buf[hashes_cnt].salt->salt_buf, hashes_buf[hashes_cnt].salt->salt_len, &hashes_buf[hashes_cnt], sort_by_salt_buf);
            if (user_options->left == true) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, (char *) hashes_buf[hashes_cnt].salt->salt_buf, hashes_buf[hashes_cnt].salt->salt_len, &hashes_buf[hashes_cnt], sort_by_salt_buf);

            hashes_cnt++;
          }

          fclose (fp);

          myfree (in);
        }
        else if (hashconfig->hash_mode == 3000)
        {
          if (hash_len == 32)
          {
            parser_status = hashconfig->parse_func (hash_buf, 16, &hashes_buf[hashes_cnt], hashconfig);

            hash_t *lm_hash_left = NULL;

            if (parser_status == PARSER_OK)
            {
              lm_hash_left = &hashes_buf[hashes_cnt];

              hashes_cnt++;
            }
            else
            {
              log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
            }

            parser_status = hashconfig->parse_func (hash_buf + 16, 16, &hashes_buf[hashes_cnt], hashconfig);

            hash_t *lm_hash_right = NULL;

            if (parser_status == PARSER_OK)
            {
              lm_hash_right = &hashes_buf[hashes_cnt];

              hashes_cnt++;
            }
            else
            {
              log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
            }

            // show / left

            if ((lm_hash_left != NULL) && (lm_hash_right != NULL))
            {
              if (user_options->show == true) potfile_show_request_lm (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, lm_hash_left, lm_hash_right, sort_by_pot);
              if (user_options->left == true) potfile_left_request_lm (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, lm_hash_left, lm_hash_right, sort_by_pot);
            }
          }
          else
          {
            parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status == PARSER_OK)
            {
              if (user_options->show == true) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
              if (user_options->left == true) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
            }

            if (parser_status == PARSER_OK)
            {
              hashes_cnt++;
            }
            else
            {
              log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
            }
          }
        }
        else
        {
          parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

          if (parser_status == PARSER_OK)
          {
            if (user_options->show == true) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
            if (user_options->left == true) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
          }

          if (parser_status == PARSER_OK)
          {
            hashes_cnt++;
          }
          else
          {
            log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
          }
        }
      }
    }
    else if (hashlist_mode == HL_MODE_FILE)
    {
      char *hashfile = hashes->hashfile;

      FILE *fp;

      if ((fp = fopen (hashfile, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", hashfile, strerror (errno));

        return -1;
      }

      uint line_num = 0;

      char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

      while (!feof (fp))
      {
        line_num++;

        int line_len = fgetl (fp, line_buf);

        if (line_len == 0) continue;

        char *hash_buf = NULL;
        int   hash_len = 0;

        hlfmt_hash (hashlist_format, line_buf, line_len, &hash_buf, &hash_len, hashconfig, user_options);

        bool hash_fmt_error = 0;

        if (hash_len < 1)     hash_fmt_error = 1;
        if (hash_buf == NULL) hash_fmt_error = 1;

        if (hash_fmt_error)
        {
          log_info ("WARNING: failed to parse hashes using the '%s' format", strhlfmt (hashlist_format));

          continue;
        }

        if (user_options->username)
        {
          char *user_buf = NULL;
          int   user_len = 0;

          hlfmt_user (hashlist_format, line_buf, line_len, &user_buf, &user_len, hashconfig);

          if (user_options->remove || user_options->show)
          {
            user_t **user = &hashes_buf[hashes_cnt].hash_info->user;

            *user = (user_t *) mymalloc (sizeof (user_t));

            user_t *user_ptr = *user;

            if (user_buf != NULL)
            {
              user_ptr->user_name = mystrdup (user_buf);
            }
            else
            {
              user_ptr->user_name = mystrdup ("");
            }

            user_ptr->user_len = user_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = mystrdup (hash_buf);
        }

        if (hashconfig->is_salted)
        {
          memset (hashes_buf[hashes_cnt].salt, 0, sizeof (salt_t));
        }

        if (hashconfig->hash_mode == 3000)
        {
          if (hash_len == 32)
          {
            int parser_status = hashconfig->parse_func (hash_buf, 16, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, line_buf, strparser (parser_status));

              continue;
            }

            hash_t *lm_hash_left = &hashes_buf[hashes_cnt];

            hashes_cnt++;

            parser_status = hashconfig->parse_func (hash_buf + 16, 16, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, line_buf, strparser (parser_status));

              continue;
            }

            hash_t *lm_hash_right = &hashes_buf[hashes_cnt];

            if (user_options->quiet == false) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

            hashes_cnt++;

            // show / left

            if (user_options->show == true) potfile_show_request_lm (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, lm_hash_left, lm_hash_right, sort_by_pot);
            if (user_options->left == true) potfile_left_request_lm (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, lm_hash_left, lm_hash_right, sort_by_pot);
          }
          else
          {
            int parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, line_buf, strparser (parser_status));

              continue;
            }

            if (user_options->quiet == false) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

            if (user_options->show == true) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);
            if (user_options->left == true) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);

            hashes_cnt++;
          }
        }
        else
        {
          int parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

          if (parser_status < PARSER_GLOBAL_ZERO)
          {
            log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, line_buf, strparser (parser_status));

            continue;
          }

          if (user_options->quiet == false) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

          if (user_options->show == true) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);
          if (user_options->left == true) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);

          hashes_cnt++;
        }
      }

      myfree (line_buf);

      fclose (fp);

      if (user_options->quiet == false) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_avail, hashes_avail, 100.00);
    }
  }

  hashes->hashes_cnt = hashes_cnt;

  if (hashconfig->is_salted)
  {
    qsort (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash);
  }
  else
  {
    qsort (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt);
  }

  return 0;
}

int hashes_init_stage2 (hashes_t *hashes, const hashconfig_t *hashconfig, opencl_ctx_t *opencl_ctx, user_options_t *user_options)
{
  hash_t *hashes_buf = hashes->hashes_buf;
  uint    hashes_cnt = hashes->hashes_cnt;

  /**
   * Remove duplicates
   */

  if (user_options->quiet == false) log_info_nn ("Removing duplicate hashes...");

  hashes_cnt = 1;

  for (uint hashes_pos = 1; hashes_pos < hashes->hashes_cnt; hashes_pos++)
  {
    if (hashconfig->is_salted)
    {
      if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) == 0)
      {
        if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest) == 0) continue;
      }
    }
    else
    {
      if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest) == 0) continue;
    }

    if (hashes_pos > hashes_cnt)
    {
      memcpy (&hashes_buf[hashes_cnt], &hashes_buf[hashes_pos], sizeof (hash_t));
    }

    hashes_cnt++;
  }

  hashes->hashes_cnt = hashes_cnt;

  /**
   * Now generate all the buffers required for later
   */

  void   *digests_buf_new = (void *) mycalloc (hashes_cnt, hashconfig->dgst_size);
  salt_t *salts_buf_new   = NULL;
  void   *esalts_buf_new  = NULL;

  if (hashconfig->is_salted)
  {
    salts_buf_new = (salt_t *) mycalloc (hashes_cnt, sizeof (salt_t));

    if (hashconfig->esalt_size)
    {
      esalts_buf_new = (void *) mycalloc (hashes_cnt, hashconfig->esalt_size);
    }
  }
  else
  {
    salts_buf_new = (salt_t *) mycalloc (1, sizeof (salt_t));
  }

  if (user_options->quiet == false) log_info_nn ("Structuring salts for cracking task...");

  uint digests_cnt  = hashes_cnt;
  uint digests_done = 0;

  uint *digests_shown     = (uint *) mycalloc (digests_cnt, sizeof (uint));
  uint *digests_shown_tmp = (uint *) mycalloc (digests_cnt, sizeof (uint));

  uint salts_cnt   = 0;
  uint salts_done  = 0;

  hashinfo_t **hash_info = NULL;

  if ((user_options->username && (user_options->remove || user_options->show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
  {
    hash_info = (hashinfo_t **) mycalloc (hashes_cnt, sizeof (hashinfo_t *));

    if (user_options->username && (user_options->remove || user_options->show))
    {
      uint user_pos;

      for (user_pos = 0; user_pos < hashes_cnt; user_pos++)
      {
        hash_info[user_pos] = (hashinfo_t *) mycalloc (hashes_cnt, sizeof (hashinfo_t));

        hash_info[user_pos]->user = (user_t *) mymalloc (sizeof (user_t));
      }
    }
  }

  uint *salts_shown = (uint *) mycalloc (digests_cnt, sizeof (uint));

  salt_t *salt_buf;

  {
    // copied from inner loop

    salt_buf = &salts_buf_new[salts_cnt];

    memcpy (salt_buf, hashes_buf[0].salt, sizeof (salt_t));

    if (hashconfig->esalt_size)
    {
      memcpy (((char *) esalts_buf_new) + (salts_cnt * hashconfig->esalt_size), hashes_buf[0].esalt, hashconfig->esalt_size);
    }

    salt_buf->digests_cnt    = 0;
    salt_buf->digests_done   = 0;
    salt_buf->digests_offset = 0;

    salts_cnt++;
  }

  if (hashes_buf[0].cracked == 1)
  {
    digests_shown[0] = 1;

    digests_done++;

    salt_buf->digests_done++;
  }

  salt_buf->digests_cnt++;

  memcpy (((char *) digests_buf_new) + (0 * hashconfig->dgst_size), hashes_buf[0].digest, hashconfig->dgst_size);

  if ((user_options->username && (user_options->remove || user_options->show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
  {
    hash_info[0] = hashes_buf[0].hash_info;
  }

  // copy from inner loop

  for (uint hashes_pos = 1; hashes_pos < hashes_cnt; hashes_pos++)
  {
    if (hashconfig->is_salted)
    {
      if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) != 0)
      {
        salt_buf = &salts_buf_new[salts_cnt];

        memcpy (salt_buf, hashes_buf[hashes_pos].salt, sizeof (salt_t));

        if (hashconfig->esalt_size)
        {
          memcpy (((char *) esalts_buf_new) + (salts_cnt * hashconfig->esalt_size), hashes_buf[hashes_pos].esalt, hashconfig->esalt_size);
        }

        salt_buf->digests_cnt    = 0;
        salt_buf->digests_done   = 0;
        salt_buf->digests_offset = hashes_pos;

        salts_cnt++;
      }
    }

    if (hashes_buf[hashes_pos].cracked == 1)
    {
      digests_shown[hashes_pos] = 1;

      digests_done++;

      salt_buf->digests_done++;
    }

    salt_buf->digests_cnt++;

    memcpy (((char *) digests_buf_new) + (hashes_pos * hashconfig->dgst_size), hashes_buf[hashes_pos].digest, hashconfig->dgst_size);

    if ((user_options->username && (user_options->remove || user_options->show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
    {
      hash_info[hashes_pos] = hashes_buf[hashes_pos].hash_info;
    }
  }

  for (uint salt_pos = 0; salt_pos < salts_cnt; salt_pos++)
  {
    salt_t *salt_buf = &salts_buf_new[salt_pos];

    if (salt_buf->digests_done == salt_buf->digests_cnt)
    {
      salts_shown[salt_pos] = 1;

      salts_done++;
    }

    if (salts_done == salts_cnt) mycracked (opencl_ctx);
  }

  myfree (hashes->digests_buf);
  myfree (hashes->salts_buf);
  myfree (hashes->esalts_buf);
  myfree (hashes->hashes_buf);

  hashes->digests_cnt        = digests_cnt;
  hashes->digests_done       = digests_done;
  hashes->digests_buf        = digests_buf_new;
  hashes->digests_shown      = digests_shown;
  hashes->digests_shown_tmp  = digests_shown_tmp;

  hashes->salts_cnt          = salts_cnt;
  hashes->salts_done         = salts_done;
  hashes->salts_buf          = salts_buf_new;
  hashes->salts_shown        = salts_shown;

  hashes->esalts_buf         = esalts_buf_new;

  hashes->hashes_cnt         = 0;
  hashes->hashes_buf         = NULL;

  hashes->hash_info          = hash_info;

  return 0;
}

int hashes_init_stage3 (hashes_t *hashes, hashconfig_t *hashconfig, user_options_t *user_options)
{
  hashconfig_general_defaults (hashconfig, hashes, user_options);

  if (hashes->salts_cnt == 1)
    hashconfig->opti_type |= OPTI_TYPE_SINGLE_SALT;

  if (hashes->digests_cnt == 1)
    hashconfig->opti_type |= OPTI_TYPE_SINGLE_HASH;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    hashconfig->opti_type |= OPTI_TYPE_NOT_ITERATED;

  if (user_options->attack_mode == ATTACK_MODE_BF)
    hashconfig->opti_type |= OPTI_TYPE_BRUTE_FORCE;

  if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE)
  {
    if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
    {
      if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
      {
        if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADD80;
        }

        if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS14)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS14;
        }

        if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS15)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS15;
        }
      }
    }
  }

  return 0;
}

void hashes_destroy (hashes_t *hashes)
{
  myfree (hashes->digests_buf);
  myfree (hashes->digests_shown);
  myfree (hashes->digests_shown_tmp);

  myfree (hashes->salts_buf);
  myfree (hashes->salts_shown);

  myfree (hashes->esalts_buf);

  myfree (hashes->hash_info);

  hashes->hashfile          = NULL;

  hashes->hashlist_mode     = 0;
  hashes->hashlist_format   = 0;

  hashes->digests_cnt       = 0;
  hashes->digests_done      = 0;
  hashes->digests_saved     = 0;
  hashes->digests_buf       = NULL;
  hashes->digests_shown     = NULL;
  hashes->digests_shown_tmp = NULL;

  hashes->salts_cnt         = 0;
  hashes->salts_done        = 0;
  hashes->salts_buf         = NULL;
  hashes->salts_shown       = NULL;

  hashes->esalts_buf        = NULL;

  hashes->hashes_cnt        = 0;
  hashes->hashes_buf        = NULL;

  hashes->hash_info         = NULL;
}

void hashes_logger (const hashes_t *hashes, const logfile_ctx_t *logfile_ctx)
{
  logfile_top_string (hashes->hashfile);
  logfile_top_uint   (hashes->hashlist_mode);
  logfile_top_uint   (hashes->hashlist_format);
  logfile_top_uint   (hashes->hashes_cnt);
  logfile_top_uint   (hashes->digests_cnt);
  logfile_top_uint   (hashes->digests_done);
  logfile_top_uint   (hashes->salts_cnt);
  logfile_top_uint   (hashes->salts_done);
}
