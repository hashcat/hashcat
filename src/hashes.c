/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "debugfile.h"
#include "filehandling.h"
#include "hlfmt.h"
#include "terminal.h"
#include "logfile.h"
#include "loopback.h"
#include "backend.h"
#include "outfile.h"
#include "potfile.h"
#include "rp.h"
#include "shared.h"
#include "thread.h"
#include "locking.h"
#include "hashes.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

int sort_by_digest_p0p1 (const void *v1, const void *v2, void *v3)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  hashconfig_t *hashconfig = (hashconfig_t *) v3;

  const u32 dgst_pos0 = hashconfig->dgst_pos0;
  const u32 dgst_pos1 = hashconfig->dgst_pos1;
  const u32 dgst_pos2 = hashconfig->dgst_pos2;
  const u32 dgst_pos3 = hashconfig->dgst_pos3;

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

  const int res_pos = (int) s1->orig_pos - (int) s2->orig_pos;

  if (res_pos != 0) return (res_pos);

  const int res1 = (int) s1->salt_len - (int) s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = (int) s1->salt_iter - (int) s2->salt_iter;

  if (res2 != 0) return (res2);

  for (int n = 0; n < 64; n++)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return  1;
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  for (int n = 0; n < 64; n++)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return  1;
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}

int sort_by_hash (const void *v1, const void *v2, void *v3)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  hashconfig_t *hashconfig = (hashconfig_t *) v3;

  if (hashconfig->is_salted == true)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2, v3);
}

int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2, v3);
}

int hash_encode (const hashconfig_t *hashconfig, const hashes_t *hashes, const module_ctx_t *module_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  if (module_ctx->module_hash_encode == MODULE_DEFAULT)
  {
    return snprintf (out_buf, out_size, "%s", hashes->hashfile);
  }

  salt_t *salts_buf = hashes->salts_buf;

  salts_buf += salt_pos;

  const u32 digest_cur = salts_buf->digests_offset + digest_pos;

  void        *digests_buf    = hashes->digests_buf;
  void        *esalts_buf     = hashes->esalts_buf;
  void        *hook_salts_buf = hashes->hook_salts_buf;
  hashinfo_t **hash_info      = hashes->hash_info;

  char       *digests_buf_ptr    = (char *) digests_buf;
  char       *esalts_buf_ptr     = (char *) esalts_buf;
  char       *hook_salts_buf_ptr = (char *) hook_salts_buf;
  hashinfo_t *hash_info_ptr      = NULL;

  digests_buf_ptr    += digest_cur * hashconfig->dgst_size;
  esalts_buf_ptr     += digest_cur * hashconfig->esalt_size;
  hook_salts_buf_ptr += digest_cur * hashconfig->hook_salt_size;

  if (hash_info) hash_info_ptr = hash_info[digest_cur];

  const int out_len = module_ctx->module_hash_encode
  (
    hashconfig,
    digests_buf_ptr,
    salts_buf,
    esalts_buf_ptr,
    hook_salts_buf_ptr,
    hash_info_ptr,
    out_buf,
    out_size
  );

  return out_len;
}

int save_hash (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t        *hashes       = hashcat_ctx->hashes;
  hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;
  module_ctx_t    *module_ctx   = hashcat_ctx->module_ctx;
  user_options_t  *user_options = hashcat_ctx->user_options;

  const char *hashfile = hashes->hashfile;

  char *new_hashfile;
  char *old_hashfile;

  hc_asprintf (&new_hashfile, "%s.new", hashfile);
  hc_asprintf (&old_hashfile, "%s.old", hashfile);

  unlink (new_hashfile);

  char separator = hashconfig->separator;

  HCFILE fp;

  if (hc_fopen (&fp, new_hashfile, "wb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  if (hc_lockfile (&fp) == -1)
  {
    hc_fclose (&fp);

    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    if (hashes->salts_shown[salt_pos] == 1) continue;

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    for (u32 digest_pos = 0; digest_pos < salt_buf->digests_cnt; digest_pos++)
    {
      const u32 idx = salt_buf->digests_offset + digest_pos;

      if (hashes->digests_shown[idx] == 1) continue;

      if (module_ctx->module_hash_binary_save != MODULE_DEFAULT)
      {
        char *binary_buf = NULL;

        const int binary_len = module_ctx->module_hash_binary_save (hashes, salt_pos, digest_pos, &binary_buf);

        hc_fwrite (binary_buf, binary_len, 1, &fp);

        hcfree (binary_buf);
      }
      else
      {
        if (user_options->username == true)
        {
          user_t *user = hashes->hash_info[idx]->user;

          u32 i;

          for (i = 0; i < user->user_len; i++) hc_fputc (user->user_name[i], &fp);

          hc_fputc (separator, &fp);
        }

        const int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_pos, digest_pos);

        out_buf[out_len] = 0;

        hc_fprintf (&fp, "%s" EOL, out_buf);
      }
    }
  }

  hcfree (out_buf);

  hc_fflush (&fp);

  if (hc_unlockfile (&fp) == -1)
  {
    hc_fclose (&fp);

    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  hc_fclose (&fp);

  unlink (old_hashfile);

  if (rename (hashfile, old_hashfile) != 0)
  {
    event_log_error (hashcat_ctx, "Rename file '%s' to '%s': %s", hashfile, old_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  unlink (hashfile);

  if (rename (new_hashfile, hashfile) != 0)
  {
    event_log_error (hashcat_ctx, "Rename file '%s' to '%s': %s", new_hashfile, hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  unlink (old_hashfile);

  hcfree (new_hashfile);
  hcfree (old_hashfile);

  return 0;
}

int check_hash (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain)
{
  const debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;
  const hashes_t        *hashes        = hashcat_ctx->hashes;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
  const loopback_ctx_t  *loopback_ctx  = hashcat_ctx->loopback_ctx;
  const module_ctx_t    *module_ctx    = hashcat_ctx->module_ctx;

  const u32 salt_pos    = plain->salt_pos;
  const u32 digest_pos  = plain->digest_pos;  // relative

  void *tmps = NULL;

  cl_event opencl_event;

  int rc = -1;

  if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
  {
    tmps = hcmalloc (hashconfig->tmp_size);

    if (device_param->is_cuda == true)
    {
      rc = hc_cuMemcpyDtoHAsync (hashcat_ctx, tmps, device_param->cuda_d_tmps + (plain->gidvid * hashconfig->tmp_size), hashconfig->tmp_size, device_param->cuda_stream);

      if (rc == 0)
      {
        rc = hc_cuEventRecord (hashcat_ctx, device_param->cuda_event3, device_param->cuda_stream);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }

    if (device_param->is_hip == true)
    {
      rc = hc_hipMemcpyDtoHAsync (hashcat_ctx, tmps, device_param->hip_d_tmps + (plain->gidvid * hashconfig->tmp_size), hashconfig->tmp_size, device_param->hip_stream);

      if (rc == 0)
      {
        rc = hc_hipEventRecord (hashcat_ctx, device_param->hip_event3, device_param->hip_stream);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      rc = hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, tmps, device_param->metal_d_tmps, plain->gidvid * hashconfig->tmp_size, hashconfig->tmp_size);

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }
    #endif

    if (device_param->is_opencl == true)
    {
      rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_tmps, CL_FALSE, plain->gidvid * hashconfig->tmp_size, hashconfig->tmp_size, tmps, 0, NULL, &opencl_event);

      if (rc == 0)
      {
        rc = hc_clFlush (hashcat_ctx, device_param->opencl_command_queue);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }
  }

  // hash

  u8 *out_buf = hashes->out_buf;

  int out_len = hash_encode (hashconfig, hashes, module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_pos, digest_pos);

  out_buf[out_len] = 0;

  // plain

  u8 plain_buf[HCBUFSIZ_TINY] = { 0 }; // while the password itself can have only length 256, the module could encode it with something like base64 which inflates the requires buffer size
  u8 postprocess_buf[HCBUFSIZ_TINY] = { 0 };

  u8 *plain_ptr = plain_buf;

  int plain_len = 0;

  build_plain (hashcat_ctx, device_param, plain, (u32 *) plain_buf, &plain_len);

  if (module_ctx->module_build_plain_postprocess != MODULE_DEFAULT)
  {
    if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuEventSynchronize (hashcat_ctx, device_param->cuda_event3) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipEventSynchronize (hashcat_ctx, device_param->hip_event3) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;
      }
    }

    plain_len = module_ctx->module_build_plain_postprocess (hashconfig, hashes, tmps, (u32 *) plain_buf, sizeof (plain_buf), plain_len, (u32 *) postprocess_buf, sizeof (postprocess_buf));

    plain_ptr = postprocess_buf;
  }

  // crackpos

  u64 crackpos = 0;

  build_crackpos (hashcat_ctx, device_param, plain, &crackpos);

  // debug

  u8  debug_rule_buf[RP_PASSWORD_SIZE] = { 0 };
  int debug_rule_len  = 0; // -1 error

  u8  debug_plain_ptr[RP_PASSWORD_SIZE] = { 0 };
  int debug_plain_len = 0;

  build_debugdata (hashcat_ctx, device_param, plain, debug_rule_buf, &debug_rule_len, debug_plain_ptr, &debug_plain_len);

  // outfile, can be either to file or stdout
  // if an error occurs opening the file, send to stdout as fallback
  // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs

  outfile_write_open (hashcat_ctx);

  u8 *tmp_buf = hashes->tmp_buf;

  tmp_buf[0] = 0;

  const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, plain_ptr, plain_len, crackpos, NULL, 0, true, (char *) tmp_buf);

  EVENT_DATA (EVENT_CRACKER_HASH_CRACKED, tmp_buf, tmp_len);

  outfile_write_close (hashcat_ctx);

  // potfile
  // we can have either used-defined hooks or reuse the same format as input format
  // no need for locking, we're in a mutex protected function

  if (module_ctx->module_hash_encode_potfile != MODULE_DEFAULT)
  {
    if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuEventSynchronize (hashcat_ctx, device_param->cuda_event3) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipEventSynchronize (hashcat_ctx, device_param->hip_event3) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;
      }
    }

    salt_t *salts_buf = hashes->salts_buf;

    salts_buf += salt_pos;

    const u32 digest_cur = salts_buf->digests_offset + digest_pos;

    void        *digests_buf    = hashes->digests_buf;
    void        *esalts_buf     = hashes->esalts_buf;
    void        *hook_salts_buf = hashes->hook_salts_buf;
    hashinfo_t **hash_info      = hashes->hash_info;

    char       *digests_buf_ptr    = (char *) digests_buf;
    char       *esalts_buf_ptr     = (char *) esalts_buf;
    char       *hook_salts_buf_ptr = (char *) hook_salts_buf;
    hashinfo_t *hash_info_ptr      = NULL;

    digests_buf_ptr    += digest_cur * hashconfig->dgst_size;
    esalts_buf_ptr     += digest_cur * hashconfig->esalt_size;
    hook_salts_buf_ptr += digest_cur * hashconfig->hook_salt_size;

    if (hash_info) hash_info_ptr = hash_info[digest_cur];

    out_len = module_ctx->module_hash_encode_potfile
    (
      hashconfig,
      digests_buf_ptr,
      salts_buf,
      esalts_buf_ptr,
      hook_salts_buf_ptr,
      hash_info_ptr,
      (char *) out_buf,
      HCBUFSIZ_LARGE,
      tmps
    );

    out_buf[out_len] = 0;
  }

  potfile_write_append (hashcat_ctx, (char *) out_buf, out_len, plain_ptr, plain_len);

  // if enabled, update also the loopback file

  if (loopback_ctx->fp.pfp != NULL)
  {
    loopback_write_append (hashcat_ctx, plain_ptr, plain_len);
  }

  // if enabled, update also the (rule) debug file

  if (debugfile_ctx->fp.pfp != NULL)
  {
    // the next check implies that:
    // - (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    // - debug_mode > 0

    if ((debug_plain_len > 0) || (debug_rule_len > 0))
    {
      debugfile_write_append (hashcat_ctx, debug_rule_buf, debug_rule_len, plain_ptr, plain_len, debug_plain_ptr, debug_plain_len);
    }
  }

  if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
  {
    hcfree (tmps);

    if (device_param->is_opencl == true)
    {
      if (hc_clReleaseEvent (hashcat_ctx, opencl_event) == -1) return -1;
    }
  }

  return 0;
}

//int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos)
int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  cpt_ctx_t      *cpt_ctx      = hashcat_ctx->cpt_ctx;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  u32 num_cracked = 0;

  int rc = -1;

  if (device_param->is_cuda == true)
  {
    if (hc_cuMemcpyDtoHAsync (hashcat_ctx, &num_cracked, device_param->cuda_d_result, sizeof (u32), device_param->cuda_stream) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipMemcpyDtoHAsync (hashcat_ctx, &num_cracked, device_param->hip_d_result, sizeof (u32), device_param->hip_stream) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, &num_cracked, device_param->metal_d_result, 0, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL) == -1) return -1;
  }

  if (num_cracked == 0 || user_options->speed_only == true)
  {
    // we want to get the num_cracked in benchmark mode because it has an influence in performance
    // however if the benchmark cracks the artificial hash used for benchmarks we don't want to see that!

    return 0;
  }

  plain_t *cracked = (plain_t *) hcmalloc (num_cracked * sizeof (plain_t));

  if (device_param->is_cuda == true)
  {
    rc = hc_cuMemcpyDtoHAsync (hashcat_ctx, cracked, device_param->cuda_d_plain_bufs, num_cracked * sizeof (plain_t), device_param->cuda_stream);

    if (rc == 0)
    {
      rc = hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream);
    }

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  if (device_param->is_hip == true)
  {
    rc = hc_hipMemcpyDtoHAsync (hashcat_ctx, cracked, device_param->hip_d_plain_bufs, num_cracked * sizeof (plain_t), device_param->hip_stream);

    if (rc == 0)
    {
      rc = hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream);
    }

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    rc = hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, cracked, device_param->metal_d_plain_bufs, 0, num_cracked * sizeof (plain_t));

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_plain_bufs, CL_TRUE, 0, num_cracked * sizeof (plain_t), cracked, 0, NULL, NULL);

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  u32 cpt_cracked = 0;

  hc_thread_mutex_lock (status_ctx->mux_display);

  for (u32 i = 0; i < num_cracked; i++)
  {
    const u32 hash_pos = cracked[i].hash_pos;

    if (hashes->digests_shown[hash_pos] == 1) continue;

    const u32 salt_pos = cracked[i].salt_pos;
    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    if ((hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) == 0)
    {
      hashes->digests_shown[hash_pos] = 1;

      hashes->digests_done++;

      hashes->digests_done_new++;

      cpt_cracked++;

      salt_buf->digests_done++;

      if (salt_buf->digests_done == salt_buf->digests_cnt)
      {
        hashes->salts_shown[salt_pos] = 1;

        hashes->salts_done++;
      }
    }

    if (hashes->salts_done == hashes->salts_cnt) mycracked (hashcat_ctx);

    rc = check_hash (hashcat_ctx, device_param, &cracked[i]);

    if (rc == -1)
    {
      break;
    }

    if (hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK)
    {
      // we need to reset cracked state on the device
      // otherwise host thinks again and again the hash was cracked
      // and returns invalid password each time

      if (device_param->is_cuda == true)
      {
        rc = run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_digests_shown + (salt_buf->digests_offset * sizeof (u32)), salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }

      if (device_param->is_hip == true)
      {
        rc = run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_digests_shown + (salt_buf->digests_offset * sizeof (u32)), salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        rc = run_metal_kernel_memset32 (hashcat_ctx, device_param, device_param->metal_d_digests_shown, salt_buf->digests_offset * sizeof (u32), 0, salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }
      #endif

      if (device_param->is_opencl == true)
      {
        /* NOTE: run_opencl_kernel_bzero() does not handle buffer offset */
        rc = run_opencl_kernel_memset32 (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, salt_buf->digests_offset * sizeof (u32), 0, salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }
    }
  }

  hc_thread_mutex_unlock (status_ctx->mux_display);

  hcfree (cracked);

  if (rc == -1)
  {
    return -1;
  }

  if (cpt_cracked > 0)
  {
    hc_thread_mutex_lock (status_ctx->mux_display);

    cpt_ctx->cpt_buf[cpt_ctx->cpt_pos].timestamp = time (NULL);
    cpt_ctx->cpt_buf[cpt_ctx->cpt_pos].cracked   = cpt_cracked;

    cpt_ctx->cpt_pos++;

    cpt_ctx->cpt_total += cpt_cracked;

    if (cpt_ctx->cpt_pos == CPT_CACHE) cpt_ctx->cpt_pos = 0;

    hc_thread_mutex_unlock (status_ctx->mux_display);
  }

  if (device_param->is_cuda == true)
  {
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_result, sizeof (u32)) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_result, sizeof (u32)) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_result, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_result, sizeof (u32)) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  return 0;
}

int hashes_init_filename (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->benchmark == true) return 0;

  /**
   * load hashes, part I: find input mode, count hashes
   */

  if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
  {
    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
    {
      if ((user_options->benchmark == false) && (user_options->keyspace == false))
      {
        hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

        if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
        {
          hashes->hashfile = user_options_extra->hc_hash;
        }
      }
    }
    else
    {
      hashes->hashlist_mode = HL_MODE_FILE_BINARY;

      if ((user_options->benchmark == false) && (user_options->keyspace == false))
      {
        if (hc_path_read (user_options_extra->hc_hash) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", user_options_extra->hc_hash, strerror (errno));

          return -1;
        }

        hashes->hashfile = user_options_extra->hc_hash;
      }
    }
  }
  else
  {
    hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

    if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      hashes->hashfile = user_options_extra->hc_hash;
    }
  }

  hashes->parser_token_length_cnt = 0;

  return 0;
}

int hashes_init_stage1 (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t              *hashes             = hashcat_ctx->hashes;
  module_ctx_t          *module_ctx         = hashcat_ctx->module_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  /**
   * load hashes, part I: find input mode, count hashes
   */

  const char *hashfile      = hashes->hashfile;
  const u32   hashlist_mode = hashes->hashlist_mode;

  u32 hashlist_format = HLFMT_HASHCAT;

  u64 hashes_avail = 0;

  if ((user_options->benchmark == false) && (user_options->stdout_flag == false) && (user_options->keyspace == false))
  {
    if (hashlist_mode == HL_MODE_ARG)
    {
      hashes_avail = 1;
    }
    else if (hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      HCFILE fp;

      if (hc_fopen (&fp, hashfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashfile, strerror (errno));

        return -1;
      }

      EVENT_DATA (EVENT_HASHLIST_COUNT_LINES_PRE, hashfile, strlen (hashfile));

      hashes_avail = count_lines (&fp);

      EVENT_DATA (EVENT_HASHLIST_COUNT_LINES_POST, hashfile, strlen (hashfile));

      hc_rewind (&fp);

      if (hashes_avail == 0)
      {
        event_log_error (hashcat_ctx, "hashfile is empty or corrupt.");

        hc_fclose (&fp);

        return -1;
      }

      hashlist_format = hlfmt_detect (hashcat_ctx, &fp, 100); // 100 = max numbers to "scan". could be hashes_avail, too

      hc_fclose (&fp);

      if ((user_options->remove == true) && (hashlist_format != HLFMT_HASHCAT))
      {
        event_log_error (hashcat_ctx, "Use of --remove is not supported in native hashfile-format mode.");

        return -1;
      }
    }
    else if (hashlist_mode == HL_MODE_FILE_BINARY)
    {
      struct stat st;

      if (stat (hashes->hashfile, &st) == -1)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (errno));

        return -1;
      }

      if (module_ctx->module_hash_binary_count != MODULE_DEFAULT)
      {
        const int binary_count = module_ctx->module_hash_binary_count (hashes);

        if (binary_count > 0)
        {
          hashes_avail = binary_count;
        }
        else if (binary_count == 0)
        {
          event_log_error (hashcat_ctx, "No hashes loaded.");

          return -1;
        }
        else if (binary_count == PARSER_HAVE_ERRNO)
        {
          event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (errno));

          return -1;
        }
        else
        {
          event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (binary_count));

          return -1;
        }
      }
      else
      {
        hashes_avail = 1;
      }
    }
  }
  else
  {
    hashes_avail = 1;
  }

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT) hashes_avail *= 2;

  hashes->hashlist_format = hashlist_format;

  /**
   * load hashes, part II: allocate required memory, set pointers
   */

  hash_t *hashes_buf     = (hash_t *) hccalloc (hashes_avail, sizeof (hash_t));
  void   *digests_buf    =            hccalloc (hashes_avail, hashconfig->dgst_size);
  salt_t *salts_buf      = NULL;
  void   *esalts_buf     = NULL;
  void   *hook_salts_buf = NULL;

  if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT))
  {
    u64 hash_pos;

    for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
    {
      hashinfo_t *hash_info = (hashinfo_t *) hcmalloc (sizeof (hashinfo_t));

      hashes_buf[hash_pos].hash_info = hash_info;

      if (user_options->username == true)
      {
        hash_info->user = (user_t *) hcmalloc (sizeof (user_t));
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
      {
        if (user_options->benchmark == false)
        {
          hash_info->orighash = (char *) hcmalloc (256);
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
      {
        hash_info->split = (split_t *) hcmalloc (sizeof (split_t));
      }
    }
  }

  if (hashconfig->is_salted == true)
  {
    salts_buf = (salt_t *) hccalloc (hashes_avail, sizeof (salt_t));

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // this disables:
      // - sorting by salt value
      // - grouping by salt value
      // - keep the salt in position relative to hashfile (not equal because of some hashes maybe failed to load)

      u64 hash_pos;

      for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
      {
        salt_t *salt = &salts_buf[hash_pos];

        salt->orig_pos = hash_pos;
      }
    }

    if (hashconfig->esalt_size > 0)
    {
      esalts_buf = hccalloc (hashes_avail, hashconfig->esalt_size);
    }

    if (hashconfig->hook_salt_size > 0)
    {
      hook_salts_buf = hccalloc (hashes_avail, hashconfig->hook_salt_size);
    }
  }
  else
  {
    salts_buf = (salt_t *) hccalloc (1, sizeof (salt_t));
  }

  for (u64 hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
  {
    /**
     * Initialize some values for later use
     */

    hashes_buf[hash_pos].orig_line_pos = hash_pos;

    hashes_buf[hash_pos].digest = ((char *) digests_buf) + (hash_pos * hashconfig->dgst_size);

    if (hashconfig->is_salted == true)
    {
      hashes_buf[hash_pos].salt = &salts_buf[hash_pos];

      if (hashconfig->esalt_size > 0)
      {
        hashes_buf[hash_pos].esalt = ((char *) esalts_buf) + (hash_pos * hashconfig->esalt_size);
      }

      if (hashconfig->hook_salt_size > 0)
      {
        hashes_buf[hash_pos].hook_salt = ((char *) hook_salts_buf) + (hash_pos * hashconfig->hook_salt_size);
      }
    }
    else
    {
      hashes_buf[hash_pos].salt = &salts_buf[0];
    }
  }

  hashes->hashes_buf     = hashes_buf;
  hashes->digests_buf    = digests_buf;
  hashes->salts_buf      = salts_buf;
  hashes->esalts_buf     = esalts_buf;
  hashes->hook_salts_buf = hook_salts_buf;

  /**
   * load hashes, part III: parse hashes
   */

  u32 hashes_cnt = 0;

  if (user_options->benchmark == true)
  {
    hashes->hashfile = "-";

    hashes_cnt = 1;
  }
  else if (user_options->hash_info == true)
  {
  }
  else if (user_options->keyspace == true)
  {
  }
  else if (user_options->stdout_flag == true)
  {
  }
  else if (user_options->backend_info > 0)
  {
  }
  else
  {
    if (hashlist_mode == HL_MODE_ARG)
    {
      char *input_buf = user_options_extra->hc_hash;

      size_t input_len = strlen (input_buf);

      char  *hash_buf = NULL;
      int    hash_len = 0;

      hlfmt_hash (hashcat_ctx, hashlist_format, input_buf, input_len, &hash_buf, &hash_len);

      bool hash_fmt_error = false;

      if (hash_len < 1)     hash_fmt_error = true;
      if (hash_buf == NULL) hash_fmt_error = true;

      if (hash_fmt_error)
      {
        event_log_warning (hashcat_ctx, "Failed to parse hashes using the '%s' format.", strhlfmt (hashlist_format));
      }
      else
      {
        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = hcstrdup (hash_buf);
        }

        if (hashconfig->is_salted == true)
        {
          memset (hashes_buf[0].salt, 0, sizeof (salt_t));
        }

        if (hashconfig->esalt_size > 0)
        {
          memset (hashes_buf[0].esalt, 0, hashconfig->esalt_size);
        }

        if (hashconfig->hook_salt_size > 0)
        {
          memset (hashes_buf[0].hook_salt, 0, hashconfig->hook_salt_size);
        }

        int parser_status = PARSER_OK;

        if (user_options->username == true)
        {
          char *user_buf = NULL;
          int   user_len = 0;

          hlfmt_user (hashcat_ctx, hashlist_format, input_buf, input_len, &user_buf, &user_len);

          // special case:
          // both hash_t need to have the username info if the pwdump format is used (i.e. we have 2 hashes for 3000, both with same user)

          u32 hashes_per_user = 1;

          if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
          {
            // the following conditions should be true if (hashlist_format == HLFMT_PWDUMP)

            if (hash_len == 32)
            {
              hashes_per_user = 2;
            }
          }

          for (u32 i = 0; i < hashes_per_user; i++)
          {
            user_t **user = &hashes_buf[hashes_cnt + i].hash_info->user;

            *user = (user_t *) hcmalloc (sizeof (user_t));

            user_t *user_ptr = *user;

            if (user_buf != NULL)
            {
              user_ptr->user_name = hcstrdup (user_buf);
            }
            else
            {
              user_ptr->user_name = hcstrdup ("");
            }

            user_ptr->user_len = (u32) user_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
        {
          if (hash_len == 32)
          {
            hash_t *hash;

            hash = &hashes_buf[hashes_cnt];

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf +  0, 16);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_LEFT;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }

            hash = &hashes_buf[hashes_cnt];

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf + 16, 16);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_RIGHT;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }
          }
          else
          {
            hash_t *hash = &hashes_buf[hashes_cnt];

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_NONE;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }
          }
        }
        else
        {
          hash_t *hash = &hashes_buf[hashes_cnt];

          parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

          if (parser_status == PARSER_OK)
          {
            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status == PARSER_OK)
              {
                // nothing to do
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
              }
            }

            hashes_cnt++;
          }
          else
          {
            event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
          }

          if (parser_status == PARSER_TOKEN_LENGTH)
          {
            hashes->parser_token_length_cnt++;
          }
        }
      }
    }
    else if (hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      HCFILE fp;

      if (hc_fopen (&fp, hashfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashfile, strerror (errno));

        return -1;
      }

      u32 line_num = 0;

      char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

      time_t prev = 0;
      time_t now  = 0;

      while (!hc_feof (&fp))
      {
        line_num++;

        const size_t line_len = fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

        if (line_len == 0) continue;

        if (hashes_avail == hashes_cnt)
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u: File changed during runtime. Skipping new data.", hashes->hashfile, line_num);

          break;
        }

        char *hash_buf = NULL;
        int   hash_len = 0;

        hlfmt_hash (hashcat_ctx, hashlist_format, line_buf, line_len, &hash_buf, &hash_len);

        bool hash_fmt_error = false;

        if (hash_len < 1)     hash_fmt_error = true;
        if (hash_buf == NULL) hash_fmt_error = true;

        if (hash_fmt_error)
        {
          event_log_warning (hashcat_ctx, "Failed to parse hashes using the '%s' format.", strhlfmt (hashlist_format));

          continue;
        }

        if (user_options->username == true)
        {
          char *user_buf = NULL;
          int   user_len = 0;

          hlfmt_user (hashcat_ctx, hashlist_format, line_buf, line_len, &user_buf, &user_len);

          // special case:
          // both hash_t need to have the username info if the pwdump format is used (i.e. we have 2 hashes for 3000, both with same user)

          u32 hashes_per_user = 1;

          if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
          {
            // the following conditions should be true if (hashlist_format == HLFMT_PWDUMP)

            if (hash_len == 32)
            {
              hashes_per_user = 2;
            }
          }

          for (u32 i = 0; i < hashes_per_user; i++)
          {
            user_t **user = &hashes_buf[hashes_cnt + i].hash_info->user;

            *user = (user_t *) hcmalloc (sizeof (user_t));

            user_t *user_ptr = *user;

            if (user_buf != NULL)
            {
              user_ptr->user_name = hcstrdup (user_buf);
            }
            else
            {
              user_ptr->user_name = hcstrdup ("");
            }

            user_ptr->user_len = (u32) user_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = hcstrdup (hash_buf);
        }

        if (hashconfig->is_salted == true)
        {
          const u32 orig_pos = hashes_buf[hashes_cnt].salt->orig_pos;

          memset (hashes_buf[hashes_cnt].salt, 0, sizeof (salt_t));

          hashes_buf[hashes_cnt].salt->orig_pos = orig_pos;
        }

        if (hashconfig->esalt_size > 0)
        {
          memset (hashes_buf[hashes_cnt].esalt, 0, hashconfig->esalt_size);
        }

        if (hashconfig->hook_salt_size > 0)
        {
          memset (hashes_buf[hashes_cnt].hook_salt, 0, hashconfig->hook_salt_size);
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
        {
          if (hash_len == 32)
          {
            hash_t *hash;

            hash = &hashes_buf[hashes_cnt];

            int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf +  0, 16);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }

              hcfree (tmp_line_buf);

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_LEFT;

            hashes_cnt++;

            hash = &hashes_buf[hashes_cnt];

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf + 16, 16);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }

              hcfree (tmp_line_buf);

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_RIGHT;

            hashes_cnt++;
          }
          else
          {
            hash_t *hash = &hashes_buf[hashes_cnt];

            int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }

              hcfree (tmp_line_buf);

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_NONE;

            hashes_cnt++;
          }
        }
        else
        {
          hash_t *hash = &hashes_buf[hashes_cnt];

          int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

          if (parser_status < PARSER_GLOBAL_ZERO)
          {
            char *tmp_line_buf;

            hc_asprintf (&tmp_line_buf, "%s", line_buf);

            compress_terminal_line_length (tmp_line_buf, 38, 32);

            if (user_options->machine_readable == true)
            {
              event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
            }

            hcfree (tmp_line_buf);

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }

            continue;
          }

          if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
          {
            int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

            if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
              }

              hcfree (tmp_line_buf);

              if (parser_status_postprocess == PARSER_TOKEN_LENGTH)
              {
                hashes->parser_token_length_cnt++;
              }

              continue;
            }
          }

          hashes_cnt++;
        }

        time (&now);

        if ((now - prev) == 0) continue;

        time (&prev);

        hashlist_parse_t hashlist_parse;

        hashlist_parse.hashes_cnt   = hashes_cnt;
        hashlist_parse.hashes_avail = hashes_avail;

        EVENT_DATA (EVENT_HASHLIST_PARSE_HASH, &hashlist_parse, sizeof (hashlist_parse_t));
      }

      hashlist_parse_t hashlist_parse;

      hashlist_parse.hashes_cnt   = hashes_cnt;
      hashlist_parse.hashes_avail = hashes_avail;

      EVENT_DATA (EVENT_HASHLIST_PARSE_HASH, &hashlist_parse, sizeof (hashlist_parse_t));

      hcfree (line_buf);

      hc_fclose (&fp);
    }
    else if (hashlist_mode == HL_MODE_FILE_BINARY)
    {
      char *input_buf = user_options_extra->hc_hash;

      size_t input_len = strlen (input_buf);

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
      {
        hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

        hash_info_tmp->orighash = hcstrdup (input_buf);
      }

      if (hashconfig->is_salted == true)
      {
        memset (hashes_buf[0].salt, 0, sizeof (salt_t));
      }

      if (hashconfig->esalt_size > 0)
      {
        memset (hashes_buf[0].esalt, 0, hashconfig->esalt_size);
      }

      if (hashconfig->hook_salt_size > 0)
      {
        memset (hashes_buf[0].hook_salt, 0, hashconfig->hook_salt_size);
      }

      if (module_ctx->module_hash_binary_parse != MODULE_DEFAULT)
      {
        const int hashes_parsed = module_ctx->module_hash_binary_parse (hashconfig, user_options, user_options_extra, hashes);

        if (hashes_parsed > 0)
        {
          hashes_cnt = hashes_parsed;
        }
        else if (hashes_parsed == 0)
        {
          event_log_warning (hashcat_ctx, "No hashes loaded.");
        }
        else if (hashes_parsed == PARSER_HAVE_ERRNO)
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s': %s", hashes->hashfile, strerror (errno));
        }
        else
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s': %s", hashes->hashfile, strparser (hashes_parsed));
        }
      }
      else
      {
        hash_t *hash = &hashes_buf[hashes_cnt];

        int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, input_buf, input_len);

        if (parser_status == PARSER_OK)
        {
          if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
          {
            parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

            if (parser_status == PARSER_OK)
            {
              // nothing to do
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
            }
          }

          hashes_cnt++;
        }
        else
        {
          event_log_warning (hashcat_ctx, "Hash '%s': %s", input_buf, strparser (parser_status));
        }

        if (parser_status == PARSER_TOKEN_LENGTH)
        {
          hashes->parser_token_length_cnt++;
        }
      }
    }
  }

  hashes->hashes_cnt = hashes_cnt;

  if (hashes_cnt)
  {
    EVENT (EVENT_HASHLIST_SORT_HASH_PRE);

    if (hashconfig->is_salted == true)
    {
      hc_qsort_r (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash, (void *) hashconfig);
    }
    else
    {
      hc_qsort_r (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);
    }

    EVENT (EVENT_HASHLIST_SORT_HASH_POST);
  }

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
  {
    // update split split_neighbor after sorting
    // see https://github.com/hashcat/hashcat/issues/1034 for good examples for testing

    for (u32 i = 0; i < hashes_cnt; i++)
    {
      split_t *split1 = hashes_buf[i].hash_info->split;

      if (split1->split_origin != SPLIT_ORIGIN_LEFT) continue;

      for (u32 j = 0; j < hashes_cnt; j++)
      {
        split_t *split2 = hashes_buf[j].hash_info->split;

        if (split2->split_origin != SPLIT_ORIGIN_RIGHT) continue;

        if (split1->split_group != split2->split_group) continue;

        split1->split_neighbor = j;
        split2->split_neighbor = i;

        break;
      }
    }
  }

  if (hashes->parser_token_length_cnt > 0)
  {
    event_log_advice (hashcat_ctx, NULL); // we can guarantee that the previous line was not an empty line
    event_log_advice (hashcat_ctx, "* Token length exception: %u/%u hashes", hashes->parser_token_length_cnt, hashes->parser_token_length_cnt + hashes->hashes_cnt);
    event_log_advice (hashcat_ctx, "  This error happens if the wrong hash type is specified, if the hashes are");
    event_log_advice (hashcat_ctx, "  malformed, or if input is otherwise not as expected (for example, if the");
    event_log_advice (hashcat_ctx, "  --username option is used but no username is present)");
    event_log_advice (hashcat_ctx, NULL);
  }

  return 0;
}

int hashes_init_stage2 (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
        hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  /**
   * Remove duplicates
   */

  EVENT (EVENT_HASHLIST_UNIQUE_HASH_PRE);

  u32 hashes_cnt_new = 1;

  for (u32 hashes_pos = 1; hashes_pos < hashes_cnt; hashes_pos++)
  {
    if (hashconfig->potfile_keep_all_hashes == true)
    {
      // do not sort, because we need to keep all hashes in this particular case
    }
    else if (hashconfig->is_salted == true)
    {
      if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) == 0)
      {
        if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest, (void *) hashconfig) == 0) continue;
      }
    }
    else
    {
      if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest, (void *) hashconfig) == 0) continue;
    }

    hash_t tmp;

    memcpy (&tmp, &hashes_buf[hashes_pos], sizeof (hash_t));

    memcpy (&hashes_buf[hashes_cnt_new], &tmp, sizeof (hash_t));

    hashes_cnt_new++;
  }

  for (u32 i = hashes_cnt_new; i < hashes->hashes_cnt; i++)
  {
    memset (&hashes_buf[i], 0, sizeof (hash_t));
  }

  hashes_cnt = hashes_cnt_new;

  hashes->hashes_cnt = hashes_cnt;

  EVENT (EVENT_HASHLIST_UNIQUE_HASH_POST);

  /**
   * Now generate all the buffers required for later
   */

  void   *digests_buf_new    = hccalloc (hashes_cnt, hashconfig->dgst_size);
  salt_t *salts_buf_new      = NULL;
  void   *esalts_buf_new     = NULL;
  void   *hook_salts_buf_new = NULL;

  if (hashconfig->is_salted == true)
  {
    salts_buf_new = (salt_t *) hccalloc (hashes_cnt, sizeof (salt_t));
  }
  else
  {
    salts_buf_new = (salt_t *) hccalloc (1, sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    esalts_buf_new = hccalloc (hashes_cnt, hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hook_salts_buf_new = hccalloc (hashes_cnt, hashconfig->hook_salt_size);
  }

  EVENT (EVENT_HASHLIST_SORT_SALT_PRE);

  u32 digests_cnt  = hashes_cnt;
  u32 digests_done = 0;

  u32 *digests_shown = (u32 *) hccalloc (digests_cnt, sizeof (u32));

  u32 salts_cnt   = 0;
  u32 salts_done  = 0;

  hashinfo_t **hash_info = NULL;

  if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT))
  {
    hash_info = (hashinfo_t **) hccalloc (hashes_cnt, sizeof (hashinfo_t *));
  }

  u32 *salts_shown = (u32 *) hccalloc (digests_cnt, sizeof (u32));

  salt_t *salt_buf;

  {
    // copied from inner loop

    salt_buf = &salts_buf_new[salts_cnt];

    memcpy (salt_buf, hashes_buf[0].salt, sizeof (salt_t));

    hashes_buf[0].salt = salt_buf;

    if (hashconfig->hook_salt_size > 0)
    {
      char *hook_salts_buf_new_ptr = ((char *) hook_salts_buf_new) + (salts_cnt * hashconfig->hook_salt_size);

      memcpy (hook_salts_buf_new_ptr, hashes_buf[0].hook_salt, hashconfig->hook_salt_size);

      hashes_buf[0].hook_salt = hook_salts_buf_new_ptr;
    }

    salt_buf->digests_cnt    = 0;
    salt_buf->digests_done   = 0;
    salt_buf->digests_offset = 0;

    salts_cnt++;
  }

  salt_buf->digests_cnt++;

  char *digests_buf_new_ptr = ((char *) digests_buf_new) + (0 * hashconfig->dgst_size);

  memcpy (digests_buf_new_ptr, hashes_buf[0].digest, hashconfig->dgst_size);

  hashes_buf[0].digest = digests_buf_new_ptr;

  if (hashconfig->esalt_size > 0)
  {
    char *esalts_buf_new_ptr = ((char *) esalts_buf_new) + (0 * hashconfig->esalt_size);

    memcpy (esalts_buf_new_ptr, hashes_buf[0].esalt, hashconfig->esalt_size);

    hashes_buf[0].esalt = esalts_buf_new_ptr;
  }

  if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT))
  {
    hash_info[0] = hashes_buf[0].hash_info;
  }

  // copy from inner loop

  for (u32 hashes_pos = 1; hashes_pos < hashes_cnt; hashes_pos++)
  {
    if (hashconfig->is_salted == true)
    {
      if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) != 0)
      {
        salt_buf = &salts_buf_new[salts_cnt];

        memcpy (salt_buf, hashes_buf[hashes_pos].salt, sizeof (salt_t));

        hashes_buf[hashes_pos].salt = salt_buf;

        if (hashconfig->hook_salt_size > 0)
        {
          char *hook_salts_buf_new_ptr = ((char *) hook_salts_buf_new) + (salts_cnt * hashconfig->hook_salt_size);

          memcpy (hook_salts_buf_new_ptr, hashes_buf[hashes_pos].hook_salt, hashconfig->hook_salt_size);

          hashes_buf[hashes_pos].hook_salt = hook_salts_buf_new_ptr;
        }

        salt_buf->digests_cnt    = 0;
        salt_buf->digests_done   = 0;
        salt_buf->digests_offset = hashes_pos;

        salts_cnt++;
      }

      hashes_buf[hashes_pos].salt = salt_buf;

      if (hashconfig->hook_salt_size > 0)
      {
        char *hook_salts_buf_new_ptr = ((char *) hook_salts_buf_new) + (salts_cnt * hashconfig->hook_salt_size);

        hashes_buf[hashes_pos].hook_salt = hook_salts_buf_new_ptr;
      }
    }

    salt_buf->digests_cnt++;

    digests_buf_new_ptr = ((char *) digests_buf_new) + (hashes_pos * hashconfig->dgst_size);

    memcpy (digests_buf_new_ptr, hashes_buf[hashes_pos].digest, hashconfig->dgst_size);

    hashes_buf[hashes_pos].digest = digests_buf_new_ptr;

    if (hashconfig->esalt_size > 0)
    {
      char *esalts_buf_new_ptr = ((char *) esalts_buf_new) + (hashes_pos * hashconfig->esalt_size);

      memcpy (esalts_buf_new_ptr, hashes_buf[hashes_pos].esalt, hashconfig->esalt_size);

      hashes_buf[hashes_pos].esalt = esalts_buf_new_ptr;
    }

    if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT))
    {
      hash_info[hashes_pos] = hashes_buf[hashes_pos].hash_info;
    }
  }

  EVENT (EVENT_HASHLIST_SORT_SALT_POST);

  hcfree (hashes->digests_buf);
  hcfree (hashes->salts_buf);
  hcfree (hashes->esalts_buf);
  hcfree (hashes->hook_salts_buf);

  hashes->digests_cnt       = digests_cnt;
  hashes->digests_done      = digests_done;
  hashes->digests_buf       = digests_buf_new;
  hashes->digests_shown     = digests_shown;

  hashes->salts_cnt         = salts_cnt;
  hashes->salts_done        = salts_done;
  hashes->salts_buf         = salts_buf_new;
  hashes->salts_shown       = salts_shown;

  hashes->esalts_buf        = esalts_buf_new;
  hashes->hook_salts_buf    = hook_salts_buf_new;

  hashes->hash_info         = hash_info;

  return 0;
}

int hashes_init_stage3 (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t *hashes = hashcat_ctx->hashes;

  u32  digests_done      = hashes->digests_done;
  u32  digests_done_zero = hashes->digests_done_zero;
  u32  digests_done_pot  = hashes->digests_done_pot;
  u32 *digests_shown     = hashes->digests_shown;

  u32  salts_cnt         = hashes->salts_cnt;
  u32  salts_done        = hashes->salts_done;
  u32 *salts_shown       = hashes->salts_shown;

  hash_t *hashes_buf     = hashes->hashes_buf;
  salt_t *salts_buf      = hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
  {
    salt_t *salt_buf = salts_buf + salt_idx;

    u32 digests_cnt = salt_buf->digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

      if (hashes_buf[hashes_idx].cracked_pot == 1)
      {
        digests_shown[hashes_idx] = 1;

        digests_done++;

        digests_done_pot++;

        salt_buf->digests_done++;
      }

      if (hashes_buf[hashes_idx].cracked_zero == 1)
      {
        digests_shown[hashes_idx] = 1;

        digests_done++;

        digests_done_zero++;

        salt_buf->digests_done++;
      }
    }

    if (salt_buf->digests_done == salt_buf->digests_cnt)
    {
      salts_shown[salt_idx] = 1;

      salts_done++;
    }

    if (salts_done == salts_cnt) mycracked (hashcat_ctx);
  }

  hashes->digests_done      = digests_done;
  hashes->digests_done_zero = digests_done_zero;
  hashes->digests_done_pot  = digests_done_pot;

  hashes->salts_cnt         = salts_cnt;
  hashes->salts_done        = salts_done;

  return 0;
}

int hashes_init_stage4 (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

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

  // test iteration count in association attack

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    salt_t *salts_buf = hashes->salts_buf;

    for (u32 salt_idx = 1; salt_idx < hashes->salts_cnt; salt_idx++)
    {
      if (salts_buf[salt_idx - 1].salt_iter != salts_buf[salt_idx].salt_iter)
      {
        event_log_error (hashcat_ctx, "Mixed iteration counts are not supported in association attack-mode.");

        return -1;
      }
    }
  }

  // time to update extra_tmp_size which is tmp_size value based on hash configuration

  if (module_ctx->module_extra_tmp_size != MODULE_DEFAULT)
  {
    const u64 extra_tmp_size = module_ctx->module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

    if (extra_tmp_size == (u64) -1)
    {
      event_log_error (hashcat_ctx, "Mixed hash settings are not supported.");

      return -1;
    }

    hashconfig->tmp_size = extra_tmp_size;
  }

  // at this point we no longer need hash_t* structure

  hash_t *hashes_buf = hashes->hashes_buf;

  hcfree (hashes_buf);

  hashes->hashes_cnt = 0;
  hashes->hashes_buf = NULL;

  // starting from here, we should allocate some scratch buffer for later use

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  hashes->out_buf = out_buf;

  // we need two buffers in parallel

  u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  hashes->tmp_buf = tmp_buf;

  // brain session

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    const u32 brain_session = brain_compute_session (hashcat_ctx);

    user_options->brain_session = brain_session;
  }
  #endif

  return 0;
}

int hashes_init_selftest (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
  hashes_t        *hashes        = hashcat_ctx->hashes;
  module_ctx_t    *module_ctx    = hashcat_ctx->module_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  if (hashconfig->st_hash == NULL) return 0;

  void   *st_digests_buf    = NULL;
  salt_t *st_salts_buf      = NULL;
  void   *st_esalts_buf     = NULL;
  void   *st_hook_salts_buf = NULL;

  st_digests_buf =          hccalloc (1, hashconfig->dgst_size);

  st_salts_buf = (salt_t *) hccalloc (1, sizeof (salt_t));

  if (hashconfig->esalt_size > 0)
  {
    st_esalts_buf = hccalloc (1, hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    st_hook_salts_buf = hccalloc (1, hashconfig->hook_salt_size);
  }

  hash_t hash;

  hash.digest    = st_digests_buf;
  hash.salt      = st_salts_buf;
  hash.esalt     = st_esalts_buf;
  hash.hook_salt = st_hook_salts_buf;
  hash.cracked   = 0;
  hash.hash_info = NULL;
  hash.pw_buf    = NULL;
  hash.pw_len    = 0;

  int parser_status;

  if (module_ctx->module_hash_init_selftest != MODULE_DEFAULT)
  {
    parser_status = module_ctx->module_hash_init_selftest (hashconfig, &hash);
  }
  else
  {
    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
    {
      if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
      {
        parser_status = module_ctx->module_hash_decode (hashconfig, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));
      }
      else
      {
        char *tmpfile_bin;

        hc_asprintf (&tmpfile_bin, "%s/selftest.hash", folder_config->session_dir);

        HCFILE fp;

        hc_fopen (&fp, tmpfile_bin, "wb");

        const size_t st_hash_len = strlen (hashconfig->st_hash);

        for (size_t i = 0; i < st_hash_len; i += 2)
        {
          const u8 c = hex_to_u8 ((const u8 *) hashconfig->st_hash + i);

          hc_fputc (c, &fp);
        }

        hc_fclose (&fp);

        parser_status = module_ctx->module_hash_decode (hashconfig, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, tmpfile_bin, strlen (tmpfile_bin));

        unlink (tmpfile_bin);

        hcfree (tmpfile_bin);
      }
    }
    else
    {
      hashconfig_t *hashconfig_st = (hashconfig_t *) hcmalloc (sizeof (hashconfig_t));

      memcpy (hashconfig_st, hashconfig, sizeof (hashconfig_t));

      hashconfig_st->separator = ':';

      if (user_options->hex_salt)
      {
        if (hashconfig->salt_type == SALT_TYPE_GENERIC)
        {
          // this is save as there's no hash mode that has both SALT_TYPE_GENERIC and OPTS_TYPE_ST_HEX by default

          hashconfig_st->opts_type &= ~OPTS_TYPE_ST_HEX;
        }
      }

      parser_status = module_ctx->module_hash_decode (hashconfig_st, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));

      hcfree (hashconfig_st);
    }
  }

  if (parser_status == PARSER_OK)
  {
    // nothing to do
  }
  else
  {
    event_log_error (hashcat_ctx, "Self-test hash parsing error: %s", strparser (parser_status));

    return -1;
  }

  hashes->st_digests_buf    = st_digests_buf;
  hashes->st_salts_buf      = st_salts_buf;
  hashes->st_esalts_buf     = st_esalts_buf;
  hashes->st_hook_salts_buf = st_hook_salts_buf;

  return 0;
}

int hashes_init_benchmark (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
        hashes_t              *hashes             = hashcat_ctx->hashes;
  const module_ctx_t          *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t        *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->benchmark == false) return 0;

  if (hashconfig->is_salted == false) return 0;

  if (module_ctx->module_benchmark_salt != MODULE_DEFAULT)
  {
    salt_t *ptr = module_ctx->module_benchmark_salt (hashconfig, user_options, user_options_extra);

    memcpy (hashes->salts_buf, ptr, sizeof (salt_t));

    hcfree (ptr);
  }
  else
  {
    memcpy (hashes->salts_buf, hashes->st_salts_buf, sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    if (module_ctx->module_benchmark_esalt != MODULE_DEFAULT)
    {
      void *ptr = module_ctx->module_benchmark_esalt (hashconfig, user_options, user_options_extra);

      memcpy (hashes->esalts_buf, ptr, hashconfig->esalt_size);

      hcfree (ptr);
    }
    else
    {
      memcpy (hashes->esalts_buf, hashes->st_esalts_buf, hashconfig->esalt_size);
    }
  }

  if (hashconfig->hook_salt_size > 0)
  {
    if (module_ctx->module_benchmark_hook_salt != MODULE_DEFAULT)
    {
      void *ptr = module_ctx->module_benchmark_hook_salt (hashconfig, user_options, user_options_extra);

      memcpy (hashes->hook_salts_buf, ptr, hashconfig->hook_salt_size);

      hcfree (ptr);
    }
    else
    {
      memcpy (hashes->hook_salts_buf, hashes->st_hook_salts_buf, hashconfig->hook_salt_size);
    }
  }

  return 0;
}

int hashes_init_zerohash (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;

  // do not use this unless really needed, for example as in LM

  if (module_ctx->module_hash_decode_zero_hash == MODULE_DEFAULT) return 0;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  // no solution for these special hash types (for instane because they use hashfile in output etc)

  hash_t hash_buf;

  hash_buf.digest    = hcmalloc (hashconfig->dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hook_salt = NULL;
  hash_buf.cracked   = 0;
  hash_buf.hash_info = NULL;
  hash_buf.pw_buf    = NULL;
  hash_buf.pw_len    = 0;

  if (hashconfig->is_salted == true)
  {
    hash_buf.salt = (salt_t *) hcmalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    hash_buf.esalt = hcmalloc (hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hash_buf.hook_salt = hcmalloc (hashconfig->hook_salt_size);
  }

  module_ctx->module_hash_decode_zero_hash (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info);

  for (u32 i = 0; i < hashes_cnt; i++)
  {
    hash_t *next = &hashes_buf[i];

    int rc = sort_by_hash_no_salt (&hash_buf, next, (void *) hashconfig);

    if (rc == 0)
    {
      next->pw_buf = (char *) hcmalloc (1);
      next->pw_len = 0;

      next->cracked_zero = 1;

      // should we show the cracked zero hash to the user?

      if (false)
      {
        // digest pos

        const u32 digest_pos = next - hashes_buf;

        // show the crack

        u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

        int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, 0, digest_pos);

        out_buf[out_len] = 0;

        // outfile, can be either to file or stdout
        // if an error occurs opening the file, send to stdout as fallback
        // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs

        outfile_write_open (hashcat_ctx);

        const u8 *plain = (const u8 *) "";

        u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

        tmp_buf[0] = 0;

        const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, plain, 0, 0, NULL, 0, true, (char *) tmp_buf);

        EVENT_DATA (EVENT_CRACKER_HASH_CRACKED, tmp_buf, tmp_len);

        outfile_write_close (hashcat_ctx);

        hcfree (tmp_buf);
        hcfree (out_buf);
      }
    }
  }

  if (hashconfig->esalt_size > 0)
  {
    hcfree (hash_buf.esalt);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hcfree (hash_buf.hook_salt);
  }

  if (hashconfig->is_salted == true)
  {
    hcfree (hash_buf.salt);
  }

  hcfree (hash_buf.digest);

  return 0;
}

void hashes_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  user_options_t *user_options = hashcat_ctx->user_options;

  hcfree (hashes->digests_buf);
  hcfree (hashes->digests_shown);

  hcfree (hashes->salts_buf);
  hcfree (hashes->salts_shown);

  if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
  {
    for (u32 hash_pos = 0; hash_pos < hashes->hashes_cnt; hash_pos++)
    {
      if (user_options->username == true)
      {
        hcfree (hashes->hash_info[hash_pos]->user);
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
      {
        hcfree (hashes->hash_info[hash_pos]->orighash);
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
      {
        hcfree (hashes->hash_info[hash_pos]->split);
      }
    }
  }

  hcfree (hashes->hash_info);

  hcfree (hashes->esalts_buf);
  hcfree (hashes->hook_salts_buf);

  hcfree (hashes->out_buf);
  hcfree (hashes->tmp_buf);

  hcfree (hashes->st_digests_buf);
  hcfree (hashes->st_salts_buf);
  hcfree (hashes->st_esalts_buf);
  hcfree (hashes->st_hook_salts_buf);

  memset (hashes, 0, sizeof (hashes_t));
}

void hashes_logger (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t      *hashes      = hashcat_ctx->hashes;
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  logfile_top_string (hashes->hashfile);
  logfile_top_uint   (hashes->hashlist_mode);
  logfile_top_uint   (hashes->hashlist_format);
  logfile_top_uint   (hashes->hashes_cnt);
  logfile_top_uint   (hashes->digests_cnt);
  logfile_top_uint   (hashes->digests_done_pot);
  logfile_top_uint   (hashes->digests_done_zero);
  logfile_top_uint   (hashes->digests_done);
  logfile_top_uint   (hashes->salts_cnt);
  logfile_top_uint   (hashes->salts_done);
}
