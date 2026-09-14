/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "bitops.h"
#include "convert.h"
#include "backend.h"
#include "thread.h"
#include "selftest.h"

static int selftest_init (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u32 *highest_pw_len)
{
  hashes_t             *hashes             = hashcat_ctx->hashes;
  module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // init : replace hashes with selftest hash

  device_param->kernel_params[15] = hc_dev_kern_arg (device_param, HC_DEV_BUF_ST_DIGESTS_BUF);
  device_param->kernel_params[17] = hc_dev_kern_arg (device_param, HC_DEV_BUF_ST_SALTS_BUF);
  device_param->kernel_params[18] = hc_dev_kern_arg (device_param, HC_DEV_BUF_ST_ESALTS_BUF);

  device_param->kernel_param.digests_cnt = 1;
  device_param->kernel_param.digests_offset_host = 0;

  // password : move the known password into a fake buffer

  const u32 module_opts_type = module_ctx->module_opts_type (hashconfig, user_options, user_options_extra);

  pw_t tmp;

  memset (&tmp, 0, sizeof (tmp));

  char *tmp_ptr = (char *) &tmp.i;

  const size_t tmp_len = strlen (hashconfig->st_pass);

  if (module_opts_type & OPTS_TYPE_PT_HEX)
  {
    tmp.pw_len = hex_decode ((const u8 *) hashconfig->st_pass, (const int) tmp_len, (u8 *) tmp_ptr);
  }
  else
  {
    memcpy (tmp_ptr, hashconfig->st_pass, tmp_len);

    tmp.pw_len = (u32) tmp_len;
  }

  pw_t pw;
  pw_t comb;
  bf_t bf;

  if (user_options->slow_candidates == true)
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      device_param->kernel_param.il_cnt = 1;
    }

    memset (&pw, 0, sizeof (pw));

    char *pw_ptr = (char *) &pw.i;

    const size_t pw_len = tmp.pw_len;

    memcpy (pw_ptr, tmp_ptr, pw_len);

    pw.pw_len = (u32) pw_len;

    if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      // The device engine self-tests as the straight kernel does. Its cell buffer is zeroed at allocation
      // and a cell with no slots extends the base word into itself, so the kernel hashes the test
      // password exactly once and the expected digest is the same one.

      if ((user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) || (user_options_extra->attack_kern == ATTACK_KERN_PCFG))
      {
        device_param->kernel_param.il_cnt = 1;

        memset (&pw, 0, sizeof (pw));

        char *pw_ptr = (char *) &pw.i;

        const size_t pw_len = tmp.pw_len;

        memcpy (pw_ptr, tmp_ptr, pw_len);

        pw.pw_len = (u32) pw_len;

        if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
        {
          uppercase ((u8 *) pw_ptr, pw.pw_len);
        }

        if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        device_param->kernel_param.il_cnt = 1;
        device_param->kernel_param.combs_mode = COMBINATOR_MODE_BASE_LEFT;

        memset (&pw, 0, sizeof (pw));

        char *pw_ptr = (char *) &pw.i;

        const size_t pw_len = tmp.pw_len;

        memcpy (pw_ptr, tmp_ptr, pw_len - 1);

        pw.pw_len = (u32) pw_len - 1;

        if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
        {
          uppercase ((u8 *) pw_ptr, pw.pw_len);
        }

        memset (&comb, 0, sizeof (comb));

        char *comb_ptr = (char *) &comb.i;

        memcpy (comb_ptr, tmp_ptr + pw_len - 1, 1);

        comb.pw_len = 1;

        if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
        {
          uppercase ((u8 *) comb_ptr, comb.pw_len);
        }

        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
        {
          comb_ptr[comb.pw_len] = 0x01;
        }

        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
        {
          comb_ptr[comb.pw_len] = 0x06;
        }

        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
        {
          comb_ptr[comb.pw_len] = 0x80;
        }

        if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_COMBS_C], 0, &comb, 1 * sizeof (pw_t)) == -1) return -1;

        if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        device_param->kernel_param.il_cnt = 1;

        if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
        {
          memset (&pw, 0, sizeof (pw));

          char *pw_ptr = (char *) &pw.i;

          const size_t pw_len = tmp.pw_len;

          memcpy (pw_ptr, tmp_ptr, pw_len);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase ((u8 *) pw_ptr, pw_len);
          }

          pw.pw_len = (u32) pw_len;

          if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
        }
        else
        {
          memset (&bf, 0, sizeof (bf));

          char *bf_ptr = (char *) &bf.i;

          memcpy (bf_ptr, tmp_ptr, 1);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
          {
            memset (bf_ptr, 0, 4);

            for (int i = 0, j = 0; i < 1; i += 1, j += 2)
            {
              bf_ptr[j + 0] = tmp_ptr[i];
              bf_ptr[j + 1] = 0;
            }
          }
          else if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE)
          {
            memset (bf_ptr, 0, 4);

            for (int i = 0, j = 0; i < 1; i += 1, j += 2)
            {
              bf_ptr[j + 0] = 0;
              bf_ptr[j + 1] = tmp_ptr[i];
            }
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase ((u8 *) bf_ptr, 4);
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_GENERATE_BE)
          {
            bf.i = byte_swap_32 (bf.i);
          }

          if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_BFS_C], 0, &bf, 1 * sizeof (bf_t)) == -1) return -1;

          memset (&pw, 0, sizeof (pw));

          char *pw_ptr = (char *) &pw.i;

          const size_t pw_len = tmp.pw_len;

          memcpy (pw_ptr + 1, tmp_ptr + 1, pw_len - 1);

          size_t new_pass_len = pw_len;

          if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
          {
            memset (pw_ptr, 0, pw_len);

            for (size_t i = 1, j = 2; i < new_pass_len; i += 1, j += 2)
            {
              pw_ptr[j + 0] = tmp_ptr[i];
              pw_ptr[j + 1] = 0;
            }

            new_pass_len *= 2;
          }
          else if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE)
          {
            memset (pw_ptr, 0, pw_len);

            for (size_t i = 1, j = 2; i < new_pass_len; i += 1, j += 2)
            {
              pw_ptr[j + 0] = 0;
              pw_ptr[j + 1] = tmp_ptr[i];
            }

            new_pass_len *= 2;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase ((u8 *) pw_ptr, new_pass_len);
          }

          if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
          {
            if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
            {
              memcpy (pw_ptr + new_pass_len, (char *) hashes->st_salts_buf[0].salt_buf, 64 - new_pass_len);

              new_pass_len += hashes->st_salts_buf[0].salt_len;
            }
          }

          pw.pw_len = (u32) new_pass_len;

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
          {
            pw_ptr[new_pass_len] = 0x01;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
          {
            pw_ptr[new_pass_len] = 0x06;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
          {
            pw_ptr[new_pass_len] = 0x80;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14)
          {
            pw.i[14] = (u32) new_pass_len * 8;
            pw.i[15] = 0;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15)
          {
            pw.i[14] = 0;
            pw.i[15] = (u32) new_pass_len * 8;
          }

          if (hashconfig->opts_type & OPTS_TYPE_PT_GENERATE_BE)
          {
            for (int i = 0; i < 14; i++) pw.i[i] = byte_swap_32 (pw.i[i]);
          }

          if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;

          *highest_pw_len = pw.pw_len;
        }
      }
    }
    else
    {
      memset (&pw, 0, sizeof (pw));

      char *pw_ptr = (char *) &pw.i;

      const size_t pw_len = tmp.pw_len;

      memcpy (pw_ptr, tmp_ptr, pw_len);

      pw.pw_len = (u32) pw_len;

      if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
    }
  }

  return 0;
}

static int selftest_run_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u32 highest_pw_len)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  hashes_t     *hashes     = hashcat_ctx->hashes;
  module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  // main : run the kernel

  const u32 kernel_threads_sav = device_param->kernel_threads;

  device_param->kernel_threads = device_param->kernel_threads_min;

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      if (highest_pw_len < 16)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, 1, false, 0, false) == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 0, 1, false, 0, false) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 0, 1, false, 0, false) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_4, 0, 1, false, 0, false) == -1) return -1;
    }
  }
  else
  {
    // missing handling hooks

    if (hashconfig->opts_type & OPTS_TYPE_POST_AMP_UTF16LE)
    {
      if (run_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF], 1) == -1) return -1;
    }

    if (hashconfig->opts_type & OPTS_TYPE_INIT)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, 1, false, 0, false) == -1) return -1;
    }

    if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_12, 0, 1, false, 0, false) == -1) return -1;

      if (device_param->is_cuda == true)
      {
        if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;

        if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;

        if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        /* blocking */
        if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;
      }

      module_ctx->module_hook12 (device_param, module_ctx->hook_extra_params[0], hashes->st_hook_salts_buf, 0, 0);

      if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
    }

    const u32 loop_step = hashconfig->kernel_loops_min + ((hashconfig->kernel_loops_max - hashconfig->kernel_loops_min) / 32);

    const u32 salt_pos = 0;

    salt_t *salt_buf = &hashes->st_salts_buf[salt_pos];

    const u32 salt_repeats = salt_buf->salt_repeats;

    for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
    {
      device_param->kernel_param.salt_repeat = salt_repeat;

      if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, 0, 1, false, 0, false) == -1) return -1;
      }

      const u32 iter = salt_buf->salt_iter;

      for (u32 loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
      {
        u32 loop_left = iter - loop_pos;

        loop_left = MIN (loop_left, loop_step);

        device_param->kernel_param.loop_pos = loop_pos;
        device_param->kernel_param.loop_cnt = loop_left;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP)
        {
          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 0, 1, false, 0, false) == -1) return -1;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2E, 0, 1, false, 0, false) == -1) return -1;
        }

        if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP)
        {
          #define COPY_TMPS 1

          if (COPY_TMPS)
          {
            if (device_param->is_cuda == true)
            {
              if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;

              if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
            }

            if (device_param->is_hip == true)
            {
              if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;

              if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
            }

            #if defined (__APPLE__)
            if (device_param->is_metal == true)
            {
              if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;
            }
            #endif

            if (device_param->is_opencl == true)
            {
              /* blocking */
              if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;
            }
          }

          hashes_t st_hashes;

          memcpy (&st_hashes, hashes, sizeof (hashes_t));

          st_hashes.digests_buf     = st_hashes.st_digests_buf;
          st_hashes.salts_buf       = st_hashes.st_salts_buf;
          st_hashes.esalts_buf      = st_hashes.st_esalts_buf;
          st_hashes.hook_salts_buf  = st_hashes.st_hook_salts_buf;

          if (bridge_ctx->launch_loop (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, &st_hashes, 0, 1) == false) return -1;

          if (COPY_TMPS)
          {
            if (device_param->is_cuda == true)
            {
              if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS], 0, device_param->h_tmps, hashconfig->tmp_size) == -1) return -1;

              if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
            }

            if (device_param->is_hip == true)
            {
              if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS], 0, device_param->h_tmps, hashconfig->tmp_size) == -1) return -1;

              if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
            }

            #if defined (__APPLE__)
            if (device_param->is_metal == true)
            {
              if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS], 0, device_param->h_tmps, hashconfig->tmp_size) == -1) return -1;
            }
            #endif

            if (device_param->is_opencl == true)
            {
              /* blocking */
              if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS], 0, device_param->h_tmps, hashconfig->tmp_size) == -1) return -1;
            }
          }
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_23, 0, 1, false, 0, false) == -1) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;

          if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;

          if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          /* blocking */
          if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->hooks_buf, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->size_hooks) == -1) return -1;
        }

        module_ctx->module_hook23 (device_param, module_ctx->hook_extra_params[0], hashes->st_hook_salts_buf, 0, 0);

        if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_HOOKS], 0, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_INIT2)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, 0, 1, false, 0, false) == -1) return -1;
    }

    for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
    {
      device_param->kernel_param.salt_repeat = salt_repeat;

      if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2P, 0, 1, false, 0, false) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
      {
        const u32 iter2 = salt_buf->salt_iter2;

        for (u32 loop_pos = 0; loop_pos < iter2; loop_pos += loop_step)
        {
          u32 loop_left = iter2 - loop_pos;

          loop_left = MIN (loop_left, loop_step);

          device_param->kernel_param.loop_pos = loop_pos;
          device_param->kernel_param.loop_cnt = loop_left;

          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, 0, 1, false, 0, false) == -1) return -1;

          if (hashconfig->bridge_type & BRIDGE_TYPE_LAUNCH_LOOP2)
          {
            #define COPY_TMPS 1

            if (COPY_TMPS)
            {
              if (device_param->is_cuda == true)
              {
                if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;

                if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;

                if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                /* blocking */
                if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, device_param->h_tmps, device_param->d_buf[HC_DEV_BUF_TMPS], 0, hashconfig->tmp_size) == -1) return -1;
              }
            }

            hashes_t st_hashes;

            memcpy (&st_hashes, hashes, sizeof (hashes_t));

            st_hashes.digests_buf     = st_hashes.st_digests_buf;
            st_hashes.salts_buf       = st_hashes.st_salts_buf;
            st_hashes.esalts_buf      = st_hashes.st_esalts_buf;
            st_hashes.hook_salts_buf  = st_hashes.st_hook_salts_buf;

            if (bridge_ctx->launch_loop2 (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, &st_hashes, 0, 1) == false) return -1;

            if (COPY_TMPS)
            {
              if (hc_dev_memcpy_h2d (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS], 0, device_param->h_tmps, hashconfig->tmp_size) == -1) return -1;
            }
          }
        }
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
    {
      device_param->kernel_param.loop_pos = 0;
      device_param->kernel_param.loop_cnt = 1;

      if (hashconfig->opts_type & OPTS_TYPE_AUX1)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, 0, 1, false, 0, false) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX2)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX2, 0, 1, false, 0, false) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX3)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX3, 0, 1, false, 0, false) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX4)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX4, 0, 1, false, 0, false) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX5)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX5, 0, 1, false, 0, false) == -1) return -1;
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_COMP)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 0, 1, false, 0, false) == -1) return -1;
    }
  }

  device_param->spin_damp = spin_damp_sav;

  device_param->kernel_threads = kernel_threads_sav;

  return 0;
}

static int selftest_cleanup (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u32 *num_cracked)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // check : check if cracked

  cl_event opencl_event;

  if (device_param->is_cuda == true)
  {
    if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, num_cracked, device_param->d_buf[HC_DEV_BUF_RESULT], 0, sizeof (u32)) == -1) return -1;

    if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event3, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, num_cracked, device_param->d_buf[HC_DEV_BUF_RESULT], 0, sizeof (u32)) == -1) return -1;

    if (hc_hipEventRecord (hashcat_ctx, device_param->hip_event3, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_dev_memcpy_d2h (hashcat_ctx, device_param, num_cracked, device_param->d_buf[HC_DEV_BUF_RESULT], 0, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->d_buf[HC_DEV_BUF_RESULT].opencl, CL_TRUE, 0, sizeof (u32), num_cracked, 0, NULL, &opencl_event) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  // finish : cleanup and restore

  // ??? bug because not set ??? device_param->kernel_param.salt_pos_host        = 0;
  device_param->kernel_param.loop_pos             = 0;
  device_param->kernel_param.loop_cnt             = 0;
  device_param->kernel_param.il_cnt               = 0;
  device_param->kernel_param.digests_cnt          = 0;
  device_param->kernel_param.digests_offset_host  = 0;
  device_param->kernel_param.combs_mode           = 0;
  device_param->kernel_param.salt_repeat          = 0;

  device_param->kernel_params[15] = hc_dev_kern_arg (device_param, HC_DEV_BUF_DIGESTS_BUF);
  device_param->kernel_params[17] = hc_dev_kern_arg (device_param, HC_DEV_BUF_SALT_BUFS);
  device_param->kernel_params[18] = hc_dev_kern_arg (device_param, HC_DEV_BUF_ESALT_BUFS);

  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PWS_BUF],       device_param->size_pws) == -1) return -1;
  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_TMPS],          device_param->size_tmps) == -1) return -1;
  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_HOOKS],         device_param->size_hooks) == -1) return -1;
  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_PLAIN_BUFS],    device_param->size_plains) == -1) return -1;
  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_DIGESTS_SHOWN], device_param->size_shown) == -1) return -1;
  if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_RESULT],        device_param->size_results) == -1) return -1;

  if (user_options->slow_candidates == true)
  {
    if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_RULES_C], device_param->size_rules_c) == -1) return -1;
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_RULES_C], device_param->size_rules_c) == -1) return -1;
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_COMBS_C], device_param->size_combs) == -1) return -1;
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      if (run_kernel_bzero (hashcat_ctx, device_param, device_param->d_buf[HC_DEV_BUF_BFS_C], device_param->size_bfs) == -1) return -1;
    }
  }

  // synchronize and ..
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

    if (hc_clReleaseEvent (hashcat_ctx, opencl_event) == -1) return -1;
  }

  return 0;
}

static int process_selftest (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (hashconfig->st_hash == NULL) return 0;

  u32 highest_pw_len = 0;
  u32 num_cracked = 0;

  if (selftest_init (hashcat_ctx, device_param, &highest_pw_len) == -1) return -1;

  if (selftest_run_kernel (hashcat_ctx, device_param, highest_pw_len) == -1) return -1;

  if (selftest_cleanup (hashcat_ctx, device_param, &num_cracked) == -1) return -1;

  // check return

  if (num_cracked == 0)
  {
    hc_thread_mutex_lock (status_ctx->mux_display);

    if (device_param->is_cuda == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! CUDA kernel self-test failed.", device_param->device_id + 1);
    }

    if (device_param->is_hip == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! HIP kernel self-test failed.", device_param->device_id + 1);
    }

    if (device_param->is_metal == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! Metal kernel self-test failed.", device_param->device_id + 1);
    }

    if (device_param->is_opencl == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! OpenCL kernel self-test failed.", device_param->device_id + 1);
    }

    if (device_param->is_metal == false)
    {
      event_log_warning (hashcat_ctx, "Your device driver installation is probably broken.");
      event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
    }

    event_log_warning (hashcat_ctx, NULL);

    hc_thread_mutex_unlock (status_ctx->mux_display);

    return -1;
  }

  return 0;
}

HC_THREAD_FUNC thread_selftest (void *p)
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return 0;

  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->self_test == false) return 0;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped == true) return 0;
  if (device_param->skipped_warning == true) return 0;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes) == false) return 0;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return 0;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return 0;
  }

  const int rc_selftest = process_selftest (hashcat_ctx, device_param);

  if (user_options->benchmark == true)
  {
    device_param->st_status = ST_STATUS_IGNORED;
  }
  else
  {
    if (rc_selftest == 0)
    {
      device_param->st_status = ST_STATUS_PASSED;
    }
    else
    {
      device_param->st_status = ST_STATUS_FAILED;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return 0;

    CUcontext cuda_context_popped;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &cuda_context_popped) == -1) return 0;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return 0;
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  if (device_param->is_opencl == true)
  {
    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return 0;
  }

  return 0;
}
