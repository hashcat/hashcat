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

static int selftest (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (hashconfig->st_hash == NULL) return 0;

  // init : replace hashes with selftest hash

  if (device_param->is_cuda == true)
  {
    device_param->kernel_params[15] = &device_param->cuda_d_st_digests_buf;
    device_param->kernel_params[17] = &device_param->cuda_d_st_salts_buf;
    device_param->kernel_params[18] = &device_param->cuda_d_st_esalts_buf;
  }

  if (device_param->is_hip == true)
  {
    device_param->kernel_params[15] = &device_param->hip_d_st_digests_buf;
    device_param->kernel_params[17] = &device_param->hip_d_st_salts_buf;
    device_param->kernel_params[18] = &device_param->hip_d_st_esalts_buf;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    device_param->kernel_params[15] = device_param->metal_d_st_digests_buf;
    device_param->kernel_params[17] = device_param->metal_d_st_salts_buf;
    device_param->kernel_params[18] = device_param->metal_d_st_esalts_buf;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    device_param->kernel_params[15] = &device_param->opencl_d_st_digests_buf;
    device_param->kernel_params[17] = &device_param->opencl_d_st_salts_buf;
    device_param->kernel_params[18] = &device_param->opencl_d_st_esalts_buf;
  }

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

  u32 highest_pw_len = 0;

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

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
    }
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
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

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
        }
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

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, &comb, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;

          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, &comb, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;

          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, &comb, 1 * sizeof (pw_t)) == -1) return -1;

          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_FALSE, 0, 1 * sizeof (pw_t), &comb, 0, NULL, NULL) == -1) return -1;

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
        }
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

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
          }
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

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bfs_c, &bf, 1 * sizeof (bf_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bfs_c, &bf, 1 * sizeof (bf_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bfs_c, 0, &bf, 1 * sizeof (bf_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bfs_c, CL_FALSE, 0, 1 * sizeof (bf_t), &bf, 0, NULL, NULL) == -1) return -1;
          }

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

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
          }

          highest_pw_len = pw.pw_len;
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

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, &pw, 1 * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, &pw, 1 * sizeof (pw_t)) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_FALSE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
      }
    }
  }

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
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, 1, false, 0) == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 0, 1, false, 0) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 0, 1, false, 0) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_4, 0, 1, false, 0) == -1) return -1;
    }
  }
  else
  {
    // missing handling hooks

    if (hashconfig->opts_type & OPTS_TYPE_POST_AMP_UTF16LE)
    {
      if (device_param->is_cuda == true)
      {
        if (run_cuda_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, 1) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (run_hip_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->hip_d_pws_buf, 1) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (run_metal_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->metal_d_pws_buf, 1) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, 1) == -1) return -1;
      }
    }

    if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, 1, false, 0) == -1) return -1;

    if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_12, 0, 1, false, 0) == -1) return -1;

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks, device_param->cuda_stream) == -1) return -1;

        if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->hip_d_hooks, device_param->size_hooks, device_param->hip_stream) == -1) return -1;

        if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, device_param->hooks_buf, device_param->metal_d_hooks, 0, device_param->size_hooks) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        /* blocking */
        if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }

      module_ctx->module_hook12 (device_param, module_ctx->hook_extra_params[0], hashes->st_hook_salts_buf, 0, 0);

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks, device_param->cuda_stream) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_hooks, device_param->hooks_buf, device_param->size_hooks, device_param->hip_stream) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_hooks, 0, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_FALSE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }
    }

    const u32 loop_step = hashconfig->kernel_loops_min + ((hashconfig->kernel_loops_max - hashconfig->kernel_loops_min) / 32);

    const u32 salt_pos = 0;

    salt_t *salt_buf = &hashes->st_salts_buf[salt_pos];

    const u32 salt_repeats = hashes->salts_buf[salt_pos].salt_repeats;

    for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
    {
      device_param->kernel_param.salt_repeat = salt_repeat;

      if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, 0, 1, false, 0) == -1) return -1;
      }

      const u32 iter = salt_buf->salt_iter;

      for (u32 loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
      {
        u32 loop_left = iter - loop_pos;

        loop_left = MIN (loop_left, loop_step);

        device_param->kernel_param.loop_pos = loop_pos;
        device_param->kernel_param.loop_cnt = loop_left;

        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 0, 1, false, 0) == -1) return -1;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2E, 0, 1, false, 0) == -1) return -1;
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_23, 0, 1, false, 0) == -1) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks, device_param->cuda_stream) == -1) return -1;

          if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->hip_d_hooks, device_param->size_hooks, device_param->hip_stream) == -1) return -1;

          if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, device_param->hooks_buf, device_param->metal_d_hooks, 0, device_param->size_hooks) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          /* blocking */
          if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }

        module_ctx->module_hook23 (device_param, module_ctx->hook_extra_params[0], hashes->st_hook_salts_buf, 0, 0);

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks, device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_hooks, device_param->hooks_buf, device_param->size_hooks, device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_hooks, 0, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_FALSE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_INIT2)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, 0, 1, false, 0) == -1) return -1;
    }

    for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
    {
      device_param->kernel_param.salt_repeat = salt_repeat;

      if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2P, 0, 1, false, 0) == -1) return -1;
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

          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, 0, 1, false, 0) == -1) return -1;
        }
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
    {
      device_param->kernel_param.loop_pos = 0;
      device_param->kernel_param.loop_cnt = 1;

      if (hashconfig->opts_type & OPTS_TYPE_AUX1)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, 0, 1, false, 0) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX2)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX2, 0, 1, false, 0) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX3)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX3, 0, 1, false, 0) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_AUX4)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX4, 0, 1, false, 0) == -1) return -1;
      }
    }

    if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 0, 1, false, 0) == -1) return -1;
  }

  device_param->spin_damp = spin_damp_sav;

  device_param->kernel_threads = kernel_threads_sav;

  // check : check if cracked

  u32 num_cracked = 0;

  cl_event opencl_event;

  if (device_param->is_cuda == true)
  {
    if (hc_cuMemcpyDtoHAsync (hashcat_ctx, &num_cracked, device_param->cuda_d_result, sizeof (u32), device_param->cuda_stream) == -1) return -1;

    if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event3, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipMemcpyDtoHAsync (hashcat_ctx, &num_cracked, device_param->hip_d_result, sizeof (u32), device_param->hip_stream) == -1) return -1;

    if (hc_hipEventRecord (hashcat_ctx, device_param->hip_event3, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, &num_cracked, device_param->metal_d_result, 0, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_result, CL_FALSE, 0, sizeof (u32), &num_cracked, 0, NULL, &opencl_event) == -1) return -1;

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

  if (device_param->is_cuda == true)
  {
    device_param->kernel_params[15] = &device_param->cuda_d_digests_buf;
    device_param->kernel_params[17] = &device_param->cuda_d_salt_bufs;
    device_param->kernel_params[18] = &device_param->cuda_d_esalt_bufs;

    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_buf,       device_param->size_pws)     == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tmps,          device_param->size_tmps)    == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_hooks,         device_param->size_hooks)   == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_digests_shown, device_param->size_shown)   == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_result,        device_param->size_results) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    device_param->kernel_params[15] = &device_param->hip_d_digests_buf;
    device_param->kernel_params[17] = &device_param->hip_d_salt_bufs;
    device_param->kernel_params[18] = &device_param->hip_d_esalt_bufs;

    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_buf,       device_param->size_pws)     == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tmps,          device_param->size_tmps)    == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_hooks,         device_param->size_hooks)   == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_digests_shown, device_param->size_shown)   == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_result,        device_param->size_results) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    device_param->kernel_params[15] = device_param->metal_d_digests_buf;
    device_param->kernel_params[17] = device_param->metal_d_salt_bufs;
    device_param->kernel_params[18] = device_param->metal_d_esalt_bufs;

    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_buf,       device_param->size_pws)     == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_tmps,          device_param->size_tmps)    == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_hooks,         device_param->size_hooks)   == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_digests_shown, device_param->size_shown)   == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_result,        device_param->size_results) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    device_param->kernel_params[15] = &device_param->opencl_d_digests_buf;
    device_param->kernel_params[17] = &device_param->opencl_d_salt_bufs;
    device_param->kernel_params[18] = &device_param->opencl_d_esalt_bufs;

    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_buf,       device_param->size_pws)     == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tmps,          device_param->size_tmps)    == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_hooks,         device_param->size_hooks)   == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, device_param->size_shown)   == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_result,        device_param->size_results) == -1) return -1;
  }

  if (user_options->slow_candidates == true)
  {
    if (device_param->is_cuda == true)
    {
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_rules_c, device_param->size_rules_c) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_rules_c, device_param->size_rules_c) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_rules_c, device_param->size_rules_c) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_rules_c, device_param->size_rules_c) == -1) return -1;
    }
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if (device_param->is_cuda == true)
      {
        if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_rules_c, device_param->size_rules_c) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_rules_c, device_param->size_rules_c) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_rules_c, device_param->size_rules_c) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_rules_c, device_param->size_rules_c) == -1) return -1;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      if (device_param->is_cuda == true)
      {
        if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_combs_c, device_param->size_combs) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_combs_c, device_param->size_combs) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_combs_c, device_param->size_combs) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_combs_c, device_param->size_combs) == -1) return -1;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      if (device_param->is_cuda == true)
      {
        if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_bfs_c, device_param->size_bfs) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_bfs_c, device_param->size_bfs) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_bfs_c, device_param->size_bfs) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_bfs_c, device_param->size_bfs) == -1) return -1;
      }
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

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! Metal kernel self-test failed.", device_param->device_id + 1);
    }
    #endif

    if (device_param->is_opencl == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! OpenCL kernel self-test failed.", device_param->device_id + 1);
    }

    event_log_warning (hashcat_ctx, "Your device driver installation is probably broken.");
    event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
    event_log_warning (hashcat_ctx, NULL);

    hc_thread_mutex_unlock (status_ctx->mux_display);

    return -1;
  }

  return 0;
}

HC_API_CALL void *thread_selftest (void *p)
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return NULL;

  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->self_test_disable == true) return NULL;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped == true) return NULL;
  if (device_param->skipped_warning == true) return NULL;

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1) return NULL;
  }

  const int rc_selftest = selftest (hashcat_ctx, device_param);

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
    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return NULL;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return NULL;

    if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1) return NULL;
  }

  if (device_param->is_opencl == true)
  {
    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return NULL;
  }

  return NULL;
}
