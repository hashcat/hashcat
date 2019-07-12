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

  if (device_param->is_opencl == true)
  {
    device_param->kernel_params[15] = &device_param->opencl_d_st_digests_buf;
    device_param->kernel_params[17] = &device_param->opencl_d_st_salts_buf;
    device_param->kernel_params[18] = &device_param->opencl_d_st_esalts_buf;
  }

  device_param->kernel_params_buf32[31] = 1;
  device_param->kernel_params_buf32[32] = 0;

  // password : move the known password into a fake buffer

  u32 highest_pw_len = 0;

  if (user_options->slow_candidates == true)
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      device_param->kernel_params_buf32[30] = 1;
    }

    pw_t pw; memset (&pw, 0, sizeof (pw));

    char *pw_ptr = (char *) &pw.i;

    const size_t pw_len = strlen (hashconfig->st_pass);

    memcpy (pw_ptr, hashconfig->st_pass, pw_len);

    pw.pw_len = (u32) pw_len;

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
    }

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
    }
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        device_param->kernel_params_buf32[30] = 1;

        pw_t pw;

        memset (&pw, 0, sizeof (pw));

        char *pw_ptr = (char *) &pw.i;

        const size_t pw_len = strlen (hashconfig->st_pass);

        memcpy (pw_ptr, hashconfig->st_pass, pw_len);

        pw.pw_len = (u32) pw_len;

        if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
        {
          uppercase ((u8 *) pw_ptr, pw.pw_len);
        }

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
        }
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        device_param->kernel_params_buf32[30] = 1;
        device_param->kernel_params_buf32[33] = COMBINATOR_MODE_BASE_LEFT;

        pw_t pw;

        memset (&pw, 0, sizeof (pw));

        char *pw_ptr = (char *) &pw.i;

        const size_t pw_len = strlen (hashconfig->st_pass);

        memcpy (pw_ptr, hashconfig->st_pass, pw_len - 1);

        pw.pw_len = (u32) pw_len - 1;

        if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
        {
          uppercase ((u8 *) pw_ptr, pw.pw_len);
        }

        pw_t comb;

        memset (&comb, 0, sizeof (comb));

        char *comb_ptr = (char *) &comb.i;

        memcpy (comb_ptr, hashconfig->st_pass + pw_len - 1, 1);

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
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_combs_c, &comb, 1 * sizeof (pw_t)) == -1) return -1;

          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_TRUE, 0, 1 * sizeof (pw_t), &comb, 0, NULL, NULL) == -1) return -1;

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
        }
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        device_param->kernel_params_buf32[30] = 1;

        if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
        {
          pw_t pw;

          memset (&pw, 0, sizeof (pw));

          char *pw_ptr = (char *) &pw.i;

          const size_t pw_len = strlen (hashconfig->st_pass);

          memcpy (pw_ptr, hashconfig->st_pass, pw_len);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase ((u8 *) pw_ptr, pw_len);
          }

          pw.pw_len = (u32) pw_len;

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
          }
        }
        else
        {
          bf_t bf;

          memset (&bf, 0, sizeof (bf));

          char *bf_ptr = (char *) &bf.i;

          memcpy (bf_ptr, hashconfig->st_pass, 1);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
          {
            memset (bf_ptr, 0, 4);

            for (int i = 0, j = 0; i < 1; i += 1, j += 2)
            {
              bf_ptr[j + 0] = hashconfig->st_pass[i];
              bf_ptr[j + 1] = 0;
            }
          }
          else if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE)
          {
            memset (bf_ptr, 0, 4);

            for (int i = 0, j = 0; i < 1; i += 1, j += 2)
            {
              bf_ptr[j + 0] = 0;
              bf_ptr[j + 1] = hashconfig->st_pass[i];
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
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bfs_c, &bf, 1 * sizeof (bf_t)) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bfs_c, CL_TRUE, 0, 1 * sizeof (bf_t), &bf, 0, NULL, NULL) == -1) return -1;
          }

          pw_t pw;

          memset (&pw, 0, sizeof (pw));

          char *pw_ptr = (char *) &pw.i;

          const size_t pw_len = strlen (hashconfig->st_pass);

          memcpy (pw_ptr + 1, hashconfig->st_pass + 1, pw_len - 1);

          size_t new_pass_len = pw_len;

          if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
          {
            memset (pw_ptr, 0, pw_len);

            for (size_t i = 1, j = 2; i < new_pass_len; i += 1, j += 2)
            {
              pw_ptr[j + 0] = hashconfig->st_pass[i];
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
              pw_ptr[j + 1] = hashconfig->st_pass[i];
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
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
          }

          highest_pw_len = pw.pw_len;
        }
      }
    }
    else
    {
      pw_t pw;

      memset (&pw, 0, sizeof (pw));

      char *pw_ptr = (char *) &pw.i;

      const size_t pw_len = strlen (hashconfig->st_pass);

      memcpy (pw_ptr, hashconfig->st_pass, pw_len);

      pw.pw_len = (u32) pw_len;

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_buf, &pw, 1 * sizeof (pw_t)) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, 0, 1 * sizeof (pw_t), &pw, 0, NULL, NULL) == -1) return -1;
      }
    }
  }

  // main : run the kernel

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      if (highest_pw_len < 16)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 1, false, 0) == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 1, false, 0) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 1, false, 0) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_4, 1, false, 0) == -1) return -1;
    }
  }
  else
  {
    // missing handling hooks

    if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 1, false, 0) == -1) return -1;

    if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_12, 1, false, 0) == -1) return -1;

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyDtoH (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }

      module_ctx->module_hook12 (device_param, hashes->st_hook_salts_buf, 0, 1);

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }
    }

    const u32 salt_pos = 0;

    salt_t *salt_buf = &hashes->st_salts_buf[salt_pos];

    const u32 loop_step = hashconfig->kernel_loops_min + ((hashconfig->kernel_loops_max - hashconfig->kernel_loops_min) / 32);

    const u32 iter = salt_buf->salt_iter;

    for (u32 loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
    {
      u32 loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 1, false, 0) == -1) return -1;
    }

    if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_23, 1, false, 0) == -1) return -1;

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyDtoH (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }

      module_ctx->module_hook23 (device_param, hashes->st_hook_salts_buf, 0, 1);

      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_INIT2)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, 1, false, 0) == -1) return -1;
    }

    if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
    {
      const u32 iter2 = salt_buf->salt_iter2;

      for (u32 loop_pos = 0; loop_pos < iter2; loop_pos += loop_step)
      {
        u32 loop_left = iter2 - loop_pos;

        loop_left = MIN (loop_left, loop_step);

        device_param->kernel_params_buf32[28] = loop_pos;
        device_param->kernel_params_buf32[29] = loop_left;

        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, 1, false, 0) == -1) return -1;
      }
    }

    if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
    {
      device_param->kernel_params_buf32[28] = 0;
      device_param->kernel_params_buf32[29] = 1;

      if (hashconfig->opts_type & OPTS_TYPE_AUX1)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, 1, false, 0) == -1) return -1;
      }
      else if (hashconfig->opts_type & OPTS_TYPE_AUX2)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX2, 1, false, 0) == -1) return -1;
      }
      else if (hashconfig->opts_type & OPTS_TYPE_AUX3)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX3, 1, false, 0) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 1, false, 0) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 1, false, 0) == -1) return -1;
    }
  }

  device_param->spin_damp = spin_damp_sav;

  // check : check if cracked

  u32 num_cracked;

  if (device_param->is_cuda == true)
  {
    if (hc_cuMemcpyDtoH (hashcat_ctx, &num_cracked, device_param->cuda_d_result, sizeof (u32)) == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL) == -1) return -1;
  }

  // finish : cleanup and restore

  device_param->kernel_params_buf32[27] = 0;
  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = 0;
  device_param->kernel_params_buf32[30] = 0;
  device_param->kernel_params_buf32[31] = 0;
  device_param->kernel_params_buf32[32] = 0;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf64[34] = 0;

  if (device_param->is_cuda == true)
  {
    device_param->kernel_params[15] = &device_param->cuda_d_digests_buf;
    device_param->kernel_params[17] = &device_param->cuda_d_salt_bufs;
    device_param->kernel_params[18] = &device_param->cuda_d_esalt_bufs;

    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_pws_buf,         device_param->size_pws)     == -1) return -1;
    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_tmps,            device_param->size_tmps)    == -1) return -1;
    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_hooks,           device_param->size_hooks)   == -1) return -1;
    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_plain_bufs,      device_param->size_plains)  == -1) return -1;
    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_digests_shown,   device_param->size_shown)   == -1) return -1;
    if (run_cuda_kernel_bzero   (hashcat_ctx, device_param, device_param->cuda_d_result,          device_param->size_results) == -1) return -1;
  }

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

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_bfs_c, device_param->size_bfs) == -1) return -1;
      }
    }
  }

  // check return

  if (num_cracked == 0)
  {
    hc_thread_mutex_lock (status_ctx->mux_display);
    if (device_param->is_opencl == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! OpenCL kernel self-test failed.", device_param->device_id + 1);
    }
    if (device_param->is_cuda == true)
    {
      event_log_error (hashcat_ctx, "* Device #%u: ATTENTION! CUDA kernel self-test failed.", device_param->device_id + 1);
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
    if (hc_cuCtxSetCurrent (hashcat_ctx, device_param->cuda_context) == -1) return NULL;
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

  return NULL;
}
