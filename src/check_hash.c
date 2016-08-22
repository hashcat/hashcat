
#include <common.h>
#include <shared.h>
#include <parse_hash.h>
#include <hc_global.h>
#include <hc_device_param_t.h>
#include <rp_kernel_on_cpu.h>
#include <stat_processor.h>
#include <logging.h>

static void check_hash(hc_device_param_t *device_param, plain_t *plain)
{
  char *outfile = data.outfile;
  uint  quiet = data.quiet;
  FILE *pot_fp = data.pot_fp;
  uint  loopback = data.loopback;
  uint  debug_mode = data.debug_mode;
  char *debug_file = data.debug_file;

  char debug_rule_buf[BLOCK_SIZE] = { 0 };
  int  debug_rule_len = 0; // -1 error
  uint debug_plain_len = 0;

  u8 debug_plain_ptr[BLOCK_SIZE] = { 0 };

  // hash

  char out_buf[HCBUFSIZ] = { 0 };

  const u32 salt_pos = plain->salt_pos;
  const u32 digest_pos = plain->digest_pos;  // relative
  const u32 gidvid = plain->gidvid;
  const u32 il_pos = plain->il_pos;

  ascii_digest(out_buf, salt_pos, digest_pos);

  // plain

  u64 crackpos = device_param->words_off;

  uint plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *)plain_buf;

  unsigned int plain_len = 0;

  switch (data.attack_mode) {
  case ATTACK_MODE_STRAIGHT:
  {
    pw_t pw;

    gidd_to_pw_t(device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    const uint off = device_param->innerloop_pos + il_pos;

    if (debug_mode > 0)
    {
      debug_rule_len = 0;

      // save rule
      if ((debug_mode == 1) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset(debug_rule_buf, 0, sizeof(debug_rule_buf));

        debug_rule_len = kernel_rule_to_cpu_rule(debug_rule_buf, &data.kernel_rules_buf[off]);
      }

      // save plain
      if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset(debug_plain_ptr, 0, sizeof(debug_plain_ptr));

        memcpy(debug_plain_ptr, plain_ptr, plain_len);

        debug_plain_len = plain_len;
      }
    }

    plain_len = apply_rules(data.kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], plain_len);

    crackpos += gidvid;
    crackpos *= data.kernel_rules_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (plain_len > data.pw_max) plain_len = data.pw_max;
  }
  break;
  case ATTACK_MODE_COMBI:
  {
    pw_t pw;

    gidd_to_pw_t(device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    char *comb_buf = (char *)device_param->combs_buf[il_pos].i;
    uint  comb_len = device_param->combs_buf[il_pos].pw_len;

    if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      memcpy(plain_ptr + plain_len, comb_buf, comb_len);
    }
    else
    {
      memmove(plain_ptr + comb_len, plain_ptr, plain_len);

      memcpy(plain_ptr, comb_buf, comb_len);
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
  break;
  case ATTACK_MODE_BF:
  {
    u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
    u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

    uint l_start = device_param->kernel_params_mp_l_buf32[5];
    uint r_start = device_param->kernel_params_mp_r_buf32[5];

    uint l_stop = device_param->kernel_params_mp_l_buf32[4];
    uint r_stop = device_param->kernel_params_mp_r_buf32[4];

    sp_exec(l_off, (char *)plain_ptr + l_start, data.root_css_buf, data.markov_css_buf, l_start, l_start + l_stop);
    sp_exec(r_off, (char *)plain_ptr + r_start, data.root_css_buf, data.markov_css_buf, r_start, r_start + r_stop);

    plain_len = data.css_cnt;

    crackpos += gidvid;
    crackpos *= data.bfs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  break;
  case ATTACK_MODE_HYBRID1:
  {
    pw_t pw;

    gidd_to_pw_t(device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop = device_param->kernel_params_mp_buf32[4];

    sp_exec(off, (char *)plain_ptr + plain_len, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  break;
  case ATTACK_MODE_HYBRID2:
  {
    pw_t pw;

    gidd_to_pw_t(device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop = device_param->kernel_params_mp_buf32[4];

    memmove(plain_ptr + stop, plain_ptr, plain_len);

    sp_exec(off, (char *)plain_ptr, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  break;
  }

  if (data.attack_mode == ATTACK_MODE_BF)
  {
    if (data.opti_type & OPTI_TYPE_BRUTE_FORCE) // lots of optimizations can happen here
    {
      if (data.opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (data.opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          plain_len = plain_len - data.salts_buf[0].salt_len;
        }
      }

      if (data.opts_type & OPTS_TYPE_PT_UNICODE)
      {
        for (uint i = 0, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
    }
  }

  // if enabled, update also the potfile

  if (pot_fp)
  {
    lock_file(pot_fp);

    fprintf(pot_fp, "%s:", out_buf);

    format_plain(pot_fp, plain_ptr, plain_len, 1);

    fputc('\n', pot_fp);

    fflush(pot_fp);

    unlock_file(pot_fp);
  }

  // outfile

  FILE *out_fp = NULL;

  if (outfile != NULL)
  {
    if ((out_fp = fopen(outfile, "ab")) == NULL)
    {
      log_error("ERROR: %s: %s", outfile, strerror(errno));

      out_fp = stdout;
    }

    lock_file(out_fp);
  }
  else
  {
    out_fp = stdout;

    if (quiet == 0) clear_prompt();
  }

  format_output(out_fp, out_buf, plain_ptr, plain_len, crackpos, NULL, 0);

  if (outfile != NULL)
  {
    if (out_fp != stdout)
    {
      fclose(out_fp);
    }
  }
  else
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      if ((data.devices_status != STATUS_CRACKED) && (data.status != 1))
      {
        if (quiet == 0) fprintf(stdout, "%s", PROMPT);
        if (quiet == 0) fflush(stdout);
      }
    }
  }

  // loopback

  if (loopback)
  {
    char *loopback_file = data.loopback_file;

    FILE *fb_fp = NULL;

    if ((fb_fp = fopen(loopback_file, "ab")) != NULL)
    {
      lock_file(fb_fp);

      format_plain(fb_fp, plain_ptr, plain_len, 1);

      fputc('\n', fb_fp);

      fclose(fb_fp);
    }
  }

  // (rule) debug mode

  // the next check implies that:
  // - (data.attack_mode == ATTACK_MODE_STRAIGHT)
  // - debug_mode > 0

  if ((debug_plain_len > 0) || (debug_rule_len > 0))
  {
    if (debug_rule_len < 0) debug_rule_len = 0;

    if ((quiet == 0) && (debug_file == NULL)) clear_prompt();

    format_debug(debug_file, debug_mode, debug_plain_ptr, debug_plain_len, plain_ptr, plain_len, debug_rule_buf, debug_rule_len);

    if ((quiet == 0) && (debug_file == NULL))
    {
      fprintf(stdout, "%s", PROMPT);

      fflush(stdout);
    }
  }
}
