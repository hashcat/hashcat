/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "shared.h"
#include "memory.h"
#include "pcfg_common.h"
#include "pcfg_cpu_omen.h"
#include "pcfg_loopback.h"

bool is_desktop_environment (void)
{
  #if defined(__APPLE__)

  return true;

  #elif defined(_WIN)

  OSVERSIONINFOEXW osvi;

  memset (&osvi, 0, sizeof (OSVERSIONINFOEXW));

  osvi.dwOSVersionInfoSize = sizeof (osvi);

  if (GetVersionExW ((LPOSVERSIONINFOW) &osvi))
  {
    return (osvi.wProductType == VER_NT_WORKSTATION);
  }

  return true;

  #else

  // x11
  if (getenv ("DISPLAY") != NULL) return true;

  // wayland
  if (getenv ("WAYLAND_DISPLAY") != NULL) return true;

  // specific desktop environment (GNOME, KDE, etc.)
  if (getenv ("XDG_CURRENT_DESKTOP") != NULL) return true;

  return false;

  #endif
}

// Portable 64x64 -> 128 high bits
#if defined(__GNUC__) || defined(__clang__)

inline u64 mulhi64 (const u64 a, const u64 b)
{
  return (u64) (((__uint128_t)a * b) >> 64);
}

#elif defined(_MSC_VER) && defined(_M_X64)

#include <intrin.h>
inline u64 mulhi64 (const u64 a, const u64 b)
{
  u64 high;

  _umul128 (a, b, &high);

  return high;
}

#else

inline u64 mulhi64 (const u64 a, const u64 b)
{
  u64 a_lo = (u32) a, a_hi = a >> 32;
  u64 b_lo = (u32) b, b_hi = b >> 32;

  u64 p0 = a_lo * b_lo;
  u64 p1 = a_lo * b_hi;
  u64 p2 = a_hi * b_lo;
  u64 p3 = a_hi * b_hi;

  u64 carry = ((p0 >> 32) + (u32) p1 + (u32) p2) >> 32;

  return p3 + (p1 >> 32) + (p2 >> 32) + carry;
}

#endif

inline u64 compute_recip64 (const u32 d)
{
  if (d == 0) return 0;
  if (d == 1) return UINT64_MAX;

  // m = ceil(2^64 / d) = floor((2^64 - 1) / d) + 1
  return (UINT64_MAX / d) + 1;
}

inline u64 fast_div64 (const u64 n, const u32 d, const u64 recip)
{
  if (d == 1) return n;

  return mulhi64 (n, recip);
}

inline u32 fast_mod64 (const u64 n, const u32 d, const u64 recip)
{
  if (d == 1) return 0;

  u64 q = mulhi64 (n, recip);

  return (u32) (n - q * d);
}
// user_options

int user_options_sanity_pcfg (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // --pcfg-loopback: validate and allow pcfg options with -a0
  if (user_options->pcfg_loopback == true)
  {
    return pcfg_loopback_sanity_check (hashcat_ctx);
  }

  if (user_options->attack_mode != ATTACK_MODE_PCFG)
  {
    if (user_options->pcfg_models_cnt > 0)
    {
      event_log_error (hashcat_ctx, "--pcfg-models-merge is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_token_types != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-token-types is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_model_file != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-model is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_train_file != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-train is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_train_format != PCFG_TRAIN_FORMAT_WORDLIST)
    {
      event_log_error (hashcat_ctx, "--pcfg-train-format is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_model_save_file != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-model-save is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_burst_size != PCFG_BURST_SIZE)
    {
      event_log_error (hashcat_ctx, "--pcfg-burst-size is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_burst_first == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-burst-first is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_pw_complex == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-pw-complex is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_terminal_count_min != PCFG_TERMINAL_COUNT_MIN)
    {
      event_log_error (hashcat_ctx, "--pcfg-terminal-count-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_pw_len_min_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-pw-len-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_pw_len_max_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-pw-len-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_token_len_min_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-token-len-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_token_len_max_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-token-len-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_token_count_max_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-token-count-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_token_count_min_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-token-count-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_struct_prob_min != PCFG_STRUCT_PROB_MIN)
    {
      event_log_error (hashcat_ctx, "--pcfg-struct-prob-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_struct_prob_max != PCFG_STRUCT_PROB_MAX)
    {
      event_log_error (hashcat_ctx, "--pcfg-struct-prob-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_keyspace_max != PCFG_KEYSPACE_MAX)
    {
      event_log_error (hashcat_ctx, "--pcfg-keyspace-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_train_df_disable == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-train-df-disable is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_train_af_disable == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-train-af-disable is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_train_af_threshold != PCFG_TRAIN_AF_THRESHOLD)
    {
      event_log_error (hashcat_ctx, "--pcfg-train-af-threshold is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_shuffle == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-shuffle is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_ahf_type != PCFG_AHF_TYPE_MARKOV)
    {
      event_log_error (hashcat_ctx, "--pcfg-ahf-type is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_ahf_terminals_min != PCFG_AHF_TERMINALS_MIN)
    {
      event_log_error (hashcat_ctx, "--pcfg-ahf-terminals-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM)
    {
      event_log_error (hashcat_ctx, "--pcfg-mode is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_model_update == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-model-update is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_model_info == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-model-info is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_model_diff_file != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-model-diff is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_type_chgd == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-type is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_cost_min != PCFG_OMEN_COST_MIN)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-cost-min is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_cost_max != PCFG_OMEN_COST_MAX)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-cost-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_keyspace_max != PCFG_OMEN_KEYSPACE_MAX)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-keyspace-max is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_max_alloc_perc != PCFG_OMEN_MAX_ALLOC_PERC)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-max-alloc-perc is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_omen_stats == true)
    {
      event_log_error (hashcat_ctx, "--pcfg-omen-stats is only allowed in attack mode 10.");
      return -1;
    }

    if (user_options->pcfg_pf_threshold != NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-perf-threshold is only allowed in attack mode 10.");
      return -1;
    }
  }
  else
  {
    if ((user_options->pcfg_model_file == NULL) && (user_options->pcfg_train_file == NULL) && (user_options->pcfg_models_cnt == 0))
    {
      event_log_error (hashcat_ctx, "PCFG attack mode requires --pcfg-model or --pcfg-train or --pcfg-models-merge");

      return -1;
    }

    if (user_options->pcfg_models_cnt != 0 && user_options->pcfg_models_cnt < 2)
    {
      event_log_error (hashcat_ctx, "--pcfg-models-merge requires at least 2 models to merge.");

      return -1;
    }

    if ((user_options->pcfg_model_file != NULL) && (user_options->pcfg_train_file != NULL))
    {
      if (user_options->pcfg_model_update == false)
      {
        event_log_error (hashcat_ctx, "Cannot use both --pcfg-model and --pcfg-train together (unless --pcfg-model-update is used).");

        return -1;
      }
      else
      {
        if (strcmp (user_options->pcfg_train_file, user_options->pcfg_model_file) == 0)
        {
          event_log_error (hashcat_ctx, "Cannot use --pcfg-train and --pcfg-model with same file.");

          return -1;
        }
      }
    }

    if (user_options->pcfg_model_update == true)
    {
      if (user_options->pcfg_model_file == NULL || user_options->pcfg_train_file == NULL)
      {
        event_log_error (hashcat_ctx, "--pcfg-model-update requires both --pcfg-model and --pcfg-train.");

        return -1;
      }
    }

    if (user_options->pcfg_model_diff_file != NULL)
    {
      if (user_options->pcfg_model_file == NULL)
      {
        event_log_error (hashcat_ctx, "--pcfg-model-diff requires --pcfg-model for the base model.");

        return -1;
      }
    }

    if (user_options->pcfg_train_file != NULL && user_options->pcfg_model_save_file != NULL)
    {
      if (strcmp (user_options->pcfg_train_file, user_options->pcfg_model_save_file) == 0)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-train and --pcfg-model-save with same file.");

        return -1;
      }
    }

    if (user_options->pcfg_train_file != NULL)
    {
      if (user_options->pcfg_train_format != PCFG_TRAIN_FORMAT_WORDLIST && user_options->pcfg_train_format != PCFG_TRAIN_FORMAT_WEIGHED_WORDLIST)
      {
        event_log_error (hashcat_ctx, "Invalid --pcfg-train-format ('%u'). Valid types are: 0 (wordlist) or 1 (weighed wordlist)", user_options->pcfg_train_format);

        return -1;
      }
    }
    else
    {
      if (user_options->pcfg_train_format != PCFG_TRAIN_FORMAT_WORDLIST)
      {
        event_log_error (hashcat_ctx, "--pcfg-train-format require --pcfg-train.");

        return -1;
      }
    }

    if (user_options->pcfg_token_types != NULL)
    {
      const char *valid_types = PCFG_TOKEN_TYPES;
      const char *input = user_options->pcfg_token_types;

      for (int i = 0; input[i] != '\0'; i++)
      {
        if (strchr (valid_types, input[i]) == NULL)
        {
          event_log_error (hashcat_ctx, "Invalid --pcfg-token-types ('%c'). Valid types are: %s", input[i], valid_types);

          return -1;
        }
      }
    }

    if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM
     && user_options->pcfg_mode != PCFG_MODE_GPU_PROB
     && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_STRUCT
     && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_COST
     && user_options->pcfg_mode != PCFG_MODE_CPU_PROB
     && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST
     && user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM_AHF
     && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      event_log_error (hashcat_ctx, "Invalid --pcfg-mode ('%u') value specified.", user_options->pcfg_mode);

      return -1;
    }

    if (user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_STRUCT && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_COST)
    {
      if (user_options->pcfg_omen_max_alloc_perc != PCFG_OMEN_MAX_ALLOC_PERC)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-omen-max-alloc-perc with --pcfg-mode != 5 (omen gpu by cost) or 7 (omen gpu by struct).");

        return -1;
      }
    }
    else
    {
      if (user_options->pcfg_omen_max_alloc_perc != PCFG_OMEN_MAX_ALLOC_PERC)
      {
        if (user_options->pcfg_omen_max_alloc_perc < 1 || user_options->pcfg_omen_max_alloc_perc > 100)
        {
          event_log_error (hashcat_ctx, "Invalid OMEN max alloc percent specified: must be >= 1 and =< 100.");

          return -1;
        }
      }
    }

    if (user_options->pcfg_keyspace_max != PCFG_KEYSPACE_MAX)
    {
      if (user_options->pcfg_keyspace_max < 1 || user_options->pcfg_keyspace_max > PCFG_KEYSPACE_MAX)
      {
        event_log_error (hashcat_ctx, "Invalid PCFG Keyspace Max specified: must be >= 1 and =< %" PRIu64 ".", (u64) PCFG_KEYSPACE_MAX);

        return -1;
      }
      else
      {
        event_log_warning (hashcat_ctx, "Structures with keyspace > %" PRIu64 " will be excluded from the attack.", (u64) user_options->pcfg_keyspace_max);
      }
    }

    if (user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_STRUCT && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      if (user_options->pcfg_omen_cost_min != PCFG_OMEN_COST_MIN || user_options->pcfg_omen_cost_max != PCFG_OMEN_COST_MAX)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-omen-cost-min/--pcfg-omen-cost-max with --pcfg-mode != 4 (omen cpu), 5 (omen gpu by cost), 6 (omen by struct cpu) or 7 (omen by struct gpu).");

        return -1;
      }

      if (user_options->pcfg_omen_keyspace_max != PCFG_OMEN_KEYSPACE_MAX)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-omen-keyspace-max with --pcfg-mode != 4 (omen cpu), 5 (omen gpu by cost), 6 (omen by struct cpu) or 7 (omen by struct gpu).");

        return -1;
      }

      if (user_options->pcfg_omen_stats == true)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-omen-stats with --pcfg-mode != 4 (omen cpu), 5 (omen gpu by cost), 6 (omen by struct cpu) or 7 (omen by struct gpu).");

        return -1;
      }
    }
    else
    {
      if (user_options->pcfg_omen_cost_max > PCFG_OMEN_COST_PRACTICAL_MAX)
      {
        event_log_error (hashcat_ctx, "PCFG: OMEN cost max cannot exceed %d (exponential complexity limit).", PCFG_OMEN_COST_PRACTICAL_MAX);

        return -1;
      }

      if (user_options->pcfg_omen_cost_min > PCFG_OMEN_COST_PRACTICAL_MAX)
      {
        event_log_error (hashcat_ctx, "PCFG: OMEN cost min cannot exceed %d (exponential complexity limit).", PCFG_OMEN_COST_PRACTICAL_MAX);

        return -1;
      }

      if (user_options->pcfg_omen_cost_max != PCFG_OMEN_COST_MAX)
      {
        if (user_options->pcfg_omen_cost_min > user_options->pcfg_omen_cost_max)
        {
          event_log_error (hashcat_ctx, "Invalid OMEN cost range: min (%u) must be <= max (%u).",
                           user_options->pcfg_omen_cost_min, user_options->pcfg_omen_cost_max);

          return -1;
        }
      }

      if (user_options->pcfg_omen_keyspace_max < user_options->pcfg_burst_size)
      {
        event_log_warning (hashcat_ctx, "PCFG: keyspace_max (%" PRIu64 ") < burst_size (%u). Auto-adjusting keyspace_max to %u.",
          user_options->pcfg_omen_keyspace_max, user_options->pcfg_burst_size, user_options->pcfg_burst_size);

        user_options->pcfg_omen_keyspace_max = user_options->pcfg_burst_size;
      }

      if (user_options->pcfg_omen_keyspace_max < 100000)
      {
        event_log_warning (hashcat_ctx,
          "PCFG: Very low keyspace_max (%" PRIu64 "). "
          "Many structures will be heavily truncated, "
          "potentially missing probable passwords.",
          user_options->pcfg_omen_keyspace_max);
      }
    }

    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      if (user_options->pcfg_omen_type != PCFG_OMEN_TYPE_INTERLEAVED && user_options->pcfg_omen_type != PCFG_OMEN_TYPE_CLASSIC)
      {
        event_log_error (hashcat_ctx, "Invalid --pcfg-omen-type ('%u'). Valid types are: 0 (interleaved) or 1 (classic)", user_options->pcfg_omen_type);

        return -1;
      }
    }
    else
    {
      if (user_options->pcfg_omen_type_chgd == true)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-omen-type with --pcfg-mode != 4 (omen cpu), 5 (omen gpu by cost), 6 (omen by struct cpu) or 7 (omen by struct gpu).");

        return -1;
      }
    }

    if (user_options->pcfg_ahf_type != PCFG_AHF_TYPE_MARKOV && user_options->pcfg_ahf_type != PCFG_AHF_TYPE_RANDOM)
    {
      event_log_error (hashcat_ctx, "Invalid --pcfg-ahf-type ('%d'). Valid types are: 0 (markov) or 1 (random)", user_options->pcfg_ahf_type);

      return -1;
    }

    if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM_AHF)
    {
      if (user_options->pcfg_ahf_terminals_min != PCFG_AHF_TERMINALS_MIN)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-ahf-terminals-min without --pcfg-mode 1 (AHF).");

        return -1;
      }
    }

    if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF && user_options->pcfg_shuffle)
    {
      event_log_error (hashcat_ctx, "Cannot use both --pcfg-mode 1 (AHF) and --pcfg-shuffle together.");

      return -1;
    }

    if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF && user_options->keyspace == true)
    {
      event_log_error (hashcat_ctx, "Cannot use --keyspace with --pcfg-mode 1 (AHF). AHF has dynamic keyspace.");

      return -1;
    }

    // AHF default burst_size is smaller than normal
    if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF && user_options->pcfg_burst_size == PCFG_BURST_SIZE)
    {
      user_options->pcfg_burst_size = PCFG_AHF_BURST_SIZE;
    }

    if (user_options->slow_candidates == true)
    {
      event_log_error (hashcat_ctx, "Use of --slow-candidates is not possible with -a 10.");

      return -1;
    }

    if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB
     || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT
     || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST)
    {
      if (strcmp (user_options->encoding_to, "utf-8") != 0)
      {
        event_log_error (hashcat_ctx, "Use of --encoding-to with GPU PCFG modes is not supported.");

        return -1;
      }
    }

    if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB
     || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT
     || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST)
    {
      if (user_options->rule_buf_l_chgd == true || user_options->rule_buf_r_chgd == true)
      {
        event_log_error (hashcat_ctx, "Use of --rule-left/--rule-right is not possible with GPU PCFG modes. Use -r instead, or switch to a CPU mode.");

        return -1;
      }
    }

    if (user_options->pcfg_token_count_max_chgd == true || user_options->pcfg_token_count_min_chgd == true)
    {
      if (user_options->pcfg_token_count_min > user_options->pcfg_token_count_max)
      {
        event_log_error (hashcat_ctx, "Invalid --pcfg-token-count-min value specified (%d): must be <= --pcfg-token-count-max (%d).",
                         user_options->pcfg_token_count_min, user_options->pcfg_token_count_max);

        return -1;
      }
    }

    if (user_options->pcfg_token_len_max_chgd == true) // || user_options->pcfg_token_len_min_chgd == true)
    {
      if (user_options->pcfg_token_len_min > user_options->pcfg_token_len_max)
      {
        event_log_error (hashcat_ctx, "Invalid --pcfg-token-len-min (%d) value specified: must be <= --pcfg-token-len-max (%d).",
                         user_options->pcfg_token_len_min, user_options->pcfg_token_len_max);

        return -1;
      }
    }

    if (user_options->pcfg_pw_len_max_chgd == true)
    {
      if (user_options->pcfg_pw_len_min > user_options->pcfg_pw_len_max)
      {
        event_log_error (hashcat_ctx, "Invalid --pcfg-pw-len-min value specified: must be <= --pcfg-pw-len-max.");

        return -1;
      }
    }

    if (user_options->pcfg_struct_prob_min > user_options->pcfg_struct_prob_max)
    {
      event_log_error (hashcat_ctx, "Invalid --pcfg-struct-prob-min value specified: must be <= --pcfg-struct-prob-max.");

      return -1;
    }

    if (user_options->pcfg_models_cnt > 0 && user_options->pcfg_model_save_file == NULL)
    {
      event_log_error (hashcat_ctx, "--pcfg-models-merge require --pcfg-model-save.");

      return -1;
    }

    for (int i = 0; i < (int) user_options->pcfg_models_cnt; i++)
    {
      char *pcfg_model = user_options->pcfg_models[i];

      if (hc_path_exist (pcfg_model) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", pcfg_model, strerror (errno));

        return -1;
      }

      if (hc_path_is_directory (pcfg_model) == true)
      {
        event_log_error (hashcat_ctx, "%s: A directory cannot be used as a modelfile argument.", pcfg_model);

        return -1;
      }

      if (hc_path_read (pcfg_model) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", pcfg_model, strerror (errno));

        return -1;
      }

      if (hc_path_has_bom (pcfg_model) == true)
      {
        event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", pcfg_model);

        //return -1;
      }
    }

    if (user_options->pcfg_train_af_disable == true || user_options->pcfg_train_df_disable == true)
    {
      if (user_options->pcfg_train_file == NULL && user_options->pcfg_models_cnt == 0)
      {
        event_log_error (hashcat_ctx, "--pcfg-train-af-disable/--pcfg-train-df-disable require --pcfg-train or --pcfg-models-merge.");

        return -1;
      }
    }

    if (user_options->pcfg_train_af_disable == true)
    {
      if (user_options->pcfg_train_af_threshold != PCFG_TRAIN_AF_THRESHOLD)
      {
        event_log_error (hashcat_ctx, "Cannot use both --pcfg-train-af-disable and --pcfg-train-af-threshold together.");

        return -1;
      }
    }

    if (user_options->pcfg_train_af_threshold != PCFG_TRAIN_AF_THRESHOLD)
    {
      if (user_options->pcfg_train_file == NULL)
      {
        event_log_error (hashcat_ctx, "--pcfg-train-af-threshold require --pcfg-train.");

        return -1;
      }

      if (user_options->pcfg_train_af_threshold < 2)
      {
        event_log_error (hashcat_ctx, "--pcfg-train-af-threshold must be >= 2.");

        return -1;
      }
    }

    if (user_options->pcfg_pf_threshold != NULL)
    {
      if (user_options->attack_mode != ATTACK_MODE_PCFG)
      {
        event_log_error (hashcat_ctx, "--pcfg-perf-threshold requires attack mode PCFG (-a 10)");
        return -1;
      }

      if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM || user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF)
      {
        event_log_error (hashcat_ctx, "Cannot use --pcfg-perf-threshold with Random or AHF");
        return -1;
      }
    }
  }

  return 0;
}

u32 calc_aligned_stride_bytes (u32 len_bytes)
{
  return (len_bytes + PCFG_CHAR_STRIDE - 1) & ~(PCFG_CHAR_STRIDE - 1);
}

void build_pattern_string (const pcfg_gpu_prob_structure_t *s, char *out, size_t out_size)
{
  size_t pos = 0;

  for (u32 k = 0; k < s->token_cnt && pos < out_size - 4; k++)
  {
    char type_char = s->types[k] & 0x7F;

    u8 len = s->lengths[k];

    if (len < 10)
    {
      out[pos++] = type_char;
      out[pos++] = '0' + len;
    }
    else if (len < 100)
    {
      out[pos++] = type_char;
      out[pos++] = '0' + (len / 10);
      out[pos++] = '0' + (len % 10);
    }
    else
    {
      int written = snprintf (out + pos, out_size - pos, "%c%u", type_char, len);

      if (written > 0) pos += written;
    }
  }

  out[pos] = '\0';
}

u32 count_structs_in_range (const pcfg_model_t *model, const u8 *struct_max_term_cost, u32 cost_start, u32 cost_end)
{
  const pcfg_omen_extra_t *omen = model->omen_data;
  const u32 struct_cnt = model->struct_cnt;

  u32 count = 0;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    u32 min_cost = (u32) omen->struct_costs[i] + (u32) omen->struct_min_term_cost[i];

    u32 max_cost = (u32) omen->struct_costs[i] + (u32) struct_max_term_cost[i];

    // structure contributes if ranges overlap
    if (min_cost <= cost_end && max_cost >= cost_start)
    {
      count++;
    }
  }

  return count;
}

// Helper: calculates the keyspace of a structure for a given residual cost
u64 get_struct_keyspace_at_cost (const pcfg_gpu_omen_structure_t *s, const pcfg_omen_extra_t *omen, int target_cost)
{
  u64 dp[128] = { 0 };
  u64 next_dp[128];

  dp[0] = 1;

  int curr_max = 0;

  for (u32 k = 0; k < s->token_cnt; k++)
  {
    const u8 ty = s->types[k] & 0x7F;
    const u8 ln = s->lengths[k];

    const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];

    memset (next_dp, 0, sizeof (next_dp));

    int next_max = -1;

    for (int p = 0; p <= curr_max; p++)
    {
      if (dp[p] == 0) continue;

      for (int c = 0; c < 32; c++)
      {
        if (map->counts[c] > 0)
        {
          int nc = p + c;

          if (nc <= target_cost)
          {
            next_dp[nc] += dp[p] * map->counts[c];

            if (nc > next_max) next_max = nc;
          }
        }
      }
    }

    if (next_max < 0) return 0;

    memcpy (dp, next_dp, sizeof (dp));

    curr_max = next_max;
  }

  if (target_cost <= curr_max) return dp[target_cost];

  return 0;
}

void calculate_struct_max_term_cost (const pcfg_model_t *model, u8 *struct_max_term_cost)
{
  const pcfg_omen_extra_t *omen = model->omen_data;
  const u32 struct_cnt = model->struct_cnt;

  // calculate max_cost for each slot (type, len)
  u8 max_cost_per_slot[256][PCFG_VALUE_MAX];
  memset (max_cost_per_slot, 0, sizeof (max_cost_per_slot));

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];

      for (int c = PCFG_OMEN_MAX_COST - 1; c >= 0; c--)
      {
        if (map->counts[c] > 0)
        {
          max_cost_per_slot[ty][ln] = (u8) c;
          break;
        }
      }
    }
  }

  // calculate max_term_cost for each structure
  for (u32 i = 0; i < struct_cnt; i++)
  {
    const pcfg_structure_t *s = &model->structures[i];

    u32 max_term_cost = 0;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u8 ty = s->types[k] & 0x7F;
      u8 ln = s->lengths[k];
      max_term_cost += max_cost_per_slot[ty][ln];
    }

    struct_max_term_cost[i] = (max_term_cost > 255) ? 255 : (u8) max_term_cost;
  }
}

bool pw_complex_check (const pcfg_structure_t *s)
{
  // for the first time ... follow Microsoft recommendations :D
  // but for now password length is not applied here

  int has_lower   = 0;
  int has_upper   = 0;
  int has_digit   = 0;
  int has_special = 0;
  int has_unicode = 0;

  for (u32 k = 0; k < s->token_cnt; k++)
  {
    u8 t = s->types[k];

    // mapping token types to Microsoft categories
    if      (t == PCFG_TK_LOWER) has_lower = 1;
    else if (t == PCFG_TK_UPPER) has_upper = 1;
    else if (t == PCFG_TK_DIGIT || t == PCFG_TK_YEAR) has_digit = 1;
    else if (t == PCFG_TK_SPECIAL || t == PCFG_TK_PUNCT) has_special = 1;
    else if (t == PCFG_TK_CAPITALIZED) { has_upper = 1; has_lower = 1; }
    else if (t == PCFG_TK_MIXED) { has_upper = 1; has_lower = 1; }
    else if (t == PCFG_TK_EMAIL) { has_lower = 1; has_special = 1; } // contains '@' e '.'
    else if (t == PCFG_TK_LATIN_EXT || t == PCFG_TK_CYRILLIC || t == PCFG_TK_HEBREW ||
             t == PCFG_TK_ARABIC || t == PCFG_TK_ASIAN || t == PCFG_TK_GREEK) has_lower = 1;
    else if (t == PCFG_TK_EMOJI || t == PCFG_TK_UNICODE) has_unicode = 1; // count as special or extra category
  }

  // enum active categories
  int categories = has_lower + has_upper + has_digit + has_special;

  if (has_unicode && !has_special) categories++;

  return (categories >= 3);
}

u64 get_theoretical_keyspace (u8 type, u8 len)
{
  // if the length is 0, the keyspace is 1 (the empty string)
  if (len == 0) return 1;
  if (len > 12) return UINT64_MAX;

  u64 base = 0;

  switch (type)
  {
    case PCFG_TK_DIGIT:
      base = sizeof (PCFG_CHARS_DIGIT) - 1;
      break;

    case PCFG_TK_LOWER:
      base = sizeof (PCFG_CHARS_LOWER) - 1;
      break;

    case PCFG_TK_UPPER:
      base = sizeof (PCFG_CHARS_UPPER) - 1;
      break;

    case PCFG_TK_SPECIAL:
      // base = ASCII symbols + common international symbols (Euro, Pound, etc.)
      // we add a conservative +10 to account for international currency and symbols
      // mapped in get_utf8_type
      base = (sizeof (PCFG_CHARS_SPECIAL) - 1) + 10;
      break;

    case PCFG_TK_PUNCT:
      base = sizeof (PCFG_CHARS_PUNCT) - 1;
      break;

    case PCFG_TK_WHITESPACE:
      base = sizeof (PCFG_CHARS_WHITE) - 1;
      break;

    case PCFG_TK_CYRILLIC:
      // Russian/Common Cyrillic: 33 lower + 33 upper = 66
      base = 66;
      break;

    case PCFG_TK_GREEK:
      // Greek: 24 lower + 24 upper = 48
      base = 48;
      break;

    case PCFG_TK_ARABIC:
      // arabic: 28 primary letters
      base = 28;
      break;

    case PCFG_TK_HEBREW:
      // Hebrew: 22 letters
      base = 22;
      break;

    case PCFG_TK_LATIN_EXT:
      // Latin Extended: covers common accented chars (approx. 94-128)
      base = 94;
      break;

    case PCFG_TK_EMOJI:
      // emojis: Thousands exist, but common ones in passwords are ~1000
      base = 1000;
      break;

    case PCFG_TK_ASIAN:
      // massive set (CJK/Thai): Too large for 64-bit keyspace if len > 4
      base = 10000;
      break;

    case PCFG_TK_UNICODE:
      // Generic Unicode/Other
      base = 20000;
      break;

    default:
      return UINT64_MAX;
  }

  if (base >= 1000 && len > 6) return UINT64_MAX;
  if (base >= 100 && len > 9) return UINT64_MAX;

  u64 ks = 1;

  for (int i = 0; i < len; i++)
  {
    // overflow protection during calculation
    if (ks > UINT64_MAX / base) return UINT64_MAX;

    ks *= base;
  }

  return ks;
}

u32 pcfg_get_pattern_str (const pcfg_structure_t *s, char *out, size_t max_len)
{
  if (out != NULL && max_len > 0) out[0] = 0;

  int pos = 0;

  u32 total_pw_len = 0;

  for (u32 i = 0; i < s->token_cnt; i++)
  {
    total_pw_len += s->lengths[i];

    if (out != NULL && pos < (int) max_len - 1)
    {
      char type_char = s->types[i] & 0x7F;

      int written = snprintf (out + pos, max_len - pos, "%c%d", type_char, s->lengths[i]);

      if (written > 0 && (size_t) written < (max_len - pos))
      {
        pos += written;
      }
    }
  }

  return total_pw_len;
}
