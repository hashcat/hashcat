/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "filehandling.h"
#include "user_options.h"
#include "pcfg_trainer.h"
#include "pcfg_model.h"
#include "pcfg.h"
#include "xxhash.h"

static void pcfg_model_filter_huge_structures (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m, u64 limit)
{
  if (limit == 0) return;

  u32 valid_cnt = 0;
  u32 skipped = 0;

  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    pcfg_structure_t *s = &m->structures[i];
    u64 ks = 1;
    bool overflow = false;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u8 ty = s->types[k] & 0x7F;
      u8 ln = s->lengths[k];
      u32 cnt = m->terminals[ty][ln].cnt;

      if (cnt == 0) { ks = 0; break; }

      if (__builtin_mul_overflow (ks, cnt, &ks)) {
         overflow = true;
         break;
      }
    }

    if (!overflow && ks <= limit)
    {
      if (valid_cnt != i) m->structures[valid_cnt] = m->structures[i];
      valid_cnt++;
    }
    else
    {
      skipped++;
    }
  }

  if (skipped > 0)
  {
    if (hashcat_ctx->user_options->quiet == false)
    {
      event_log_warning (hashcat_ctx, "PCFG: Skipped %u structures with keyspace > %" PRIu64, skipped, limit);
    }
    m->struct_cnt = valid_cnt;
  }
}

static const char *get_token_name (int type)
{
  switch (type)
  {
    case PCFG_TK_LOWER:       return "Lower Alpha";
    case PCFG_TK_UPPER:       return "Upper Alpha";
    case PCFG_TK_MIXED:       return "Mixed Case";
    case PCFG_TK_CAPITALIZED: return "Capitalized";
    case PCFG_TK_DIGIT:       return "Digit";
    case PCFG_TK_SPECIAL:     return "Special";
    case PCFG_TK_PUNCT:       return "Punctuation";
    case PCFG_TK_WHITESPACE:  return "Whitespace";
    case PCFG_TK_YEAR:        return "Year";
    case PCFG_TK_EMAIL:       return "Email Provider";
    case PCFG_TK_KEYBOARD:    return "Keyboard Walk";
    case PCFG_TK_REPEAT:      return "Repetitions";
    case PCFG_TK_SEQUENCE:    return "Logical Sequences";
    case PCFG_TK_EMOJI:       return "Emoji";
    case PCFG_TK_LATIN_EXT:   return "Latin Ext/Accents";
    case PCFG_TK_CYRILLIC:    return "Cyrillic";
    case PCFG_TK_ARABIC:      return "Arabic/Persian";
    case PCFG_TK_ASIAN:       return "Asian/Hindi";
    case PCFG_TK_GREEK:       return "Greek";
    case PCFG_TK_HEBREW:      return "Hebrew";
    case PCFG_TK_UNICODE:     return "Generic Unicode";
    default:                  return "Unknown";
  }
}

static char get_type_char (u8 type)
{
  const u8 raw_type = type & 0x7F;

  switch (raw_type)
  {
    case PCFG_TK_LOWER:       return 'L';
    case PCFG_TK_UPPER:       return 'U';
    case PCFG_TK_MIXED:       return 'M';
    case PCFG_TK_CAPITALIZED: return 'C';
    case PCFG_TK_DIGIT:       return 'D';
    case PCFG_TK_SPECIAL:     return 'S';
    case PCFG_TK_PUNCT:       return 'P';
    case PCFG_TK_UNICODE:     return 'X';
    case PCFG_TK_WHITESPACE:  return 'W';
    case PCFG_TK_YEAR:        return 'Y';
    case PCFG_TK_EMAIL:       return 'E';
    case PCFG_TK_KEYBOARD:    return 'K';
    case PCFG_TK_REPEAT:      return 'R';
    case PCFG_TK_SEQUENCE:    return 'Q';
    case PCFG_TK_EMOJI:       return 'J';
    case PCFG_TK_LATIN_EXT:   return 'A';
    case PCFG_TK_CYRILLIC:    return 'I';
    case PCFG_TK_ARABIC:      return 'B';
    case PCFG_TK_ASIAN:       return 'H';
    case PCFG_TK_GREEK:       return 'G';
    case PCFG_TK_HEBREW:      return 'V';

    default: return '?'; // unknown type
  }
}

static void get_table_stats (pcfg_markov_row_t *table, u32 *active_states, double *avg_successors)
{
  if (table == NULL)
  {
    *active_states = 0;
    *avg_successors = 0.0;
    return;
  }

  u32 active = 0;
  u64 total_unique_targets = 0;

  for (u32 s = 0; s < 65536; s++)
  {
    u8 row_targets[256] = { 0 };
    u32 row_cnt = 0;

    bool has_data = false;

    for (int b = 0; b < 256; b++)
    {
      u8 target = table[s].bins[b];

      if (target != 0)
      {
        has_data = true;
        if (row_targets[target] == 0)
        {
          row_targets[target] = 1;
          row_cnt++;
        }
      }
    }

    if (has_data)
    {
      active++;
      total_unique_targets += row_cnt;
    }
  }

  *active_states = active;
  *avg_successors = (active > 0) ? (double) total_unique_targets / active : 0.0;
}

static void format_human_count (u64 val, char *buf, size_t len)
{
  //const char *units[] = { "", "k", "M", "G", "T", "P", "E" };
  const char *units[] = { "", " Thousand", " Million", " Billion", " Trillion", " Quadrillion", " Quintillion" };

  double d = (double)val;

  int i = 0;

  while (d >= 1000.0 && i < 6)
  {
    d /= 1000.0;
    i++;
  }

  if (i == 0)
  {
    snprintf (buf, len, "%.0f", d);
  }
  else
  {
    snprintf (buf, len, "%.2f%s", d, units[i]);
  }
}

static void format_keyspace (double keyspace, char *buffer, size_t buf_size)
{
  if (keyspace <= 0)
  {
    snprintf (buffer, buf_size, "BROKEN (0)");
    return;
  }

  // standard suffix: Kilo, Mega, Giga, Tera, Peta, Exa, Zetta, Yotta
  const char *suffixes[] = {"", "K", "M", "G", "T", "P", "E", "Z", "Y"};

  int s = 0;

  double val = keyspace;

  while (val >= 1000 && s < 8)
  {
    val /= 1000;
    s++;
  }

  if (s == 0)
  {
    snprintf (buffer, buf_size, "%.0f", val);
  }
  else
  {
    snprintf (buffer, buf_size, "%.1f%s", val, suffixes[s]);
  }
}

// inspect helpers

static double pcfg_inspect_calc_entropy (pcfg_model_t *m)
{
  double entropy = 0;

  if (m->pw_total > 0)
  {
    for (u32 i = 0; i < m->struct_cnt; i++)
    {
      pcfg_structure_t *s = &m->structures[i];

      if (s->count == 0 || s->keyspace == 0) continue;

      double p = (double) s->count / (double) m->pw_total;

      if (p > 0)
      {
        entropy -= p * log2 (p);
        entropy += p * log2 ((double) s->keyspace);
      }
    }
  }

  return entropy;
}

static u32 pcfg_inspect_find_best_bin (const pcfg_markov_row_t *row, u8 mask, u8 skip_below, u8 *best_out)
{
  u32 dst_counts[256] = { 0 };

  u32 max_v = 0;
  u8  best  = 0;

  for (int b = 0; b < 256; b++)
  {
    u8 target = row->bins[b] & mask;

    if (target < skip_below) continue;

    dst_counts[target]++;

    if (dst_counts[target] > max_v)
    {
      max_v = dst_counts[target];
      best  = target;
    }
  }

  if (best_out) *best_out = best;

  return max_v;
}

static u32 pcfg_inspect_find_max_u32 (const u32 *counts, u32 size, u32 *best_idx)
{
  u32 max_v = 0;
  u32 idx   = 0;

  for (u32 i = 0; i < size; i++)
  {
    if (counts[i] > max_v)
    {
      max_v = counts[i];
      idx   = i;
    }
  }

  if (best_idx) *best_idx = idx;

  return max_v;
}

static double pcfg_inspect_max_prob_bins (const pcfg_markov_row_t *table, u32 size, u8 mask, u8 skip_below, u32 threshold)
{
  double max_prob = 0.0;

  for (u32 s = 0; s < size; s++)
  {
    u32 max_v = pcfg_inspect_find_best_bin (&table[s], mask, skip_below, NULL);

    if (max_v > threshold)
    {
      double prob = (max_v / 256.0) * 100.0;

      if (prob > max_prob) max_prob = prob;
    }
  }

  return max_prob;
}

static double pcfg_inspect_max_prob_counts (const u32 *counts, u32 size, double divisor)
{
  double max_prob = 0.0;

  for (u32 i = 0; i < size; i++)
  {
    if (counts[i] > 0)
    {
      double prob = ((double) counts[i] / divisor) * 100.0;

      if (prob > max_prob) max_prob = prob;
    }
  }

  return max_prob;
}

static u32 pcfg_inspect_count_matching_bins (const pcfg_markov_row_t *row, u8 mask, u8 target)
{
  u32 count = 0;

  for (int b = 0; b < 256; b++)
  {
    if ((row->bins[b] & mask) == target) count++;
  }

  return count;
}

// helper for generating graphic bar

static void generate_bar (char *buf, size_t buf_size, double percentage, int bar_width, bool filled_style)
{
  if (percentage < 0.0) percentage = 0.0;
  if (percentage > 100.0) percentage = 100.0;

  int filled = (int) ((percentage / 100.0) * bar_width + 0.5);

  if (filled > bar_width) filled = bar_width;

  buf[0] = '|';

  int pos = 1;

  for (int i = 0; i < bar_width && pos < (int) buf_size - 2; i++)
  {
    if (i < filled)
      buf[pos++] = (filled_style) ? '#' : '\xE2', buf[pos++] = '\x96', buf[pos++] = '\x88'; // █
    else
      buf[pos++] = (filled_style) ? '.' : '\xE2', buf[pos++] = '\x96', buf[pos++] = '\x91'; // ░
  }

  buf[pos++] = '|';
  buf[pos] = '\0';
}

/*
// unused for now
static void generate_bar_ascii (char *buf, size_t buf_size, double percentage, int bar_width)
{
  if (percentage < 0.0) percentage = 0.0;
  if (percentage > 100.0) percentage = 100.0;

  int filled = (int) ((percentage / 100.0) * bar_width + 0.5);

  if (filled > bar_width) filled = bar_width;

  int pos = 0;

  buf[pos++] = '|';

  for (int i = 0; i < bar_width && pos < (int) buf_size - 2; i++)
  {
    buf[pos++] = (i < filled) ? '#' : ' ';
  }

  buf[pos++] = '|';
  buf[pos] = '\0';
}
*/

static void generate_bar_auto (char *buf, size_t buf_size, double percentage, int bar_width)
{
  return generate_bar (buf, buf_size, percentage, bar_width, false);
}

static inline void pcfg_inspect_bar (double prob, double max_prob, char *bar_buf, size_t buf_size)
{
  double bar_pct = (max_prob > 0) ? (prob / max_prob) * 100.0 : 0.0;

  generate_bar_auto (bar_buf, buf_size, bar_pct, 20);
}

static void pcfg_build_structure_example (pcfg_model_t *m, pcfg_structure_t *s, char *out)
{
  u32 pos = 0;

  for (u32 k = 0; k < s->token_cnt; k++)
  {
    u8 ty = s->types[k] & 0x7F;
    u8 ln = s->lengths[k];

    u32 num_terminals = m->terminals[ty][ln].cnt;

    if (num_terminals > 0)
    {
      // find the terminal with the highest count
      u32 best_idx = 0;
      u32 max_count = 0;

      for (u32 i = 0; i < num_terminals; i++)
      {
        if (m->terminals[ty][ln].items[i].count > max_count)
        {
          max_count = m->terminals[ty][ln].items[i].count;
          best_idx = i;
        }
      }

      const char *val = m->terminals[ty][ln].items[best_idx].value;

      u32 val_len = (u32) strlen (val);

      if (pos + val_len < 256)
      {
        memcpy (out + pos, val, val_len);

        pos += val_len;
      }
    }
    else
    {
      // if no terminal exists for this slot, use a placeholder
      if (pos < 255) out[pos++] = '?';
    }
  }
  out[pos] = 0;
}

// inspect sub-functions

static void pcfg_inspect_print_header (pcfg_model_t *m)
{
  u32 active_structs = 0;

  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    if (m->structures[i].keyspace > 0) active_structs++;
  }

  char total_passwords_buf[64];

  format_human_count (m->pw_total, total_passwords_buf, sizeof (total_passwords_buf));

  double total_entropy = pcfg_inspect_calc_entropy (m);

  // quality score
  int quality_score = 0;

  // structure diversity (max 30 points)
  if      (active_structs >= 10000) quality_score += 30;
  else if (active_structs >= 1000)  quality_score += 20;
  else if (active_structs >= 100)   quality_score += 10;

  // terminal coverage - need to count first
  u64 global_unique_precalc = 0;

  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      if (m->terminals[t][l].cnt > 0)
      {
        global_unique_precalc += m->terminals[t][l].cnt;
      }
    }
  }

  // terminal coverage (max 30 points)
  if      (global_unique_precalc >= 1000000) quality_score += 30;
  else if (global_unique_precalc >= 100000)  quality_score += 20;
  else if (global_unique_precalc >= 10000)   quality_score += 10;

  // entropy (max 40 points)
  if      (total_entropy >= 60) quality_score += 40;
  else if (total_entropy >= 40) quality_score += 30;
  else if (total_entropy >= 25) quality_score += 20;
  else                          quality_score += 10;

  const char *quality_desc;

  if      (quality_score >= 80) quality_desc = "EXCELLENT";
  else if (quality_score >= 60) quality_desc = "GOOD";
  else if (quality_score >= 40) quality_desc = "MODERATE";
  else if (quality_score >= 20) quality_desc = "LIMITED";
  else                          quality_desc = "MINIMAL";

  // HEADER

  fprintf (stderr, "\n\n");
  fprintf (stderr, "=== PCFG MODEL INSPECTOR ===\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Model     : %s\n", m->name ? m->name : "N/A");
  fprintf (stderr, "  Quality   : %d/100 (%s)\n", quality_score, quality_desc);
  fprintf (stderr, "  Trained   : %" PRIu64 " passwords (%s)\n", m->pw_total, total_passwords_buf);
  fprintf (stderr, "  Encoding  : %s\n", m->encoding_from[0] ? m->encoding_from : "RAW");
  fprintf (stderr, "  Structs   : %u active / %u loaded / %u total\n", active_structs, m->struct_cnt, m->struct_cnt_file);

  // terminal summary

  typedef struct
  {
    int type;
    u64 unique;

  } type_stats_t;

  type_stats_t stats[256];

  u64 global_unique = 0;
  u64 total_active_occurrences = 0;

  for (int t = 0; t < 256; t++)
  {
    stats[t].type = t;
    stats[t].unique = 0;

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      if (m->terminals[t][l].cnt > 0)
      {
        stats[t].unique += m->terminals[t][l].cnt;

        for (u32 i = 0; i < m->terminals[t][l].cnt; i++)
        {
          total_active_occurrences += m->terminals[t][l].items[i].count;
        }
      }
    }

    global_unique += stats[t].unique;
  }

  char unique_buf[64];
  char instances_buf[64];

  format_human_count (global_unique, unique_buf, sizeof (unique_buf));
  format_human_count (total_active_occurrences, instances_buf, sizeof (instances_buf));

  double avg_tokens = (m->pw_total > 0) ? (double) total_active_occurrences / (double) m->pw_total : 0.0;

  const char *avg_desc;

  if      (avg_tokens < 1.20) avg_desc = "Monolithic";
  else if (avg_tokens < 2.0)  avg_desc = "Efficient";
  else if (avg_tokens < 3.5)  avg_desc = "Granular";
  else                        avg_desc = "Fragmented";

  fprintf (stderr, "  Terminals : %s unique (%s instances, avg %.2f/pw - %s)\n",
           unique_buf, instances_buf, avg_tokens, avg_desc);

  // entropy

  const char *entropy_rating;

  if      (total_entropy < 28) entropy_rating = "VERY WEAK";
  else if (total_entropy < 36) entropy_rating = "WEAK";
  else if (total_entropy < 50) entropy_rating = "MODERATE";
  else if (total_entropy < 70) entropy_rating = "STRONG";
  else                         entropy_rating = "VERY STRONG";

  if (total_entropy < 64.0)
  {
    fprintf (stderr, "  Entropy   : %.2f bits (2^%.0f combinations) - %s\n", total_entropy, total_entropy, entropy_rating);
  }
  else
  {
    fprintf (stderr, "  Entropy   : %.2f bits (> 2^64 combinations) - %s\n", total_entropy, entropy_rating);
  }
}

static void pcfg_inspect_print_terminal_dist (pcfg_model_t *m)
{
  typedef struct
  {
    int type;
    u64 unique;

  } type_stats_t;

  type_stats_t stats[256];

  u64 global_unique = 0;

  for (int t = 0; t < 256; t++)
  {
    stats[t].type = t;
    stats[t].unique = 0;

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      if (m->terminals[t][l].cnt > 0)
      {
        stats[t].unique += m->terminals[t][l].cnt;
      }
    }

    global_unique += stats[t].unique;
  }

  // sort by unique count descending
  for (int i = 0; i < 255; i++)
  {
    for (int j = i + 1; j < 256; j++)
    {
      if (stats[j].unique > stats[i].unique)
      {
        type_stats_t tmp = stats[i];

        stats[i] = stats[j];
        stats[j] = tmp;
      }
    }
  }

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TERMINAL DISTRIBUTION ---\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Type | Name               |      Count |  Ratio\n");
  fprintf (stderr, "  -----+--------------------+------------+--------\n");

  for (int i = 0; i < 256; i++)
  {
    if (stats[i].unique == 0) continue;

    u8 t = stats[i].type;

    const char *name = get_token_name (t);

    char type_char = (t >= 32 && t <= 126) ? (char) t : '?';

    double pct = (global_unique > 0) ? (double) stats[i].unique / (double) global_unique * 100.0 : 0.0;

    if (pct >= 0.1)
    {
      fprintf (stderr, "  %c    | %-18s | %10" PRIu64 " | %6.1f%%\n", type_char, name, stats[i].unique, pct);
    }
    else
    {
      fprintf (stderr, "  %c    | %-18s | %10" PRIu64 " |   <0.1%%\n", type_char, name, stats[i].unique);
    }
  }

  fprintf (stderr, "  -----+--------------------+------------+--------\n");
}

static void pcfg_inspect_print_top_structs (pcfg_model_t *m, u32 top_structs, const char *filter_types)
{
  const int BAR_NARROW = 18;

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TOP %u STRUCTURES (Filtered: %s) ---\n", top_structs, filter_types ? filter_types : "None");
  fprintf (stderr, "\n");

  u32 count_shown = 0;

  // find max prob for scaling
  double max_prob = 0.0;

  u32 max_depth = 65536;

  for (u32 i = 0; i < m->struct_cnt && i < max_depth; i++)
  {
    if (m->structures[i].prob > max_prob) max_prob = m->structures[i].prob;
  }

  if (max_prob <= 0) max_prob = 1.0;

  fprintf (stderr, "    # | Pattern              |   Keyspace | Example               |      Count |##################|    Prob\n");
  fprintf (stderr, "  ----+----------------------+------------+-----------------------+------------+------------------+--------\n");

  char bar_buf[128];

  for (u32 i = 0; i < m->struct_cnt && count_shown < top_structs; i++)
  {
    pcfg_structure_t *s = &m->structures[i];

    if (filter_types && *filter_types)
    {
      bool keep = false;

      for (u32 k = 0; k < s->token_cnt; k++)
      {
        for (const char *f = filter_types; *f; f++)
        {
          if (s->types[k] == *f)
          {
            keep = true;
            break;
          }
        }

        if (keep) break;
      }

      if (!keep) continue;
    }

    count_shown++;

    unsigned __int128 keyspace = 1;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      keyspace *= m->terminals[s->types[k]][s->lengths[k]].cnt;
    }

    if (keyspace == 0) continue;

    char example[256] = { 0 };

    pcfg_build_structure_example (m, s, example);

    char ks_str[32] = { 0 };

    format_keyspace (keyspace, ks_str, sizeof (ks_str));

    char pattern_buf[PCFG_PATTERN_MAX];

    pcfg_get_pattern_str (s, pattern_buf, sizeof (pattern_buf));

    // scale: 10% probability = full bar
    double bar_pct = (s->prob * 100.0) * 10.0;

    if (bar_pct > 100.0) bar_pct = 100.0;

    generate_bar_auto (bar_buf, sizeof (bar_buf), bar_pct, BAR_NARROW);

    fprintf (stderr, "  %3u | %-20s | %10s | %-21.21s | %10" PRIu64 " %s %6.3f%%\n",
             count_shown, pattern_buf, ks_str, example, (u64) s->count, bar_buf, s->prob * 100.0);
  }

  fprintf (stderr, "  ----+----------------------+------------+-----------------------+------------+------------------+--------\n");

  // calculate top N coverage
  double coverage = 0.0;

  for (u32 i = 0; i < m->struct_cnt && i < top_structs; i++)
  {
    coverage += m->structures[i].prob;
  }

  fprintf (stderr, "  Top %u coverage: %.1f%%\n", top_structs, coverage * 100.0);
}

static void pcfg_inspect_print_length_dist (pcfg_model_t *m)
{
  typedef struct
  {
    int    len;
    u32    count;
    double prob;

  } len_stat_t;

  len_stat_t len_stats[256];

  u32 total_len_bins = 0;

  for (int i = 0; i < 256; i++)
  {
    len_stats[i].len = i;
    len_stats[i].count = 0;

    for (int j = 0; j < 256; j++)
    {
      if (m->pw_len_table.states[j] == i)
      {
        len_stats[i].count++;
      }
    }

    total_len_bins += len_stats[i].count;
  }

  for (int i = 0; i < 256; i++)
  {
    len_stats[i].prob = (total_len_bins > 0) ? (double) len_stats[i].count / total_len_bins * 100.0 : 0.0;
  }

  // find peak
  int peak_len = 0;

  double peak_prob = 0.0;

  for (int i = 0; i < 256; i++)
  {
    if (len_stats[i].prob > peak_prob)
    {
      peak_prob = len_stats[i].prob;
      peak_len = i;
    }
  }

  fprintf (stderr, "\n");
  fprintf (stderr, "--- PASSWORD LENGTH DISTRIBUTION ---\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Len |#############################|    Prob\n");
  fprintf (stderr, "  ----+-----------------------------+--------\n");

  char bar_buf[128];

  for (int i = 1; i < 256; i++)
  {
    if (len_stats[i].count == 0) continue;

    double bar_pct = (peak_prob > 0) ? (len_stats[i].prob / peak_prob) * 100.0 : 0.0;

    generate_bar_auto (bar_buf, sizeof (bar_buf), bar_pct, 29);

    if (i == peak_len)
    {
      fprintf (stderr, "  %3d %s %6.2f%% <- Peak\n", i, bar_buf, len_stats[i].prob);
    }
    else
    {
      fprintf (stderr, "  %3d %s %6.2f%%\n", i, bar_buf, len_stats[i].prob);
    }
  }

  fprintf (stderr, "  ----+-----------------------------+--------\n");
}

static void pcfg_inspect_print_struct_by_type (pcfg_model_t *m, const char *types_to_check, const char *filter_types)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- STRUCTURE BY TOKEN TYPE (Filtered: %s) ---\n", filter_types ? filter_types : "None");
  fprintf (stderr, "\n");

  fprintf (stderr, "  Type | Name               | Top Structure   |      Count |   Keyspace | Example\n");
  fprintf (stderr, "  -----+--------------------+-----------------+------------+------------+---------------\n");

  for (const char *ptr = types_to_check; *ptr; ptr++)
  {
    int target_type = (unsigned char) *ptr;
    bool found = false;

    for (u32 i = 0; i < m->struct_cnt; i++)
    {
      pcfg_structure_t *s = &m->structures[i];

      for (u32 k = 0; k < s->token_cnt; k++)
      {
        if (s->types[k] == target_type)
        {
          unsigned __int128 keyspace = 1;

          for (u32 j = 0; j < s->token_cnt; j++)
          {
            keyspace *= m->terminals[s->types[j]][s->lengths[j]].cnt;
          }

          char example[256] = { 0 };

          pcfg_build_structure_example (m, s, example);

          char ks_str[32] = { 0 };

          format_keyspace (keyspace, ks_str, sizeof (ks_str));

          char pattern_buf[PCFG_PATTERN_MAX] = { 0 };

          pcfg_get_pattern_str (s, pattern_buf, sizeof (pattern_buf));

          const char *type_name = get_token_name (target_type);

          fprintf (stderr, "  %c    | %-18s | %-15s | %10" PRIu64 " | %10s | %s\n",
                   (char) target_type, type_name, pattern_buf, (u64) s->count, ks_str, example);

          found = true;
          break;
        }
      }

      if (found) break;
    }
  }

  fprintf (stderr, "  -----+--------------------+-----------------+------------+------------+---------------\n");
}

// inspect verbose sub-functions

static void pcfg_inspect_print_top_lengths (pcfg_model_t *m)
{
  int top_lens = 10;

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TOP %d PASSWORD LENGTHS ---\n", top_lens);
  fprintf (stderr, "\n");

  u32 l_counts[256] = { 0 };

  for (int i = 0; i < 256; i++)
  {
    l_counts[m->pw_len_table.states[i]]++;
  }

  double max_prob_len = pcfg_inspect_max_prob_counts (l_counts, 256, 256.0);

  fprintf (stderr, "    # |  Len |####################|    Prob\n");
  fprintf (stderr, "  ----+------+--------------------+--------\n");

  for (int iter = 0; iter < top_lens; iter++)
  {
    u32 best_idx;
    u32 max_v = pcfg_inspect_find_max_u32 (l_counts, 256, &best_idx);

    if (max_v == 0) break;

    double prob = (max_v / 256.0) * 100.0;
    char bar_buf[64];
    pcfg_inspect_bar (prob, max_prob_len, bar_buf, sizeof (bar_buf));

    fprintf (stderr, "  %3d | %4d %s %6.2f%%\n", iter + 1, (int) best_idx, bar_buf, prob);

    l_counts[best_idx] = 0;
  }

  fprintf (stderr, "  ----+------+--------------------+--------\n");
}

static void pcfg_inspect_print_start_types (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- STARTING TOKEN TYPES ---\n");
  fprintf (stderr, "\n");

  u32 start_counts[256] = { 0 };

  for (int i = 0; i < 256; i++)
  {
    start_counts[m->struct_start_row.states[i] & 0x7F]++;
  }

  double max_prob_type = pcfg_inspect_max_prob_counts (start_counts, 256, 256.0);

  fprintf (stderr, "    # | Type |####################|    Prob\n");
  fprintf (stderr, "  ----+------+--------------------+--------\n");

  int s_rank = 1;

  for (int iter = 0; iter < 256; iter++)
  {
    u32 best_idx;
    u32 max_v = pcfg_inspect_find_max_u32 (start_counts, 256, &best_idx);

    if (max_v == 0) break;

    double prob = (max_v / 256.0) * 100.0;
    char bar_buf[64];
    pcfg_inspect_bar (prob, max_prob_type, bar_buf, sizeof (bar_buf));

    fprintf (stderr, "  %3d |  %c   %s %6.2f%%\n", s_rank++, get_type_char (best_idx), bar_buf, prob);

    start_counts[best_idx] = 0;
  }

  fprintf (stderr, "  ----+------+--------------------+--------\n");
}

static void pcfg_inspect_print_1st_transitions (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- FIRST ORDER TRANSITIONS (T1 -> T2) ---\n");
  fprintf (stderr, "\n");

  double max_prob_trans = pcfg_inspect_max_prob_bins (m->struct_trans_table, 256, 0x7F, 1, 0);

  fprintf (stderr, "  Transition   |####################|    Prob\n");
  fprintf (stderr, "  -------------+--------------------+--------\n");

  for (int t1 = 0; t1 < 256; t1++)
  {
    u8 best_t2;
    u32 max_v = pcfg_inspect_find_best_bin (&m->struct_trans_table[t1], 0x7F, 1, &best_t2);

    if (max_v > 0)
    {
      double prob = (max_v / 256.0) * 100.0;
      char bar_buf[64];
      pcfg_inspect_bar (prob, max_prob_trans, bar_buf, sizeof (bar_buf));

      fprintf (stderr, "     %c -> %c    %s %6.2f%%\n", get_type_char (t1), get_type_char (best_t2), bar_buf, prob);
    }
  }

  fprintf (stderr, "  -------------+--------------------+--------\n");
}

static void pcfg_inspect_print_2nd_transitions (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- SECOND ORDER TRANSITIONS (T1 + T2 -> T3) ---\n");
  fprintf (stderr, "\n");

  double max_prob_2nd = pcfg_inspect_max_prob_bins (m->struct_trans_table, 65536, 0x7F, 1, 0);

  fprintf (stderr, "  Transition   |####################|    Prob\n");
  fprintf (stderr, "  -------------+--------------------+--------\n");

  int printed_2nd = 0;

  for (u32 s = 0; s < 65536; s++)
  {
    u8 best_t3;
    u32 max_v = pcfg_inspect_find_best_bin (&m->struct_trans_table[s], 0x7F, 1, &best_t3);

    if (max_v > 0)
    {
      u8 t1 = s >> 8;
      u8 t2 = s & 0xFF;

      double prob = (max_v / 256.0) * 100.0;
      char bar_buf[64];
      pcfg_inspect_bar (prob, max_prob_2nd, bar_buf, sizeof (bar_buf));

      if (t1 == 0)
      {
        if (max_v > 128)
        {
          fprintf (stderr, "  (^ + %c) -> %c %s %6.2f%%\n", get_type_char (t2), get_type_char (best_t3), bar_buf, prob);
        }
      }
      else
      {
        if (max_v > 180 || (max_v > 110 && printed_2nd < 30))
        {
          fprintf (stderr, "  (%c + %c) -> %c %s %6.2f%%\n", get_type_char (t1), get_type_char (t2), get_type_char (best_t3), bar_buf, prob);
          printed_2nd++;
        }
      }
    }
  }

  fprintf (stderr, "  -------------+--------------------+--------\n");
}

static void pcfg_inspect_print_script_cohesion (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- SCRIPT COHESION (Sandwich Pattern) ---\n");
  fprintf (stderr, "\n");

  u8 scripts[] =
  {
    PCFG_TK_LOWER, PCFG_TK_UPPER, PCFG_TK_CAPITALIZED, PCFG_TK_MIXED,
    PCFG_TK_CYRILLIC, PCFG_TK_ARABIC, PCFG_TK_GREEK, PCFG_TK_HEBREW,
    PCFG_TK_LATIN_EXT, PCFG_TK_ASIAN
  };

  int script_count = sizeof (scripts) / sizeof (scripts[0]);

  double max_prob_cohesion = 0.0;

  for (int i = 0; i < script_count; i++)
  {
    u16 state = (scripts[i] << 8) | (u8) PCFG_TK_DIGIT;
    u32 back = pcfg_inspect_count_matching_bins (&m->struct_trans_table[state], 0x7F, scripts[i]);

    double prob = (back / 256.0) * 100.0;

    if (prob > max_prob_cohesion) max_prob_cohesion = prob;
  }

  fprintf (stderr, "  Transition   |####################|    Prob\n");
  fprintf (stderr, "  -------------+--------------------+--------\n");

  for (int i = 0; i < script_count; i++)
  {
    u16 state = (scripts[i] << 8) | (u8) PCFG_TK_DIGIT;
    u32 back = pcfg_inspect_count_matching_bins (&m->struct_trans_table[state], 0x7F, scripts[i]);

    double prob = (back / 256.0) * 100.0;
    char bar_buf[64];
    pcfg_inspect_bar (prob, max_prob_cohesion, bar_buf, sizeof (bar_buf));

    fprintf (stderr, "  %c + D -> %c   %s %6.1f%%\n", scripts[i], scripts[i], bar_buf, prob);
  }

  fprintf (stderr, "  -------------+--------------------+--------\n");
}

static void pcfg_inspect_print_alpha_bigrams (pcfg_model_t *m)
{
  int top_alpha_start_bigrams = 10;

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TOP %d ALPHA STARTING BIGRAMS ---\n", top_alpha_start_bigrams);
  fprintf (stderr, "\n");

  u32 t_start_counts[65536] = { 0 };
  u32 total_sum = 0;

  for (int i = 0; i < 4096; i++)
  {
    t_start_counts[m->start_row_alpha.states[i]]++;
    total_sum++;
  }

  double max_prob_bigram = pcfg_inspect_max_prob_counts (t_start_counts, 65536, (double) total_sum);

  fprintf (stderr, "    # | Bigram |####################|    Prob\n");
  fprintf (stderr, "  ----+--------+--------------------+--------\n");

  for (int iter = 0; iter < top_alpha_start_bigrams; iter++)
  {
    u32 best_idx;
    u32 max_v = pcfg_inspect_find_max_u32 (t_start_counts, 65536, &best_idx);

    if (max_v == 0) break;

    unsigned char c1 = (unsigned char) (best_idx >> 8);
    unsigned char c2 = (unsigned char) (best_idx & 0xFF);

    char d1 = (c1 >= 32 && c1 <= 126) ? c1 : '.';
    char d2 = (c2 >= 32 && c2 <= 126) ? c2 : '.';

    double prob = (total_sum > 0) ? ((double) max_v / total_sum) * 100.0 : 0.0;
    char bar_buf[64];
    pcfg_inspect_bar (prob, max_prob_bigram, bar_buf, sizeof (bar_buf));

    fprintf (stderr, "  %3d |  '%c%c'  %s %6.2f%%\n", iter + 1, d1, d2, bar_buf, prob);

    t_start_counts[best_idx] = 0;
  }

  fprintf (stderr, "  ----+--------+--------------------+--------\n");
}

static void pcfg_inspect_print_trigrams (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- TOP TRIGRAM TRANSITIONS ---\n");
  fprintf (stderr, "\n");

  double max_prob_trigram = pcfg_inspect_max_prob_bins (m->markov_table_lower, 65536, 0xFF, 32, 128);

  fprintf (stderr, "  Transition   |####################|    Prob\n");
  fprintf (stderr, "  -------------+--------------------+--------\n");

  int printed_succ = 0;

  for (u32 s = 0; s < 65536; s++)
  {
    u8 best_next;
    u32 max_v = pcfg_inspect_find_best_bin (&m->markov_table_lower[s], 0xFF, 32, &best_next);

    if (max_v > 128)
    {
      double prob = (max_v / 256.0) * 100.0;
      char bar_buf[64];
      pcfg_inspect_bar (prob, max_prob_trigram, bar_buf, sizeof (bar_buf));

      fprintf (stderr, "  '%c%c' -> '%c'  %s %6.1f%%\n", (char) (s >> 8), (char) (s & 0xFF), (char) best_next, bar_buf, prob);

      if (++printed_succ > 25) break;
    }
  }

  fprintf (stderr, "  -------------+--------------------+--------\n");
}

static void pcfg_inspect_print_letter_trans (pcfg_model_t *m)
{
  fprintf (stderr, "\n");
  fprintf (stderr, "--- MARKOV TRANSITIONS BY LETTER (a-z) ---\n");
  fprintf (stderr, "\n");

  // first pass: find max prob for bar scaling
  double max_prob_letter = 0.0;

  for (char c = 'a'; c <= 'z'; c++)
  {
    u32 best_total_count = 0;

    for (int next_c = 0; next_c < 256; next_c++)
    {
      u16 state = ((u8) c << 8) | (u8) next_c;

      u32 max_v = pcfg_inspect_find_best_bin (&m->markov_table_lower[state], 0xFF, 1, NULL);

      if (max_v > best_total_count)
      {
        best_total_count = max_v;
      }
    }

    if (best_total_count > 0)
    {
      double prob = (best_total_count / 256.0) * 100.0;

      if (prob > max_prob_letter) max_prob_letter = prob;
    }
  }

  fprintf (stderr, "  Transition   |####################|    Prob\n");
  fprintf (stderr, "  -------------+--------------------+--------\n");

  for (char c = 'a'; c <= 'z'; c++)
  {
    u32 best_total_count = 0;
    u16 best_state = 0;
    u8 best_next = 0;

    for (int next_c = 0; next_c < 256; next_c++)
    {
      u16 state = ((u8) c << 8) | (u8) next_c;

      u8 row_best;
      u32 row_max = pcfg_inspect_find_best_bin (&m->markov_table_lower[state], 0xFF, 1, &row_best);

      if (row_max > best_total_count)
      {
        best_total_count = row_max;
        best_state = state;
        best_next = row_best;
      }
    }

    if (best_total_count > 0)
    {
      double prob = (best_total_count / 256.0) * 100.0;
      char bar_buf[64];
      pcfg_inspect_bar (prob, max_prob_letter, bar_buf, sizeof (bar_buf));

      fprintf (stderr, "  '%c%c' -> '%c'  %s %6.1f%%\n",
               (char) (best_state >> 8), (char) (best_state & 0xFF), (char) best_next, bar_buf, prob);
    }
  }

  fprintf (stderr, "  -------------+--------------------+--------\n");
}

static void pcfg_inspect_print_terminal_examples (pcfg_model_t *m, const char *types_to_check)
{
  u32 top_examples = 3;

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TOP %u TERMINAL EXAMPLES ---\n", top_examples);
  fprintf (stderr, "\n");

  for (const char *ptr = types_to_check; *ptr; ptr++)
  {
    int t = (unsigned char) *ptr;
    bool found_any = false;

    // first pass: find max coverage for bar scaling
    double max_coverage = 0.0;

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      u64 cnt = m->terminals[t][l].cnt;

      if (cnt > 0)
      {
        u64 theo = get_theoretical_keyspace (t, l);

        if (theo != UINT64_MAX && theo > 0)
        {
          double coverage = ((double) cnt / (double) theo) * 100.0;

          if (coverage > 100.0) coverage = 100.0;
          if (coverage > max_coverage) max_coverage = coverage;
        }
      }
    }

    if (max_coverage <= 0) max_coverage = 100.0;

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      u64 cnt = m->terminals[t][l].cnt;

      if (cnt > 0)
      {
        if (!found_any)
        {
          fprintf (stderr, "  [ Type '%c' - %s ]\n\n", (char) t, get_token_name (t));
          fprintf (stderr, "    Len |     Count | Coverage | Examples\n");
          fprintf (stderr, "  ------+-----------+----------+-----------\n");

          found_any = true;
        }

        u64 theo = get_theoretical_keyspace (t, l);

        double coverage = 0.0;

        bool has_coverage = false;

        if (theo != UINT64_MAX && theo > 0)
        {
          coverage = ((double) cnt / (double) theo) * 100.0;

          if (coverage > 100.0) coverage = 100.0;

          has_coverage = true;
        }

        // format coverage string
        char cov_str[16] = { 0 };

        if (!has_coverage)
        {
          snprintf (cov_str, sizeof (cov_str), "     N/A");
        }
        else if (coverage >= 99.995)
        {
          snprintf (cov_str, sizeof (cov_str), " 100.00%%");
        }
        else if (coverage < 0.01)
        {
          snprintf (cov_str, sizeof (cov_str), "  <0.01%%");
        }
        else
        {
          snprintf (cov_str, sizeof (cov_str), " %6.2f%%", coverage);
        }

        // build examples string
        char examples[256] = { 0 };

        int ex_pos = 0;

        for (u32 k = 0; k < top_examples && k < cnt; k++)
        {
          if (k > 0 && ex_pos < 250)
          {
            examples[ex_pos++] = ' ';
          }

          int written = snprintf (examples + ex_pos, sizeof (examples) - ex_pos, "\"%s\"", m->terminals[t][l].items[k].value);

          if (written > 0) ex_pos += written;

          if (ex_pos >= 250) break;
        }

        if (cnt > top_examples && ex_pos < 253)
        {
          snprintf (examples + ex_pos, sizeof (examples) - ex_pos, " ...");
        }

        fprintf (stderr, "  %5d | %9" PRIu64 " | %s | %s\n", l, cnt, cov_str, examples);
      }
    }

    if (found_any)
    {
      fprintf (stderr, "  ------+-----------+----------+-----------\n");
      fprintf (stderr, "\n");
    }
  }
}

static bool struct_match (const pcfg_structure_t *a, const pcfg_structure_t *b)
{
  if (a->token_cnt != b->token_cnt) return false;

  return (memcmp (a->types,   b->types,   a->token_cnt) == 0) &&
         (memcmp (a->lengths, b->lengths, a->token_cnt) == 0);
}

static u32 struct_hash (const pcfg_structure_t *s)
{
  return (u32) XXH64 (s, PCFG_TOKEN_MAX + PCFG_TOKEN_MAX + sizeof (u32), 0);
}

static int calc_quality_score (pcfg_model_t *m)
{
  int score = 0;

  u32 active_structs = 0;

  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    if (m->structures[i].keyspace > 0) active_structs++;
  }

  if      (active_structs >= 10000) score += 30;
  else if (active_structs >= 1000)  score += 20;
  else if (active_structs >= 100)   score += 10;

  u64 global_unique = 0;

  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      global_unique += m->terminals[t][l].cnt;
    }
  }

  if      (global_unique >= 1000000) score += 30;
  else if (global_unique >= 100000)  score += 20;
  else if (global_unique >= 10000)   score += 10;

  double entropy = pcfg_inspect_calc_entropy (m);

  if      (entropy >= 60) score += 40;
  else if (entropy >= 40) score += 30;
  else if (entropy >= 25) score += 20;
  else                    score += 10;

  return score;
}

static const char *quality_label (int score)
{
  if      (score >= 80) return "EXCELLENT";
  else if (score >= 60) return "GOOD";
  else if (score >= 40) return "MODERATE";
  else if (score >= 20) return "LIMITED";
  else                  return "MINIMAL";
}

static void pcfg_check_markov_health (pcfg_model_t *m)
{
  fprintf (stderr, "  --- Markov Multi-Language Tables Health ---\n");
  fprintf (stderr, "  %-15s | %-15s | %-11s | %-9s\n", "Table Name", "Active States", "Avg Density", "Status");
  fprintf (stderr, "  ----------------+-----------------+-------------+-----------\n");

  const char *names[] =
  {
    "Lower Alpha", "Upper Alpha", "Digits", "Latin Ext", "Cyrillic",
    "Arabic", "Asian", "Greek", "Hebrew", "Catch-all", "Structures"
  };

  pcfg_markov_row_t *tables[] =
  {
    m->markov_table_lower, m->markov_table_upper, m->markov_table_digit,
    m->markov_table_latin, m->markov_table_cyrillic, m->markov_table_arabic,
    m->markov_table_asian, m->markov_table_greek, m->markov_table_hebrew,
    m->markov_table_all, m->struct_trans_table
  };

  for (int i = 0; i < 11; i++)
  {
    u32 active = 0;

    double avg = 0.0;

    get_table_stats (tables[i], &active, &avg);

    const char *status;

    if      (avg >= 15.0) status = "EXCELLENT";
    else if (avg >= 10.0) status = "GOOD";
    else if (avg >= 5.0)  status = "OK";
    else if (avg >= 2.0)  status = "LIMITED";
    else if (avg >= 1.0)  status = "SPARSE";
    else                  status = "MINIMAL";

    if (active > 0)
    {
      fprintf (stderr, "  %-15s | %-15u | %5.2f       | %s\n", names[i], active, avg, status);
    }
    else
    {
      fprintf (stderr, "  %-15s | %-15s |  0.00       | %s\n", names[i], "EMPTY", status);
    }
  }

  fprintf (stderr, "  ----------------+-----------------+-------------+-----------\n");
}

static void pcfg_model_free_omen_data (pcfg_model_t *m)
{
  if (m->omen_data)
  {
    if (m->omen_data->struct_keyspace_current) hcfree (m->omen_data->struct_keyspace_current);

    hcfree (m->omen_data->struct_costs);
    hcfree (m->omen_data->max_count_per_slot);
    hcfree (m->omen_data->struct_min_term_cost);
    hcfree (m->omen_data);

    m->omen_data = NULL;
  }
}

static void pcfg_model_calculate_max_loops (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m, u32 burst_size, u32 cost_min, u32 cost_max, u64 user_limit)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (!m || burst_size == 0) return;

  // Fast path: if limit is set, max_loops is determined by limit, not keyspace
  if (user_limit > 0)
  {
    m->omen_max_loops = (user_limit / burst_size) + 1;

    if (m->omen_max_loops > PCFG_OMEN_MAX_LOOPS)
    {
      m->omen_max_loops = PCFG_OMEN_MAX_LOOPS;
    }

    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, "PCFG: OMEN Max Loops for cost %u-%u: %" PRIu64 " (based on --limit %" PRIu64 ")", cost_min, cost_max, m->omen_max_loops, user_limit);
    }

    return;
  }

  u64 max_ks_found = 0;

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculating OMEN max Loops (using pre-calculated keyspaces)...");
  }

  // Iterate over all structures and find the max keyspace
  // We can use the pre-calculated keyspace from the DP phase!

  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    u64 ks = m->structures[i].keyspace;

    if (ks > max_ks_found) max_ks_found = ks;
  }

  if (max_ks_found == 0)
  {
    m->omen_max_loops = 1;
  }
  else
  {
    // Ceiling division
    m->omen_max_loops = (max_ks_found + burst_size - 1) / burst_size;
  }

  if (m->omen_max_loops > PCFG_OMEN_MAX_LOOPS)
  {
    m->omen_max_loops = PCFG_OMEN_MAX_LOOPS;
  }

  if (user_options->quiet == false)
  {
    event_log_info (hashcat_ctx, "PCFG: OMEN Max Loops: %" PRIu64, m->omen_max_loops);
  }
}

static int cmp_top_pw_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const pcfg_top_pw_t *pa = (const pcfg_top_pw_t *) a;
  const pcfg_top_pw_t *pb = (const pcfg_top_pw_t *) b;

  return (pb->prob > pa->prob) - (pb->prob < pa->prob);
}

static void generate_top_pw_combinations (pcfg_model_t *m, pcfg_structure_t *s, u32 struct_idx, u32 slot, double current_prob, char *current_pw, u32 pw_len, u32 top_k, pcfg_top_pw_t *candidates, u32 *candidate_cnt, u32 max_candidates, double min_prob_threshold)
{
  // pruning: if the current probability is already below the threshold, skip
  if (current_prob < min_prob_threshold) return;

  // base case: all slots processed
  if (slot == s->token_cnt)
  {
    if (*candidate_cnt < max_candidates)
    {
      pcfg_top_pw_t *c = &candidates[*candidate_cnt];

      c->prob = current_prob;
      c->struct_idx = struct_idx;

      memcpy (c->password, current_pw, pw_len);

      c->password[pw_len] = '\0';

      (*candidate_cnt)++;
    }

    return;
  }

  // get the list of terminals for this slot
  u8 ty = s->types[slot];
  u8 ln = s->lengths[slot];

  pcfg_terminal_list_t *tlist = &m->terminals[ty][ln];

  if (tlist->cnt == 0 || tlist->items == NULL) return;

  // take the top K terminals (or fewer if there are not enough)
  u32 k_limit = (tlist->cnt < top_k) ? tlist->cnt : top_k;

  for (u32 k = 0; k < k_limit; k++)
  {
    pcfg_terminal_t *term = &tlist->items[k];

    // calculate new probability
    double new_prob = current_prob * (double) term->prob;

    // aggressive pruning
    if (new_prob < min_prob_threshold) continue;

    // verify that we do not exceed the buffer
    if (pw_len + term->len >= 255) continue;

    // add the terminal to the current password
    memcpy (current_pw + pw_len, term->value, term->len);

    // recursion to the next slot
    generate_top_pw_combinations (m, s, struct_idx, slot + 1, new_prob, current_pw, pw_len + term->len, top_k, candidates, candidate_cnt, max_candidates, min_prob_threshold);
  }
}

static void pcfg_print_top_passwords (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m, u32 top_n, bool detailed)
{
  if (!m || m->struct_cnt == 0) return;

  const u32 TOP_STRUCTURES = 200;
  const u32 TOP_K_TERMINALS = 5;
  const u32 MAX_CANDIDATES = 50000;

  pcfg_top_pw_t *candidates = (pcfg_top_pw_t *) hcmalloc (MAX_CANDIDATES * sizeof (pcfg_top_pw_t));

  u32 candidate_cnt = 0;
  double min_prob_threshold = 0.0;

  char pw_buffer[256];

  u32 structs_to_check = (m->struct_cnt < TOP_STRUCTURES) ? m->struct_cnt : TOP_STRUCTURES;

  for (u32 i = 0; i < structs_to_check; i++)
  {
    pcfg_structure_t *s = &m->structures[i];

    if (s->token_cnt == 0) continue;

    bool valid = true;

    for (u32 j = 0; j < s->token_cnt; j++)
    {
      u8 ty = s->types[j];
      u8 ln = s->lengths[j];

      if (m->terminals[ty][ln].cnt == 0)
      {
        valid = false;
        break;
      }
    }

    if (!valid) continue;

    generate_top_pw_combinations (m, s, i, 0, (double) s->prob, pw_buffer, 0, TOP_K_TERMINALS, candidates, &candidate_cnt, MAX_CANDIDATES, min_prob_threshold);

    if (candidate_cnt > MAX_CANDIDATES / 2)
    {
      hc_qsort_r (candidates, candidate_cnt, sizeof (pcfg_top_pw_t), cmp_top_pw_desc, NULL);

      u32 keep = (top_n * 2 < candidate_cnt) ? (top_n * 2) : candidate_cnt;

      candidate_cnt = keep;

      min_prob_threshold = candidates[keep - 1].prob * 0.9;
    }
  }

  hc_qsort_r (candidates, candidate_cnt, sizeof (pcfg_top_pw_t), cmp_top_pw_desc, NULL);

  // collect unique passwords
  char collected[50][256];
  double collected_prob[50];
  u32 collected_struct[50];
  u32 collected_cnt = 0;

  char last_pw[256] = { 0 };

  u32 idx = 0;

  while (collected_cnt < top_n && idx < candidate_cnt)
  {
    pcfg_top_pw_t *c = &candidates[idx];
    idx++;

    if (strcmp (c->password, last_pw) == 0) continue;

    strncpy (last_pw, c->password, sizeof (last_pw) - 1);
    strncpy (collected[collected_cnt], c->password, 255);

    collected_prob[collected_cnt] = c->prob;
    collected_struct[collected_cnt] = c->struct_idx;
    collected_cnt++;
  }

  if (detailed)
  {
    event_log_info (hashcat_ctx, "    # | Pattern        |       Prob | Password");
    event_log_info (hashcat_ctx, "  ----+----------------+------------+-----------------------");

    for (u32 i = 0; i < collected_cnt; i++)
    {
      char pattern_buf[PCFG_PATTERN_MAX];

      pcfg_get_pattern_str (&m->structures[collected_struct[i]], pattern_buf, sizeof (pattern_buf));

      double prob_pct = collected_prob[i] * 100.0;

      if (prob_pct >= 0.01)
      {
        event_log_info (hashcat_ctx, "  %3u | %-14s | %9.4f%% | %s", i + 1, pattern_buf, prob_pct, collected[i]);
      }
      else if (prob_pct >= 0.0001)
      {
        event_log_info (hashcat_ctx, "  %3u | %-14s | %9.6f%% | %s", i + 1, pattern_buf, prob_pct, collected[i]);
      }
      else
      {
        event_log_info (hashcat_ctx, "  %3u | %-14s | %9.2e%% | %s", i + 1, pattern_buf, prob_pct, collected[i]);
      }
    }

    event_log_info (hashcat_ctx, "  ----+----------------+------------+-----------------------");

    // coverage stats
    if (collected_cnt > 0)
    {
      double cumulative = 0.0;

      for (u32 i = 0; i < collected_cnt; i++)
      {
        cumulative += collected_prob[i];
      }

      event_log_info (hashcat_ctx, "  Top 1 covers : %.4f%%", collected_prob[0] * 100.0);
      event_log_info (hashcat_ctx, "  Top %u cover: %.4f%%", collected_cnt, cumulative * 100.0);
    }
  }
  else
  {
    // simple grid format: 5 passwords per row, vertical layout
    const int COLS = 5;
    const int COL_WIDTH = 14;

    u32 rows = (collected_cnt + COLS - 1) / COLS;

    for (u32 row = 0; row < rows; row++)
    {
      event_log_info (hashcat_ctx, "  ");

      for (int col = 0; col < COLS; col++)
      {
        u32 ci = col * rows + row;

        if (ci < collected_cnt)
        {
          event_log_info (hashcat_ctx, " %2u | %-*.*s", ci + 1, COL_WIDTH, COL_WIDTH, collected[ci]);
        }
      }

      event_log_info (hashcat_ctx, NULL);
    }
  }

  hcfree (candidates);
}

static int compare_structures_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const pcfg_structure_t *sa = (const pcfg_structure_t *) a;
  const pcfg_structure_t *sb = (const pcfg_structure_t *) b;

  return (sb->prob > sa->prob) - (sb->prob < sa->prob);
}

static int compare_terminals_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const pcfg_terminal_t *ta = (const pcfg_terminal_t *) a;
  const pcfg_terminal_t *tb = (const pcfg_terminal_t *) b;

  return (tb->count > ta->count) - (tb->count < ta->count);
}

static void pcfg_model_sort_all (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  if (!m || m->struct_cnt == 0) return;

  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Sorting model structures ...");
  }

  hc_qsort_r (m->structures, m->struct_cnt, sizeof (pcfg_structure_t), compare_structures_desc, NULL);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Sorting terminals ...");
  }

  // find total count for progress
  u64 total_terminals = 0;

  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      const u32 cnt = m->terminals[t][l].cnt;

      if (cnt > 1 && m->terminals[t][l].items != NULL)
      {
        total_terminals += cnt;
      }
    }
  }

  if (total_terminals == 0)
  {
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Sorting terminals ... done");
    }

    return;
  }

  // Progress tracking
  u64 sorted_count = 0;
  u64 next_progress = total_terminals / 100;

  if (next_progress == 0) next_progress = 1;

  for (int t = 0; t < 256; t++)
  {
    pcfg_terminal_list_t *row = m->terminals[t];

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      const u32 cnt = row[l].cnt;

      if (cnt <= 1 || row[l].items == NULL) continue;

      hc_qsort_r (row[l].items, cnt, sizeof (pcfg_terminal_t), compare_terminals_desc, NULL);

      sorted_count += cnt;

      if (sorted_count >= next_progress)
      {
        const u32 pct = (u32) ((sorted_count * 100) / total_terminals);

        if (user_options->quiet == false)
        {
          event_log_info_nn (hashcat_ctx, "PCFG: Sorting terminals: %u%%", pct);
        }

        next_progress = ((pct + 1) * total_terminals) / 100;
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Sorting terminals ... done");
  }

  // pre-compute reciprocals for fast division
  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      m->terminals[t][l].recip = compute_recip64 (m->terminals[t][l].cnt);
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Recalculate structures keyspace ...");
  }

  // recalculate keyspace for each structure to ensure Prob/OMEN mode works
  pcfg_model_keyspace_update_all (hashcat_ctx, m);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Recalculate structures keyspace ... done");
  }
}

void pcfg_model_keyspace_update_all (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Recalculate model keyspace ...");
  }

  // recalculate keyspace for each structure to ensure Prob/OMEN mode works
  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    pcfg_structure_t *s = &m->structures[i];

    s->keyspace = 1;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u8 ty = s->types[k] & 0x7F;
      u8 ln = s->lengths[k];

      u32 num_terminals = m->terminals[ty][ln].cnt;

      if (num_terminals > 0)
      {
        // check for overflow before multiplying
        if (s->keyspace > UINT64_MAX / num_terminals)
        {
          s->keyspace = UINT64_MAX;
        }
        else
        {
          s->keyspace *= num_terminals;
        }
      }
      else
      {
        // if a slot has no terminals, this structure is impossible to generate
        s->keyspace = 0;
        break;
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Recalculate model keyspace ... done");
  }
}

void pcfg_model_build_omen_metadata (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;

  m->omen_data = (pcfg_omen_extra_t *) hccalloc (1, sizeof (pcfg_omen_extra_t));
  m->omen_data->struct_costs = (u8 *) hccalloc (m->struct_cnt, 1);

  u8 *max_cost_per_slot = (u8 *) hccalloc (256 * PCFG_VALUE_MAX, sizeof (u8));

  const u32 struct_cnt = m->struct_cnt;

  // update every 10%
  const u32 progress_step_struct = (struct_cnt > 10) ? (struct_cnt / 10) : 1;

  // Calculate Structure Costs
  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculating structure costs (%u structures)...", struct_cnt);
  }

  const pcfg_structure_t *structures = m->structures;

  u8 *costs = m->omen_data->struct_costs;
  u32 next_progress = progress_step_struct;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    const float p = structures[i].prob;

    int cost = (p <= 0.0f) ? 31 : (int) (-log2f (p));

    costs[i] = (cost > 31) ? 31 : (u8) cost;

    if (i >= next_progress)
    {
      if (user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Structure costs: %u%%", (u32) ((u64) i * 100 / struct_cnt));
      }

      next_progress += progress_step_struct;
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated %u Structure Costs", struct_cnt);
  }

  // Calculate Terminal Ranks and Counts
  u64 total_terminals = 0;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      total_terminals += m->terminals[ty][ln].cnt;
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculating Terminal Ranks (%" PRIu64 " Terminals)...", total_terminals);
  }

  u64 processed_terminals = 0;

  const u64 progress_step_terms = (total_terminals > 10) ? (total_terminals / 10) : 1;

  u32 next_progress_terms = progress_step_terms;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const u32 num_terms = m->terminals[ty][ln].cnt;

      if (num_terms == 0) continue;

      pcfg_terminal_t * const items = m->terminals[ty][ln].items;

      // first pass: compute sum
      u64 actual_total_cnt = 0;
      u32 i = 0;

      const u32 unroll_limit = num_terms & ~3U;

      for (; i < unroll_limit; i += 4)
      {
        actual_total_cnt += items[i].count;
        actual_total_cnt += items[i + 1].count;
        actual_total_cnt += items[i + 2].count;
        actual_total_cnt += items[i + 3].count;
      }
      for (; i < num_terms; i++)
      {
        actual_total_cnt += items[i].count;
      }

      if (actual_total_cnt == 0)
      {
        processed_terminals += num_terms;
        continue;
      }

      const double inv_total = 1.0 / (double) actual_total_cnt;

      pcfg_omen_slot_map_t * const map = &m->omen_data->term_maps[ty][ln];

      int cur_lvl = 0;

      map->ranks[0] = 0;

      for (u32 j = 0; j < num_terms; j++)
      {
        const double p_term = (double) items[j].count * inv_total;

        int c_term;

        if (p_term >= 1.0)
        {
          c_term = 0;
        }
        else if (p_term <= 0.0)
        {
          c_term = 31;
        }
        else
        {
          c_term = (int) (-log2 (p_term));

          if (c_term > 31) c_term = 31;
        }

        if (cur_lvl < c_term)
        {
          do
          {
            map->ranks[++cur_lvl] = j;

          } while (cur_lvl < c_term);
        }
      }

      max_cost_per_slot[(ty * PCFG_VALUE_MAX) + ln] = (u8) cur_lvl;

      for (int j = cur_lvl + 1; j < 32; j++) map->ranks[j] = num_terms;

      for (int j = 0; j < 31; j++) map->counts[j] = map->ranks[j + 1] - map->ranks[j];

      map->counts[31] = num_terms - map->ranks[31];

      processed_terminals += num_terms;

      if (processed_terminals >= next_progress_terms)
      {
        if (user_options->quiet == false)
        {
          event_log_info_nn (hashcat_ctx, "PCFG: Terminal ranks: %u%%", (u32) (processed_terminals * 100 / total_terminals));
        }

        next_progress_terms += progress_step_terms;
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated %" PRIu64 " Terminal Ranks", total_terminals);

    event_log_info_nn (hashcat_ctx, "PCFG: Pre-computing division reciprocals ...");
  }

  // Pre-calculate division reciprocals
  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      pcfg_omen_slot_map_t *map = &m->omen_data->term_maps[ty][ln];

      for (int c = 0; c < 32; c++)
      {
        map->recip[c] = compute_recip64 (map->counts[c]);
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Pre-computed division reciprocals");
  }

  // Pre-calculate max count per slot
  m->omen_data->max_count_per_slot = (u32 *) hccalloc (256 * PCFG_VALUE_MAX, sizeof (u32));

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const pcfg_omen_slot_map_t *map = &m->omen_data->term_maps[ty][ln];

      u32 max_c = 0;

      for (int c = 0; c < 32; c++)
      {
        if (map->counts[c] > max_c) max_c = map->counts[c];
      }

      m->omen_data->max_count_per_slot[(ty * PCFG_VALUE_MAX) + ln] = max_c;
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Pre-calculating structure keyspaces (%u structures)...", struct_cnt);
  }

  // Pre-calculate max keyspace per structure

  const u64 keyspace_cap = user_options->pcfg_omen_keyspace_max;

  u32 next_progress_ks = progress_step_struct;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    pcfg_structure_t *s = &m->structures[i];

    const u32 token_cnt = s->token_cnt;

    if (token_cnt == 0)
    {
      s->keyspace = 0;
      continue;
    }

    u64 ks = 1;

    bool overflow = false;

    for (u32 k = 0; k < token_cnt; k++)
    {
      const u8 ty  = s->types[k] & 0x7F;
      const u8 ln  = s->lengths[k];
      const u32 mc = m->omen_data->max_count_per_slot[(ty * PCFG_VALUE_MAX) + ln];

      if (mc == 0)
      {
        ks = 0;
        break;
      }

      if (ks > keyspace_cap / mc)
      {
        overflow = true;
        break;
      }

      ks *= mc;

      if (ks >= keyspace_cap)
      {
        overflow = true;
        break;
      }
    }

    s->keyspace = overflow ? keyspace_cap : ks;

    if (i >= next_progress_ks)
    {
      if (user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Keyspace calc: %u%%", (u32) ((u64) i * 100 / struct_cnt));
      }

      next_progress_ks += progress_step_struct;
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated %u Structure Keyspaces", struct_cnt);

    event_log_info_nn (hashcat_ctx, "PCFG: Pre-calculating Min Terminal Costs (%u Structures)...", struct_cnt);
  }

  // Pre-calculate minimum terminal cost per structure
  // for each structure, calculate the sum of the minimum terminal costs
  // this is the minimum cost that the structure can have (in addition to the structure cost)
  // if target_cost < struct_cost + min_term_cost, the structure has no partitions.

  m->omen_data->struct_min_term_cost = (u8 *) hccalloc (struct_cnt, sizeof (u8));

  // first calculate the minimum cost for each slot (type, length)
  u8 *min_cost_per_slot = (u8 *) hccalloc (256 * PCFG_VALUE_MAX, sizeof (u8));

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const pcfg_omen_slot_map_t *map = &m->omen_data->term_maps[ty][ln];

      u8 min_c = 31;

      for (int c = 0; c < 32; c++)
      {
        if (map->counts[c] > 0)
        {
          min_c = (u8) c;
          break; // found
        }
      }

      min_cost_per_slot[(ty * PCFG_VALUE_MAX) + ln] = min_c;
    }
  }

  // now calculate for each structure
  next_progress_ks = progress_step_struct;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    const pcfg_structure_t *s = &m->structures[i];

    const u32 token_cnt = s->token_cnt;

    u32 min_term_cost = 0;

    for (u32 k = 0; k < token_cnt; k++)
    {
      const u8 ty = s->types[k] & 0x7F;
      const u8 ln = s->lengths[k];

      min_term_cost += min_cost_per_slot[(ty * PCFG_VALUE_MAX) + ln];
    }

    // cap at 255 for u8 (just for be sure)
    m->omen_data->struct_min_term_cost[i] = (min_term_cost > 255) ? 255 : (u8) min_term_cost;

    if (i >= next_progress_ks)
    {
      if (user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Min cost calc: %u%%", (u32) ((u64) i * 100 / struct_cnt));
      }

      next_progress_ks += progress_step_struct;
    }
  }

  hcfree (min_cost_per_slot);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated Min Terminal Costs for %u Structures)", struct_cnt);
  }

  // Calculate OMEN max cost

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculating Max Cost (%u Structures)...", struct_cnt);
  }

  u32 absolute_max = 0;

  next_progress = progress_step_struct;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    const pcfg_structure_t *s = &m->structures[i];

    u32 current_struct_max = m->omen_data->struct_costs[i];

    const u32 token_cnt = s->token_cnt;

    for (u32 k = 0; k < token_cnt; k++)
    {
      const u8 ty = s->types[k] & 0x7F;
      const u8 ln = s->lengths[k];

      current_struct_max += max_cost_per_slot[(ty * PCFG_VALUE_MAX) + ln];
    }

    if (current_struct_max > absolute_max) absolute_max = current_struct_max;

    if (i >= next_progress)
    {
      if (user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Max Cost calc: %u%%", (u32) ((u64) i * 100 / struct_cnt));
      }

      next_progress += progress_step_struct;
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated OMEN Max Cost on %u Structures)", struct_cnt);
  }

  m->omen_max_cost = (u16) absolute_max;

  if (m->omen_max_cost > PCFG_OMEN_COST_PRACTICAL_MAX)
  {
    if (user_options->quiet == false)
    {
      event_log_warning (hashcat_ctx, "PCFG: OMEN Cost Max capped from %u to %d (due to complexity limit).", m->omen_max_cost, PCFG_OMEN_COST_PRACTICAL_MAX);
    }

    m->omen_max_cost = PCFG_OMEN_COST_PRACTICAL_MAX;
  }

  if (user_options->quiet == false)
  {
    event_log_info (hashcat_ctx, "PCFG: OMEN Max Cost: %u", m->omen_max_cost);
  }

  u32 cost_min = user_options->pcfg_omen_cost_min;
  u32 cost_max = m->omen_max_cost;

  // check if user choose a new one
  if (user_options->pcfg_omen_cost_max != PCFG_OMEN_COST_MAX && user_options->pcfg_omen_cost_max < cost_max)
  {
    cost_max = user_options->pcfg_omen_cost_max;
  }

  // but set the Cap for be sure
  if (cost_max > PCFG_OMEN_COST_PRACTICAL_MAX)
  {
    cost_max = PCFG_OMEN_COST_PRACTICAL_MAX;
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculating Total Keyspace per OMEN Cost ...");
  }

  // Pre-calculate total keyspace per cost

  const u32 cost_cap = PCFG_OMEN_COST_PRACTICAL_MAX;
  m->omen_data->cost_keyspace = (u64 *) hccalloc (cost_cap + 1, sizeof (u64));

  // alloc keyspace array for structs at the current cost (for ETA)
  m->omen_data->struct_keyspace_current = (u64 *) hccalloc (struct_cnt, sizeof (u64));
  m->omen_data->current_cost_cached = UINT32_MAX;

  u32 progress_step_lvl = (struct_cnt > 1000) ? (struct_cnt / 1000) : 10;
  u32 next_progress_lvl = progress_step_lvl;

  // DP buffer, allocated only once (max cost = 31 * 4 = 124)
  #define DP_MAX_COST 128

  u64 *dp_buf_a = (u64 *) hccalloc (DP_MAX_COST, sizeof (u64));
  u64 *dp_buf_b = (u64 *) hccalloc (DP_MAX_COST, sizeof (u64));

  // DP buffer for partitions counter
  u64 *dp_part_a = (u64 *) hccalloc (DP_MAX_COST, sizeof (u64));
  u64 *dp_part_b = (u64 *) hccalloc (DP_MAX_COST, sizeof (u64));

  // cap for max keyspace/partitions
  const u64 keyspace_max  = user_options->pcfg_omen_keyspace_max;
  const u64 partition_max = PCFG_OMEN_PARTITIONS_MAX;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    const pcfg_structure_t *s = &m->structures[i];

    const u32 token_cnt = s->token_cnt;

    if (token_cnt == 0) continue;

    const u8 s_cost = m->omen_data->struct_costs[i];
    const u8 min_terms = m->omen_data->struct_min_term_cost[i];

    // calculate cost ranges
    u32 lvl_start = s_cost + min_terms;

    if (lvl_start < cost_min) lvl_start = cost_min;
    if (lvl_start > cost_max) continue;

    // set the limits
    const u32 max_tokens_limit = (token_cnt < 4) ? token_cnt : 4;
    const u32 max_rem_limit = 31 * max_tokens_limit;

    u32 lvl_end = s_cost + max_rem_limit;

    if (lvl_end > s_cost + token_cnt * 31) lvl_end = s_cost + token_cnt * 31;
    if (lvl_end > cost_max) lvl_end = cost_max;

    // set the complexity limit, as the generator do
    u32 complexity_limit = s_cost + (31 * ((s->token_cnt < 4) ? s->token_cnt : 4));

    if (lvl_end > complexity_limit) lvl_end = complexity_limit;

    if (lvl_start > lvl_end) continue;

    const int max_rem = (int) (lvl_end - s_cost);

    // pre-cache pointers to term_maps
    const pcfg_omen_slot_map_t *slot_maps[PCFG_TOKEN_MAX];

    for (u32 slot = 0; slot < token_cnt; slot++)
    {
      const u8 ty = s->types[slot] & 0x7F;
      const u8 ln = s->lengths[slot];

      slot_maps[slot] = &m->omen_data->term_maps[ty][ln];
    }

    // DP: dp[c] = sum of product combinations with total cost c
    // DP partitions: dp_part[c] = number of partitions with total cost c
    u64 *dp_curr = dp_buf_a;
    u64 *dp_next = dp_buf_b;

    u64 *dp_part_curr = dp_part_a;
    u64 *dp_part_next = dp_part_b;

    memset (dp_curr, 0, (max_rem + 1) * sizeof (u64));
    memset (dp_part_curr, 0, (max_rem + 1) * sizeof (u64));

    dp_curr[0] = 1;
    dp_part_curr[0] = 1;

    int curr_max = 0;

    // iter over each slot and update DP
    for (u32 slot = 0; slot < token_cnt; slot++)
    {
      const pcfg_omen_slot_map_t *map = slot_maps[slot];

      memset (dp_next, 0, (max_rem + 1) * sizeof (u64));
      memset (dp_part_next, 0, (max_rem + 1) * sizeof (u64));

      int next_max = -1;

      for (int prev = 0; prev <= curr_max; prev++)
      {
        const u64 ways  = dp_curr[prev];
        const u64 parts = dp_part_curr[prev];

        if (ways == 0) continue;

        const int cmax = (max_rem - prev < 31) ? (max_rem - prev) : 31;

        for (int c = 0; c <= cmax; c++)
        {
          const u64 cnt = map->counts[c];

          if (cnt == 0) continue;

          const int nc = prev + c;

          dp_next[nc] += ways * cnt;
          dp_part_next[nc] += parts;

          if (nc > next_max) next_max = nc;
        }
      }

      // swap pointers (O(1) instead of memcpy)
      u64 *tmp = dp_curr;

      dp_curr = dp_next;
      dp_next = tmp;

      tmp = dp_part_curr;
      dp_part_curr = dp_part_next;
      dp_part_next = tmp;

      curr_max = next_max;

      // early exit, no valid combinations
      if (curr_max < 0) break;
    }

    // accumulate results for all costs in a single step

    // accumulator for the real total keyspace of the structure
    u64 struct_total_keyspace_real = 0;

    if (curr_max >= 0)
    {
      for (u32 lvl = lvl_start; lvl <= lvl_end; lvl++)
      {
        const int rem = (int) lvl - (int) s_cost;

        if (rem <= curr_max && dp_curr[rem] > 0)
        {
          u64 struct_keyspace   = dp_curr[rem];
          u64 struct_partitions = dp_part_curr[rem];

          if (struct_partitions > partition_max)
          {
            // the first 1024 are much less dense than average
            // using a logarithmic scale or reduction factor to avoid overestimating the ETA.

            // additional 50% reduction to compensate for density
            struct_keyspace = (u64) ((double) struct_keyspace * ((double) partition_max / struct_partitions) * 0.5);
          }

          // set the cap on keyspace
          if (struct_keyspace > keyspace_max)
          {
            struct_keyspace = keyspace_max;
          }

          m->omen_data->cost_keyspace[lvl] += struct_keyspace;

          // add to the structure total
          struct_total_keyspace_real += struct_keyspace;
        }
      }
    }

    // Update the structure keyspace with the real OMEN value
    // This overwrites the rough estimate calculated in phase 2.2
    m->structures[i].keyspace = struct_total_keyspace_real;

    // progress update
    if (i >= next_progress_lvl)
    {
      u32 pct = (u32) ((u64)i * 100 / struct_cnt);

      if (user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Cost totals: %u%%", pct);
      }

      next_progress_lvl += progress_step_lvl;
    }
  }

  hcfree (dp_buf_a);
  hcfree (dp_buf_b);

  hcfree (dp_part_a);
  hcfree (dp_part_b);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Calculated Total Keyspace per OMEN Cost");
  }

  // calculate max loop (only for Interleaved mode)

  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
  {
    pcfg_model_calculate_max_loops (hashcat_ctx, m, user_options->pcfg_burst_size, cost_min, cost_max, pcfg_ctx->pcfg_limit);
  }

  hcfree (max_cost_per_slot);
}

pcfg_model_t *pcfg_model_load_filtered (hashcat_ctx_t *hashcat_ctx, const char *path)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;
  const char     *filter_types = user_options->pcfg_token_types;

  // convert from % to 0.0-1.0
  float prob_min_val = (float) (user_options->pcfg_struct_prob_min) / 100.0f;
  float prob_max_val = (float) (user_options->pcfg_struct_prob_max) / 100.0f;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return NULL;

  u32 magic, version;

  if (hc_fread (&magic, 4, 1, &fp)   != 1) { hc_fclose (&fp); return NULL; }
  if (hc_fread (&version, 4, 1, &fp) != 1) { hc_fclose (&fp); return NULL; }

  if (magic != PCFG_MAGIC)
  {
    event_log_error (hashcat_ctx, "PCFG: Invalid Model.");
    hc_fclose (&fp);
    return NULL;
  }

  if (version < PCFG_VERSION)
  {
    event_log_error (hashcat_ctx, "PCFG: Model version too old. Please retrain.");
    hc_fclose (&fp);
    return NULL;
  }

  pcfg_model_t *m = (pcfg_model_t *) hccalloc (1, sizeof (pcfg_model_t));

  m->name = hcstrdup (path);

  hc_fread (&m->pw_total, 8, 1, &fp);

  hc_fread (m->encoding_from, PCFG_ENCODING_MAX, 1, &fp);

  // markov structures
  m->struct_trans_table    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));

  // markov terminals
  m->markov_table_lower    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_upper    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_digit    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_latin    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_cyrillic = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_arabic   = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_asian    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_greek    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_hebrew   = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_all      = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->char_freq             = (float *)             hcmalloc (65536 * sizeof (float));

  // markov pw len
  hc_fread (&m->pw_len_table, sizeof (pcfg_markov_start_row_t), 1, &fp);

  // structures
  hc_fread (&m->struct_start_row, sizeof (pcfg_markov_start_row_t), 1, &fp);

  hc_fread (m->struct_trans_table, sizeof (pcfg_markov_row_t), 65536, &fp);

  // terminals
  hc_fread (&m->start_row_alpha, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fread (&m->start_row_alpha_unicode, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fread (&m->start_row_digit, sizeof (pcfg_markov_start_row_digit_t), 1, &fp);

  hc_fread (m->markov_table_lower, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_upper, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_digit, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_latin, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_cyrillic, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_arabic, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_asian, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_greek, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_hebrew, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_all, sizeof (pcfg_markov_row_t), 65536, &fp);

  hc_fread (m->char_freq, sizeof (float), 65536, &fp);

  u32 file_struct_cnt;

  hc_fread (&file_struct_cnt, 4, 1, &fp);

  m->struct_cnt_file = file_struct_cnt;

  if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF)
  {
    hc_fseek (&fp, sizeof (pcfg_structure_t) * file_struct_cnt, SEEK_CUR);

    file_struct_cnt = 0;

    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, "PCFG: Skip loading structures (AHF mode) ...");
    }
  }
  else
  {
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Loading filtered structures (0/%u) into model ...", file_struct_cnt);
    }

    pcfg_structure_t *all_structs = (pcfg_structure_t *) hcmalloc (file_struct_cnt * sizeof (pcfg_structure_t));

    hc_fread (all_structs, sizeof (pcfg_structure_t), file_struct_cnt, &fp);

    u32 cap = 100000;

    if (cap > file_struct_cnt) cap = file_struct_cnt;

    m->structures = (pcfg_structure_t *) hccalloc (cap, sizeof (pcfg_structure_t));
    m->struct_cnt = 0;

    for (u32 i = 0; i < file_struct_cnt; i++)
    {
      const pcfg_structure_t *temp_s_p = &all_structs[i];

      // check filters
      bool keep = true;

      if (user_options->pcfg_pw_complex)
      {
        if (!pw_complex_check (temp_s_p)) keep = false;
      }

      if (keep && user_options->pcfg_token_count_min_chgd == true)
      {
        if (temp_s_p->token_cnt < user_options->pcfg_token_count_min) keep = false;
      }

      if (keep && user_options->pcfg_token_count_max_chgd == true)
      {
        if (temp_s_p->token_cnt > user_options->pcfg_token_count_max) keep = false;
      }

      if (keep)
      {
        if (prob_min_val > 0.0 && temp_s_p->prob < prob_min_val) keep = false;
        if (prob_max_val < 1.0 && temp_s_p->prob > prob_max_val) keep = false;
      }

      if (keep && filter_types != NULL)
      {
        keep = false;

        for (u32 k = 0; k < temp_s_p->token_cnt; k++)
        {
          for (const char *f = filter_types; *f; f++)
          {
            if (temp_s_p->types[k] == *f)
            {
              keep = true;
              break;
            }
          }

          if (keep) break;
        }
      }

      if (keep && (user_options->pcfg_token_len_min_chgd == true || user_options->pcfg_token_len_max_chgd == true))
      {
        u32 t_len_min = user_options->pcfg_token_len_min;
        u32 t_len_max = user_options->pcfg_token_len_max;

        for (u32 k = 0; k < temp_s_p->token_cnt; k++)
        {
          u8 len = temp_s_p->lengths[k];

          if (user_options->pcfg_token_len_min_chgd && len < t_len_min)
          {
            keep = false;

            break;
          }

          if (user_options->pcfg_token_len_max_chgd && len > t_len_max)
          {
            keep = false;

            break;
          }
        }
      }

      // Password length limits - default from hashconfig, override if user changed
      u32 pw_len_min = hashconfig->pw_min;
      u32 pw_len_max = hashconfig->pw_max;

      if (pw_len_min == 0) pw_len_min = 1;

      if (user_options->pcfg_pw_len_min_chgd || user_options->pcfg_pw_len_max_chgd)
      {
        if (user_options->pcfg_pw_len_min_chgd)
        {
          if (user_options->pcfg_pw_len_min > pw_len_min) pw_len_min = user_options->pcfg_pw_len_min;
        }

        if (user_options->pcfg_pw_len_max_chgd)
        {
          if (user_options->pcfg_pw_len_max < pw_len_max) pw_len_max = user_options->pcfg_pw_len_max;
        }
      }

      if (pw_len_max >= PCFG_PW_MAX) pw_len_max = PCFG_PW_MAX - 1;

      if (pw_len_min > pw_len_max) pw_len_min = pw_len_max;

      u32 total_len = temp_s_p->total_len;

      if (total_len < pw_len_min) keep = false;
      if (total_len > pw_len_max) keep = false;

      // time to update the model
      if (keep)
      {
        // resize if is full
        if (m->struct_cnt == cap)
        {
          u32 new_cap = cap * 2;

          if (new_cap > file_struct_cnt) new_cap = file_struct_cnt;

          m->structures = (pcfg_structure_t *) hcrealloc (m->structures, cap * sizeof (pcfg_structure_t), new_cap * sizeof (pcfg_structure_t));

          cap = new_cap;
        }

        memcpy (&m->structures[m->struct_cnt], temp_s_p, sizeof (pcfg_structure_t));

        m->struct_cnt++;

        if (user_options->quiet == false)
        {
          if ((m->struct_cnt & 0x7FFF) == 0)
          {
            event_log_info_nn (hashcat_ctx, "PCFG: Loading filtered structures (%u/%u) into model ...", m->struct_cnt, file_struct_cnt);
          }
        }
      }
    }

    hcfree (all_structs);

    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, "PCFG: Loaded filtered structures (%u of %u) into model ...", m->struct_cnt, file_struct_cnt);
    }

    // final shrink
    if (m->struct_cnt < cap)
    {
      if (m->struct_cnt == 0)
      {
        hcfree (m->structures);

        m->structures = NULL;
      }
      else
      {
        m->structures = (pcfg_structure_t *) hcrealloc (m->structures, cap * sizeof (pcfg_structure_t), m->struct_cnt * sizeof (pcfg_structure_t));
      }
    }

    if (m->struct_cnt == 0)
    {
      event_log_error (hashcat_ctx, "PCFG: No structure loaded in the model ...");

      pcfg_model_destroy (m);

      return NULL;
    }
  }

  // load terminals

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Loading filtered terminals into model ...");
  }

  u32 min_count  = user_options->pcfg_terminal_count_min;
  u64 next_print = 0x7FFF;
  u64 term_cnt   = 0;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      u32 cnt;

      if (hc_fread (&cnt, 4, 1, &fp) != 1) break;

      m->terminals[ty][ln].cnt = cnt;

      if (cnt > 0)
      {
        const u32 record_size = sizeof (u16) + sizeof (u32) + sizeof (float) + ln; // 10 + ln

        char *bulk = (char *) hcmalloc (cnt * record_size);

        hc_fread (bulk, 1, cnt * record_size, &fp);

        m->terminals[ty][ln].items = (pcfg_terminal_t *) hccalloc (cnt, sizeof (pcfg_terminal_t));

        char *string_block = (char *) hccalloc (cnt, ln + 1);

        u32 kept = 0;

        char *curr_str_ptr = string_block;
        char *p = bulk;

        for (u32 k = 0; k < cnt; k++)
        {
          const u16   t_len  = *(u16 *)  p; p += sizeof (u16);
          const u32   t_cnt  = *(u32 *)  p; p += sizeof (u32);
          const float t_prob = *(float *) p; p += sizeof (float);

          // filter
          if (t_cnt < min_count)
          {
            p += t_len;
            continue;
          }

          pcfg_terminal_t *item = &m->terminals[ty][ln].items[kept];

          item->len   = t_len;
          item->count = t_cnt;
          item->prob  = t_prob;

          item->value = curr_str_ptr;

          memcpy (item->value, p, t_len);
          p += t_len;

          item->value[t_len] = 0;
          curr_str_ptr += (t_len + 1);

          kept++;
        }

        hcfree (bulk);

        // shrink
        if (kept < cnt)
        {
          if (kept == 0)
          {
            hcfree (m->terminals[ty][ln].items);
            hcfree (string_block);

            m->terminals[ty][ln].items = NULL;
            m->terminals[ty][ln].string_pool = NULL;
          }
          else
          {
            m->terminals[ty][ln].items = hcrealloc (m->terminals[ty][ln].items, cnt * sizeof (pcfg_terminal_t), kept * sizeof (pcfg_terminal_t));

            m->terminals[ty][ln].string_pool = string_block;
          }

          // update cnt
          m->terminals[ty][ln].cnt = kept;
        }
        else
        {
          m->terminals[ty][ln].string_pool = string_block;
        }

        // update total
        term_cnt += m->terminals[ty][ln].cnt;

        if (term_cnt >= next_print)
        {
          if (user_options->quiet == false)
          {
            event_log_info_nn (hashcat_ctx, "PCFG: Loading %" PRIu64 " filtered terminals into model ...", term_cnt);
          }

          next_print += 0x7FFF;
        }
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info (hashcat_ctx, "PCFG: Loaded %" PRIu64 " filtered terminals into model ...", term_cnt);
  }

  // omen

  hc_fread (m->term_totals, sizeof (u64), 256 * PCFG_VALUE_MAX, &fp);

  if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM_AHF)
  {
    pcfg_model_filter_huge_structures (hashcat_ctx, m, user_options->pcfg_keyspace_max);

    // sort model if requested by order mode
    if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_PROB || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      pcfg_model_sort_all (hashcat_ctx, m);
    }
    else
    {
      pcfg_model_keyspace_update_all (hashcat_ctx, m);
    }

    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      u32 magic_omen = 0;

      if (hc_fread (&magic_omen, 4, 1, &fp) && magic == 0x4E454D4F)
      {
        if (user_options->quiet == false)
        {
          event_log_info_nn (hashcat_ctx, "PCFG: OMEN metadata found in model file. Loading now...");
        }

        m->omen_data = (pcfg_omen_extra_t *) hccalloc (1, sizeof (pcfg_omen_extra_t));
        m->omen_data->struct_costs = hccalloc (m->struct_cnt, 1);

        hc_fread (m->omen_data->struct_costs, 1, m->struct_cnt, &fp);
        hc_fread (m->omen_data->term_maps, sizeof (pcfg_omen_slot_map_t), 256 * PCFG_VALUE_MAX, &fp);
      }
      else
      {
        if (user_options->quiet == false)
        {
          event_log_info_nn (hashcat_ctx, "PCFG: OMEN metadata not found in model file. Calculating now, please be patient...");
        }

        pcfg_model_build_omen_metadata (hashcat_ctx, m);
      }
    }
  }

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Model loaded, %u structures and %" PRIu64 " terminals.", m->struct_cnt, term_cnt);

    event_log_info (hashcat_ctx, NULL);
  }

  hc_fclose (&fp);

  return m;
}

pcfg_model_t *pcfg_model_load_fast (hashcat_ctx_t *hashcat_ctx, const char *path)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false)
  {
    event_log_error (hashcat_ctx, "PCFG: Cannot open model file (%s).", path);

    return NULL;
  }

  u32 magic, version;

  hc_fread (&magic,   4, 1, &fp);
  hc_fread (&version, 4, 1, &fp);

  if (magic != PCFG_MAGIC)
  {
    event_log_error (hashcat_ctx, "PCFG: Invalid Model.");

    hc_fclose (&fp);

    return NULL;
  }

  if (version < PCFG_VERSION)
  {
    event_log_error (hashcat_ctx, "PCFG: Model version too old. Please retrain.");

    hc_fclose (&fp);

    return NULL;
  }

  pcfg_model_t *m = (pcfg_model_t *) hccalloc (1, sizeof (pcfg_model_t));

  hc_fread (&m->pw_total, 8, 1, &fp);

  hc_fread (m->encoding_from, PCFG_ENCODING_MAX, 1, &fp);

  // markov structures
  m->struct_trans_table    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));

  // markov terminals
  m->markov_table_lower    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_upper    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_digit    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_latin    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_cyrillic = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_arabic   = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_asian    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_greek    = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_hebrew   = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->markov_table_all      = (pcfg_markov_row_t *) hcmalloc (65536 * sizeof (pcfg_markov_row_t));
  m->char_freq             = (float *)             hcmalloc (65536 * sizeof (float));

  // markov pw len
  hc_fread (&m->pw_len_table, sizeof (pcfg_markov_start_row_t), 1, &fp);

  // structures
  hc_fread (&m->struct_start_row, sizeof (pcfg_markov_start_row_t), 1, &fp);

  hc_fread (m->struct_trans_table, sizeof (pcfg_markov_row_t), 65536, &fp);

  // terminals
  hc_fread (&m->start_row_alpha, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fread (&m->start_row_alpha_unicode, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fread (&m->start_row_digit, sizeof (pcfg_markov_start_row_digit_t), 1, &fp);

  hc_fread (m->markov_table_lower, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_upper, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_digit, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_latin, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_cyrillic, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_arabic, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_asian, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_greek, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_hebrew, sizeof (pcfg_markov_row_t), 65536, &fp);
  hc_fread (m->markov_table_all, sizeof (pcfg_markov_row_t), 65536, &fp);

  hc_fread (m->char_freq, sizeof (float), 65536, &fp);

  hc_fread (&m->struct_cnt, 4, 1, &fp);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Fast loading %u structures into model ...", m->struct_cnt);
  }

  m->structures = (pcfg_structure_t *) hccalloc (m->struct_cnt, sizeof (pcfg_structure_t));

  hc_fread (m->structures, sizeof (pcfg_structure_t), m->struct_cnt, &fp);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Fast loading terminals into model ...");
  }

  u64 term_cnt = 0;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      u32 cnt;

      hc_fread (&cnt, 4, 1, &fp);

      m->terminals[ty][ln].cnt = cnt;

      if (cnt > 0)
      {
        const u32 record_size = sizeof (u16) + sizeof (u32) + sizeof (float) + ln; // 10 + ln

        char *bulk = (char *) hcmalloc (cnt * record_size);

        hc_fread (bulk, 1, cnt * record_size, &fp);

        m->terminals[ty][ln].items = (pcfg_terminal_t *) hccalloc (cnt, sizeof (pcfg_terminal_t));

        char *string_block = (char *) hccalloc (cnt, ln + 1);

        m->terminals[ty][ln].string_pool = string_block;

        char *p = bulk;

        for (u32 k = 0; k < cnt; k++)
        {
          pcfg_terminal_t *item = &m->terminals[ty][ln].items[k];

          item->len   = *(u16 *)  p; p += sizeof (u16);
          item->count = *(u32 *)  p; p += sizeof (u32);
          item->prob  = *(float *) p; p += sizeof (float);

          item->value = string_block + (k * (ln + 1));

          memcpy (item->value, p, item->len);
          p += item->len;

          item->value[item->len] = 0;
        }

        hcfree (bulk);

        term_cnt += cnt;
      }
    }
  }

  // omen

  hc_fread (m->term_totals, sizeof (u64), 256 * PCFG_VALUE_MAX, &fp);

  hc_fclose (&fp);

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Model loaded, %u structures and %" PRIu64 " terminals.", m->struct_cnt, term_cnt);
  }

  return m;
}

int pcfg_model_merge (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  char **model_files = user_options->pcfg_models;
  int    num_files   = user_options->pcfg_models_cnt;
  char  *output_file = user_options->pcfg_model_save_file;

  if (num_files < 1)
  {
    event_log_error (hashcat_ctx, "PCFG: No models specified for merge.");

    return -1;
  }

  if (output_file == NULL)
  {
    event_log_error (hashcat_ctx, "PCFG: Output file (--pcfg-model-save) required for merge.");

    return -1;
  }

  event_log_info_nn (hashcat_ctx, "PCFG: Starting Merge of %d models into '%s'", num_files, output_file);

  u64 total_pws_estimate = 0;
  u64 total_pws_len_estimate = 0;

  for (int i = 0; i < num_files; i++)
  {
    HCFILE fp;

    hc_fopen (&fp, model_files[i], "rb");

    u32 magic, version;

    hc_fread (&magic, 4, 1, &fp);
    hc_fread (&version, 4, 1, &fp);

    if (magic != PCFG_MAGIC)
    {
      event_log_error (hashcat_ctx, "PCFG: Invalid Model (%s)", model_files[i]);
      hc_fclose (&fp);
      return -1;
    }

    if (version < PCFG_VERSION)
    {
      event_log_error (hashcat_ctx, "PCFG: Model version too old for (%s)", model_files[i]);
      hc_fclose (&fp);
      return -1;
    }

    u64 pw_total;
    u32 struct_cnt;
    hc_fread (&pw_total, 8, 1, &fp);

    // calculate skipping offset
    off_t skip_off =
      sizeof (pcfg_markov_start_row_t) * 2 +       // pw_len_table + struct_start_row
      65536 * sizeof (pcfg_markov_row_t) +         // struct_trans_table
      sizeof (pcfg_markov_start_row_alpha_t) * 2 + // start_row_alpha + start_row_alpha_unicode
      sizeof (pcfg_markov_start_row_digit_t) +     // start_row_digit
      (65536 * sizeof (pcfg_markov_row_t)) * 10 +  // markov_tables (10)
      65536 * sizeof (float);                      // char_freq

    hc_fseek (&fp, skip_off, SEEK_CUR);

    hc_fread (&struct_cnt, 4, 1, &fp);

    total_pws_estimate += pw_total;

    hc_fclose (&fp);
  }

  pcfg_trainer_t *t = (pcfg_trainer_t *) hccalloc (1, sizeof (pcfg_trainer_t));

  if (!t) return -1;

  t->admit_counters = NULL;
  t->admit_mask = 0;

  u64 available_ram = 0;
  u64 available_swap = 0;
  u64 available_memory = 0;

  bool fallback = false;

  if (get_free_memory (&available_ram) == false)
  {
    // fallback
    available_ram = 4ULL * 1024 * 1024 * 1024;
    fallback = true;
  }

  if (get_free_swap_memory (&available_swap) == true)
  {
    // 1/4 of swap
    available_swap /= 4;
  }

  available_memory = available_ram + available_swap;

  u64 reserve = (fallback) ? 512ULL * 1024 * 1024 : 0; // reserve only if get_free_memory() fail
  u64 safe_ram_budget = 0;

  // agressive setting on RAM
  // server headless: 0.98
  // desktop: 0.90
  double multiplier = (is_desktop_environment()) ? 0.90 : 0.98;

  if (available_memory > reserve)
  {
    safe_ram_budget = (u64) ((available_memory - reserve) * multiplier);
  }
  else
  {
    safe_ram_budget = available_memory / 2;
  }

  t->memory_limit = safe_ram_budget;

  // calculate estimate RAM needed

  // average length of a password/terminal string estimated
  double avg_len = (double) total_pws_len_estimate / (double) total_pws_estimate;
  const u32 avg_string_len = (u32) (avg_len + 1.0);

  // base cost = size of the hash table node + the string buffer + memory allocator overhead
  u64 bytes_per_unique_entry = sizeof (term_node_t) + avg_string_len + 16;

  double estimated_uniqueness = 1.0;

  if      (t->file_lines > 1000000000ULL) estimated_uniqueness = 0.40; // 40% unique (conservative for HIBP)
  else if (t->file_lines > 100000000ULL)  estimated_uniqueness = 0.60;
  else if (t->file_lines > 1000000ULL)    estimated_uniqueness = 0.85;
  else                                    estimated_uniqueness = 1.00;

  u64 fixed_trainer_overhead = 1536ULL * 1024 * 1024; // ~1.5 GB

  u64 estimated_ram_needed = (u64) (t->file_lines * estimated_uniqueness * bytes_per_unique_entry) + fixed_trainer_overhead;

  bool disable_filter = user_options->pcfg_train_af_disable;
  bool ram_pressure   = (estimated_ram_needed > safe_ram_budget);
  bool big_file       = (total_pws_estimate > 5000000ULL);

  bool use_filter = ram_pressure || big_file;

  if (disable_filter == true)
  {
    use_filter = false;

    if (ram_pressure)
    {
      event_log_warning (hashcat_ctx, "PCFG: Admission Filter is disabled by user.");
      //event_log_warning (hashcat_ctx, "Estimated RAM for %" PRIu64 " lines (uniqueness ~%d%%): %" PRIu64 " MB.",
      //                   t->file_lines, (int)(estimated_uniqueness * 100), estimated_ram_needed / (1024 * 1024));
      //event_log_warning (hashcat_ctx, "Available budget: %" PRIu64 " MB.", safe_ram_budget / (1024 * 1024));
      event_log_warning (hashcat_ctx, "If you run out of memory, do not use --pcfg-train-af-disable.");
    }
  }

  u64 admit_bytes = 0;

  if (use_filter)
  {
    u64 filter_target = total_pws_estimate * 4;

    u64 min_filter =   64ULL * 1024 * 1024; // min 64MB
    u64 max_filter = 2048ULL * 1024 * 1024; // max 2GB

    // set Cap to 7%
    u64 ram_cap = safe_ram_budget / 7;

    if (max_filter > ram_cap) max_filter = ram_cap;

    if (filter_target < min_filter) filter_target = min_filter;
    if (filter_target > max_filter) filter_target = max_filter;

    // must be power of 2
    admit_bytes = next_power_of_two_64 (filter_target);

    t->admit_counters = (u8 *) hccalloc ((size_t) admit_bytes, 1);

    if (!t->admit_counters)
    {
      pcfg_trainer_destroy (t);

      return -1;
    }

    t->admit_mask = (admit_bytes * 2) - 1;
  }

  // handle ht_size

  u64 ht_ram_budget = safe_ram_budget / 5;
  u64 ptr_size      = sizeof (void *);

  // target Bucket Count

  u64 target_buckets = 0;

  if (use_filter)
  {
    target_buckets = total_pws_estimate / 5;
  }
  else
  {
    target_buckets = total_pws_estimate * 2;
  }

  // min 1 Mil of buckets
  if (target_buckets < 1000000) target_buckets = 1000000;

  while ((target_buckets * ptr_size) > ht_ram_budget)
  {
    target_buckets /= 2;
  }

  u64 table_cost_per_bucket = 16;

  u64 max_table_ram = safe_ram_budget / 4;
  u64 max_buckets   = max_table_ram / table_cost_per_bucket;

  if (target_buckets > max_buckets)
  {
    target_buckets = max_buckets;
  }

  t->ht_size = next_power_of_two_64 (target_buckets);

  // pool size
  if (safe_ram_budget > 8ULL * 1024 * 1024 * 1024)      t->pool_block_size = 16 * 1024 * 1024; // 16MB (High end)
  else if (safe_ram_budget > 2ULL * 1024 * 1024 * 1024) t->pool_block_size = 4 * 1024 * 1024;  // 4MB (Mid range)
  else                                                  t->pool_block_size = 1 * 1024 * 1024;  // 1MB (Low end / 8GB tot)

  event_log_info (hashcat_ctx, "PCFG: pws_est %" PRIu64 ", ht_size %" PRIu64 ", pool_size: %" PRIu64 "", total_pws_estimate, t->ht_size, (u64) t->pool_block_size);

  t->struct_ht      = (ht_node_t **)   hccalloc (t->ht_size, sizeof (ht_node_t *));
  t->global_term_ht = (term_node_t **) hccalloc (t->ht_size, sizeof (term_node_t *));

  if (!t->struct_ht || !t->global_term_ht)
  {
    pcfg_trainer_destroy (t);

    return -1;
  }

  // init Pool head
  t->pool_head = (mem_pool_t *) hccalloc (1, sizeof (mem_pool_t));

  if (t->pool_head == NULL)
  {
    pcfg_trainer_destroy (t);

    return -1;
  }

  t->pool_head->size   = t->pool_block_size;
  t->pool_head->ptr    = (char *) hccalloc (t->pool_block_size, 1);
  t->pool_head->offset = 0;
  t->pool_head->next   = NULL;

  if (!t->pool_head->ptr)
  {
    pcfg_trainer_destroy (t);

    return -1;
  }

  // init markov
  t->struct_start_counts        = (u64 *) hccalloc (256, sizeof (u64));
  t->struct_trans_counts        = (u64 *) hccalloc (65536 * 256, sizeof (u64));
  t->markov_start_alpha         = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_start_alpha_unicode = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_start_digit         = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_table               = (u64 *) hccalloc (10ULL * 65536 * 256, sizeof (u64));
  t->char_freq                  = (u64 *) hccalloc (65536, sizeof (u64));

  if (!t->struct_start_counts || !t->struct_trans_counts || !t->markov_start_alpha
   || !t->markov_start_alpha_unicode || !t->markov_start_digit || !t->markov_table || !t->char_freq)
  {
    pcfg_trainer_destroy (t);

    return -1;
  }

  // track initial used memory
  u64 ht_mem = (u64) t->ht_size * sizeof (void *) * 2;

  // calculate total memory for all Markov tables
  u64 markov_mem = (256ULL * sizeof (u64))                    // struct_start_counts
                 + (65536ULL * 256ULL * sizeof (u64))         // struct_trans_counts
                 + (65536ULL * sizeof (u64))                  // markov_start_alpha
                 + (65536ULL * sizeof (u64))                  // markov_start_alpha_unicode
                 + (65536ULL * sizeof (u64))                  // markov_start_digit
                 + (10ULL * 65536ULL * 256ULL * sizeof (u64)) // markov_table
                 + (65536ULL * sizeof (u64));                 // char_freq

  t->memory_used = ht_mem + admit_bytes + t->pool_block_size + markov_mem;

  // starting merge logic

  // import loop
  for (int i = 0; i < num_files; i++)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Loading model %d: %s", i+1, model_files[i]);

    if (!pcfg_trainer_import_from_file (hashcat_ctx, t, model_files[i]))
    {
      event_log_error (hashcat_ctx, "PCFG: Failed to import model from file %s. Aborting merge.", model_files[i]);

      pcfg_trainer_destroy (t);

      return -1;
    }
  }

  // export to file
  if (!pcfg_trainer_export_to_file (hashcat_ctx, t, output_file))
  {
    event_log_error (hashcat_ctx, "PCFG: Export to %s failed.", output_file);

    pcfg_trainer_destroy (t);

    return -1;
  }

  // cleanup
  pcfg_trainer_destroy (t);

  event_log_info_nn (hashcat_ctx, "PCFG: Merge models to %s completed successfully.", output_file);

  return 0;
}

void pcfg_model_free_terminal_data (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  if (m == NULL) return;

  // hide compiler warning about unused hashcat_ctx
  (void) hashcat_ctx;
  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      pcfg_terminal_list_t *list = &m->terminals[ty][ln];

      if (list->string_pool != NULL)
      {
        hcfree (list->string_pool);
        list->string_pool = NULL;
      }

      if (list->items != NULL)
      {
        hcfree (list->items);
        list->items = NULL;
      }

      list->cap = 0;
      // NOTE: keep list->cnt and list->recip for ETA calculations
    }
  }
}

void pcfg_model_destroy (pcfg_model_t *m)
{
  if (!m) return;

  if (m->name) hcfree (m->name);

  hcfree (m->structures);

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      hcfree (m->terminals[ty][ln].items);

      if (m->terminals[ty][ln].string_pool) hcfree (m->terminals[ty][ln].string_pool);
    }
  }

  if (m->struct_trans_table) hcfree (m->struct_trans_table);
  if (m->markov_table_lower) hcfree (m->markov_table_lower);
  if (m->markov_table_upper) hcfree (m->markov_table_upper);
  if (m->markov_table_digit) hcfree (m->markov_table_digit);
  if (m->markov_table_latin) hcfree (m->markov_table_latin);
  if (m->markov_table_cyrillic) hcfree (m->markov_table_cyrillic);
  if (m->markov_table_arabic) hcfree (m->markov_table_arabic);
  if (m->markov_table_asian) hcfree (m->markov_table_asian);
  if (m->markov_table_greek) hcfree (m->markov_table_greek);
  if (m->markov_table_hebrew) hcfree (m->markov_table_hebrew);
  if (m->markov_table_all) hcfree (m->markov_table_all);
  if (m->char_freq) hcfree (m->char_freq);

  pcfg_model_free_omen_data (m);

  hcfree (m);
}

u64 pcfg_model_count_elements (pcfg_model_t *m)
{
  // start with structures
  u64 total = m->struct_cnt;

  // and add terminals
  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      total += m->terminals[t][l].cnt;
    }
  }

  return total;
}

void pcfg_model_info (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  const char *filter_types = user_options->pcfg_token_types;
  const bool verbose = !user_options->quiet;
  const char *types_to_check = filter_types ? filter_types : PCFG_TOKEN_TYPES;

  #if defined (_WIN) || defined (_WIN32)
  UINT old_cp = GetConsoleOutputCP ();
  SetConsoleOutputCP (CP_UTF8);
  #endif

  pcfg_inspect_print_header (m);
  pcfg_inspect_print_terminal_dist (m);

  fprintf (stderr, "\n--- TOP 25 WEAKEST PASSWORDS ---\n\n");
  pcfg_print_top_passwords (hashcat_ctx, m, 25, verbose);

  pcfg_inspect_print_top_structs (m, 30, filter_types);
  pcfg_inspect_print_length_dist (m);

  fprintf (stderr, "\n--- MARKOV ENGINE HEALTH ---\n\n");
  pcfg_check_markov_health (m);

  pcfg_inspect_print_struct_by_type (m, types_to_check, filter_types);

  if (verbose)
  {
    pcfg_inspect_print_top_lengths (m);
    pcfg_inspect_print_start_types (m);
    pcfg_inspect_print_1st_transitions (m);
    pcfg_inspect_print_2nd_transitions (m);
    pcfg_inspect_print_script_cohesion (m);
    pcfg_inspect_print_alpha_bigrams (m);
    pcfg_inspect_print_trigrams (m);
    pcfg_inspect_print_letter_trans (m);
    pcfg_inspect_print_terminal_examples (m, types_to_check);
  }
  else
  {
    fprintf (stderr, "\n");
  }

  #if defined (_WIN) || defined (_WIN32)
  SetConsoleOutputCP (old_cp);
  #endif
}

void pcfg_model_diff (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *a, pcfg_model_t *b)
{
  (void) hashcat_ctx;

  // --- HEADER ---

  fprintf (stderr, "\n");
  fprintf (stderr, "=== PCFG MODEL DIFF ===\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Model A   : %s\n", a->name ? a->name : "N/A");
  fprintf (stderr, "  Model B   : %s\n", b->name ? b->name : "N/A");

  // compute stats

  u64 terms_a = 0, terms_b = 0;

  for (int t = 0; t < 256; t++)
  {
    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      terms_a += a->terminals[t][l].cnt;
      terms_b += b->terminals[t][l].cnt;
    }
  }

  double ent_a = pcfg_inspect_calc_entropy (a);
  double ent_b = pcfg_inspect_calc_entropy (b);

  int qa = calc_quality_score (a);
  int qb = calc_quality_score (b);

  // format values

  char pw_a[64], pw_b[64], st_a[64], st_b[64], tm_a[64], tm_b[64];

  format_human_count (a->pw_total,    pw_a, sizeof (pw_a));
  format_human_count (b->pw_total,    pw_b, sizeof (pw_b));
  format_human_count (a->struct_cnt,  st_a, sizeof (st_a));
  format_human_count (b->struct_cnt,  st_b, sizeof (st_b));
  format_human_count (terms_a,        tm_a, sizeof (tm_a));
  format_human_count (terms_b,        tm_b, sizeof (tm_b));

  char qa_buf[32], qb_buf[32], ent_a_buf[32], ent_b_buf[32];

  snprintf (qa_buf,    sizeof (qa_buf),    "%d/100 (%s)", qa, quality_label (qa));
  snprintf (qb_buf,    sizeof (qb_buf),    "%d/100 (%s)", qb, quality_label (qb));
  snprintf (ent_a_buf, sizeof (ent_a_buf), "%.2f bits", ent_a);
  snprintf (ent_b_buf, sizeof (ent_b_buf), "%.2f bits", ent_b);

  // compute deltas

  char dpw[32], dst[32], dtm[32], dent[32], dqa[32];

  double pct_pw = (a->pw_total > 0) ? ((double) b->pw_total - (double) a->pw_total) / (double) a->pw_total * 100.0 : 0.0;
  double pct_st = (a->struct_cnt > 0) ? ((double) b->struct_cnt - (double) a->struct_cnt) / (double) a->struct_cnt * 100.0 : 0.0;
  double pct_tm = (terms_a > 0) ? ((double) terms_b - (double) terms_a) / (double) terms_a * 100.0 : 0.0;

  snprintf (dpw,  sizeof (dpw),  "%+.1f%%", pct_pw);
  snprintf (dst,  sizeof (dst),  "%+.1f%%", pct_st);
  snprintf (dtm,  sizeof (dtm),  "%+.1f%%", pct_tm);
  snprintf (dent, sizeof (dent), "%+.2f bits", ent_b - ent_a);
  snprintf (dqa,  sizeof (dqa),  "%+d", qb - qa);

  fprintf (stderr, "\n");
  fprintf (stderr, "  Metric     |              Model A |              Model B |         Delta\n");
  fprintf (stderr, "  -----------+----------------------+----------------------+---------------\n");
  const char *enc_a = a->encoding_from[0] ? a->encoding_from : "RAW";
  const char *enc_b = b->encoding_from[0] ? b->encoding_from : "RAW";
  const char *denc  = (strcmp (enc_a, enc_b) == 0) ? "same" : "DIFFERENT";

  fprintf (stderr, "  Passwords  | %20s | %20s | %13s\n", pw_a, pw_b, dpw);
  fprintf (stderr, "  Encoding   | %20s | %20s | %13s\n", enc_a, enc_b, denc);
  fprintf (stderr, "  Structs    | %20s | %20s | %13s\n", st_a, st_b, dst);
  fprintf (stderr, "  Terminals  | %20s | %20s | %13s\n", tm_a, tm_b, dtm);
  fprintf (stderr, "  Entropy    | %20s | %20s | %13s\n", ent_a_buf, ent_b_buf, dent);
  fprintf (stderr, "  Quality    | %20s | %20s | %13s\n", qa_buf, qb_buf, dqa);
  fprintf (stderr, "  -----------+----------------------+----------------------+---------------\n");

  // --- TERMINAL DISTRIBUTION DIFF ---

  typedef struct
  {
    int type;
    u64 unique_a;
    u64 unique_b;
    i64 delta;

  } term_diff_t;

  term_diff_t tdiff[256];

  int tdiff_cnt = 0;

  for (int t = 0; t < 256; t++)
  {
    u64 ua = 0, ub = 0;

    for (int l = 0; l < PCFG_VALUE_MAX; l++)
    {
      ua += a->terminals[t][l].cnt;
      ub += b->terminals[t][l].cnt;
    }

    if (ua == 0 && ub == 0) continue;

    tdiff[tdiff_cnt].type     = t;
    tdiff[tdiff_cnt].unique_a = ua;
    tdiff[tdiff_cnt].unique_b = ub;
    tdiff[tdiff_cnt].delta    = (i64) ub - (i64) ua;
    tdiff_cnt++;
  }

  // sort by absolute delta descending

  for (int i = 0; i < tdiff_cnt - 1; i++)
  {
    for (int j = i + 1; j < tdiff_cnt; j++)
    {
      i64 abs_i = tdiff[i].delta < 0 ? -tdiff[i].delta : tdiff[i].delta;
      i64 abs_j = tdiff[j].delta < 0 ? -tdiff[j].delta : tdiff[j].delta;

      if (abs_j > abs_i)
      {
        term_diff_t tmp = tdiff[i];
        tdiff[i] = tdiff[j];
        tdiff[j] = tmp;
      }
    }
  }

  fprintf (stderr, "\n");
  fprintf (stderr, "--- TERMINAL DISTRIBUTION DIFF ---\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Type | Name               |    Model A |    Model B |      Delta |  Change\n");
  fprintf (stderr, "  -----+--------------------+------------+------------+------------+--------\n");

  for (int i = 0; i < tdiff_cnt; i++)
  {
    term_diff_t *d = &tdiff[i];

    const char *name = get_token_name (d->type);

    char type_char = (d->type >= 32 && d->type <= 126) ? (char) d->type : '?';

    double pct = (d->unique_a > 0) ? (double) d->delta / (double) d->unique_a * 100.0 : (d->unique_b > 0 ? 100.0 : 0.0);

    if (d->delta != 0)
    {
      fprintf (stderr, "  %c    | %-18s | %10" PRIu64 " | %10" PRIu64 " | %+10" PRId64 " | %+6.1f%%\n",
               type_char, name, d->unique_a, d->unique_b, d->delta, pct);
    }
    else
    {
      fprintf (stderr, "  %c    | %-18s | %10" PRIu64 " | %10" PRIu64 " |          0 |   0.0%%\n",
               type_char, name, d->unique_a, d->unique_b);
    }
  }

  fprintf (stderr, "  -----+--------------------+------------+------------+------------+--------\n");

  // --- STRUCTURE DIFF ---
  // stream approach: keep only top-N results, no large arrays

  #define ONLY_TOP_N   20

  typedef struct
  {
    u32    idx_a;
    u32    idx_b;
    float  prob_a;
    float  prob_b;
    float  abs_delta;
    float  delta;
    u64    count_a;
    u64    count_b;

  } struct_diff_t;

  typedef struct
  {
    u32  idx;
    u64  count;
    bool from_b;

  } only_entry_t;

  // build hash table for model B (open addressing, power-of-2 size)

  u32 ht_bits = 1;

  while ((1u << ht_bits) < b->struct_cnt * 2) ht_bits++;

  const u32 ht_size = 1u << ht_bits;
  const u32 ht_mask = ht_size - 1;

  u32 *ht_idx  = (u32 *) hcmalloc (ht_size * sizeof (u32));
  u32 *ht_hash = (u32 *) hcmalloc (ht_size * sizeof (u32));

  memset (ht_idx, 0xFF, ht_size * sizeof (u32));  // 0xFFFFFFFF = empty

  for (u32 i = 0; i < b->struct_cnt; i++)
  {
    u32 h = struct_hash (&b->structures[i]);
    u32 slot = h & ht_mask;

    while (ht_idx[slot] != 0xFFFFFFFF) slot = (slot + 1) & ht_mask;

    ht_idx[slot]  = i;
    ht_hash[slot] = h;
  }

  // collect ALL diffs and top-10 only-A

  u32 diffs_cap = 1024;
  u32 diffs_cnt = 0;

  struct_diff_t *all_diffs = (struct_diff_t *) hcmalloc (diffs_cap * sizeof (struct_diff_t));

  only_entry_t  top_only_a[ONLY_TOP_N];
  u32 top_only_a_cnt = 0;
  u64 min_only_a_count = 0;

  bool *b_matched = (bool *) hccalloc (b->struct_cnt, sizeof (bool));

  u32 match_cnt  = 0;
  u32 only_a_cnt = 0;

  for (u32 i = 0; i < a->struct_cnt; i++)
  {
    pcfg_structure_t *sa = &a->structures[i];
    u32 ha = struct_hash (sa);
    u32 slot = ha & ht_mask;

    bool found = false;

    while (ht_idx[slot] != 0xFFFFFFFF)
    {
      if (ht_hash[slot] == ha)
      {
        u32 j = ht_idx[slot];

        if (struct_match (sa, &b->structures[j]))
        {
          float delta = b->structures[j].prob - sa->prob;

          match_cnt++;
          b_matched[j] = true;

          // collect only if there is an actual difference
          if (delta != 0.0f || sa->count != b->structures[j].count)
          {
            if (diffs_cnt == diffs_cap)
            {
              diffs_cap *= 2;

              all_diffs = (struct_diff_t *) hcrealloc (all_diffs, (diffs_cap / 2) * sizeof (struct_diff_t), diffs_cap * sizeof (struct_diff_t));
            }

            float abs_d = delta < 0 ? -delta : delta;

            all_diffs[diffs_cnt].idx_a     = i;
            all_diffs[diffs_cnt].idx_b     = j;
            all_diffs[diffs_cnt].prob_a    = sa->prob;
            all_diffs[diffs_cnt].prob_b    = b->structures[j].prob;
            all_diffs[diffs_cnt].delta     = delta;
            all_diffs[diffs_cnt].abs_delta = abs_d;
            all_diffs[diffs_cnt].count_a   = sa->count;
            all_diffs[diffs_cnt].count_b   = b->structures[j].count;
            diffs_cnt++;
          }

          found = true;
          break;
        }
      }

      slot = (slot + 1) & ht_mask;
    }

    if (!found)
    {
      only_a_cnt++;

      if (top_only_a_cnt < ONLY_TOP_N || sa->count > min_only_a_count)
      {
        only_entry_t oa;

        oa.idx   = i;
        oa.count = sa->count;
        oa.from_b = false;

        if (top_only_a_cnt < ONLY_TOP_N)
        {
          top_only_a[top_only_a_cnt++] = oa;

          if (top_only_a_cnt == ONLY_TOP_N)
          {
            min_only_a_count = top_only_a[0].count;

            for (u32 k = 1; k < ONLY_TOP_N; k++)
            {
              if (top_only_a[k].count < min_only_a_count) min_only_a_count = top_only_a[k].count;
            }
          }
        }
        else
        {
          for (u32 k = 0; k < ONLY_TOP_N; k++)
          {
            if (top_only_a[k].count == min_only_a_count)
            {
              top_only_a[k] = oa;
              break;
            }
          }

          min_only_a_count = top_only_a[0].count;

          for (u32 k = 1; k < ONLY_TOP_N; k++)
          {
            if (top_only_a[k].count < min_only_a_count) min_only_a_count = top_only_a[k].count;
          }
        }
      }
    }
  }

  hcfree (ht_idx);
  hcfree (ht_hash);

  // print structure changes (only if there are differences)

  if (diffs_cnt > 0)
  {
    // partial sort: find top 20 by abs_delta descending
    u32 sort_cnt = (diffs_cnt > 20) ? 20 : diffs_cnt;

    for (u32 i = 0; i < sort_cnt; i++)
    {
      u32 max_idx = i;

      for (u32 j = i + 1; j < diffs_cnt; j++)
      {
        if (all_diffs[j].abs_delta > all_diffs[max_idx].abs_delta) max_idx = j;
      }

      if (max_idx != i)
      {
        struct_diff_t tmp = all_diffs[i];
        all_diffs[i] = all_diffs[max_idx];
        all_diffs[max_idx] = tmp;
      }
    }

    fprintf (stderr, "\n");
    u32 show_cnt = (diffs_cnt > 20) ? 20 : diffs_cnt;

    fprintf (stderr, "--- STRUCTURE CHANGES (top %u of %u) ---\n", show_cnt, diffs_cnt);
    fprintf (stderr, "\n");
    fprintf (stderr, "    # | Pattern              |   Prob A |   Prob B | Prob Delta |     Count A |     Count B | Count Delta\n");
    fprintf (stderr, "  ----+----------------------+----------+----------+------------+-------------+-------------+------------\n");

    for (u32 i = 0; i < show_cnt; i++)
    {
      struct_diff_t *d = &all_diffs[i];

      char pattern_buf[PCFG_PATTERN_MAX];

      pcfg_get_pattern_str (&a->structures[d->idx_a], pattern_buf, sizeof (pattern_buf));

      double count_delta = (d->count_a > 0) ? ((double) d->count_b - (double) d->count_a) / (double) d->count_a * 100.0 : 0.0;

      fprintf (stderr, "  %3u | %-20s | %7.3f%% | %7.3f%% | %+9.3f%% | %11" PRIu64 " | %11" PRIu64 " | %+10.1f%%\n",
               i + 1, pattern_buf,
               d->prob_a * 100.0, d->prob_b * 100.0, d->delta * 100.0,
               d->count_a, d->count_b, count_delta);
    }
  }

  hcfree (all_diffs);

  // sort top-10 only-A by count descending

  for (u32 i = 0; i < top_only_a_cnt; i++)
  {
    for (u32 j = i + 1; j < top_only_a_cnt; j++)
    {
      if (top_only_a[j].count > top_only_a[i].count)
      {
        only_entry_t tmp = top_only_a[i];
        top_only_a[i] = top_only_a[j];
        top_only_a[j] = tmp;
      }
    }
  }

  if (top_only_a_cnt > 0)
  {
    fprintf (stderr, "\n");
    u32 show_only_a = (top_only_a_cnt > 20) ? 20 : top_only_a_cnt;

    fprintf (stderr, "--- STRUCTURES ONLY IN MODEL A (top %u of %u) ---\n", show_only_a, only_a_cnt);
    fprintf (stderr, "\n");
    fprintf (stderr, "    # | Pattern              |    Prob |      Count\n");
    fprintf (stderr, "  ----+----------------------+---------+-----------\n");

    for (u32 i = 0; i < show_only_a; i++)
    {
      pcfg_structure_t *s = &a->structures[top_only_a[i].idx];

      char pattern_buf[PCFG_PATTERN_MAX];

      pcfg_get_pattern_str (s, pattern_buf, sizeof (pattern_buf));

      fprintf (stderr, "  %3u | %-20s | %6.3f%% | %9" PRIu64 "\n",
               i + 1, pattern_buf, s->prob * 100.0, s->count);
    }
  }

  // structures only in B (top 20 by count) — streaming

  only_entry_t top_only_b[ONLY_TOP_N];

  u32 top_only_b_cnt = 0;
  u32 only_b_cnt     = 0;
  u64 min_only_b_count = 0;

  for (u32 j = 0; j < b->struct_cnt; j++)
  {
    if (b_matched[j]) continue;

    only_b_cnt++;

    u64 cnt = b->structures[j].count;

    if (top_only_b_cnt < ONLY_TOP_N || cnt > min_only_b_count)
    {
      only_entry_t ob;

      ob.idx   = j;
      ob.count = cnt;
      ob.from_b = true;

      if (top_only_b_cnt < ONLY_TOP_N)
      {
        top_only_b[top_only_b_cnt++] = ob;

        if (top_only_b_cnt == ONLY_TOP_N)
        {
          min_only_b_count = top_only_b[0].count;

          for (u32 k = 1; k < ONLY_TOP_N; k++)
          {
            if (top_only_b[k].count < min_only_b_count) min_only_b_count = top_only_b[k].count;
          }
        }
      }
      else
      {
        for (u32 k = 0; k < ONLY_TOP_N; k++)
        {
          if (top_only_b[k].count == min_only_b_count)
          {
            top_only_b[k] = ob;
            break;
          }
        }

        min_only_b_count = top_only_b[0].count;

        for (u32 k = 1; k < ONLY_TOP_N; k++)
        {
          if (top_only_b[k].count < min_only_b_count) min_only_b_count = top_only_b[k].count;
        }
      }
    }
  }

  hcfree (b_matched);

  // sort top-20 only-B by count descending

  for (u32 i = 0; i < top_only_b_cnt; i++)
  {
    for (u32 j = i + 1; j < top_only_b_cnt; j++)
    {
      if (top_only_b[j].count > top_only_b[i].count)
      {
        only_entry_t tmp = top_only_b[i];
        top_only_b[i] = top_only_b[j];
        top_only_b[j] = tmp;
      }
    }
  }

  if (top_only_b_cnt > 0)
  {
    fprintf (stderr, "\n");
    u32 show_only_b = (top_only_b_cnt > 20) ? 20 : top_only_b_cnt;

    fprintf (stderr, "--- STRUCTURES ONLY IN MODEL B (top %u of %u) ---\n", show_only_b, only_b_cnt);
    fprintf (stderr, "\n");
    fprintf (stderr, "    # | Pattern              |    Prob |      Count\n");
    fprintf (stderr, "  ----+----------------------+---------+-----------\n");

    for (u32 i = 0; i < show_only_b; i++)
    {
      pcfg_structure_t *s = &b->structures[top_only_b[i].idx];

      char pattern_buf[PCFG_PATTERN_MAX];

      pcfg_get_pattern_str (s, pattern_buf, sizeof (pattern_buf));

      fprintf (stderr, "  %3u | %-20s | %6.3f%% | %9" PRIu64 "\n",
               i + 1, pattern_buf, s->prob * 100.0, s->count);
    }
  }

  // summary

  fprintf (stderr, "\n");
  fprintf (stderr, "--- SUMMARY ---\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "  Matched structures  : %u\n", match_cnt);
  fprintf (stderr, "  Structure changes   : %u\n", diffs_cnt);
  fprintf (stderr, "  Only in Model A     : %u\n", only_a_cnt);
  fprintf (stderr, "  Only in Model B     : %u\n", only_b_cnt);
  fprintf (stderr, "\n");

  #undef ONLY_TOP_N
}
