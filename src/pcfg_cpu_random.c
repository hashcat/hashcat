/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "xxhash.h"
#include "pcfg_common.h"
#include "pcfg_cpu_random.h"
#include "pcfg_trainer.h"
#include "pcfg.h"

// local RNG (xorshift64)

static inline u32 fast_rand_local (u64 *state)
{
  u64 x = *state;

  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;

  *state = x;

  return (u32) x;
}

// synthetic character generation

static inline char get_synthetic_char (u8 type, u64 *state)
{
  u64 r = fast_rand_local (state);

  switch (type)
  {
    case PCFG_TK_DIGIT:
    {
      static const char *s = PCFG_CHARS_DIGIT;
      return s[r % 10];
    }

    case PCFG_TK_LOWER:
    {
      static const char *s = PCFG_CHARS_LOWER;
      return s[r % 26];
    }

    case PCFG_TK_UPPER:
    {
      static const char *s = PCFG_CHARS_UPPER;
      return s[r % 26];
    }

    case PCFG_TK_SPECIAL:
    {
      static const char *s = PCFG_CHARS_SPECIAL;
      static const int len = sizeof (PCFG_CHARS_SPECIAL) - 1;
      return s[r % len];
    }

    case PCFG_TK_PUNCT:
    {
      static const char *s = PCFG_CHARS_PUNCT;
      static const int len = sizeof (PCFG_CHARS_PUNCT) - 1;
      return s[r % len];
    }

    case PCFG_TK_WHITESPACE:
    {
      static const char *s = PCFG_CHARS_WHITE;
      static const int len = sizeof (PCFG_CHARS_WHITE) - 1;
      return s[r % len];
    }

    default: return '?';
  }
}

// Markov-based terminal generation

static void generate_markov_terminal (pcfg_model_t *m, u8 type, u8 len, char *out, u64 *rng_state)
{
  const u8 raw_type = type & 0x7F;

  pcfg_markov_row_t *table;

  u16 *s_states;
  u32 s_mask;

  // select the appropriate table and starting states based on the terminal type
  if (raw_type == PCFG_TK_DIGIT || raw_type == PCFG_TK_YEAR)
  {
    table = m->markov_table_digit;
    s_states = m->start_row_digit.states;
    s_mask = 0x7F; // 127 for 128 bins
  }
  else if (raw_type == PCFG_TK_UPPER)
  {
    table = m->markov_table_upper;
    s_states = m->start_row_alpha.states;
    s_mask = 0xFFF; // 4095 for 4096 bins
  }
  else if (raw_type == PCFG_TK_LATIN_EXT)
  {
    table = m->markov_table_latin;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else if (raw_type == PCFG_TK_CYRILLIC)
  {
    table = m->markov_table_cyrillic;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else if (raw_type == PCFG_TK_ARABIC)
  {
    table = m->markov_table_arabic;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else if (raw_type == PCFG_TK_ASIAN)
  {
    table = m->markov_table_asian;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else if (raw_type == PCFG_TK_GREEK)
  {
    table = m->markov_table_greek;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else if (raw_type == PCFG_TK_HEBREW)
  {
    table = m->markov_table_hebrew;
    s_states = m->start_row_alpha_unicode.states;
    s_mask = 0xFFF;
  }
  else
  {
    table = m->markov_table_lower;
    s_states = m->start_row_alpha.states;
    s_mask = 0xFFF;
  }

  // pick the initial bigram state using the specific mask for the bin size
  u32 state = s_states[fast_rand_local (rng_state) & s_mask];

  out[0] = (char) (state >> 8);
  out[1] = (char) (state & 0xFF);

  for (int i = 2; i < len; i++)
  {
    pcfg_markov_row_t *row = &table[state];

    // if the transition row is empty, pick a new starting bigram
    if (row->bins[0] == 0)
    {
      u32 new_start = s_states[fast_rand_local (rng_state) & s_mask];

      out[i] = (char) (new_start & 0xFF);

      state = new_start;

      continue;
    }

    // select the next character from the 256 probability bins
    u8 next_char = row->bins[fast_rand_local (rng_state) & 0xFF];

    out[i] = (char) next_char;

    state = ((state & 0xFF) << 8) | next_char;
  }

  out[len] = '\0';
}

// heap helpers

static inline void heap_swap (pcfg_candidate_t *a, pcfg_candidate_t *b)
{
  pcfg_candidate_t t = *a;

  *a = *b;

  *b = t;
}

static u64 hash_structure_signature_xxh64 (const pcfg_structure_t *s)
{
  u8 buf[PCFG_TOKEN_MAX * 2];

  memcpy (buf, s->types, s->token_cnt);

  memcpy (buf + s->token_cnt, s->lengths, s->token_cnt);

  return XXH64 (buf, s->token_cnt * 2, 0);
}

static bool pcfg_gen_valid_type (pcfg_gen_t *gen, u8 check_ty)
{
  for (u32 i = 0; i < gen->ahf_valid_types_cnt; i++)
  {
    u8 ty = gen->ahf_valid_types[i];

    if (ty == check_ty) return true;
  }

  return false;
}

static u64 pcfg_estimate_structural_keyspace (pcfg_gen_t *gen)
{
  pcfg_model_t *m = gen->model;

  u64 total_blocks = 0;

  for (u32 i = 0; i < gen->ahf_valid_types_cnt; i++)
  {
    u8 ty = gen->ahf_valid_types[i];

    for (int l = 1; l < PCFG_VALUE_MAX; l++)
    {
      if (m->terminals[ty][l].cnt > 0) total_blocks++;
    }
  }

  u64 s2 = total_blocks * total_blocks;
  u64 s3 = s2 * total_blocks;
  u64 s4 = s3 * total_blocks;

  return s2 + s3 + s4;
}

// find pivot and push next candidate

static int find_pivot_and_push (pcfg_gen_t *gen, pcfg_model_t *m, pcfg_structure_t *s, pcfg_candidate_t *state, int burst_token, bool burst_start, u8 ahf_type)
{
  state->term_idx[burst_token] = 0;

  int pivot = -1;

  if (burst_start)
  {
    for (int i = 1; i < (int) s->token_cnt; i++)
    {
      u8 raw_ty_local = s->types[i];
      u8 clean_ty_local = raw_ty_local & 0x7F;
      u8 ln_local = s->lengths[i];

      bool is_synth_local = (raw_ty_local & PCFG_SYNTHETIC_FLAG);

      u64 limit_local = (is_synth_local) ? 100 : m->terminals[clean_ty_local][ln_local].cnt;

      if (state->term_idx[i] + 1 < limit_local)
      {
        pivot = i;
        break;
      }
    }
  }
  else
  {
    for (int i = s->token_cnt - 2; i >= 0; i--)
    {
      u8 raw_ty_local = s->types[i];
      u8 clean_ty_local = raw_ty_local & 0x7F;
      u8 ln_local = s->lengths[i];

      bool is_synth_local = (raw_ty_local & PCFG_SYNTHETIC_FLAG);

      u64 limit_local = (is_synth_local) ? 100 : m->terminals[clean_ty_local][ln_local].cnt;

      if (state->term_idx[i] + 1 < limit_local)
      {
        pivot = i;
        break;
      }
    }
  }

  if (pivot != -1)
  {
    state->term_idx[pivot]++;

    if (burst_start)
    {
      for (int k = 0; k < pivot; k++) state->term_idx[k] = 0;
    }
    else
    {
      for (u32 k = pivot + 1; k < s->token_cnt; k++) state->term_idx[k] = 0;
    }

    if (pcfg_cpu_random_build_candidate (m, s, state->struct_idx, state, NULL, &gen->ahf_rng_state, ahf_type) == 0)
    {
      pcfg_cpu_random_heap_push (gen->ahf_heap, state);

      return 0;
    }
  }

  return -1;
}

// heap

static int pcfg_cpu_random_heap_pop (pcfg_heap_t *h, pcfg_candidate_t *out)
{
  if (h->size == 0) return -1;

  *out = h->data[0];

  h->data[0] = h->data[--h->size];

  // sift down
  u64 i = 0;

  while (1)
  {
    u64 l = 2*i + 1;
    u64 r = 2*i + 2;

    u64 largest = i;

    if (l < h->size && h->data[l].prob > h->data[largest].prob) largest = l;
    if (r < h->size && h->data[r].prob > h->data[largest].prob) largest = r;

    if (largest != i)
    {
      heap_swap (&h->data[i], &h->data[largest]);

      i = largest;
    }
    else
    {
      break;
    }
  }

  return 0;
}

pcfg_heap_t *pcfg_cpu_random_heap_alloc (u64 cap)
{
  pcfg_heap_t *h = (pcfg_heap_t *) hccalloc (1, sizeof (pcfg_heap_t));

  if (!h) return NULL;

  h->data = (pcfg_candidate_t *) hccalloc (cap, sizeof (pcfg_candidate_t));

  h->cap = cap;

  return h;
}

void pcfg_cpu_random_heap_free (pcfg_heap_t *h)
{
  if (!h) return;

  hcfree (h->data);
  hcfree (h);
}

int pcfg_cpu_random_heap_push (pcfg_heap_t *h, const pcfg_candidate_t *c)
{
  if (!h) return -1;

  if (h->size >= h->cap)
  {
    u64 newcap = h->cap * 2;

    pcfg_candidate_t *newd = (pcfg_candidate_t *) hcrealloc (h->data, h->cap * sizeof (pcfg_candidate_t), newcap * sizeof (pcfg_candidate_t));

    if (!newd) return -1;

    h->data = newd;
    h->cap = newcap;
  }

  h->data[h->size] = *c;

  // sift up (max heap by prob)
  u64 i = h->size++;

  while (i > 0)
  {
    u64 p = (i - 1) / 2;

    if (h->data[i].prob > h->data[p].prob)
    {
      heap_swap (&h->data[i], &h->data[p]);

      i = p;
    }
    else
    {
      break;
    }
  }

  return 0;
}

// build candidate

int pcfg_cpu_random_build_candidate (pcfg_model_t *m, pcfg_structure_t *s, u32 struct_idx, pcfg_candidate_t *out, char *out_buf, u64 *rng_state, u8 ahf_type)
{
  out->struct_idx = struct_idx;
  out->prob = (double) s->prob;

  size_t current_len = 0;

  for (u32 i = 0; i < s->token_cnt; i++)
  {
    u8 raw_ty = s->types[i];
    u8 clean_ty = raw_ty & 0x7F;
    u8 ln = s->lengths[i];

    bool is_synthetic = (raw_ty & PCFG_SYNTHETIC_FLAG);

    u32 idx = out->term_idx[i];

    pcfg_terminal_list_t *list = &m->terminals[clean_ty][ln];

    if (!is_synthetic && idx >= list->cnt) return -1;

    pcfg_terminal_t *term = NULL;

    if (!is_synthetic)
    {
      term = &list->items[idx];

      out->prob *= (double) term->prob;
    }
    else
    {
      out->prob *= (double) 0.1;
    }

    if (current_len + ln >= PCFG_PW_MAX)
    {
      return -1;
    }

    if (out_buf != NULL)
    {
      if (is_synthetic)
      {
        if (ahf_type == PCFG_AHF_TYPE_RANDOM)
        {
          // gen random 'ln' chars
          for (int k = 0; k < ln; k++)
          {
            out_buf[current_len + k] = get_synthetic_char (clean_ty, rng_state);
          }
        }
        else if (ahf_type == PCFG_AHF_TYPE_MARKOV)
        {
          generate_markov_terminal (m, clean_ty, ln, out_buf+current_len, rng_state);
        }
      }
      else
      {
        memcpy (out_buf + current_len, term->value, ln);
      }
    }

    current_len += ln;
  }

  if (out_buf != NULL)
  {
    out_buf[current_len] = 0;
  }

  out->pw_len = (u32) current_len;

  return 0;
}

// structure shuffle (for --pcfg-shuffle)

void pcfg_cpu_random_structure_shuffle (pcfg_gen_t *gen, pcfg_structure_t *s)
{
  if (s->token_cnt < 2) return;

  int max_attempts = 10;
  int attempts = 0;
  bool valid = false;

  while (!valid && attempts < max_attempts)
  {
    attempts++;

    // shuffle
    for (u32 i = s->token_cnt - 1; i > 0; i--)
    {
      u32 j = (u32) (fast_rand_local (&gen->ahf_rng_state) % (i + 1));

      u8 t_tmp = s->types[i];

      s->types[i] = s->types[j];
      s->types[j] = t_tmp;

      u8 l_tmp = s->lengths[i];

      s->lengths[i] = s->lengths[j];
      s->lengths[j] = l_tmp;
    }

    // validation
    valid = true;

    if (s->types[0] == PCFG_TK_EMAIL)
    {
      valid = false;

      continue;
    }

    u64 h64 = hash_structure_signature_xxh64 (s);

    u64 bloom_bits = gen->ahf_bloom_size * 8;

    u64 idx1 = (h64 & 0xFFFFFFFF) % bloom_bits;
    u64 idx2 = (h64 >> 32)        % bloom_bits;

    int bit1 = (gen->ahf_bloom[idx1 / 8] >> (idx1 % 8)) & 1;
    int bit2 = (gen->ahf_bloom[idx2 / 8] >> (idx2 % 8)) & 1;

    if (bit1 && bit2)
    {
      valid = false;

      continue;
    }

    gen->ahf_bloom[idx1 / 8] |= (1 << (idx1 % 8));
    gen->ahf_bloom[idx2 / 8] |= (1 << (idx2 % 8));
  }
}

// reset heap for AHF refresh

int pcfg_cpu_random_ahf_reset (pcfg_gen_t *gen)
{
  pcfg_model_t *m = gen->model;

  // reset counters
  gen->ahf_burst_left = 0;
  gen->ahf_heap->size = 0;

  // push the new structures on heap
  for (u32 i = 0; i < gen->ahf_struct_cnt; i++)
  {
    pcfg_structure_t *s = &gen->ahf_structures[i];

    // don't allow empty structs
    if (s->token_cnt == 0) continue;

    pcfg_candidate_t c;

    memset (&c, 0, sizeof (pcfg_candidate_t));

    c.struct_idx = i;

    if (pcfg_cpu_random_build_candidate (m, s, i, &c, NULL, &gen->ahf_rng_state, gen->ahf_type) == 0)
    {
      if (c.pw_len > 0 && c.pw_len < PCFG_PW_MAX)
      {
        if (pcfg_cpu_random_heap_push (gen->ahf_heap, &c) == -1) return -1;
      }
    }
  }

  return 0;
}

// CPU_RANDOM / Weighted Random handler
// Returns: 0 = success, -1/-2 = done/error, 2 = restart (caller should goto restart)

int pcfg_cpu_random_gen_next (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len)
{
  (void) hashcat_ctx;

  pcfg_model_t *m = gen->model;

  const u8 ahf_type = gen->ahf_type;

  const bool burst_start = gen->ahf_burst_first;

  pcfg_structure_t *structures_base = gen->ahf_structures ? gen->ahf_structures : m->structures;

  // fast lane (burst)
  if (gen->ahf_burst_left > 0)
  {
    pcfg_candidate_t *c = &gen->burst_cand;
    pcfg_structure_t *s = &structures_base[c->struct_idx];

    const u32 token_cnt = s->token_cnt;
    const u8 *types     = s->types;
    const u8 *lengths   = s->lengths;

    const int burst_token = burst_start ? 0 : ((int) token_cnt - 1);

    const u8 ln       = lengths[burst_token];
    const u8 raw_ty   = types[burst_token];
    const u8 clean_ty = raw_ty & 0x7F;

    const bool is_synth = (raw_ty & PCFG_SYNTHETIC_FLAG);

    const u64 limit = is_synth ? 100 : m->terminals[clean_ty][ln].cnt;

    c->term_idx[burst_token]++;

    if (c->term_idx[burst_token] < limit)
    {
      if (__builtin_expect(ln > c->pw_len, 0)) return -1;

      const u32 offset = burst_start ? 0 : (c->pw_len - ln);

      if (__builtin_expect(offset + ln >= PCFG_PW_MAX, 0)) return -1;

      // fill cache
      if (is_synth)
      {
        if (ahf_type == PCFG_AHF_TYPE_RANDOM)
        {
          for (int k = 0; k < ln; k++)
          {
            gen->ahf_pw_cache[offset + k] = get_synthetic_char (clean_ty, &gen->ahf_rng_state);
          }
        }
        else if (ahf_type == PCFG_AHF_TYPE_MARKOV)
        {
          generate_markov_terminal(m, clean_ty, ln, gen->ahf_pw_cache + offset, &gen->ahf_rng_state);
        }
      }
      else
      {
        const char *val = m->terminals[clean_ty][ln].items[c->term_idx[burst_token]].value;

        switch (ln)
        {
          case 1:  gen->ahf_pw_cache[offset] = val[0];           break;
          case 2:  memcpy (gen->ahf_pw_cache + offset, val, 2);  break;
          case 3:  memcpy (gen->ahf_pw_cache + offset, val, 3);  break;
          case 4:  memcpy (gen->ahf_pw_cache + offset, val, 4);  break;
          case 5:  memcpy (gen->ahf_pw_cache + offset, val, 5);  break;
          case 6:  memcpy (gen->ahf_pw_cache + offset, val, 6);  break;
          case 7:  memcpy (gen->ahf_pw_cache + offset, val, 7);  break;
          case 8:  memcpy (gen->ahf_pw_cache + offset, val, 8);  break;
          default: memcpy (gen->ahf_pw_cache + offset, val, ln); break;
        }
      }

      if (out != NULL)
      {
        const u32 pw_len = c->pw_len;

        memcpy (out, gen->ahf_pw_cache, pw_len);
        out[pw_len] = 0;

        *len = pw_len;
      }

      // lazy
      c->prob = (double)s->prob;

      gen->generated++;
      gen->ahf_burst_left--;
      gen->curr_comb_idx++;

      if (gen->ahf_burst_left == 0)
      {
        pcfg_candidate_t next_state = *c;

        if (next_state.term_idx[burst_token] + 1 < limit)
        {
          if (pcfg_cpu_random_build_candidate (m, s, next_state.struct_idx, &next_state, NULL, &gen->ahf_rng_state, ahf_type) == 0)
          {
            pcfg_cpu_random_heap_push (gen->ahf_heap, &next_state);
          }
        }
        else
        {
          find_pivot_and_push (gen, m, s, &next_state, burst_token, burst_start, ahf_type);
        }
      }

      return 0;
    }

    // end of burst
    gen->ahf_burst_left = 0;

    pcfg_candidate_t current = *c;

    find_pivot_and_push (gen, m, s, &current, burst_token, burst_start, ahf_type);

    return 2; // restart
  }

  // slow lane (heap)
  if (__builtin_expect (!gen->ahf_heap || gen->ahf_heap->size == 0, 0)) return -1;

  pcfg_candidate_t cur;

  if (pcfg_cpu_random_heap_pop (gen->ahf_heap, &cur) != 0) return -1;

  pcfg_structure_t *s = &structures_base[cur.struct_idx];

  if (pcfg_cpu_random_build_candidate (m, s, cur.struct_idx, &cur, gen->ahf_pw_cache, &gen->ahf_rng_state, ahf_type) != 0)
  {
    return 2; // restart
  }

  if (out != NULL)
  {
    const u32 pw_len = cur.pw_len;

    memcpy (out, gen->ahf_pw_cache, pw_len);
    out[pw_len] = 0;

    *len = pw_len;
  }

  gen->generated++;
  gen->curr_comb_idx++;

  // planning next
  const u32 token_cnt = s->token_cnt;
  const u8 *types     = s->types;
  const u8 *lengths   = s->lengths;

  const int burst_token  = burst_start ? 0 : ((int) token_cnt - 1);

  const u8 b_ln     = lengths[burst_token];
  const u8 raw_ty   = types[burst_token];
  const u8 clean_ty = raw_ty & 0x7F;

  const bool is_synth = (raw_ty & PCFG_SYNTHETIC_FLAG);

  const u64 term_cnt = is_synth ? 100 : m->terminals[clean_ty][b_ln].cnt;

  // check for burst
  if (cur.term_idx[burst_token] + 1 < term_cnt)
  {
    gen->burst_cand = cur;

    u64 remaining = term_cnt - (cur.term_idx[burst_token] + 1);

    u32 b_size = gen->burst_size;

    if (remaining < b_size) b_size = (u32) remaining;

    gen->ahf_burst_left = b_size;

    return 0;
  }

  int pivot = -1;

  if (burst_start)
  {
    for (int i = 1; i < (int)token_cnt; i++)
    {
      const u8 rty  = types[i];
      const u8 cty  = rty & 0x7F;
      const u8 lln  = lengths[i];
      const u64 lim = (rty & PCFG_SYNTHETIC_FLAG) ? 100 : m->terminals[cty][lln].cnt;

      if (cur.term_idx[i] + 1 < lim)
      {
        pivot = i;
        break;
      }
    }
  }
  else
  {
    for (int i = (int)token_cnt - 2; i >= 0; i--)
    {
      const u8 rty  = types[i];
      const u8 cty  = rty & 0x7F;
      const u8 lln  = lengths[i];
      const u64 lim = (rty & PCFG_SYNTHETIC_FLAG) ? 100 : m->terminals[cty][lln].cnt;

      if (cur.term_idx[i] + 1 < lim)
      {
        pivot = i;
        break;
      }
    }
  }

  if (pivot != -1)
  {
    pcfg_candidate_t next = cur;
    next.term_idx[pivot]++;

    if (burst_start)
    {
      for (int k = 0; k < pivot; k++) next.term_idx[k] = 0;
    }
    else
    {
      for (u32 k = pivot + 1; k < token_cnt; k++) next.term_idx[k] = 0;
    }

    if (pcfg_cpu_random_build_candidate (m, s, next.struct_idx, &next, NULL, &gen->ahf_rng_state, ahf_type) == 0)
    {
      pcfg_cpu_random_heap_push (gen->ahf_heap, &next);
    }
  }

  return 0;
}

// Skip/restore for CPU_RANDOM mode

void pcfg_cpu_random_gen_skip (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, u64 local_skip, u64 restore_skip, int thread_count, int thread_id)
{
  // skip entire structures via heap_pop

  while (gen->ahf_heap->size > 0 && local_skip > 0)
  {
    pcfg_candidate_t *top = &gen->ahf_heap->data[0];
    pcfg_structure_t *s = &gen->model->structures[top->struct_idx];

    unsigned __int128 struct_ks = 1;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      struct_ks *= gen->model->terminals[s->types[k]][s->lengths[k]].cnt;
    }

    if (local_skip >= (u64) struct_ks)
    {
      pcfg_candidate_t trash;
      pcfg_cpu_random_heap_pop (gen->ahf_heap, &trash);
      local_skip -= (u64) struct_ks;
    }
    else
    {
      break;
    }
  }

  // arithmetic skip on burst_cand

  if (gen->ahf_heap->size > 0 && local_skip > 0)
  {
    if (pcfg_gen_next (hashcat_ctx, gen, NULL, NULL) == 0)
    {
      local_skip--;

      if (local_skip > 0)
      {
        pcfg_candidate_t *c = &gen->burst_cand;
        pcfg_structure_t *s = &gen->model->structures[c->struct_idx];

        u64 carry = local_skip;

        for (int k = s->token_cnt - 1; k >= 0; k--)
        {
          if (carry == 0) break;

          u64 limit   = gen->model->terminals[s->types[k]][s->lengths[k]].cnt;
          u64 current = c->term_idx[k];
          u64 new_val = current + carry;

          c->term_idx[k] = new_val % limit;
          carry = new_val / limit;
        }

        if (carry > 0)
        {
          gen->ahf_burst_left = 0;
        }
        else
        {
          gen->generated += local_skip;
          local_skip = 0;
        }
      }
    }
  }

  // fallback
  if (local_skip > 0)
  {
    char dummy[256];
    u32 dummy_len;

    while (local_skip > 0)
    {
      if (pcfg_gen_next (hashcat_ctx, gen, dummy, &dummy_len) != 0) break;

      local_skip--;
    }
  }

  // update generated
  gen->generated = restore_skip / thread_count;

  if ((u64) thread_id < (restore_skip % thread_count)) gen->generated++;
}

// pcfg_cpu_random_ahf_refresh

void pcfg_cpu_random_ahf_refresh (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  pcfg_model_t   *m            = gen->model;

  // cache frequent ptrs
  pcfg_terminal_list_t (*terminals)[PCFG_VALUE_MAX] = m->terminals;

  pcfg_markov_row_t *trans_table = m->struct_trans_table;
  pcfg_markov_start_row_t *start_row = &m->struct_start_row;

  const bool is_markov = (gen->ahf_type == PCFG_AHF_TYPE_MARKOV);

  u64 batch_size = gen->burst_size;

  // initialization (only first time)
  if (gen->ahf_valid_types_cnt == 0)
  {
    for (int t = 0; t < 256; t++)
    {
      u64 total_terminals = 0;
      bool has_data = false;

      for (int l = 1; l < PCFG_VALUE_MAX; l++)
      {
        if (terminals[t][l].cnt > 0)
        {
          has_data = true;
          total_terminals += terminals[t][l].cnt;
        }
      }

      if (!has_data) continue;

      // filter out if min count is not reached
      if (total_terminals < gen->ahf_terminals_min) continue;

      if (user_options->pcfg_token_types != NULL)
      {
        bool allowed = false;

        for (char *f = user_options->pcfg_token_types; *f; f++)
        {
          if ((u8)*f == t)
          {
            allowed = true;
            break;
          }
        }

        if (!allowed) continue;
      }

      gen->ahf_valid_types[gen->ahf_valid_types_cnt++] = (u8) t;
    }

    if (gen->ahf_valid_types_cnt == 0) return;

    u64 keyspace = pcfg_estimate_structural_keyspace (gen);

    if (batch_size < 1000) batch_size = 1000;

    gen->ahf_cand_unique = (keyspace > (batch_size * 2));
    gen->ahf_estimated_unique_structs = keyspace;

    // adjust batch_size based on estimated keyspace
    if (gen->ahf_estimated_unique_structs > 0)
    {
      // if keyspace is small, limit batch_size
      if (gen->ahf_estimated_unique_structs < batch_size)
      {
        batch_size = (u32) (gen->ahf_estimated_unique_structs / 2);

        if (batch_size < 100) batch_size = 100;
      }
      // even for medium-large keyspaces, limit to 10% to avoid too many duplicates
      else if (gen->ahf_estimated_unique_structs < batch_size * 100)
      {
        u32 safe_batch = (u32) (gen->ahf_estimated_unique_structs / 10);
        if (safe_batch < batch_size && safe_batch >= 1000)
        {
          batch_size = safe_batch;
        }
      }
    }

    // update gen batch_size
    gen->burst_size = batch_size;
  }

  // cache after init
  u8 *valid_types = gen->ahf_valid_types;
  const u32 valid_types_cnt = gen->ahf_valid_types_cnt;

  // memory management
  if (gen->ahf_structures == NULL)
  {
    gen->ahf_structures = hccalloc (batch_size, sizeof (pcfg_structure_t));
    gen->ahf_struct_cnt = batch_size;
  }
  else if (gen->ahf_struct_cnt != batch_size)
  {
    gen->ahf_structures = hcrealloc (gen->ahf_structures, gen->ahf_struct_cnt * sizeof (pcfg_structure_t), batch_size * sizeof (pcfg_structure_t));
    gen->ahf_struct_cnt = batch_size;
  }

  // user constraints
  const int retry_max = 3000; //5000;

  const bool use_token_cnt_min = user_options->pcfg_token_count_min_chgd;
  const bool use_token_cnt_max = user_options->pcfg_token_count_max_chgd;

  int token_cnt_min = PCFG_TOKEN_COUNT_MIN;
  int token_cnt_max = PCFG_TOKEN_COUNT_MAX;

  if (use_token_cnt_min)
  {
    token_cnt_min = user_options->pcfg_token_count_min;

    if (token_cnt_min < 1) token_cnt_min = 1;
  }

  if (use_token_cnt_max)
  {
    token_cnt_max = user_options->pcfg_token_count_max;

    if (token_cnt_max > PCFG_TOKEN_COUNT_MAX) token_cnt_max = PCFG_TOKEN_COUNT_MAX;
    if (token_cnt_max < PCFG_TOKEN_COUNT_MIN) token_cnt_max = PCFG_TOKEN_COUNT_MIN;
  }

  const bool use_t_len_min = user_options->pcfg_token_len_min_chgd;
  const bool use_t_len_max = user_options->pcfg_token_len_max_chgd;

  u32 t_len_min = 1;
  u32 t_len_max = PCFG_VALUE_MAX - 1;

  if (use_t_len_min)
  {
    t_len_min = user_options->pcfg_token_len_min;

    if (t_len_min < 1) t_len_min = 1;
  }

  if (use_t_len_max)
  {
    t_len_max = user_options->pcfg_token_len_max;

    if (t_len_max >= PCFG_VALUE_MAX) t_len_max = PCFG_VALUE_MAX - 1;
  }

  u32 pw_len_min = hashconfig->pw_min;
  u32 pw_len_max = hashconfig->pw_max;

  if (pw_len_min == 0) pw_len_min = 1;

  if (user_options->pcfg_pw_len_min_chgd)
  {
    if (user_options->pcfg_pw_len_min > pw_len_min) pw_len_min = user_options->pcfg_pw_len_min;
  }

  if (user_options->pcfg_pw_len_max_chgd)
  {
    if (user_options->pcfg_pw_len_max < pw_len_max) pw_len_max = user_options->pcfg_pw_len_max;
  }

  if (pw_len_max >= PCFG_PW_MAX) pw_len_max = PCFG_PW_MAX - 1;
  if (pw_len_min > pw_len_max) pw_len_min = pw_len_max;

  const u32 pw_len_range = pw_len_max - pw_len_min + 1;
  const bool check_complexity = user_options->pcfg_pw_complex;
  const bool check_unique = gen->ahf_cand_unique;

  // local Hash table for fast duplicate check

  #define HASH_TABLE_SIZE 65536
  u32 *hash_table = NULL;
  u32 *hash_chain = NULL;

  if (check_unique)
  {
    hash_table = (u32 *) hccalloc (HASH_TABLE_SIZE, sizeof (u32));
    hash_chain = (u32 *) hccalloc (batch_size + 1, sizeof (u32));

    // 0 = empty, indexes are 1-based
    for (u32 j = 0; j < HASH_TABLE_SIZE; j++) hash_table[j] = 0;
  }

  // batch generation
  for (u32 i = 0; i < batch_size; i++)
  {
    pcfg_structure_t *s = &gen->ahf_structures[i];

    int retries = 0;

    bool unique = false;

    while (!unique && retries < retry_max)
    {
      retries++;

      s->prob = 0.000001f;

      // choose target password length

      u32 target_len = 0;

      if (is_markov)
      {
        // maximum 5 attempts for Markov length
        for (int len_attempts = 0; len_attempts < 5; len_attempts++)
        {
          u32 picked_len = (u32) m->pw_len_table.states[fast_rand_local (&gen->ahf_rng_state) & 0xFF];

          if (picked_len >= pw_len_min && picked_len <= pw_len_max)
          {
            target_len = picked_len;
            break;
          }
        }
      }

      // uniform fallback
      if (target_len == 0)
      {
        target_len = pw_len_min + (u32) (fast_rand_local (&gen->ahf_rng_state) % pw_len_range);
      }

      u32 current_len = 0;
      u32 k = 0;

      bool email_placed = false;
      bool generation_failed = false;

      int prev_type = -1;
      int unicode_script_locked = -1;

      u8 p1 = 0;
      u8 p2 = 0;

      // token generation
      while (current_len < target_len)
      {
        if (k >= PCFG_TOKEN_COUNT_MAX || (use_token_cnt_max && k >= (u32) token_cnt_max))
        {
          generation_failed = true;
          break;
        }

        const u32 remaining = target_len - current_len;

        u32 tokens_still_needed = 0;

        if (use_token_cnt_min && (k + 1 < (u32) token_cnt_min))
        {
          tokens_still_needed = (u32) token_cnt_min - k - 1;
        }

        u32 max_len_this_token = remaining;

        if (tokens_still_needed > 0 && remaining > tokens_still_needed)
        {
          max_len_this_token = remaining - tokens_still_needed;
        }
        if (use_t_len_max && max_len_this_token > t_len_max)
        {
          max_len_this_token = t_len_max;
        }

        u32 min_len_this_token = use_t_len_min ? t_len_min : 1;

        if (min_len_this_token > max_len_this_token)
        {
          generation_failed = true;
          break;
        }

        // select type
        u8 selected_type = 0;

        bool type_found = false;

        if (is_markov)
        {
          u32 rnd = fast_rand_local (&gen->ahf_rng_state);

          // 25% chance of using random selection for greater variety
          bool use_random_noise = ((rnd >> 8) % 100) < 25;

          if (use_random_noise)
          {
            // Direct random selection from valid types
            for (int noise_att = 0; noise_att < 10 && !type_found; noise_att++)
            {
              selected_type = valid_types[fast_rand_local (&gen->ahf_rng_state) % valid_types_cnt];

              if (k == 0 && selected_type == PCFG_TK_EMAIL) continue;
              if (selected_type == PCFG_TK_EMAIL && email_placed) continue;

              // verify that it has lengths within the required range
              for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
              {
                if (terminals[selected_type][l].cnt > 0)
                {
                  type_found = true;
                  break;
                }
              }
            }
          }

          // if random noise found nothing, use normal Markov
          if (!type_found)
          {
            rnd = fast_rand_local (&gen->ahf_rng_state);

            if (k == 0)
            {
              // select from start_row but k0 must be a valid_type
              do
              {
                selected_type = (u8) start_row->states[rnd & 0xFF];

                if (pcfg_gen_valid_type (gen, selected_type) == false)
                {
                  rnd = fast_rand_local (&gen->ahf_rng_state);
                  continue;
                }

                break;

              } while (1);
            }
            else if (k == 1)
            {
              selected_type = trans_table[p1].bins[rnd & 0xFF];
            }
            else
            {
              u16 state = (p2 << 8) | p1;
              selected_type = trans_table[state].bins[rnd & 0xFF];
            }

            // validation
            if ((k == 0 && selected_type == PCFG_TK_EMAIL) ||
                (selected_type == PCFG_TK_EMAIL && email_placed))
            {
              type_found = false;
            }
            else
            {
              // verify that it has lengths within the required range
              for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
              {
                if (terminals[selected_type][l].cnt > 0)
                {
                  type_found = true;
                  break;
                }
              }
            }

            // if not found, try again with Markov (max 16 times)
            if (!type_found)
            {
              for (int markov_retry = 0; markov_retry < 16 && !type_found; markov_retry++)
              {
                rnd = fast_rand_local (&gen->ahf_rng_state);

                if (k == 0)
                {
                  // select from start_row but k0 must be a valid_type
                  do
                  {
                    selected_type = (u8) start_row->states[rnd & 0xFF];

                    if (pcfg_gen_valid_type (gen, selected_type) == false)
                    {
                      rnd = fast_rand_local (&gen->ahf_rng_state);
                      continue;
                    }

                    break;

                  } while (1);
                }
                else if (k == 1)
                {
                  selected_type = trans_table[p1].bins[rnd & 0xFF];
                }
                else
                {
                  u16 state = (p2 << 8) | p1;
                  selected_type = trans_table[state].bins[rnd & 0xFF];
                }

                if (k == 0 && selected_type == PCFG_TK_EMAIL) continue;
                if (selected_type == PCFG_TK_EMAIL && email_placed) continue;

                // check lengths in the range
                for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
                {
                  if (terminals[selected_type][l].cnt > 0)
                  {
                    type_found = true;
                    break;
                  }
                }
              }
            }

            // final fallback with random selection
            if (!type_found)
            {
              for (int fb = 0; fb < 20 && !type_found; fb++)
              {
                selected_type = valid_types[fast_rand_local (&gen->ahf_rng_state) % valid_types_cnt];

                if (k == 0 && selected_type == PCFG_TK_EMAIL) continue;
                if (selected_type == PCFG_TK_EMAIL && email_placed) continue;

                for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
                {
                  if (terminals[selected_type][l].cnt > 0)
                  {
                    type_found = true;
                    break;
                  }
                }
              }
            }
          }
        }
        else // RANDOM mode
        {
          int attempts = 0;

          do
          {
            int idx = (int)(fast_rand_local (&gen->ahf_rng_state) % valid_types_cnt);
            selected_type = valid_types[idx];
            attempts++;

            bool ok = true;

            if (k == 0 && selected_type == PCFG_TK_EMAIL) ok = false;
            if (selected_type == PCFG_TK_EMAIL && email_placed) ok = false;
            if (selected_type == prev_type && valid_types_cnt > 1) ok = false;

            if (is_unicode_script_type (selected_type))
            {
              if (unicode_script_locked != -1 && selected_type != unicode_script_locked)
              {
                ok = false;
              }
            }

            if (ok)
            {
              bool has_valid_len = false;

              for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
              {
                if (terminals[selected_type][l].cnt > 0)
                {
                  has_valid_len = true;
                  break;
                }
              }

              if (!has_valid_len) ok = false;
            }

            if (ok)
            {
              type_found = true;
              break;
            }

          } while (attempts < 100);
        }

        // final fallback with length verification within the range
        if (!type_found)
        {
          for (int attempts = 0; attempts < 20; attempts++)
          {
            u8 try_type = valid_types[fast_rand_local (&gen->ahf_rng_state) % valid_types_cnt];

            if (k == 0 && try_type == PCFG_TK_EMAIL) continue;
            if (try_type == PCFG_TK_EMAIL && email_placed) continue;

            if (!is_markov)
            {
              if (is_unicode_script_type (try_type) && unicode_script_locked != -1 && try_type != unicode_script_locked) continue;
            }

            // check lengths within the required range
            for (u32 l = min_len_this_token; l <= max_len_this_token && l < PCFG_VALUE_MAX; l++)
            {
              if (terminals[try_type][l].cnt > 0)
              {
                selected_type = try_type;
                type_found = true;
                break;
              }
            }

            if (type_found) break;
          }

          // if still not found, report failure instead of using invalid type
          if (!type_found)
          {
            generation_failed = true;
            break;
          }
        }

        if (selected_type == PCFG_TK_EMAIL) email_placed = true;

        if (!is_markov && is_unicode_script_type (selected_type) && unicode_script_locked == -1)
        {
          unicode_script_locked = selected_type;
        }

        s->types[k] = selected_type;

        // fast length selection
        u32 chosen_len = 0;

        const u32 max_l = (max_len_this_token < PCFG_VALUE_MAX) ? max_len_this_token : PCFG_VALUE_MAX - 1;

        // check validity of range first
        if (max_l < min_len_this_token)
        {
          generation_failed = true;
          break;
        }

        // try exact match, but not always on the first token to increase variety
        const bool can_finish = (!use_token_cnt_min) || (k + 1 >= (u32) token_cnt_min);

        // on the first token, only a 30% chance of using exact match
        // this forces multi-token structures for greater variety
        bool allow_exact_match = true;

        if (k == 0 && remaining >= 6 && can_finish)
        {
          // for long passwords, often enforce multi-token structures
          allow_exact_match = (fast_rand_local (&gen->ahf_rng_state) % 100) < 30;
        }

        if (allow_exact_match && can_finish && remaining >= min_len_this_token && remaining <= max_l && terminals[selected_type][remaining].cnt > 0)
        {
          chosen_len = remaining;
        }
        else
        {
          // random scan with early exit
          const u32 range = max_l - min_len_this_token + 1;
          const u32 start_offset = fast_rand_local (&gen->ahf_rng_state) % range;

          for (u32 y = 0; y < range; y++)
          {
            u32 check_l = min_len_this_token + ((start_offset + y) % range);

            if (terminals[selected_type][check_l].cnt > 0)
            {
              chosen_len = check_l;
              break;
            }
          }
        }

        if (chosen_len == 0)
        {
          generation_failed = true;
          break;
        }

        s->lengths[k] = (u8) chosen_len;

        // adaptive Fuzzing
        bool apply_synth = false;
        bool can_be_synthetic = false;

        const int raw_type = selected_type;
        const int len = chosen_len;

        if (is_markov)
        {
          switch (raw_type)
          {
            case PCFG_TK_YEAR:       can_be_synthetic = (len <= 4); break;
            case PCFG_TK_DIGIT:      can_be_synthetic = (len <= 10); break;
            case PCFG_TK_LOWER:
            case PCFG_TK_UPPER:
            case PCFG_TK_CAPITALIZED:
            case PCFG_TK_LATIN_EXT:
            case PCFG_TK_CYRILLIC:
            case PCFG_TK_ARABIC:
            case PCFG_TK_ASIAN:
            case PCFG_TK_GREEK:
            case PCFG_TK_HEBREW:     can_be_synthetic = (len <= 12); break;
          }
        }
        else
        {
          switch (raw_type)
          {
            case PCFG_TK_DIGIT:      can_be_synthetic = (len <= 8); break;
            case PCFG_TK_LOWER:
            case PCFG_TK_UPPER:
            case PCFG_TK_SPECIAL:
            case PCFG_TK_PUNCT:
            case PCFG_TK_WHITESPACE: can_be_synthetic = (len <= 5); break;
          }
        }

        if (can_be_synthetic)
        {
          u64 theo = get_theoretical_keyspace (raw_type, len);

          if (theo != UINT64_MAX)
          {
            u64 real = terminals[raw_type][len].cnt;

            if (real < theo)
            {
              // calculation with a 50% cap, we don't want synthetic too frequent
              u64 diff = theo - real;
              u32 threshold = (u32) ((diff * 500) / theo);

              // require at least 10x difference to apply synthetic
              if (theo > real * 10 && (fast_rand_local (&gen->ahf_rng_state) % 1001) < threshold)
              {
                apply_synth = true;
              }
            }
          }
        }

        if (apply_synth)
        {
          s->types[k] |= PCFG_SYNTHETIC_FLAG;
        }

        prev_type    = selected_type;
        current_len += chosen_len;

        p2 = p1;
        p1 = selected_type;

        k++;
      }

      s->token_cnt = k;

      if (generation_failed) continue;
      if (current_len != target_len) continue;
      if (current_len < pw_len_min || current_len > pw_len_max) continue;
      if (use_token_cnt_min && s->token_cnt < (u32) token_cnt_min) continue;
      if (use_token_cnt_max && s->token_cnt > (u32) token_cnt_max) continue;

      // token length validation
      if (use_t_len_min || use_t_len_max)
      {
        bool len_ok = true;

        for (u32 tk = 0; tk < s->token_cnt && len_ok; tk++)
        {
          u8 tlen = s->lengths[tk];

          if (use_t_len_min && tlen < t_len_min) len_ok = false;
          if (use_t_len_max && tlen > t_len_max) len_ok = false;
        }

        if (!len_ok) continue;
      }

      if (check_complexity && !pw_complex_check (s)) continue;

      // Duplicate check
      if (check_unique)
      {
        // fast hash of the structure
        u32 h = 0;

        for (u32 tk = 0; tk < s->token_cnt; tk++)
        {
          h = h * 31 + s->types[tk];
          h = h * 31 + s->lengths[tk];
        }

        h = h * 31 + s->token_cnt;

        u32 bucket = h % HASH_TABLE_SIZE;

        // check duplicates in the chain
        bool dup = false;

        u32 idx = hash_table[bucket];

        while (idx != 0 && !dup)
        {
          pcfg_structure_t *other = &gen->ahf_structures[idx - 1];

          if (other->token_cnt == s->token_cnt)
          {
            bool match = true;

            for (u32 tk = 0; tk < s->token_cnt && match; tk++)
            {
              if (other->types[tk] != s->types[tk] || other->lengths[tk] != s->lengths[tk])
              {
                match = false;
              }
            }

            if (match) dup = true;
          }

          idx = hash_chain[idx];
        }

        if (dup)
        {
          continue;
        }

        // add to hash table
        hash_chain[i + 1] = hash_table[bucket];
        hash_table[bucket] = i + 1;

        // bloom filter check (16MB)
        if (gen->ahf_bloom)
        {
          u64 h64 = hash_structure_signature_xxh64 (s);
          u64 bloom_bits = gen->ahf_bloom_size * 8;
          u64 idx1 = (h64 & 0xFFFFFFFF) % bloom_bits;
          u64 idx2 = (h64 >> 32) % bloom_bits;

          int bit1 = (gen->ahf_bloom[idx1 / 8] >> (idx1 % 8)) & 1;
          int bit2 = (gen->ahf_bloom[idx2 / 8] >> (idx2 % 8)) & 1;

          if (bit1 && bit2) continue;

          gen->ahf_bloom[idx1 / 8] |= (1 << (idx1 % 8));
          gen->ahf_bloom[idx2 / 8] |= (1 << (idx2 % 8));
        }
      }

      unique = true;
    }
    if (!unique)
    {
      gen->ahf_struct_cnt = (i == 0) ? 0 : i;

      if (hash_table) hcfree (hash_table);
      if (hash_chain) hcfree (hash_chain);
      return;
    }

    // update keyspace with overflow check
    u64 ks = 1;

    bool overflow = false;

    for (u32 tk = 0; tk < s->token_cnt && !overflow; tk++)
    {
      u64 mult;

      if (s->types[tk] & PCFG_SYNTHETIC_FLAG)
      {
        mult = 100;
      }
      else
      {
        mult = terminals[s->types[tk] & 0x7F][s->lengths[tk]].cnt;
      }

      // overflow check
      if (ks > UINT64_MAX / mult)
      {
        ks = UINT64_MAX;

        overflow = true;
      }
      else
      {
        ks *= mult;
      }
    }

    s->keyspace = ks;
    s->count = 0;
  }

  if (hash_table) hcfree (hash_table);
  if (hash_chain) hcfree (hash_chain);
}
