/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "timer.h"
#include "filehandling.h"
#include "convert.h"
#include "thread.h"
#include "shared.h"
#include "terminal.h"
#include "bitops.h"
#include "xxhash.h"
#include "pcfg_trainer_utils.h"
#include "pcfg_trainer.h"
#include "pcfg.h"

// comparators (descending)

static int compare_ht_node_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const ht_node_t *na = *(const ht_node_t **) a;
  const ht_node_t *nb = *(const ht_node_t **) b;

  return (nb->cnt > na->cnt) - (nb->cnt < na->cnt);
}

static int compare_term_node_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const term_node_t *na = *(const term_node_t **) a;
  const term_node_t *nb = *(const term_node_t **) b;

  return (nb->cnt > na->cnt) - (nb->cnt < na->cnt);
}

// markov sorting

static int compare_start_rows_entries_desc (const void *a, const void *b, void *arg)
{
  (void) arg;

  const pcfg_markov_start_row_entry_t *ea = (const pcfg_markov_start_row_entry_t *) a;
  const pcfg_markov_start_row_entry_t *eb = (const pcfg_markov_start_row_entry_t *) b;

  return (eb->count > ea->count) - (eb->count < ea->count);
}

// stats

// keyboard walks

#define MAX_LAYOUTS 5

static const char *rows_qwerty[] = { "1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./", NULL };
static const char *rows_azerty[] = { "1234567890-=", "azertyuiop^$", "qsdfghjklm%", "wxcvbn,;:!", NULL };
static const char *rows_qwertz[] = { "1234567890\xDF", "qwertzuiop\xFC+", "asdfghjkl\xF6\xE4#", "<yxcvbnm,.-", NULL };
static const char *rows_keypad[] = { "789", "456", "123", " 0.", NULL };

static keyboard_layout_t layouts[MAX_LAYOUTS] =
{
  { "QWERTY", {{ 0 }}, false, rows_qwerty },
  { "AZERTY", {{ 0 }}, false, rows_azerty },
  { "QWERTZ", {{ 0 }}, false, rows_qwertz },
  { "KEYPAD", {{ 0 }}, false, rows_keypad },
  { NULL,     {{ 0 }}, false, NULL }
};

static void init_single_layout (keyboard_layout_t *layout)
{
  if (layout->initialized) return;

  for (int i = 0; i<256; i++)
  {
    layout->map[i].x = -1;
    layout->map[i].y = -1;
  }

  for (int y = 0; layout->rows[y]; y++)
  {
    const char *row = layout->rows[y];

    for (int x = 0; row[x]; x++)
    {
      unsigned char c = (unsigned char) row[x];

      layout->map[c].x = x;
      layout->map[c].y = y;

      if (isalpha (c))
      {
        layout->map[toupper (c)].x = x;
        layout->map[toupper (c)].y = y;
      }
    }
  }

  layout->initialized = true;
}

static void init_all_layouts (void)
{
  for (int i = 0; layouts[i].name; i++)
  {
    init_single_layout (&layouts[i]);
  }
}

static u32 get_keyboard_span_layout (const char *s, u32 max_len, keyboard_layout_t *layout)
{
  if (max_len < 3) return 0;

  if (s[0] == 0) return 0;

  key_coord_t p1 = layout->map[(unsigned char) s[0]];

  if (p1.x == -1) return 0;

  key_coord_t p2 = layout->map[(unsigned char) s[1]];

  if (p2.x == -1) return 0;

  // delta
  int dx = p2.x - p1.x;
  int dy = p2.y - p1.y;

  // must be adjacent and not the same key
  if (abs (dx) > 1 || abs (dy) > 1 || (dx == 0 && dy == 0)) return 0;

  u32 i = 2;
  key_coord_t prev = p2;

  while (i < max_len)
  {
    key_coord_t curr = layout->map[(unsigned char) s[i]];

    if (curr.x == -1) break;

    int new_dx = curr.x - prev.x;
    int new_dy = curr.y - prev.y;

    // check direction
    if (new_dx != dx || new_dy != dy)
    {
      // don't allow change direction
      break;
    }

    prev = curr;

    i++;
  }

  if (i >= 3) return i;

  return 0;
}

static u32 get_best_keyboard_span (const char *s, u32 max_len)
{
  if (max_len < 4) return 0;

  static bool global_init = false;

  if (!global_init)
  {
    init_all_layouts ();

    global_init = true;
  }

  u32 best_len = 0;

  for (int i = 0; layouts[i].name; i++)
  {
    u32 len = get_keyboard_span_layout (s, max_len, &layouts[i]);

    if (len > best_len)
    {
      best_len = len;
    }
  }

  return best_len;
}

bool is_unicode_script_type (u8 type)
{
  return (type == PCFG_TK_LATIN_EXT || type == PCFG_TK_CYRILLIC || type == PCFG_TK_ARABIC ||
          type == PCFG_TK_ASIAN     || type == PCFG_TK_GREEK    || type == PCFG_TK_HEBREW);
}

// raw versions used only to populate the LUT
static bool is_punct_raw (char c)
{
  return (strchr (PCFG_CHARS_PUNCT, c) != NULL);
}

static bool is_symbol_raw (char c)
{
  return (strchr (PCFG_CHARS_SPECIAL, c) != NULL);
}

static bool is_whitespace_raw (char c)
{
  return (strchr (PCFG_CHARS_WHITE, c) != NULL);
}

static inline bool is_year (const char *s, u32 len)
{
  if (len != 4) return false;

  for (int i = 0; i < 4; i++)
  {
    if (!isdigit ((unsigned char) s[i])) return false;
  }

  int y = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');

  return (y >= 1900 && y <= 2050);
}

// bitmask for each ASCII character
static u16 char_types_lut[256];

void init_char_types_lut (void)
{
  memset (char_types_lut, 0, sizeof (char_types_lut));

  for (int i = 0; i < 256; i++)
  {
    u16 mask = 0;

    // standard ASCII
    if (isdigit ((unsigned char) i)) mask |= (1 << 0);
    if (islower ((unsigned char) i)) mask |= (1 << 1);
    if (isupper ((unsigned char) i)) mask |= (1 << 2);
    if (is_symbol_raw ((char) i))     mask |= (1 << 3);
    if (is_punct_raw ((char) i))      mask |= (1 << 4);
    if (is_whitespace_raw ((char) i)) mask |= (1 << 5);

    // unicode
    if (i > 127)
    {
      mask |= 0x8000; // generic flag

      // continuation bytes
      if (i <= 0xBF)
      {
        mask |= (1 <<  6); // Latin Ext
        mask |= (1 <<  7); // cyrillic
        mask |= (1 <<  8); // arabic
        mask |= (1 <<  9); // asian
        mask |= (1 << 10); // emoji
        mask |= (1 << 11); // Greek
        mask |= (1 << 12); // Hebrew
      }

      // lead bytes

      if (i >= 0xc2 && i <= 0xc5) mask |= (1 << 6);
      if (i >= 0xce && i <= 0xcf) mask |= (1 << 11);
      if (i >= 0xd0 && i <= 0xd3) mask |= (1 << 7);
      if (i >= 0xd6 && i <= 0xd7) mask |= (1 << 12);
      if (i >= 0xd8 && i <= 0xdb) mask |= (1 << 8);
      if (i >= 0xe0 && i <= 0xef)
      {
        mask |= (1 <<  9); // asian ...
        mask |= (1 << 10); // ... but also Emoji
      }
      if (i >= 0xf0 && i <= 0xf7) mask |= (1 << 10);
    }

    char_types_lut[i] = mask;
  }
}

// LUT-accelerated versions used everywhere in the tokenizer
static inline bool is_punct (char c)
{
  return (char_types_lut[(unsigned char) c] & (1 << 4)) != 0;
}

static inline bool is_symbol (char c)
{
  return (char_types_lut[(unsigned char) c] & (1 << 3)) != 0;
}

static inline bool is_whitespace (char c)
{
  return (char_types_lut[(unsigned char) c] & (1 << 5)) != 0;
}

static u16 get_mask_for_type (u8 type)
{
  switch (type & 0x7F)
  {
    case PCFG_TK_DIGIT:       return (1 <<  0);
    case PCFG_TK_LOWER:       return (1 <<  1);
    case PCFG_TK_UPPER:       return (1 <<  2);
    case PCFG_TK_SPECIAL:     return (1 <<  3);
    case PCFG_TK_PUNCT:       return (1 <<  4);
    case PCFG_TK_WHITESPACE:  return (1 <<  5);
    case PCFG_TK_YEAR:        return (1 <<  0);
    case PCFG_TK_CAPITALIZED: return (1 <<  1); // as lower
    // unicode
    case PCFG_TK_LATIN_EXT:   return (1 <<  6);
    case PCFG_TK_CYRILLIC:    return (1 <<  7);
    case PCFG_TK_ARABIC:      return (1 <<  8);
    case PCFG_TK_ASIAN:       return (1 <<  9);
    case PCFG_TK_EMOJI:       return (1 << 10);
    case PCFG_TK_GREEK:       return (1 << 11);
    case PCFG_TK_HEBREW:      return (1 << 12);

    case PCFG_TK_UNICODE:     return 0x8000; // fallback
    default:                  return 0xFFFF;
  }
}

static inline pcfg_token_type_t classify_alpha (const char *s, u32 len)
{
  bool has_upper = false;
  bool has_lower = false;
  bool has_junk  = false; // ! A-Z o a-z

  bool first_upper = isupper ((unsigned char) s[0]);
  bool rest_lower = true;

  for (u32 i = 0; i < len; i++)
  {
    unsigned char c = (unsigned char) s[i];

    if (isupper (c)) has_upper = true;
    else if (islower (c)) has_lower = true;
    else has_junk = true;

    // check Capitalized: from the second char onwards must be lower
    if (i > 0)
    {
      if (!islower (c)) rest_lower = false;
    }
  }

  if (has_junk) return PCFG_TK_MIXED;

  if (has_upper && has_lower)
  {
    if (first_upper && rest_lower && len > 1)
    {
      return PCFG_TK_CAPITALIZED; // "Super"
    }

    return PCFG_TK_MIXED; // "sUpEr"
  }

  return has_upper ? PCFG_TK_UPPER : PCFG_TK_LOWER;
}

static u32 get_alpha_span_classified (const char *s, u32 max_len, pcfg_token_type_t *out_type)
{
  if (s == NULL || max_len == 0) { *out_type = PCFG_TK_MIXED; return 0; }

  u32 run;

  if (isupper ((unsigned char) s[0]))
  {
    if (max_len == 1) { *out_type = PCFG_TK_UPPER; return 1; }

    if (islower ((unsigned char) s[1]))
    {
      // Capitalized: Uppercase + lowercase run
      run = 2;

      while (run < max_len && islower ((unsigned char) s[run])) run++;

      *out_type = PCFG_TK_CAPITALIZED;
      return run;
    }

    if (isupper ((unsigned char) s[1]))
    {
      // All-upper run, possibly ending at camelCase boundary
      run = 2;

      while (run < max_len && isupper ((unsigned char) s[run])) run++;

      if (run == max_len) { *out_type = PCFG_TK_UPPER; return run; }

      if (islower ((unsigned char) s[run]))
      {
        u32 span = (run > 2) ? run - 1 : run;

        *out_type = PCFG_TK_UPPER;
        return span;
      }

      *out_type = PCFG_TK_UPPER;
      return run;
    }

    // single uppercase not followed by alpha
    *out_type = PCFG_TK_UPPER;
    return 1;
  }

  if (islower ((unsigned char) s[0]))
  {
    run = 1;

    while (run < max_len && islower ((unsigned char) s[run])) run++;

    *out_type = PCFG_TK_LOWER;
    return run;
  }

  // non-alpha leading char
  *out_type = PCFG_TK_MIXED;
  return 1;
}

static u32 get_email_span (const char *s, u32 max_len)
{
  if (max_len < 5) return 0;

  if (s[0] != '@') return 0;

  u32 domain_span = get_domain_span (s + 1, max_len - 1);

  if (domain_span == 0) return 0;

  return domain_span + 1;
}

static u32 get_repeat_span (const char *s, u32 max_len)
{
  if (max_len < 3) return 0;

  u32 run = 1;
  while (run < max_len && s[run] == s[0]) run++;

  // we only classify as 'R' if the same character repeats
  if (run >= 3) return run;

  return 0;
}

static u32 get_sequence_span (const char *s, u32 max_len)
{
  if (max_len < 3) return 0;

  // check Forward (+1)
  u32 i = 1;
  while (i < max_len)
  {
    if ((unsigned char) s[i] != (unsigned char) s[i-1] + 1) break;
    i++;
  }

  if (i >= 3) return i;

  // check Backward (-1) (es. "321", "cba")
  i = 1;
  while (i < max_len)
  {
    if ((unsigned char) s[i] != (unsigned char) s[i-1] - 1) break;
    i++;
  }

  if (i >= 3) return i;

  return 0;
}

static int get_utf8_type (const char *p, u32 rem_len, int *char_len)
{
  unsigned char c = (unsigned char) p[0];

  if (c < 128)
  {
    *char_len = 1;

    return 0; // aSCII
  }

  // eMOJI 4-byte (J)
  if ((c & 0xF8) == 0xF0)
  {
    if (rem_len >= 4 &&
       ((unsigned char) p[1] & 0xC0) == 0x80 &&
       ((unsigned char) p[2] & 0xC0) == 0x80 &&
       ((unsigned char) p[3] & 0xC0) == 0x80)
    {
      *char_len = 4;

      return 1;
    }
  }

  // 3-byte sequence (UTF-8: 1110xxxx 10xxxxxx 10xxxxxx)
  if ((c & 0xF0) == 0xE0)
  {
    if (rem_len >= 3 &&
       ((unsigned char) p[1] & 0xC0) == 0x80 &&
       ((unsigned char) p[2] & 0xC0) == 0x80)
    {
      *char_len = 3;

      unsigned char b1 = (unsigned char) p[1];
      unsigned char b2 = (unsigned char) p[2];

      // range E0: South/SE Asian Scripts
      // thai, Devanagari (Hindi), Bengali, etc.
      if (c == 0xE0) return 6; // 'H' Asian

      // range E1: Various Scripts & Extended Alpha
      if (c == 0xE1)
      {
        // e1 B8 80 - E1 B9 BF: Latin Extended Additional
        if (b1 >= 0xB8 && b1 <= 0xB9) return 2; // 'A' Latin Ext

        // e1 BA 80 - E1 BB BF: Latin Extended Additional (cont)
        if (b1 >= 0xBA && b1 <= 0xBB) return 2; // 'A' Latin Ext

        // e1 BC 80 - E1 BF BF: Greek Extended
        if (b1 >= 0xBC && b1 <= 0xBF) return 5; // 'G' Greek

        // fallback for E1: Myanmar, Khmer, Georgian, Ethiopian, etc.
        return 6; // 'H' Asian
      }

      // range E2: Symbols, Punctuation and Shapes
      if (c == 0xE2)
      {
        // e2 80 80 - E2 81 BF: General Punctuation, Superscripts, Subscripts
        if (b1 == 0x80 || b1 == 0x81) return 4; // 'X' Generic Unicode

        // e2 82 xx = Currency Symbols: €, ₤, ₹, ₩, etc. (U+20A0-U+20CF)
        // we return 3 ('S' Special) because these are functional symbols in passwords
        if (b1 == 0x82) return 9; // 'S' Special Characters

        // e2 83 xx - E2 85 xx: Diacritics, Letterlike, Fractions
        if (b1 >= 0x83 && b1 <= 0x85) return 4; // 'X'

        // e2 86 xx - E2 87 xx: Arrows
        if (b1 == 0x86 || b1 == 0x87) return 1; // 'J' Emoji/Symbols

        // e2 88 xx - E2 95 xx: Math, Technical, OCR, Box Drawing
        if (b1 >= 0x88 && b1 <= 0x95) return 4; // 'X'

        // e2 96 xx - E2 9F xx: Geometric Shapes, Dingbats, Symbols
        // these are frequently used as "Emoji-like" decorations
        if (b1 >= 0x96 && b1 <= 0x9F) return 1; // 'J' Emoji

        return 4; // 'X' Default for E2
      }

      // range E3: CJK Symbols and Radicals
      if (c == 0xE3) return 6; // 'H' Asian

      // range E4 - E9: CJK Unified Ideographs (Chinese, Japanese Kanji)
      if (c >= 0xE4 && c <= 0xE9) return 6; // 'H' Asian

      // range EA - ED: Hangul (Korean) and others
      if (c >= 0xEA && c <= 0xED) return 6; // 'H' Asian

      // range EE: Private Use Area
      if (c == 0xEE) return 4; // 'X' Generic Unicode

      // range EF: Specials and Halfwidth forms
      if (c == 0xEF)
      {
        // variation selectors (Emoji modifiers)
        if (b1 == 0xB8 && (b2 == 0x8E || b2 == 0x8F)) return 1; // 'J' Emoji

        // eF BF BD = Replacement Character (GARBAGE)
        if (b1 == 0xBF && b2 == 0xBD) return -1;

        // eF BF BE/BF = Non-characters (GARBAGE)
        if (b1 == 0xBF && (b2 == 0xBE || b2 == 0xBF)) return -1;

        return 4; // 'X' Default for EF
      }

      return 6; // 'H' Asian as final fallback for 3-byte sequences
    }
  }

  // 2-byte seq (Accents, Cyrillic, Arabic)
  if ((c & 0xE0) == 0xC0)
  {
    if (rem_len >= 2 && ((unsigned char) p[1] & 0xC0) == 0x80)
    {
      *char_len = 2;

      unsigned char b1 = (unsigned char) p[1];

      // LATIN-1 SUPPLEMENT / EXTENDED
      if (c == 0xC2)
      {
        // c2 80 - C2 A0: Control chars and non-breaking space (usually garbage)
        if (b1 <= 0xA0) return 4; // 'X' Generic Unicode

        // c2 A1 - C2 BF: Symbols and Currencies (£, §, ©, ®, °, ±, etc.)
        // these are logically SPECIAL characters
        return 9; // 'S' Special Characters
      }

      // c3 = Latin-1 Supplement Letters (àáâãäå, èéêë, etc.)
      // c4-C5 = Latin Extended-A (Eastern European)
      if (c >= 0xC3 && c <= 0xC5) return 2; // 'A' Latin Ext (Purely Letters)

      // c6-C7 = Latin Extended-B
      if (c == 0xC6 || c == 0xC7) return 2; // 'A'

      // c8-CB = Latin Extended-B, IPA, Spacing Modifiers
      if (c >= 0xC8 && c <= 0xCB) return 2; // 'A' (or 'X' if you prefer)

      // cC-CD = Combining Diacritical Marks
      if (c == 0xCC || c == 0xCD) return 4; // 'X' (usually garbage when standalone)

      // GREEK (G)
      // cE-CF = Greek and Coptic
      if (c == 0xCE || c == 0xCF) return 7; // 'G'

      // CYRILLIC (I)
      // D0-D3 = Cyrillic
      if (c >= 0xD0 && c <= 0xD3) return 3; // 'I'

      // D4 = Armenian
      if (c == 0xD4) return 4; // 'X' (or create separate type)

      // D5 = Armenian continued
      if (c == 0xD5) return 4; // 'X'

      // HEBREW (V)
      // D6-D7 = Hebrew
      if (c == 0xD6 || c == 0xD7) return 8; // 'V'

      // ARABIC (B)
      // D8-DB = Arabic
      if (c >= 0xD8 && c <= 0xDB) return 5; // 'B'

      // DC-DF = Syriac, Arabic Supplement, Thaana, NKo
      if (c >= 0xDC && c <= 0xDF) return 5; // 'B' or 'X'

      return 4; // 'X' generic unicode for other 2-byte
    }
  }

  // fallback
  *char_len = 1;

  return 4; // unicode (X)
}

static int calc_optimal_sizes (hashcat_ctx_t *hashcat_ctx, const char *filepath, pcfg_trainer_t *t, u64 *admit_bytes_out)
{
  user_options_t *user_options = hashcat_ctx->user_options;

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
  double multiplier = (is_desktop_environment ()) ? 0.90 : 0.98;

  if (available_memory > reserve)
  {
    safe_ram_budget = (u64) ((available_memory - reserve) * multiplier);
  }
  else
  {
    safe_ram_budget = available_memory / 2;
  }

  t->memory_limit = safe_ram_budget;

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: counting lines in %s ... ", filepath);

  if (filepath)
  {
    HCFILE fp;

    if (hc_fopen (&fp, filepath, "rb") == true)
    {
      t->file_lines = count_lines (&fp);

      hc_fclose (&fp);
    }
  }

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: counting lines in %s done: %" PRIu64 "", filepath, t->file_lines);

  if (t->file_lines == 0)
  {
    event_log_error (hashcat_ctx, "PCFG: Training file (%s) is empty or unreadable.", filepath);
    return -1;
  }

  // average length of a password/terminal string estimated
  const u32 avg_string_len = 16;

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
  bool big_file       = (t->file_lines > 5000000ULL);

  bool use_filter = ram_pressure || big_file;

  if (disable_filter == true)
  {
    use_filter = false;

    if (ram_pressure)
    {
      event_log_warning (hashcat_ctx, "PCFG: Admission Filter is disabled by user.");
      event_log_warning (hashcat_ctx, "If you run out of memory, do not use --pcfg-train-af-disable.");
    }
  }

  *admit_bytes_out = 0;

  if (use_filter)
  {
    u64 filter_target = t->file_lines * 4;

    u64 min_filter =   64ULL * 1024 * 1024;   // min 64MB
    u64 max_filter = 2048ULL * 1024 * 1024; // max 2GB

    // set Cap to 7%
    u64 ram_cap = safe_ram_budget / 7;

    if (max_filter > ram_cap) max_filter = ram_cap;

    if (filter_target < min_filter) filter_target = min_filter;
    if (filter_target > max_filter) filter_target = max_filter;

    // must be power of 2
    *admit_bytes_out = next_power_of_two_64 (filter_target);
  }

  // handle ht_size

  u64 ht_ram_budget = safe_ram_budget / 5;
  u64 ptr_size = sizeof (void *);

  // target Bucket Count

  u64 target_buckets = 0;

  if (use_filter)
  {
    target_buckets = t->file_lines / 5;
  }
  else
  {
    target_buckets = t->file_lines * 2;
  }

  // min 1 Mil of buckets
  if (target_buckets < 1000000) target_buckets = 1000000;

  // 64M buckets = 512MB ptrs
  u64 max_reasonable_buckets = 256ULL * 1024 * 1024;

  if (target_buckets > max_reasonable_buckets)
  {
    target_buckets = max_reasonable_buckets;
  }

  while ((target_buckets * ptr_size) > ht_ram_budget)
  {
    target_buckets /= 2;
  }

  u64 table_cost_per_bucket = 16;
  u64 max_table_ram = safe_ram_budget / 4;

  u64 max_buckets = max_table_ram / table_cost_per_bucket;

  if (target_buckets > max_buckets)
  {
    target_buckets = max_buckets;
  }

  t->ht_size = next_power_of_two_64 (target_buckets);

  // pool size
  if      (safe_ram_budget > 8ULL * 1024 * 1024 * 1024) t->pool_block_size = 16 * 1024 * 1024; // 16MB (High end)
  else if (safe_ram_budget > 2ULL * 1024 * 1024 * 1024) t->pool_block_size =  4 * 1024 * 1024;  // 4MB (Mid range)
  else                                                  t->pool_block_size =  1 * 1024 * 1024;  // 1MB (Low end / 8GB tot)

  return 0;
}

static inline bool cbf_increment_and_check (pcfg_trainer_t *t, u64 h, u16 filter_threshold)
{
  if (!t->admit_counters || t->admit_mask == 0) return true;

  const u64 h2 = rotl64 (h, 33);

  const u8 MAX_COUNT = 15;

  u8 min_count = MAX_COUNT;

  for (int i = 0; i < 3; i++)
  {
    u64 pos = (h + i * h2) & t->admit_mask;

    u64 byte_idx = pos >> 1;
    u8  shift    = (pos & 1) << 2;
    u8 byte_val  = t->admit_counters[byte_idx];

    u8 cnt = (byte_val >> shift) & 0x0F;

    if (cnt < MAX_COUNT)
    {
      cnt++;

      t->admit_counters[byte_idx] = (byte_val & ~(0x0F << shift)) | (cnt << shift);
    }

    if (cnt < min_count) min_count = cnt;
  }

  return (min_count >= filter_threshold);
}

static size_t pcfg_build_pattern (const u8 *types, const u8 *lengths, u32 cnt, char *out)
{
  int pos = 0;

  for (u32 i = 0; i < cnt; i++)
  {
    if (pos >= (PCFG_PATTERN_MAX - 5)) break;

    char type_char = types[i] & 0x7F;

    int written = snprintf (out + pos, PCFG_PATTERN_MAX - pos, "%c%u", type_char, lengths[i]);

    if (written < 0 || written >= (PCFG_PATTERN_MAX - pos)) break;

    pos += written;
  }

  out[pos] = '\0';

  return (size_t) pos;
}

static void *pool_alloc (pcfg_trainer_t *t, size_t size)
{
  // align to 8 bytes
  size = (size + 7) & ~7;

  if (!t->pool_head || t->pool_head->offset + size > t->pool_head->size)
  {
    size_t block_size = (size > t->pool_block_size) ? size : t->pool_block_size;

    if (t->memory_used + block_size > t->memory_limit)
    {
      // memory is full, don't add
      static bool warned = false;

      if (!warned)
      {
        fprintf (stderr, "\nPCFG: Memory limit reached (%" PRIu64 " GB). Stop learning new terminals.\n", t->memory_limit >> 30);
        warned = true;
      }
      return NULL;
    }

    mem_pool_t *new_pool = hccalloc (1, sizeof (mem_pool_t));

    if (!new_pool) return NULL;

    new_pool->ptr = hcmalloc (block_size);

    if (!new_pool->ptr)
    {
      hcfree (new_pool);
      return NULL;
    }

    new_pool->size = block_size;
    new_pool->offset = 0;
    new_pool->next = t->pool_head;

    t->pool_head = new_pool;

    t->memory_used += block_size + sizeof (mem_pool_t);
  }

  void *ret = t->pool_head->ptr + t->pool_head->offset;

  t->pool_head->offset += size;

  return ret;
}

static int pcfg_tokenize (const char *pw, u32 pw_len, u8 *types, u8 *lengths, u32 *token_cnt, char values[][PCFG_VALUE_MAX])
{
  *token_cnt = 0;

  u32 pos = 0;

  while (pos < pw_len && *token_cnt < PCFG_TOKEN_MAX)
  {
    const char *cur = pw + pos;

    u32 rem = pw_len - pos;
    u32 idx = *token_cnt;

    // check year
    if (rem >= 4 && is_year (cur, 4))
    {
      types[idx] = PCFG_TK_YEAR;
      lengths[idx] = 4;

      memcpy (values[idx], cur, 4);
      values[idx][4] = 0;

      pos += 4;
      (*token_cnt)++;
      continue;
    }

    // check Email
    u32 email_len = get_email_span (cur, rem);
    if (email_len > 0)
    {
      if (email_len >= PCFG_VALUE_MAX) email_len = PCFG_VALUE_MAX - 1;

      types[idx] = PCFG_TK_EMAIL;
      lengths[idx] = (u8) email_len;

      memcpy (values[idx], cur, email_len);
      values[idx][email_len] = 0;

      pos += email_len;
      (*token_cnt)++;
      continue;
    }

    // check repeats
    u32 rep_len = get_repeat_span (cur, rem);
    if (rep_len > 0)
    {
      if (rep_len >= PCFG_VALUE_MAX) rep_len = PCFG_VALUE_MAX - 1;

      types[idx] = PCFG_TK_REPEAT;
      lengths[idx] = (u8) rep_len;

      memcpy (values[idx], cur, rep_len);
      values[idx][rep_len] = 0;

      pos += rep_len;
      (*token_cnt)++;
      continue;
    }

    // check Keyboard Walk (no digits)
    u32 kb_len = get_best_keyboard_span (cur, rem);
    if (kb_len > 0)
    {
      // check if the detected walk is purely numeric
      bool all_digits = true;
      for (u32 i = 0; i < kb_len; i++)
      {
        if (!isdigit ((unsigned char)cur[i]))
        {
          all_digits = false;
          break;
        }
      }

      // if it contains at least one letter/symbol, it's a real keyboard walk (e.g., 'qwe' or 'asd')
      // if it's all digits (e.g., '123'), we skip this block so it can be handled as a DIGIT token later
      if (all_digits == false)
      {
        if (kb_len >= PCFG_VALUE_MAX) kb_len = PCFG_VALUE_MAX - 1;

        types[idx] = PCFG_TK_KEYBOARD;
        lengths[idx] = (u8) kb_len;

        memcpy (values[idx], cur, kb_len);
        values[idx][kb_len] = 0;

        pos += kb_len;
        (*token_cnt)++;
        continue;
      }
    }

    // check Sequence
    u32 seq_len = get_sequence_span (cur, rem);
    if (seq_len > 0)
    {
      if (seq_len >= PCFG_VALUE_MAX) seq_len = PCFG_VALUE_MAX - 1;

      types[idx] = PCFG_TK_SEQUENCE;
      lengths[idx] = (u8) seq_len;

      memcpy (values[idx], cur, seq_len);
      values[idx][seq_len] = 0;

      pos += seq_len;
      (*token_cnt)++;
      continue;
    }

    // check Mixed
    if (isalnum ((unsigned char) cur[0]))
    {
      u32 span = 0;
      u32 transitions = 0;
      int last_type = -1; // 0=alpha, 1=digit, 2=special/punct
      u32 alnum_count = 0;

      while (span < rem)
      {
        unsigned char ch = (unsigned char) cur[span];
        int cur_type;

        if (ch > 127) break;

        if (isdigit (ch))
        {
          cur_type = 1;
          alnum_count++;
        }
        else if (isalpha (ch))
        {
          cur_type = 0;
          alnum_count++;
        }
        else if (is_punct (ch) || is_symbol (ch))
        {
          break; // stop immediately on any symbol, punctuation or space
          cur_type = 2;
        }
        else
        {
          break;
        }

        if (last_type != -1 && cur_type != last_type)
        {
          transitions++;
        }

        last_type = cur_type;
        span++;

        if (span >= PCFG_VALUE_MAX - 1) break;
      }

      // requires at least 3 transitions (e.g., 'a1b2' or '12a3b')
      // this forces 'Firenze19' (1 transition) to be split into C7 + D2
      if (span >= 5 && transitions >= 3 && alnum_count == span)
      {
        types[idx] = PCFG_TK_MIXED;
        lengths[idx] = (u8) span;

        memcpy (values[idx], cur, span);
        values[idx][span] = 0;

        pos += span;
        (*token_cnt)++;
        continue;
      }
    }

    // same type sequence
    char c = cur[0];
    u32 run = 1;

    // emoji/Unicode/Extended ... sequence
    if ((unsigned char) c > 127)
    {
      int clen = 0;
      int first_type = get_utf8_type (cur, rem, &clen);

      // check for garbage marker from get_utf8_type
      if (first_type == -1)
      {
        // skip this byte and continue
        pos++;
        continue;
      }

      if (clen <= 0)
      {
        pos++;
        continue;
      }

      run = clen;

      while (run < rem)
      {
        unsigned char next_byte = (unsigned char) cur[run];

        // stop at ASCII
        if (next_byte < 128) break;

        // check for stray continuation byte (shouldn't happen in valid UTF-8)
        // a continuation byte (10xxxxxx) without a proper lead byte is invalid
        if ((next_byte & 0xC0) == 0x80)
        {
          // this might be a malformed sequence, skip it
          break;
        }

        int next_clen = 0;
        int next_type = get_utf8_type (cur + run, rem - run, &next_clen);

        // stop on garbage or type change
        if (next_type == -1) break;
        if (next_type != first_type) break;
        if (next_clen <= 0) break;

        run += next_clen;

        if (run >= PCFG_VALUE_MAX - 1) break;
      }

      // assign type
      switch (first_type)
      {
        case 1:  types[idx] = PCFG_TK_EMOJI;     break; // 'J'
        case 2:  types[idx] = PCFG_TK_LATIN_EXT; break; // 'A'
        case 3:  types[idx] = PCFG_TK_CYRILLIC;  break; // 'I'
        case 4:  types[idx] = PCFG_TK_UNICODE;   break; // 'X'
        case 5:  types[idx] = PCFG_TK_ARABIC;    break; // 'B'
        case 6:  types[idx] = PCFG_TK_ASIAN;     break; // 'H'
        case 7:  types[idx] = PCFG_TK_GREEK;     break; // 'G'
        case 8:  types[idx] = PCFG_TK_HEBREW;    break; // 'V'
        case 9:  types[idx] = PCFG_TK_SPECIAL;   break; // 'S'
        default: types[idx] = PCFG_TK_UNICODE;   break; // 'X' fallback
      }
    }
    else if (is_whitespace (c))
    {
      while (run < rem && is_whitespace (cur[run])) run++;
      types[idx] = PCFG_TK_WHITESPACE;
    }
    else if (is_punct (c))
    {
      while (run < rem && is_punct (cur[run])) run++;
      types[idx] = PCFG_TK_PUNCT;
    }
    else if (is_symbol (c))
    {
      while (run < rem && is_symbol (cur[run])) run++;
      types[idx] = PCFG_TK_SPECIAL;
    }
    else if (isdigit ((unsigned char) c))
    {
      while (run < rem && isdigit ((unsigned char) cur[run])) run++;
      types[idx] = PCFG_TK_DIGIT;
    }
    else if (isalpha ((unsigned char) c))
    {
      pcfg_token_type_t alpha_type;

      run = get_alpha_span_classified (cur, rem, &alpha_type);

      types[idx] = alpha_type;

      // capitalized requires at least 2 chars (first upper + rest lower)
      // single uppercase letter should be classified as Upper
      if (types[idx] == PCFG_TK_CAPITALIZED && run < 2)
      {
        types[idx] = PCFG_TK_UPPER;
      }

    }
    else
    {
      // skip control characters (0x00-0x1F) — they have no business in password tokens
      // tab (0x09) and space (0x20) are already caught by is_whitespace above
      if ((unsigned char) c < 0x20)
      {
        pos++;
        continue;
      }

      // all other to Special
      run = 1;
      types[idx] = PCFG_TK_SPECIAL;
    }

    lengths[idx] = (run < PCFG_VALUE_MAX) ? run : PCFG_VALUE_MAX - 1;

    memcpy (values[idx], cur, lengths[idx]);
    values[idx][lengths[idx]] = 0;

    pos += run;
    (*token_cnt)++;
  }

  // main merge loop
  for (u32 i = 0; i + 1 < *token_cnt; )
  {
    bool merge = false;

    // define flags for the current and next token
    bool t1_alpha = (types[i]   == PCFG_TK_LOWER || types[i] == PCFG_TK_UPPER || types[i] == PCFG_TK_CAPITALIZED || types[i] == PCFG_TK_MIXED);
    bool t2_alpha = (types[i+1] == PCFG_TK_LOWER || types[i+1] == PCFG_TK_UPPER || types[i+1] == PCFG_TK_CAPITALIZED || types[i+1] == PCFG_TK_MIXED);
    bool t1_digit = (types[i]   == PCFG_TK_DIGIT);
    bool t2_digit = (types[i+1] == PCFG_TK_DIGIT);
    bool t1_sym   = (types[i]   == PCFG_TK_SPECIAL || types[i] == PCFG_TK_PUNCT);
    bool t2_sym   = (types[i+1] == PCFG_TK_SPECIAL || types[i+1] == PCFG_TK_PUNCT);

    // alpha + Alpha Consolidation
    if (t1_alpha && t2_alpha)
    {
      // Do not merge if they are the exact same word/block (len > 2)
      // this preserves patterns like "CiaoCiao" as [C4][C4] instead of [C8]
      if (lengths[i] == lengths[i+1] && lengths[i] > 2 && memcmp (values[i], values[i+1], lengths[i]) == 0)
      {
        merge = false;
      }
      else
      {
        merge = true;
      }
    }

    // Digit + Digit Consolidation
    else if (t1_digit && t2_digit)
    {
      // same protection for numbers (e.g., "123123" stays [D3][D3])
      if (lengths[i] == lengths[i+1] && lengths[i] > 2 && memcmp (values[i], values[i+1], lengths[i]) == 0)
      {
        merge = false;
      }
      else
      {
        merge = true;
      }
    }

    // symbol + Symbol -> Always Merge (Keep symbols together)
    else if (t1_sym && t2_sym) merge = true;

    // merge different types only if we have at least 3 tiny fragments in a row (len <= 2).
    else if (lengths[i] <= 2 && lengths[i+1] <= 2)
    {
      if (i + 2 < *token_cnt && lengths[i+2] <= 2)
      {
        merge = true;
      }
    }

    if (merge)
    {
      u32 nlen = lengths[i] + lengths[i+1];
      if (nlen < PCFG_VALUE_MAX)
      {
        memcpy (values[i] + lengths[i], values[i+1], lengths[i+1]);
        values[i][nlen] = 0;
        lengths[i] = (u8)nlen;

        // final classification: Use classify_alpha to keep L, U, C pure
        if (t1_alpha && t2_alpha)
          types[i] = classify_alpha (values[i], lengths[i]);
        else if (t1_digit && t2_digit)
          types[i] = PCFG_TK_DIGIT;
        else if (t1_sym && t2_sym)
          types[i] = (types[i] == PCFG_TK_SPECIAL || types[i+1] == PCFG_TK_SPECIAL) ? PCFG_TK_SPECIAL : PCFG_TK_PUNCT;
        else
          types[i] = PCFG_TK_MIXED;

        // shift the remaining tokens array
        for (u32 j = i + 1; j + 1 < *token_cnt; j++)
        {
          types[j] = types[j+1];
          lengths[j] = lengths[j+1];

          memcpy (values[j], values[j+1], PCFG_VALUE_MAX);
        }

        (*token_cnt)--;
        continue;
      }
    }
    i++;
  }

  return 0;
}

pcfg_trainer_t *pcfg_trainer_init (hashcat_ctx_t *hashcat_ctx, const char *train_file, u64 min_elements)
{
  pcfg_trainer_t *t = (pcfg_trainer_t *) hccalloc (1, sizeof (pcfg_trainer_t));

  if (!t) return NULL;

  u64 admit_bytes = 0;

  if (calc_optimal_sizes (hashcat_ctx, train_file, t, &admit_bytes) != 0) return NULL;

  // using base model size as target

  // target HT size = elements * 1.5 (per load factor < 0.7) or elements
  if (min_elements > 0)
  {
    u64 target_size = min_elements * 2;

    u64 max_ram_for_tables = 16ULL * 1024 * 1024 * 1024; // 16 GB Hard Limit

    // if t->memory_limit is small (ex. 4GB on 8GB system), reduction
    if (t->memory_limit < 32ULL * 1024 * 1024 * 1024)
    {
      max_ram_for_tables = t->memory_limit / 4;
    }

    u64 ptr_size    = sizeof (void *);
    u64 max_buckets = max_ram_for_tables / (ptr_size * 2); // 2 tables

    // set the cap
    if (target_size > max_buckets)
    {
      target_size = max_buckets;
    }

    u64 final_size = next_power_of_two_64 (target_size);

    if (final_size > max_buckets && final_size > 1024) final_size /= 2;

    if (final_size > t->ht_size)
    {
      t->ht_size = final_size;
    }
  }

  if (admit_bytes > 0)
  {
    t->admit_counters = (u8 *) hccalloc ((size_t) admit_bytes, 1);
  }

  if (t->admit_counters)
  {
    t->admit_mask = (admit_bytes * 2) - 1;
  }
  else
  {
    t->admit_mask = 0;
  }

  t->struct_ht = (ht_node_t **) hccalloc (t->ht_size, sizeof (ht_node_t *));
  t->global_term_ht = (term_node_t **) hccalloc (t->ht_size, sizeof (term_node_t *));

  if (!t->struct_ht || !t->global_term_ht)
  {
    if (t->struct_ht) hcfree (t->struct_ht);
    if (t->global_term_ht) hcfree (t->global_term_ht);

    hcfree (t);
    return NULL;
  }

  t->struct_start_counts        = (u64 *) hccalloc (256, sizeof (u64));
  t->struct_trans_counts        = (u64 *) hccalloc (65536 * 256, sizeof (u64));
  t->markov_start_alpha         = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_start_alpha_unicode = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_start_digit         = (u64 *) hccalloc (65536, sizeof (u64));
  t->markov_table               = (u64 *) hccalloc (10ULL * 65536 * 256, sizeof (u64));
  t->char_freq                  = (u64 *) hccalloc (65536, sizeof (u64));

  if (!t->struct_start_counts || !t->struct_trans_counts || !t->markov_start_alpha || !t->markov_start_alpha_unicode || !t->markov_start_digit || !t->markov_table || !t->char_freq)
  {
    if (t->struct_ht) hcfree (t->struct_ht);
    if (t->global_term_ht) hcfree (t->global_term_ht);

    if (t->struct_start_counts) hcfree (t->struct_start_counts);
    if (t->struct_trans_counts) hcfree (t->struct_trans_counts);
    if (t->markov_start_alpha) hcfree (t->markov_start_alpha);
    if (t->markov_start_alpha_unicode) hcfree (t->markov_start_alpha_unicode);
    if (t->markov_start_digit) hcfree (t->markov_start_digit);
    if (t->markov_table) hcfree (t->markov_table);
    if (t->char_freq) hcfree (t->char_freq);

    hcfree (t);
    return NULL;
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

  t->memory_used = ht_mem + admit_bytes +  t->pool_block_size + markov_mem;

  return t;
}

void pcfg_trainer_destroy (pcfg_trainer_t *t)
{
  if (!t) return;

  if (t->struct_ht) hcfree (t->struct_ht);

  t->struct_ht = NULL;

  if (t->global_term_ht) hcfree (t->global_term_ht);

  t->global_term_ht = NULL;

  mem_pool_t *p = t->pool_head;

  while (p)
  {
    mem_pool_t *n = p->next;

    hcfree (p->ptr);
    hcfree (p);

    p = n;
  }

  if (t->admit_counters) hcfree (t->admit_counters);

  t->admit_counters = NULL;
  t->admit_mask = 0;

  if (t->struct_start_counts) hcfree (t->struct_start_counts);
  if (t->struct_trans_counts) hcfree (t->struct_trans_counts);
  if (t->markov_start_alpha) hcfree (t->markov_start_alpha);
  if (t->markov_start_alpha_unicode) hcfree (t->markov_start_alpha_unicode);
  if (t->markov_start_digit) hcfree (t->markov_start_digit);
  if (t->markov_table) hcfree (t->markov_table);
  if (t->char_freq) hcfree (t->char_freq);

  hcfree (t);
}

static void ht_inc (pcfg_trainer_t *t, ht_node_t **ht, const char *key, size_t key_len, u64 count, u64 *total)
{
  u64 h = XXH64 (key, key_len, 0);
  u64 idx = h & (t->ht_size - 1);

    // prefetch
  __builtin_prefetch (&ht[idx], 1, 3);

  ht_node_t *n    = ht[idx];
  ht_node_t *prev = NULL;

  while (n)
  {
    if (n->full_hash == h)
    {
      if (memcmp (n->key, key, key_len) == 0 && n->key[key_len] == '\0')
      {
        n->cnt += count;
        *total += count;

        // move to front
        if (prev != NULL)
        {
          prev->next = n->next;
          n->next = ht[idx];
          ht[idx] = n;
        }

        return;
      }
    }

    prev = n;
    n = n->next;
  }

  n = (ht_node_t *) pool_alloc (t, sizeof (ht_node_t));
  if (!n) return;

  n->key = (char *) pool_alloc (t, key_len + 1);
  if (!n->key) return;

  memcpy (n->key, key, key_len);
  n->key[key_len] = '\0';

  n->full_hash = h;
  n->cnt  = count;
  n->next = ht[idx];
  ht[idx] = n;

  *total += count;
}

static void term_ht_inc (pcfg_trainer_t *t, u8 type, u8 len, const char *val, u64 count, bool use_filter, u16 filter_threshold)
{
  u64 h = XXH64 (val, len, 0) ^ ((u64) type << 8) ^ (u64) len;
  u64 idx = h & (t->ht_size - 1);

  // prefetch while we do other work
  __builtin_prefetch (&t->global_term_ht[idx], 1, 3);

  if (use_filter)
  {
    if (count < filter_threshold)
    {
      if (!cbf_increment_and_check (t, h, filter_threshold))
      {
        return; // drop
      }
    }
  }

  t->term_totals[type][len] += count;

  term_node_t *n = t->global_term_ht[idx];
  term_node_t *prev = NULL;

  bool found = false;

  while (n)
  {
    // fast path: check hash first (single comparison)
    if (n->full_hash == h)
    {
      // then check type and len (cheap)
      if (n->type == type && n->len == len)
      {
        // only then do strcmp (expensive)
        if (memcmp (n->val, val, len) == 0)  // memcmp faster than strcmp for known length
        {
          n->cnt += count;

          // move to front (hot entries stay at front)
          if (prev != NULL)
          {
            prev->next = n->next;
            n->next = t->global_term_ht[idx];
            t->global_term_ht[idx] = n;
          }

          found = true;
          break;
        }
      }
    }

    prev = n;
    n = n->next;
  }

  if (found) return;

  n = (term_node_t *) pool_alloc (t, sizeof (term_node_t));

  if (!n) return;

  n->type = type;
  n->len  = len;

  n->val  = pool_alloc (t, len + 1);

  if (!n->val) return;

  memcpy (n->val, val, len);
  n->val[len] = 0;

  n->full_hash = h;

  n->cnt  = (use_filter && count <= filter_threshold) ? (u64) filter_threshold : count;

  n->next = t->global_term_ht[idx];
  t->global_term_ht[idx] = n;
}

void pcfg_trainer_update_struct_stats (pcfg_trainer_t *t, const u8 *types, u32 token_cnt, u64 count)
{
  if (token_cnt == 0) return;

  // record the very first token type
  u8 t0 = types[0] & 0x7F;

  t->struct_start_counts[t0] += count;

  if (token_cnt < 2) return;

  // record the first transition (Virtual state 0 + Type 0 -> Type 1)
  u8 t1 = types[1] & 0x7F;

  t->struct_trans_counts[(t0 * 256) + t1] += count;

  // record all subsequent 2nd order transitions
  for (u32 i = 2; i < token_cnt; i++)
  {
    u8 prev2  = types[i-2] & 0x7F;
    u8 prev1  = types[i-1] & 0x7F;
    u8 curr   = types[i]   & 0x7F;
    u16 state = (prev2 << 8) | prev1;

    t->struct_trans_counts[(state * 256) + curr] += count;
  }
}

bool pcfg_trainer_import_from_file (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *path)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return false;

  u32 magic, version;

  hc_fread (&magic, 4, 1, &fp);
  hc_fread (&version, 4, 1, &fp);

  if (magic != PCFG_MAGIC)
  {
    hc_fclose (&fp);
    return false;
  }

  u64 pw_total;
  u32 struct_cnt;

  hc_fread (&pw_total, 8, 1, &fp);

  // calculate skipping offset
  off_t skip_off =
    PCFG_ENCODING_MAX +                          // encoding_from
    sizeof (pcfg_markov_start_row_t) * 2 +       // pw_len_table + struct_start_row
    65536 * sizeof (pcfg_markov_row_t) +         // struct_trans_table
    sizeof (pcfg_markov_start_row_alpha_t) * 2 + // start_row_alpha + start_row_alpha_unicode
    sizeof (pcfg_markov_start_row_digit_t) +     // start_row_digit
    (65536 * sizeof (pcfg_markov_row_t)) * 10 +  // markov_tables (10)
    65536 * sizeof (float);                      // char_freq

  hc_fseek (&fp, skip_off, SEEK_CUR);

  hc_fread (&struct_cnt, 4, 1, &fp);

  event_log_info_nn (hashcat_ctx, "PCFG: Streaming %u structures from disk (%s) ...", struct_cnt, path);

  // import structures
  for (u32 i = 0; i < struct_cnt; i++)
  {
    pcfg_structure_t s;

    if (hc_fread (&s, sizeof (pcfg_structure_t), 1, &fp) != 1) break;

    char pattern_buf[PCFG_PATTERN_MAX];
    size_t pattern_len = pcfg_build_pattern (s.types, s.lengths, s.token_cnt, pattern_buf);

    // add to trainer
    ht_inc (t, t->struct_ht, pattern_buf, pattern_len, s.count, &t->struct_total);

    // rebuild Markov Structure from these types
    pcfg_trainer_update_struct_stats (t, s.types, s.token_cnt, s.count);

    if (i > 0 && (i % 1000000) == 0)
    {
      event_log_info_nn (hashcat_ctx, "> Structures: %u/%u (%.2f%%)", i, struct_cnt, (double)i/struct_cnt*100);
    }

    u32 full_pw_len = s.total_len;

    if (full_pw_len < 256) t->pw_len_counts[full_pw_len] += s.count;
  }

  event_log_info_nn (hashcat_ctx, "PCFG: Streaming terminal lists from disk...");

  // import terminals
  u64 term_imported = 0;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      u32 cnt;

      if (hc_fread (&cnt, 4, 1, &fp) != 1) break;

      if (cnt > 0)
      {
        for (u32 k = 0; k < cnt; k++)
        {
          u16 t_len;
          u32 t_cnt;

          float t_prob;

          char val_buf[PCFG_VALUE_MAX];

          hc_fread (&t_len, 2, 1, &fp);
          hc_fread (&t_cnt, 4, 1, &fp);
          hc_fread (&t_prob, 4, 1, &fp);

          if (t_len >= sizeof (val_buf)) t_len = sizeof (val_buf)-1;

          hc_fread (val_buf, 1, t_len, &fp);
          val_buf[t_len] = 0;

          // skip terminals containing control characters (0x00-0x1F)
          bool has_control = false;
          for (u32 j = 0; j < t_len; j++)
          {
            if ((unsigned char) val_buf[j] < 0x20)
            {
              has_control = true;
              break;
            }
          }
          if (has_control) continue;

          u64 cur_count = t_cnt;
          if (ty == PCFG_TK_MIXED && ln > 16) cur_count = 1;

          // add to trainer
          term_ht_inc (t, (u8) ty, (u8)ln, val_buf, cur_count, false, 0);

          if (ty == PCFG_TK_LOWER || ty == PCFG_TK_CAPITALIZED || ty == PCFG_TK_UPPER ||
              ty == PCFG_TK_DIGIT || ty == PCFG_TK_YEAR || ty == PCFG_TK_LATIN_EXT ||
              ty == PCFG_TK_CYRILLIC || ty == PCFG_TK_ARABIC || ty == PCFG_TK_ASIAN ||
              ty == PCFG_TK_GREEK || ty == PCFG_TK_HEBREW)
          {
            for (u32 y = 0; y < (u32) ln; y++)
            {
              unsigned char c = (unsigned char) val_buf[y];

              t->char_freq[ty * 256 + c] += cur_count;
            }
          }

          if (ty != PCFG_TK_YEAR && ty != PCFG_TK_DIGIT && ty != PCFG_TK_LOWER &&
              ty != PCFG_TK_UPPER && ty != PCFG_TK_CAPITALIZED && ty != PCFG_TK_LATIN_EXT &&
              ty != PCFG_TK_CYRILLIC && ty != PCFG_TK_ARABIC && ty != PCFG_TK_ASIAN &&
              ty != PCFG_TK_GREEK && ty != PCFG_TK_HEBREW)
          {

          }
          else
          {
            if (ln >= 2)
            {
              unsigned char s1 = (unsigned char) val_buf[0];
              unsigned char s2 = (unsigned char) val_buf[1];
              u32 start_state = (s1 << 8) | s2;

              if (ty == PCFG_TK_DIGIT || ty == PCFG_TK_YEAR)
              {
                t->markov_start_digit[start_state] += cur_count;
              }
              else if (ty == PCFG_TK_LOWER || ty == PCFG_TK_UPPER || ty == PCFG_TK_CAPITALIZED)
              {
                t->markov_start_alpha[start_state] += cur_count;
              }
              else
              {
                t->markov_start_alpha_unicode[start_state] += cur_count;
              }

              u32 table_idx = 9; // default to Catch-all (for Mixed or unknown)

              switch (ty)
              {
                case PCFG_TK_LOWER:       table_idx = 0; break;
                case PCFG_TK_CAPITALIZED: table_idx = 0; break; // share phonetics with Lower
                case PCFG_TK_UPPER:       table_idx = 1; break;
                case PCFG_TK_DIGIT:       table_idx = 2; break;
                case PCFG_TK_YEAR:        table_idx = 2; break;
                case PCFG_TK_LATIN_EXT:   table_idx = 3; break;
                case PCFG_TK_CYRILLIC:    table_idx = 4; break;
                case PCFG_TK_ARABIC:      table_idx = 5; break;
                case PCFG_TK_ASIAN:       table_idx = 6; break;
                case PCFG_TK_GREEK:       table_idx = 7; break;
                case PCFG_TK_HEBREW:      table_idx = 8; break;
                default:                  table_idx = 9; break; // catch-all
              }

              u64 table_offset = (u64)table_idx * 65536 * 256;

              // transitions
              for (u32 y = 2; y < (u32) ln; y++)
              {
                unsigned char c1   = (unsigned char) val_buf[y-2];
                unsigned char c2   = (unsigned char) val_buf[y-1];
                unsigned char next = (unsigned char) val_buf[y];

                u32 trans_state = (c1 << 8) | c2;

                t->markov_table[table_offset + (trans_state * 256) + next] += cur_count;
              }
            }
          }

          term_imported++;

          if ((term_imported % 5000000) == 0)
          {
            event_log_info_nn (hashcat_ctx, "> Terminals: %" PRIu64 " milion(s) ...", term_imported / 1000000);
          }
        }
      }
    }
  }

  t->pw_cnt += pw_total;

  hc_fclose (&fp);

  event_log_info_nn (hashcat_ctx, "PCFG: Streamed import completed.");

  return true;
}

// repair Mojibake in-place
void repair_mojibake_cyrillic (char *line, u32 *len_ptr)
{
  u32 len = *len_ptr;

  if (len < 4) return;

  u32 r = 0; // read index
  u32 w = 0; // write index

  unsigned char *buf = (unsigned char *)line;

  while (r < len)
  {
    int repaired = 0;

    // Pattern base: C3 90 (Ð -> D0) or C3 91 (Ñ -> D1)
    if (r + 2 < len && buf[r] == 0xC3 && (buf[r+1] == 0x90 || buf[r+1] == 0x91))
    {
      unsigned char lead_byte = (buf[r+1] == 0x90) ? 0xD0 : 0xD1;
      unsigned char tail_byte = 0;

      // how many EXTRA bytes do we consume after the C3 9x prefix?
      int consumed = 0;

      // look at the byte following the prefix (buf[r+2])
      unsigned char next_b = buf[r+2];

      // ISO-8859-1 standard (C2 80 - C2 BF)
      // recovers direct bytes such as Â, Ã, ©, etc.
      if (next_b == 0xC2 && r + 3 < len)
      {
        if (buf[r+3] >= 0x80 && buf[r+3] <= 0xBF)
        {
          tail_byte = buf[r+3];
          consumed = 2; // c2 xx
        }
      }

      // windows-1252 Punctuation/Symbols (3 Bytes: E2 80 xx)
      // many Cyrillic letters end up here (e.g., Ñ‚ -> D1 82 -> ‚)
      else if (next_b == 0xE2 && r + 4 < len && buf[r+3] == 0x80)
      {
        unsigned char end_b = buf[r+4];

        switch (end_b)
        {
          case 0x9A: tail_byte = 0x82; consumed = 3; break; // ‚ (low 9 quote)
          case 0x9E: tail_byte = 0x84; consumed = 3; break; // „
          case 0xA6: tail_byte = 0x85; consumed = 3; break; // … (ellipsis)
          case 0xA0: tail_byte = 0x86; consumed = 3; break; // †
          case 0xA1: tail_byte = 0x87; consumed = 3; break; // ‡
          case 0xB0: tail_byte = 0x89; consumed = 3; break; // ‰
          case 0xB9: tail_byte = 0x8B; consumed = 3; break; // ‹
          case 0x98: tail_byte = 0x91; consumed = 3; break; // ‘
          case 0x99: tail_byte = 0x92; consumed = 3; break; // ’
          case 0x9C: tail_byte = 0x93; consumed = 3; break; // “
          case 0x9D: tail_byte = 0x94; consumed = 3; break; // ”
          case 0xA2: tail_byte = 0x95; consumed = 3; break; // • (bullet)
          case 0x93: tail_byte = 0x96; consumed = 3; break; // – (en dash)
          case 0x94: tail_byte = 0x97; consumed = 3; break; // — (em dash)
          case 0xBA: tail_byte = 0x9B; consumed = 3; break; // ›
        }
      }

      // windows-1252 Special characters (2 or 3 bytes)
      // euro, Trademark, and accented Latin letters
      else if (next_b == 0xE2 && r + 4 < len) // euro and Trademark
      {
        if (buf[r+3] == 0x82 && buf[r+4] == 0xAC) { tail_byte = 0x80; consumed = 3; } // €
        else if (buf[r+3] == 0x84 && buf[r+4] == 0xA2) { tail_byte = 0x99; consumed = 3; } // ™
      }
      else if (next_b == 0xCB && r + 3 < len) // modifiers (ˆ, ˜)
      {
        if (buf[r+3] == 0x86) { tail_byte = 0x88; consumed = 2; } // ˆ
        else if (buf[r+3] == 0x9C) { tail_byte = 0x98; consumed = 2; } // ˜
      }
      else if (next_b == 0xC5 && r + 3 < len) // Latin Letters Ext (Š, Œ, ž, Ÿ)
      {
        unsigned char end_b = buf[r+3];
        switch (end_b)
        {
          case 0xA0: tail_byte = 0x8A; consumed = 2; break; // Š
          case 0x92: tail_byte = 0x8C; consumed = 2; break; // Œ
          case 0xBD: tail_byte = 0x8E; consumed = 2; break; // Ž
          case 0xA1: tail_byte = 0x9A; consumed = 2; break; // š
          case 0x93: tail_byte = 0x9C; consumed = 2; break; // œ
          case 0xBE: tail_byte = 0x9E; consumed = 2; break; // ž
          case 0xB8: tail_byte = 0x9F; consumed = 2; break; // Ÿ
        }
      }
      else if (next_b == 0xC6 && r + 3 < len) // ƒ (Florin)
      {
        if (buf[r+3] == 0x92) { tail_byte = 0x83; consumed = 2; }
      }

      // repair buffer
      if (consumed > 0)
      {
        buf[w++] = lead_byte;
        buf[w++] = tail_byte;

        // skip C3 9x + the bytes consumed
        r += (2 + consumed);

        repaired = 1;
      }
    }

    if (!repaired)
    {
      buf[w++] = buf[r++];
    }
  }

  buf[w] = 0;
  *len_ptr = w;
}

// returns 1 if the string contains mojibake signatures
// called before tokenize to reject garbage early
static int has_mojibake_signature (const char *s, u32 len)
{
  if (len < 4) return 0;

  const unsigned char *buf = (const unsigned char *)s;

  int c2_count = 0;
  int c3_count = 0;
  int consecutive_high = 0;
  int max_consecutive_high = 0;

  for (u32 i = 0; i < len; i++)
  {
    unsigned char c = buf[i];

    // count C2/C3 occurrences (double-encoding signature)
    if (c == 0xC2) c2_count++;
    if (c == 0xC3) c3_count++;

    // track consecutive high bytes (valid UTF-8 alternates high/low in specific patterns)
    if (c > 127)
    {
      consecutive_high++;

      if (consecutive_high > max_consecutive_high) max_consecutive_high = consecutive_high;
    }
    else
    {
      consecutive_high = 0;
    }
  }

  // excessive C2 bytes
  // valid UTF-8 rarely has this many C2 lead bytes
  if (c2_count > 0 && (c2_count * 4) > (int) len) return 1;

  // excessive C3 bytes (double-encoding signature)
  if (c3_count > 0 && (c3_count * 4) > (int) len) return 1;

  // c3 followed by C2 or C3 at offset +2 (double-encoding signature)
  for (u32 i = 0; i + 3 < len; i++)
  {
    if (buf[i] == 0xC3)
    {
      // check if byte at i+2 is another lead byte
      unsigned char b2 = buf[i + 2];

      if (b2 == 0xC2 || b2 == 0xC3 || b2 == 0xC4 || b2 == 0xC5) return 1;
    }
  }

  // replacement character (EF BF BD)
  for (u32 i = 0; i + 2 < len; i++)
  {
    if (buf[i] == 0xEF && buf[i+1] == 0xBF && buf[i+2] == 0xBD) return 1;
  }

  // пїЅ - Cyrillic representation of replacement char
  // D0 BF = п, D1 97 = ї (Ukrainian), D0 BD = н OR D1 95 = ѕ
  for (u32 i = 0; i + 5 < len; i++)
  {
    if (buf[i] == 0xD0 && buf[i+1] == 0xBF &&
        buf[i+2] == 0xD1 && buf[i+3] == 0x97)
    {
      return 1;
    }
  }

  // ГЇВїВЅ - Double-encoded replacement char appearing as Cyrillic
  // Г = D0 93, Ї = D0 87, В = D0 92, etc.
  for (u32 i = 0; i + 11 < len; i++)
  {
    if (buf[i] == 0xD0 && buf[i+1] == 0x93 &&      // Г
        buf[i+2] == 0xD0 && buf[i+3] == 0x87)      // Ї
    {
      return 1;
    }

    // also check: ГўВЂВ (D0 93 D1 9C D0 92 E2 80)
    if (buf[i] == 0xD0 && buf[i+1] == 0x93 &&      // Г
        buf[i+2] == 0xD1 && buf[i+3] == 0x9C)      // ў
    {
      return 1;
    }
  }

  // double-encoded Cyrillic lead byte
  // Ð (C3 90) or Ñ (C3 91) appearing in text
  for (u32 i = 0; i + 1 < len; i++)
  {
    if (buf[i] == 0xC3 && (buf[i+1] == 0x90 || buf[i+1] == 0x91)) return 1;
  }

  // double-encoded Arabic lead byte
  // Ø (C3 98), Ù (C3 99), Ú (C3 9A), Û (C3 9B)
  for (u32 i = 0; i + 1 < len; i++)
  {
    if (buf[i] == 0xC3 && buf[i+1] >= 0x98 && buf[i+1] <= 0x9B) return 1;
  }

  // double-encoded Greek lead byte
  // Î (C3 8E), Ï (C3 8F)
  for (u32 i = 0; i + 1 < len; i++)
  {
    if (buf[i] == 0xC3 && (buf[i+1] == 0x8E || buf[i+1] == 0x8F)) return 1;
  }

  // â€ sequences (E2 82 AC = €, but â€ is garbage pattern)
  // "â€" appears as E2 80 9x in valid UTF-8 but as C3 A2 E2 82 AC when double-encoded
  for (u32 i = 0; i + 4 < len; i++)
  {
    if (buf[i] == 0xC3 && buf[i+1] == 0xA2 && buf[i+2] == 0xE2) return 1;
  }

  // excessive combining diacriticals (Zalgo text)
  // cC xx or CD xx repeated many times
  int combining_count = 0;

  for (u32 i = 0; i + 1 < len; i++)
  {
    if (buf[i] == 0xCC || buf[i] == 0xCD)
    {
      if ((buf[i+1] & 0xC0) == 0x80) combining_count++;
    }
  }

  // more than 5 combining marks is suspicious
  if (combining_count > 5) return 1;

  return 0;
}

static int is_repetitive_spam (const char *val, u32 len)
{
  if (len < 4) return 0;

  // if the string is very long (>64), we are more tolerant.
  // if it is short (e.g., 8-16 characters), it must be almost entirely the same to be considered spam.
  double threshold = (len < 16) ? 0.90 : 0.75;

  // checks patterns from 1 to 4 bytes (covers single chars, 2-byte utf-8, 3-byte utf-8, 4-byte emoji)
  // Note: I added ‘pat=1’ to capture simple “aaaaaaaa”
  int max_pattern = (len > 64) ? 4 : (len/2);
  if (max_pattern > 12) max_pattern = 12;

  for (int pat = 1; pat <= max_pattern; pat++)
  {
    // if the length is not a multiple of the pattern, we only check if the pattern is small
    if (len % pat != 0 && pat > 1) continue;

    int repeats = 0;
    // compare each block with the first block
    for (u32 i = pat; i <= len - pat; i += pat)
    {
      if (memcmp (val + i, val, pat) == 0) repeats++;
    }

    // calculate coverage
    double coverage = (double)(repeats * pat) / (double) len;

    if (coverage > threshold) return 1;
  }

  return 0;
}

// convert HTML
bool sanitize_fragment_safe (char *str)
{
  // there must be at least “&#” + a number
  if (str == NULL || str[0] != '&' || str[1] != '#') return false;

  char *num_ptr = str + 2;
  if (*num_ptr == '\0' || !isdigit ((unsigned char) *num_ptr)) return false;

  // validate the conversion before touching the input
  char *endptr;
  long code = strtol (num_ptr, &endptr, 10);

  // must be printable ASCII (reject control chars 0x00-0x1F and DEL 0x7F)
  if (code >= 32 && code <= 255 && code != 127)
  {
    // now we can touch original input
    char c_converted = (char) code;

    str[0] = c_converted;
    str[1] = '\0';

    return true;
  }

  // if not in range, no touch
  return false;
}

static int is_garbage_token (pcfg_token_type_t type, const char *value, u32 len)
{
  if (!value || len == 0) return 1;

  const unsigned char *buf = (const unsigned char *) value;

  // fast path: ASCII-only types don't need heavy checks
  if (type == PCFG_TK_LOWER || type == PCFG_TK_UPPER ||
      type == PCFG_TK_DIGIT || type == PCFG_TK_YEAR ||
      type == PCFG_TK_CAPITALIZED || type == PCFG_TK_SPECIAL)
  {
    return 0;
  }

  // single byte checks
  if (len == 1)
  {
    unsigned char c = buf[0];
    if (c == 0xEF || c == 0xBF || c == 0xBD || c < 32) return 1;
    if ((c & 0xC0) == 0x80) return 1;
    if (type == PCFG_TK_UNICODE && c > 0x7F) return 1;
  }

  // stray continuation byte at start
  if ((buf[0] & 0xC0) == 0x80) return 1;

  // truncated Unicode at end
  if (len > 1 && buf[len - 1] > 0xF4) return 1;

  // short Unicode tokens
  if (type == PCFG_TK_UNICODE && len < 4)
  {
    unsigned char c = buf[0];
    if (c == 0xBD) return 1;
    if (c < 0xC0 && c > 0x7F) return 1;
  }

  // type-specific prefix checks
  if (type == PCFG_TK_MIXED)
  {
    if (len > 100)
    {
      if (isalpha (buf[0]) && (buf[1] == 'A' || buf[1] == 'a') && (buf[2] == 'A' || buf[2] == 'a')) return 1;
      if (strncasecmp (value, "AYA", 3) == 0) return 1;
    }
    if (len > 70 && strncasecmp (value, "MT", 2) == 0 && isalpha (buf[2])) return 1;
    if (len > 50 && strncmp (value, "eyJ", 3) == 0) return 1;
    if (len == 42 && buf[0] == '0' && buf[1] == 'x') return 1;
    if (len > 40 && strncasecmp (value, "L9Ir", 4) == 0) return 1;
    if (len >= 58 && strncasecmp (value, "addr1", 5) == 0) return 1;
  }

  // single-char special cases (before loop)
  if (type == PCFG_TK_UNICODE && len == 3 && buf[0] == 0xE2 && buf[1] == 0x80 && buf[2] >= 0x90 && buf[2] <= 0x9F) return 1;
  if (type == PCFG_TK_EMOJI && len == 3 && buf[0] == 0xE2 && buf[1] == 0x82 && buf[2] == 0xAC) return 1;

  // single pass for all byte pattern checks
  int c2_count = 0;
  int ef_count = 0;
  int ro_count = 0;
  int zwx_count = 0;

  for (u32 i = 0; i < len; i++)
  {
    unsigned char b0 = buf[i];
    unsigned char b1 = (i + 1 < len) ? buf[i + 1] : 0;
    unsigned char b2 = (i + 2 < len) ? buf[i + 2] : 0;
    unsigned char b3 = (i + 3 < len) ? buf[i + 3] : 0;
    unsigned char b4 = (i + 4 < len) ? buf[i + 4] : 0;
    unsigned char b5 = (i + 5 < len) ? buf[i + 5] : 0;
    unsigned char b6 = (i + 6 < len) ? buf[i + 6] : 0;
    unsigned char b7 = (i + 7 < len) ? buf[i + 7] : 0;

    // count bytes for ratio checks
    if (b0 == 0xC2) c2_count++;
    if (b0 == 0xEF) ef_count++;
    if (b0 == 0xD0 && b1 == 0xA0) ro_count++;

    // GLOBAL

    // replacement Character U+FFFD (EF BF BD)
    if (b0 == 0xEF && b1 == 0xBF && b2 == 0xBD) return 1;

    // Non-characters U+FFFE, U+FFFF (EF BF BE, EF BF BF)
    if (b0 == 0xEF && b1 == 0xBF && (b2 == 0xBE || b2 == 0xBF)) return 1;

    // double-encoded replacement char (C3 AF C2 BF C2 BD)
    if (b0 == 0xC3 && b1 == 0xAF && b2 == 0xC2 && b3 == 0xBF && b4 == 0xC2 && b5 == 0xBD) return 1;

    // thai Mojibake "à¸" (C3 A0 C2 B8)
    if (b0 == 0xC3 && b1 == 0xA0 && b2 == 0xC2 && b3 == 0xB8) return 1;

    // DOS/OEM remnants "ÔÇå" (C3 94 C3 87 C3 A5)
    if (b0 == 0xC3 && b1 == 0x94 && b2 == 0xC3 && b3 == 0x87 && b4 == 0xC3 && b5 == 0xA5) return 1;

    // DOS/OEM remnants "Ôäû" (C3 94 C3 A4 C3 BB)
    if (b0 == 0xC3 && b1 == 0x94 && b2 == 0xC3 && b3 == 0xA4 && b4 == 0xC3 && b5 == 0xBB) return 1;

    // CYRILLIC (Type I)
    if (type == PCFG_TK_CYRILLIC)
    {
      // Latin C3 in Cyrillic
      if (b0 == 0xC3) return 1;

      // пїЅ pattern (D0 BF D1 97 D0 BD or D0 BF D1 97 D1 95)
      if (b0 == 0xD0 && b1 == 0xBF && b2 == 0xD1 && b3 == 0x97) return 1;

      // ГЇВїВЅ (D0 93 + D0 87 or D0 AF)
      if (b0 == 0xD0 && b1 == 0x93 && b2 == 0xD0 && (b3 == 0x87 || b3 == 0xAF)) return 1;

      // ГўВЂВў pattern (D0 93 D1 9C)
      if (b0 == 0xD0 && b1 == 0x93 && b2 == 0xD1 && b3 == 0x9C) return 1;

      // РІвЂ (D0 B2 E2 80)
      if (b0 == 0xD0 && b1 == 0xB2 && b2 == 0xE2 && b3 == 0x80) return 1;

      // РІР (D0 B2 D0)
      if (b0 == 0xD0 && b1 == 0xB2 && b2 == 0xD0) return 1;

      // "Р" + xx + "Р" pattern (D0 A0 + D0/D1 xx + D0 A0)
      if (b0 == 0xD0 && b1 == 0xA0 && (b2 == 0xD0 || b2 == 0xD1) && b4 == 0xD0 && b5 == 0xA0) return 1;

      // "Г" followed by C2/C3
      if (b0 == 0xD0 && b1 == 0x93 && (b2 == 0xC2 || b2 == 0xC3)) return 1;

      // ГѓВї pattern (D0 93 D1 83 D0 92 D1 97)
      if (b0 == 0xD0 && b1 == 0x93 && b2 == 0xD1 && b3 == 0x83 && b4 == 0xD0 && b5 == 0x92 && b6 == 0xD1 && b7 == 0x97) return 1;
    }

    // LATIN EXTENDED (Type A)
    if (type == PCFG_TK_LATIN_EXT)
    {
      // Georgian double-encoded (C3 A1 C6 92)
      if (b0 == 0xC3 && b1 == 0xA1 && b2 == 0xC6 && b3 == 0x92) return 1;

      // Generic áƒ (C3 A1 C6)
      if (b0 == 0xC3 && b1 == 0xA1 && b2 == 0xC6) return 1;

      // double-encoding signature (C3 xx C2/C3/C4/C5)
      if (b0 == 0xC3 && (b2 == 0xC2 || b2 == 0xC3 || b2 == 0xC4 || b2 == 0xC5)) return 1;

      // double-encoded Cyrillic (C3 90, C3 91)
      if (b0 == 0xC3 && (b1 == 0x90 || b1 == 0x91)) return 1;

      // double-encoded Arabic (C3 98-9B)
      if (b0 == 0xC3 && b1 >= 0x98 && b1 <= 0x9B) return 1;

      // double-encoded Greek (C3 8E, C3 8F)
      if (b0 == 0xC3 && (b1 == 0x8E || b1 == 0x8F)) return 1;

      // double-encoded Hebrew (C3 96, C3 97)
      if (b0 == 0xC3 && (b1 == 0x96 || b1 == 0x97)) return 1;

      // ð + C2 (C3 B0 C2)
      if (b0 == 0xC3 && b1 == 0xB0 && b2 == 0xC2) return 1;

      // ð + C3 (C3 B0 C3)
      if (b0 == 0xC3 && b1 == 0xB0 && b2 == 0xC3) return 1;

      // broken bar (C2 A6)
      if (b0 == 0xC2 && b1 == 0xA6) return 1;

      // DOS artifacts (C3 94 C3 87)
      if (b0 == 0xC3 && b1 == 0x94 && b2 == 0xC3 && b3 == 0x87) return 1;
    }

    // eMOJI (Type J)
    if (type == PCFG_TK_EMOJI)
    {
      // box drawing (E2 94, E2 95)
      if (b0 == 0xE2 && (b1 == 0x94 || b1 == 0x95)) return 1;
    }

    // ARABIC (Type B)
    if (type == PCFG_TK_ARABIC)
    {
      // Latin bytes (C2-C5)
      if (b0 >= 0xC2 && b0 <= 0xC5) return 1;
    }

    // ASIAN (Type H)
    if (type == PCFG_TK_ASIAN)
    {
      // Non-character (EF BF BE)
      if (b0 == 0xEF && b1 == 0xBF && b2 == 0xBE) return 1;

      // Halfwidth/Fullwidth Forms (EF BC-BF)
      if (b0 == 0xEF && b1 >= 0xBC && b1 <= 0xBF) return 1;

      // Pattern ￐ﾱ (EF 90)
      if (b0 == 0xEF && b1 == 0x90) return 1;
    }

    // GREEK (Type G)
    if (type == PCFG_TK_GREEK)
    {
      if (b0 == 0xC3) return 1;
    }

    // HEBREW (Type V)
    if (type == PCFG_TK_HEBREW)
    {
      if (b0 == 0xC3) return 1;
    }

    // GENERIC UNICODE (Type X)
    if (type == PCFG_TK_UNICODE)
    {
      // № repeated (E2 84 96 E2 84 96)
      if (b0 == 0xE2 && b1 == 0x84 && b2 == 0x96 && b3 == 0xE2 && b4 == 0x84 && b5 == 0x96) return 1;

      // Dash repeated (E2 80 93/94 E2 80 93/94)
      if (b0 == 0xE2 && b1 == 0x80 && (b2 == 0x93 || b2 == 0x94) && b3 == 0xE2 && b4 == 0x80 && (b5 == 0x93 || b5 == 0x94)) return 1;

      // ZWx chars (E2 80 8A-8F)
      if (b0 == 0xE2 && b1 == 0x80 && b2 >= 0x8A && b2 <= 0x8F) zwx_count++;
    }
  }

  // ratio-based checks (after single pass)
  if (type == PCFG_TK_LATIN_EXT && len > 6 && (c2_count * 5) > (int) len) return 1;
  if (type == PCFG_TK_CYRILLIC && len > 20 && ro_count > (int) (len / 8)) return 1;
  if (type == PCFG_TK_ASIAN && len < 30 && ef_count > 0 && (ef_count * 3) > (int) len) return 1;
  if (type == PCFG_TK_UNICODE && zwx_count > 2) return 1;

  // repetitive spam check
  if (type == PCFG_TK_CYRILLIC || type == PCFG_TK_LATIN_EXT ||
      type == PCFG_TK_ARABIC || type == PCFG_TK_ASIAN ||
      type == PCFG_TK_GREEK || type == PCFG_TK_HEBREW)
  {
    if (is_repetitive_spam (value, len)) return 1;
  }

  return 0;
}

int pcfg_trainer_add_pw (pcfg_trainer_t *t, char *pw, u32 len, u64 count, bool use_filter, u16 filter_threshold, bool use_data_filters)
{
  if (len < 2 || len > PCFG_PW_MAX - 1) return -1;
  if (count == 0) count = 1;

  // pre-filtering
  if (use_data_filters == true)
  {
    repair_mojibake_cyrillic (pw, &len);

    if (has_mojibake_signature (pw, len))
    {
      return -2; // still bad after repair
    }
  }

  u8 types[PCFG_TOKEN_MAX];
  u8 lengths[PCFG_TOKEN_MAX];
  char values[PCFG_TOKEN_MAX][PCFG_VALUE_MAX];
  u32 token_cnt;

  pcfg_tokenize (pw, len, types, lengths, &token_cnt, values);

  // post-filtering
  if (token_cnt == 0)
  {
    return -3;
  }

  if (token_cnt > PCFG_TOKEN_MAX)
  {
    return -4;
  }

  if (use_data_filters == true)
  {
    for (u32 i = 0; i < token_cnt; i++)
    {
      u8 ty = types[i];
      u8 ln = lengths[i];

      char *val_tmp = values[i];

      if (is_garbage_token (ty, val_tmp, ln))
      {
        return -5;
      }

      // trying converting
      if (ty == PCFG_TK_MIXED)
      {
        if (sanitize_fragment_safe (val_tmp) == true)
        {
          lengths[i] = strlen (val_tmp);
        }
      }
    }

    // additional cross-token validation
    // e.g., reject if mix of incompatible scripts
    int has_cyrillic = 0, has_arabic = 0;

    for (u32 i = 0; i < token_cnt; i++)
    {
      if (types[i] == PCFG_TK_CYRILLIC) has_cyrillic = 1;
      if (types[i] == PCFG_TK_ARABIC) has_arabic = 1;
    }

    // cyrillic + Arabic in same password is very suspicious
    if (has_cyrillic && has_arabic)
    {
      return -6;
    }
  }

  // processing

  char pattern[PCFG_PATTERN_MAX];
  size_t pattern_len = pcfg_build_pattern (types, lengths, token_cnt, pattern);

  ht_inc (t, t->struct_ht, pattern, pattern_len, count, &t->struct_total);

  pcfg_trainer_update_struct_stats (t, types, token_cnt, count);

  for (u32 i = 0; i < token_cnt; i++)
  {
    u8 ty = types[i];
    u8 ln = lengths[i];

    const char *val = values[i];

    // set min count with PCFG_TK_MIXED if length of token > 16
    // for the future: measuring entropy of string to check this?
    u64 cur_count = count;
    if (ty == PCFG_TK_MIXED && ln > 16) cur_count = 1;

    // early prefetch for i+2
    if (i + 2 < token_cnt)
    {
      u8 next_ty = types[i + 2];
      u8 next_ln = lengths[i + 2];

      const char *next_val = values[i + 2];

      u64 next_h = XXH64 (next_val, next_ln, 0) ^ ((u64) next_ty << 8) ^ (u64) next_ln;
      u64 next_idx = next_h & (t->ht_size - 1);

      __builtin_prefetch (&t->global_term_ht[next_idx], 1, 3);
    }

    term_ht_inc (t, ty, ln, val, cur_count, use_filter, filter_threshold);

    // markov learning

    if (len < 256) t->pw_len_counts[len] += cur_count;

    // character Frequency Learning
    if (ty == PCFG_TK_LOWER || ty == PCFG_TK_CAPITALIZED || ty == PCFG_TK_UPPER ||
        ty == PCFG_TK_DIGIT || ty == PCFG_TK_YEAR || ty == PCFG_TK_LATIN_EXT ||
        ty == PCFG_TK_CYRILLIC || ty == PCFG_TK_ARABIC || ty == PCFG_TK_ASIAN ||
        ty == PCFG_TK_GREEK || ty == PCFG_TK_HEBREW || ty == PCFG_TK_MIXED)
    {
      for (u32 k = 0; k < ln; k++)
      {
        unsigned char c = (unsigned char) val[k];

        t->char_freq[ty * 256 + c] += cur_count;
      }
    }

    // N-Gram (Transition) Learning
    if (ty == PCFG_TK_LOWER || ty == PCFG_TK_CAPITALIZED || ty == PCFG_TK_UPPER ||
        ty == PCFG_TK_DIGIT || ty == PCFG_TK_YEAR || ty == PCFG_TK_LATIN_EXT ||
        ty == PCFG_TK_CYRILLIC || ty == PCFG_TK_ARABIC || ty == PCFG_TK_ASIAN ||
        ty == PCFG_TK_GREEK || ty == PCFG_TK_HEBREW || ty == PCFG_TK_MIXED ||
        ty == PCFG_TK_EMOJI || ty == PCFG_TK_UNICODE)
    {
      if (ln >= 2)
      {
        unsigned char s1 = (unsigned char) val[0];
        unsigned char s2 = (unsigned char) val[1];
        u32 start_state = (s1 << 8) | s2;

        // update Start Rows
        if (ty == PCFG_TK_DIGIT || ty == PCFG_TK_YEAR)
        {
          t->markov_start_digit[start_state] += cur_count;
        }
        else if (ty == PCFG_TK_LOWER || ty == PCFG_TK_UPPER || ty == PCFG_TK_CAPITALIZED)
        {
          t->markov_start_alpha[start_state] += cur_count;
        }
        else
        {
          t->markov_start_alpha_unicode[start_state] += cur_count;
        }

        // select table offset
        u32 table_idx = 9; // default to Catch-all (for Mixed or unknown)

        switch (ty)
        {
          case PCFG_TK_LOWER:       table_idx = 0; break;
          case PCFG_TK_CAPITALIZED: table_idx = 0; break; // share phonetics with Lower
          case PCFG_TK_UPPER:       table_idx = 1; break;
          case PCFG_TK_DIGIT:       table_idx = 2; break;
          case PCFG_TK_YEAR:        table_idx = 2; break;
          case PCFG_TK_LATIN_EXT:   table_idx = 3; break;
          case PCFG_TK_CYRILLIC:    table_idx = 4; break;
          case PCFG_TK_ARABIC:      table_idx = 5; break;
          case PCFG_TK_ASIAN:       table_idx = 6; break;
          case PCFG_TK_GREEK:       table_idx = 7; break;
          case PCFG_TK_HEBREW:      table_idx = 8; break;
          default:                  table_idx = 9; break; // catch-all
        }

        u64 table_offset = (u64)table_idx * 65536 * 256;

        // transitions
        for (u32 k = 2; k < ln; k++)
        {
          unsigned char c1   = (unsigned char) val[k-2];
          unsigned char c2   = (unsigned char) val[k-1];
          unsigned char next = (unsigned char) val[k];

          u32 trans_state = (c1 << 8) | c2;

          // write into the specific sub-table zone
          t->markov_table[table_offset + (trans_state * 256) + next] += cur_count;
        }
      }
    }
  }

  t->pw_cnt += count;

  return 0;
}

// process each line of input
static int process_entry (u64 weigh, char *line, size_t len, char *decoded, size_t decoded_size, pcfg_trainer_t *t, bool use_filter, u16 filter_threshold, bool use_data_filters)
{
  int cnt = 0;

  char *current = line;
  size_t current_len = len;
  bool from_hex = false;
  int depth = 0;

  if (use_data_filters == false)
  {
    if (pcfg_trainer_add_pw (t, current, current_len, weigh, use_filter, filter_threshold, use_data_filters) == 0) return 1;

    return 0;
  }

  while (depth < MAX_DECODE_DEPTH && current_len > 0)
  {
    depth++;

    // check if start with $HEX[
    size_t hex_part_len = 0;
    size_t suffix_len   = 0;

    const char *suffix_ptr = NULL;

    if (find_hex_bounds (current, current_len, &hex_part_len, &suffix_ptr, &suffix_len))
    {
      int hex_depth = 0;
      bool keep_processing = true;

      while (keep_processing && hex_depth < MAX_DECODE_DEPTH)
      {
        bool was_utf16 = false;
        size_t new_len = unhexify_smart (current, hex_part_len, decoded, decoded_size, &was_utf16);

        if (new_len == 0)
        {
          return cnt;
        }

        decoded[new_len] = 0;
        current = decoded;
        current_len = new_len;
        from_hex = true;
        hex_depth++;

        if (find_hex_bounds (current, current_len, &hex_part_len, &suffix_ptr, &suffix_len))
        {
        }
        else
        {
          keep_processing = false;
        }
      }

      continue;
    }

    // search pattern "string:$HEX[...]" or "string;$HEX[...]"
    size_t prefix_len = 0;
    size_t hex_len = 0;
    suffix_len = 0;

    char *hex_delim = find_hex_delimiter_ex (current, current_len, &prefix_len, &hex_len, &suffix_len);

    if (hex_delim != NULL)
    {
      if (prefix_len > 0)
      {
        char saved_char = *hex_delim;
        *hex_delim = '\0';

        size_t trimmed_len = trim_padding_fast (current, prefix_len);

        if (trimmed_len > 0)
        {
          if (!from_hex || !is_garbage_content (current, trimmed_len, false))
          {
            if (pcfg_trainer_add_pw (t, current, trimmed_len, weigh, use_filter, filter_threshold, use_data_filters) == 0) cnt++;
          }
        }

        *hex_delim = saved_char;
      }

      char *hex_start = hex_delim + 1;
      size_t hex_actual_len = hex_len;

      if (current == decoded)
      {
        memmove (decoded, hex_start, hex_actual_len);
      }
      else
      {
        memcpy (decoded, hex_start, hex_actual_len);
      }

      decoded[hex_actual_len] = 0;
      current = decoded;
      current_len = hex_actual_len;
      from_hex = true;

      continue;
    }

    // search pattern "email:password" or "email;password"
    size_t email_len = 0;
    size_t pass_len = 0;

    char *email_delim = find_email_delimiter (current, current_len, &email_len, &pass_len);

    if (email_delim != NULL && pass_len > 0)
    {
      char saved_char = *email_delim;

      *email_delim = '\0';

      size_t trimmed_email_len = trim_padding_fast (current, email_len);

      if (trimmed_email_len > 0)
      {
        if (!from_hex || !is_garbage_content (current, trimmed_email_len, false))
        {
          if (pcfg_trainer_add_pw (t, current, trimmed_email_len, weigh, use_filter, filter_threshold, use_data_filters) == 0) cnt++;
        }
      }

      *email_delim = saved_char;

      char *pass_start = email_delim + 1;

      if (current == decoded)
      {
        memmove (decoded, pass_start, pass_len);
      }
      else
      {
        memcpy (decoded, pass_start, pass_len);
      }

      decoded[pass_len] = 0;
      current = decoded;
      current_len = pass_len;

      continue;
    }

    // hex bare check (ex: HEX2122a72425)
    if (starts_with_bare_hex (current, current_len))
    {
      const char *hex_content = current + 3;

      size_t remaining = current_len - 3;

      size_t hex_chars = find_hex_chars_length (hex_content, remaining);

      size_t bare_suffix_len = remaining - hex_chars;

      bool should_try_decode = (hex_chars >= 2) && (bare_suffix_len <= 10);

      if (should_try_decode && bare_suffix_len > 0)
      {
        const char *bare_suffix = hex_content + hex_chars;

        for (size_t i = 0; i < bare_suffix_len; i++)
        {
          if (bare_suffix[i] == ':' || bare_suffix[i] == ';')
          {
            should_try_decode = false;
            break;
          }
        }
      }

      if (should_try_decode)
      {
        size_t hex_to_decode = hex_chars & ~(size_t)1;

        if (hex_to_decode >= 2)
        {
          bool was_utf16 = false;

          size_t new_len = unhexify_bare (hex_content, hex_to_decode, decoded, decoded_size, &was_utf16);

          if (new_len > 0 && !is_garbage_content (decoded, new_len, true))
          {
            decoded[new_len] = 0;
            current = decoded;
            current_len = new_len;
            from_hex = true;

            continue;
          }
        }
      }
    }

    // skip malformed HEX
    if (starts_with_hex (current, current_len))
    {
      return cnt;
    }

    if (is_probably_base64 (current, current_len))
    {
      // check for Base64
      size_t b64_end = find_base64_boundary (current, current_len);

      // all is base64
      if (b64_end == current_len && current_len >= 4)
      {
        u8 b64_tmp[PCFG_PW_MAX];

        size_t new_len = base64_decode (base64_to_int, (const u8 *) current, current_len, (u8 *) b64_tmp);

        if (new_len > 0 && new_len < decoded_size && !is_garbage_content ((const char *) b64_tmp, new_len, true))
        {
          memcpy (decoded, b64_tmp, new_len);
          decoded[new_len] = 0;
          current = decoded;
          current_len = new_len;
          continue;
        }
      }
      // mixed base64 + string
      else if (b64_end >= 4 && b64_end < current_len)
      {
        u8 b64_tmp[PCFG_PW_MAX];

        size_t new_len = base64_decode (base64_to_int, (const u8 *) current, b64_end, (u8 *) b64_tmp);

        if (new_len > 0 && new_len < decoded_size && !is_garbage_content ((const char *) b64_tmp, new_len, true))
        {
          memcpy (decoded, b64_tmp, new_len);
          decoded[new_len] = 0;

          // add remainder
          char *remainder = current + b64_end;

          size_t remainder_len  = current_len - b64_end;

          if (remainder_len > 0 && !is_garbage_content (remainder, remainder_len, true))
          {
            if (pcfg_trainer_add_pw (t, remainder, remainder_len, weigh, use_filter, filter_threshold, use_data_filters) == 0) cnt++;
          }

          // reprocess new decoded string
          current = decoded;
          current_len = new_len;
          continue;
        }
      }
    }

    // final string
    current_len = trim_padding_fast (current, current_len);

    if (current_len > 0)
    {
      if (!from_hex || !is_garbage_content (current, current_len, false))
      {
        if (pcfg_trainer_add_pw (t, current, current_len, weigh, use_filter, filter_threshold, use_data_filters) == 0) cnt++;
      }
    }

    return cnt;
  }

  return cnt;
}

static line_block_t *block_create (size_t capacity)
{
  line_block_t *b = hcmalloc (sizeof (line_block_t));

  b->lines    = hcmalloc (capacity * sizeof (char *));
  b->lens     = hcmalloc (capacity * sizeof (size_t));
  b->weighs   = hcmalloc (capacity * sizeof (u64));
  b->count    = 0;
  b->capacity = capacity;

  return b;
}

static void block_reset (line_block_t *b)
{
  for (size_t i = 0; i < b->count; i++)
  {
    hcfree (b->lines[i]);
  }

  b->count = 0;
}

static void block_destroy (line_block_t *b)
{
  block_reset (b);

  hcfree (b->lines);
  hcfree (b->lens);
  hcfree (b->weighs);
  hcfree (b);
}

// reads a block of lines from the file
static bool read_block (HCFILE *fp, line_block_t *block, char *line_buf, size_t line_buf_size, int train_format)
{
  block_reset (block);

  while (block->count < block->capacity && !hc_feof (fp))
  {
    size_t len = fgetl (fp, line_buf, line_buf_size);

    if (len == 0) continue;

    while (len > 0 && (line_buf[len-1] == '\n' || line_buf[len-1] == '\r'))
    {
      line_buf[--len] = 0;
    }

    if (len == 0) continue;

    char *ptr_line = line_buf;

    size_t ptr_line_len = len;

    u64 weigh = 1;

    if (train_format == PCFG_TRAIN_FORMAT_WEIGHED_WORDLIST)
    {
      char *sep = strchr (line_buf, ':');

      if (sep == NULL) continue;

      *sep = 0;

      weigh = strtoull (line_buf, NULL, 10);

      ptr_line     = sep + 1;
      ptr_line_len = len - (size_t)(sep - line_buf) - 1;

      if (ptr_line_len == 0) continue;
    }

    block->lines[block->count]  = hcstrdup (ptr_line);
    block->lens[block->count]   = ptr_line_len;
    block->weighs[block->count] = weigh;
    block->count++;
  }

  return block->count > 0;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_reader (void *p)
#else
HC_API_CALL void *thread_reader (void *p)
#endif
{
  reader_ctx_t *ctx = (reader_ctx_t *) p;
  block_queue_t *q = ctx->queue;

  while (1)
  {
    int idx = q->current_read;

    // wait until the block is free
    hc_thread_mutex_lock (q->mutex);

    while (q->ready[idx] == 1 && !q->done)
    {
      hc_thread_cond_wait (q->cond_free, q->mutex);
    }

    hc_thread_mutex_unlock (q->mutex);

    if (q->done) break;

    // read the block
    bool has_data = read_block (ctx->fp, q->blocks[idx], ctx->line_buf, ctx->line_buf_size, ctx->train_format);

    hc_thread_mutex_lock (q->mutex);

    if (has_data)
    {
      q->ready[idx]   = 1;
      q->current_read = (idx + 1) % TRAINER_NUM_BLOCKS;

      hc_thread_cond_signal (q->cond_ready);
    }
    else
    {
      q->done = true;

      hc_thread_cond_signal (q->cond_ready);
    }

    hc_thread_mutex_unlock (q->mutex);

    if (!has_data) break;
  }

  return 0;
}

static block_queue_t *queue_create (void)
{
  block_queue_t *q = (block_queue_t *) hccalloc (1, sizeof (block_queue_t));

  for (int i = 0; i < TRAINER_NUM_BLOCKS; i++)
  {
    q->blocks[i] = block_create (TRAINER_BLOCK_SIZE);
    q->ready[i]  = 0;
  }

  q->current_read    = 0;
  q->current_process = 0;

  q->done = false;

  hc_thread_mutex_init (q->mutex);
  hc_thread_cond_init  (q->cond_ready);
  hc_thread_cond_init  (q->cond_free);

  return q;
}

static void queue_destroy (block_queue_t *q)
{
  for (int i = 0; i < TRAINER_NUM_BLOCKS; i++)
  {
    block_destroy (q->blocks[i]);
  }

  hc_thread_mutex_delete (q->mutex);
  hc_thread_cond_delete  (q->cond_ready);
  hc_thread_cond_delete  (q->cond_free);

  free (q);
}

// returns the next block ready, or NULL if finished
static line_block_t *queue_get_block (block_queue_t *q)
{
  hc_thread_mutex_lock (q->mutex);

  int idx = q->current_process;

  while (q->ready[idx] == 0 && !q->done)
  {
    hc_thread_cond_wait (q->cond_ready, q->mutex);
  }

  if (q->ready[idx] == 0 && q->done)
  {
    hc_thread_mutex_unlock (q->mutex);

    return NULL;
  }

  hc_thread_mutex_unlock (q->mutex);

  return q->blocks[idx];
}

// mark block as processed
static void queue_release_block (block_queue_t *q)
{
  hc_thread_mutex_lock (q->mutex);

  int idx = q->current_process;

  q->ready[idx]      = 0;
  q->current_process = (idx + 1) % TRAINER_NUM_BLOCKS;

  hc_thread_cond_signal  (q->cond_free);
  hc_thread_mutex_unlock (q->mutex);
}

int pcfg_trainer_from_file (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *path)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return -1;

  size_t line_len    = HCBUFSIZ_LARGE;
  size_t decoded_len = HCBUFSIZ_LARGE;

  char *line    = (char *) hcmalloc (line_len);
  char *decoded = (char *) hcmalloc (decoded_len);

  if (!line || !decoded)
  {
    hcfree (line);
    hcfree (decoded);
    hc_fclose (&fp);
    return -1;
  }

  // setup queue and reader thread
  block_queue_t *queue = queue_create ();

  reader_ctx_t reader_ctx =
  {
    .queue = queue,
    .fp = &fp,
    .line_buf = (char *) hcmalloc (line_len),
    .line_buf_size = line_len,
    .train_format = user_options->pcfg_train_format
  };

  hc_thread_t reader_tid;

  hc_thread_create (reader_tid, thread_reader, &reader_ctx);

  // timer
  hc_timer_t start;
  hc_timer_set (&start);

  double last_update_ms = 0;
  double avg_speed = 0;

  u64 last_words = 0;

  bool use_data_filters = user_options->pcfg_train_df_disable == false;
  bool use_filter = (t->admit_counters && t->admit_mask);

  u16 filter_threshold = user_options->pcfg_train_af_threshold;

  char adf_buf[48];
  memset (adf_buf, 0, sizeof (adf_buf));

  int adf_pos = snprintf (adf_buf, sizeof (adf_buf) - 1, "AF: %s", (use_filter) ? "On" : "Off");
  if (use_filter) adf_pos += snprintf (adf_buf + adf_pos, sizeof (adf_buf) - adf_pos - 1, " (Thr.: %u)", filter_threshold);
  snprintf (adf_buf + adf_pos, sizeof (adf_buf) - adf_pos - 1, " | DF: %s", (use_data_filters) ? "On" : "Off");

  char *train_format = (user_options->pcfg_train_format == PCFG_TRAIN_FORMAT_WEIGHED_WORDLIST) ? "Weighed Wordlist" : "Wordlist";

  u64 cnt = 0;
  u64 total_words = 0;

  // encoding conversion: convert training data from encoding_from to UTF-8

  bool iconv_enabled = strcmp (user_options->encoding_from, "utf-8") != 0;

  iconv_t iconv_ctx = (iconv_t) -1;

  char *iconv_tmp = NULL;

  if (iconv_enabled)
  {
    iconv_ctx = iconv_open ("utf-8", user_options->encoding_from);

    if (iconv_ctx == (iconv_t) -1)
    {
      event_log_error (hashcat_ctx, "iconv_open: %s", strerror (errno));

      hcfree (line);
      hcfree (decoded);
      hc_fclose (&fp);

      return -1;
    }

    iconv_tmp = (char *) hcmalloc (HCBUFSIZ_LARGE);
  }

  // main processing loop (single thread, no blocking)
  line_block_t *block;

  tty_break ();

  while ((block = queue_get_block (queue)) != NULL)
  {
    total_words += block->count;

    for (size_t i = 0; i < block->count; i++)
    {
      char  *entry_buf = block->lines[i];
      size_t entry_len = block->lens[i];

      if (iconv_enabled)
      {
        char   *src    = entry_buf;
        size_t  src_sz = entry_len;
        char   *dst    = iconv_tmp;
        size_t  dst_sz = HCBUFSIZ_LARGE;

        if (iconv (iconv_ctx, &src, &src_sz, &dst, &dst_sz) == (size_t) -1) continue;

        entry_buf = iconv_tmp;
        entry_len = HCBUFSIZ_LARGE - dst_sz;
      }

      int rc = process_entry (block->weighs[i], entry_buf, entry_len, decoded, decoded_len, t, use_filter, filter_threshold, use_data_filters);

      if (rc > 0) cnt += rc;
    }

    queue_release_block (queue);

    // check time every block (lightweight, no expensive syscalls)
    double current_ms = hc_timer_get (start);

    if (current_ms - last_update_ms >= 500.0)  // update every 500ms
    {
      double delta_time_sec = (current_ms - last_update_ms) / 1000.0;

      u64 delta_words = total_words - last_words;

      double current_speed = (delta_time_sec > 0) ? (double) delta_words / delta_time_sec : 0;

      if (avg_speed == 0) avg_speed = current_speed;
      else avg_speed = (0.3 * current_speed) + (0.7 * avg_speed);

      double percent = (t->file_lines > 0) ? (double) total_words / t->file_lines * 100.0 : 0;

      u64 remaining = (t->file_lines > total_words) ? t->file_lines - total_words : 0;

      unsigned long eta = (avg_speed > 0) ? (unsigned long) (remaining / avg_speed) : 0;

      double m_words_per_sec = avg_speed / 1000000.0;

      char eta_buf[32];

      if (eta > 3600)
      {
        snprintf (eta_buf, sizeof (eta_buf), "%luh %02lum %02lus", eta / 3600, (eta % 3600) / 60, eta % 60);
      }
      else if (eta > 60)
      {
        snprintf (eta_buf, sizeof (eta_buf), "%02lum %02lus", eta / 60, eta % 60);
      }
      else
      {
        snprintf (eta_buf, sizeof (eta_buf), "%lus", eta);
      }

      event_log_info_nn (hashcat_ctx,
        "PCFG Training | Progress: %5.2f%% (%lu pws) | Mode: %s (%" PRIu64 " words, %.3f mWords/s) | Mem: %" PRIu64 "/%" PRIu64 " GB | %s | ETA: %s | [q]uit",
        percent, (unsigned long) cnt, train_format, total_words, m_words_per_sec, t->memory_used >> 30, t->memory_limit >> 30, adf_buf, eta_buf);

      last_update_ms = current_ms;
      last_words = total_words;

      // check for 'q' keypress (non-blocking)
      int ch = tty_getchar_nb ();

      if (ch == 'q' || ch == 'Q')
      {
        event_log_info (hashcat_ctx, "\nPCFG Training: Quit requested. Stopping ...");

        hc_thread_mutex_lock (queue->mutex);
        queue->done = true;
        hc_thread_cond_signal (queue->cond_free);
        hc_thread_mutex_unlock (queue->mutex);

        break;
      }
    }
  }

  tty_fix ();

  // cleanup
  hc_thread_join (reader_tid);

  hcfree (reader_ctx.line_buf);

  queue_destroy (queue);

  double total_time_sec = hc_timer_get (start) / 1000.0;
  double final_speed    = (total_time_sec > 0) ? ((double) total_words / total_time_sec) / 1000000.0 : 0;

  if (user_options->quiet == false)
  {
    event_log_info (hashcat_ctx, "PCFG: %lu passwords trained in %.2fs (%" PRIu64 " words, %.3f mWords/s)",
      (unsigned long) cnt, total_time_sec, total_words, final_speed);
  }

  if (iconv_enabled)
  {
    iconv_close (iconv_ctx);
    hcfree (iconv_tmp);
  }

  hcfree (line);
  hcfree (decoded);
  hc_fclose (&fp);

  return 0;
}
// converts 64-bit starting counts into a 256-slot start row
static void compact_struct_start_to_bins (u64 *src_counts, pcfg_markov_start_row_t *dest_row)
{
  u64 total     = 0;
  u32 max_val   = 0;
  u16 best_type = 0;

  // calculate total and find the most frequent type for the final fill
  for (int i = 0; i < 256; i++)
  {
    if (src_counts[i] < 3) continue; // pruning

    total += src_counts[i];

    if (src_counts[i] > max_val)
    {
      max_val   = src_counts[i];
      best_type = (u16) i;
    }
  }

  if (total == 0)
  {
    memset (dest_row->states, 0, sizeof (dest_row->states));
    return;
  }

  // fill 256 bins based on probability
  int bin_idx = 0;

  for (int i = 0; i < 256; i++)
  {
    if (src_counts[i] < 3) continue;

    // calculate how many of the 256 slots this type deserves
    int num_bins = (int)((double) src_counts[i] / total * 256.0 + 0.5);

    // ensure that even rare types get at least one slot
    if (num_bins < 1) num_bins = 1;

    for (int b = 0; b < num_bins && bin_idx < 256; b++)
    {
      dest_row->states[bin_idx++] = (u16) i;
    }
  }

  // final fill: if there are empty slots left due to rounding,
  // fill them with the most frequent type instead of just the last one.
  while (bin_idx < 256)
  {
    dest_row->states[bin_idx++] = best_type;
  }
}

// converts 64-bit transition counts into a 256-slot transition row
static void compact_struct_row_to_bins (u64 *src_row, pcfg_markov_row_t *dest_row)
{
  u64 total    = 0;
  u32 max_val  = 0;
  u8 best_type = 0;

  // calculate total and find the most frequent transition target for the final fill
  for (int j = 0; j < 256; j++)
  {
    if (src_row[j] < 3) continue; // pruning

    total += src_row[j];

    if (src_row[j] > max_val)
    {
      max_val   = src_row[j];
      best_type = (u8) j;
    }
  }

  if (total == 0)
  {
    memset (dest_row->bins, 0, 256);
    return;
  }

  // fill bins based on probability distribution
  int bin_idx = 0;

  for (int j = 0; j < 256; j++)
  {
    if (src_row[j] < 3) continue;

    // calculate how many of the 256 slots this target type deserves
    int num_bins = (int)((double) src_row[j] / total * 256.0 + 0.5);

    // ensure even rare transitions get at least one slot
    if (num_bins < 1) num_bins = 1;

    for (int b = 0; b < num_bins && bin_idx < 256; b++)
    {
      dest_row->bins[bin_idx++] = (u8) j;
    }
  }

  // final fill: if there are empty slots left due to rounding,
  // fill them with the most frequent target type.
  while (bin_idx < 256)
  {
    dest_row->bins[bin_idx++] = best_type;
  }
}

static void compact_markov_row_to_bins (u64 *src_row, pcfg_markov_row_t *dest_row, u8 type)
{
  u64 total       = 0;
  u16 target_mask = get_mask_for_type (type);

  // calculate total for valid characters in this specific type
  for (int j = 0; j < 256; j++)
  {
    u64 val = src_row[j];

    if (val < 3) continue; // pruning noise

    bool is_valid = false;

    // always check the LUT for the specific script mask.
    // this allows Cyrillic/Arabic/etc bytes (>127) to be validated correctly.
    if (char_types_lut[j] & target_mask)
    {
      is_valid = true;
    }
    // fallback: if we are building the generic Unicode table (Catch-all), accept anything above 127.
    else if (j > 127 && target_mask == 0x8000)
    {
      is_valid = true;
    }

    if (is_valid) total += val;
  }

  if (total == 0)
  {
    memset (dest_row->bins, 0, 256);
    return;
  }

  // fill 256 probability bins
  int bin_idx = 0;

  for (int j = 0; j < 256; j++)
  {
    u64 val = src_row[j];

    if (val < 3) continue;

    bool is_valid = false;

    if (char_types_lut[j] & target_mask) is_valid = true;
    else if (j > 127 && target_mask == 0x8000) is_valid = true;

    if (is_valid)
    {
      // convert raw frequency to portion of 256 bins
      int num_bins = (int)(((double)val / (double) total) * 256.0 + 0.5);

      if (num_bins < 1) num_bins = 1;

      for (int b = 0; b < num_bins && bin_idx < 256; b++)
      {
        dest_row->bins[bin_idx++] = (u8) j;
      }
    }
  }

  // final fill: ensure all 256 bins are populated.
  // we fill remaining slots with the most frequent character found in this row.
  u8 best_byte = 0;
  u64 max_v = 0;

  for (int j = 0; j < 256; j++)
  {
    if (src_row[j] > max_v)
    {
      max_v = src_row[j];
      best_byte = j;
    }
  }

  while (bin_idx < 256)
  {
    dest_row->bins[bin_idx++] = best_byte;
  }
}

static void compact_markov_start_to_bins (u64 *src_table, u16 *dest_states, u32 num_bins)
{
  pcfg_markov_start_row_entry_t *entries = (pcfg_markov_start_row_entry_t *) hcmalloc (65536 * sizeof (pcfg_markov_start_row_entry_t));

  if (entries == NULL) return;

  u32 found = 0;

  // collect all entries that pass the pruning threshold to filter noise
  for (u32 i = 0; i < 65536; i++)
  {
    if (src_table[i] < 3) continue;

    entries[found].index = i;
    entries[found].count = src_table[i];

    found++;
  }

  // handle cases where no data meets the minimum threshold
  if (found == 0)
  {
    memset (dest_states, 0, num_bins * sizeof (u16));
    hcfree (entries);
    return;
  }

  // sort discovered entries by frequency in descending order
  hc_qsort_r (entries, found, sizeof (pcfg_markov_start_row_entry_t), compare_start_rows_entries_desc, NULL);

  // limit processing to the top entries that can fit in the destination buffer
  u32 limit = (found > num_bins) ? num_bins : found;
  u64 total = 0;

  for (u32 i = 0; i < limit; i++)
  {
    total += entries[i].count;
  }

  // populate states proportionally based on their relative weight
  u32 bin_idx = 0;

  for (u32 i = 0; i < limit; i++)
  {
    u64 val = entries[i].count;

    int assigned_slots = (int)(((double) val / (double) total) * num_bins + 0.5);

    if (assigned_slots < 1) assigned_slots = 1;

    for (int b = 0; b < assigned_slots && bin_idx < num_bins; b++)
    {
      dest_states[bin_idx++] = (u16) entries[i].index;
    }
  }

  // ensure all remaining slots are filled with the most frequent entry
  u16 best_index = (u16) entries[0].index;

  while (bin_idx < num_bins)
  {
    dest_states[bin_idx++] = best_index;
  }

  hcfree (entries);
}

bool pcfg_trainer_export_to_file (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *filename)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == false) event_log_info (hashcat_ctx, "PCFG: Exporting model to %s ...", filename);

  HCFILE fp;

  if (hc_fopen (&fp, filename, "wb") == false)
  {
    event_log_error (hashcat_ctx, "PCFG: Failed opening file (%s) for write.", filename);

    return false;
  }

  // Header
  u32 magic = PCFG_MAGIC;
  u32 version = PCFG_VERSION;

  hc_fwrite (&magic, 4, 1, &fp);
  hc_fwrite (&version, 4, 1, &fp);
  hc_fwrite (&t->pw_cnt, 8, 1, &fp);

  // encoding_from: "RAW" if no conversion was applied, otherwise the source encoding
  char encoding_buf[PCFG_ENCODING_MAX];
  memset (encoding_buf, 0, sizeof (encoding_buf));

  if (strcmp (user_options->encoding_from, "utf-8") != 0)
  {
    strncpy (encoding_buf, user_options->encoding_from, PCFG_ENCODING_MAX - 1);
  }
  else
  {
    strncpy (encoding_buf, "RAW", PCFG_ENCODING_MAX - 1);
  }

  hc_fwrite (encoding_buf, PCFG_ENCODING_MAX, 1, &fp);

  // Markov Tables
  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Markov tables ...");

  pcfg_markov_start_row_t *pw_len_table     = (pcfg_markov_start_row_t *) hccalloc (1, sizeof (pcfg_markov_start_row_t));
  pcfg_markov_start_row_t *struct_start_row = (pcfg_markov_start_row_t *) hccalloc (1, sizeof (pcfg_markov_start_row_t));
  pcfg_markov_row_t *struct_trans_table     = (pcfg_markov_row_t *) hccalloc (65536, sizeof (pcfg_markov_row_t));

  pcfg_markov_start_row_alpha_t *start_row_alpha         = (pcfg_markov_start_row_alpha_t *) hccalloc (1, sizeof (pcfg_markov_start_row_alpha_t));
  pcfg_markov_start_row_alpha_t *start_row_alpha_unicode = (pcfg_markov_start_row_alpha_t *) hccalloc (1, sizeof (pcfg_markov_start_row_alpha_t));
  pcfg_markov_start_row_digit_t *start_row_digit         = (pcfg_markov_start_row_digit_t *) hccalloc (1, sizeof (pcfg_markov_start_row_digit_t));

  pcfg_markov_row_t *markov_tables[10];

  for (int i = 0; i < 10; i++)
  {
    markov_tables[i] = (pcfg_markov_row_t *) hccalloc (65536, sizeof (pcfg_markov_row_t));
  }

  float *char_freq = (float *) hccalloc (65536, sizeof (float));

  if (!pw_len_table || !struct_start_row || !struct_trans_table
   || !start_row_alpha || !start_row_alpha_unicode || !start_row_digit || !char_freq)
  {
    event_log_error (hashcat_ctx, "PCFG: alloc failed.");
    return false;
  }

  for (int i = 0; i < 10; i++)
  {
    if (!markov_tables[i])
    {
      event_log_error (hashcat_ctx, "PCFG: alloc (markov table %d) failed.", i);
      return false;
    }
  }

  static const u8 table_types[10] = {
    PCFG_TK_LOWER, PCFG_TK_UPPER, PCFG_TK_DIGIT, PCFG_TK_LATIN_EXT, PCFG_TK_CYRILLIC,
    PCFG_TK_ARABIC, PCFG_TK_ASIAN, PCFG_TK_GREEK, PCFG_TK_HEBREW, 0xFF
  };

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Compact Markov tables ...");

  compact_struct_start_to_bins (t->pw_len_counts, pw_len_table);
  compact_struct_start_to_bins (t->struct_start_counts, struct_start_row);

  // Progress for struct_trans_table (65536 rows)
  for (int i = 0; i < 65536; i++)
  {
    compact_struct_row_to_bins (&t->struct_trans_counts[i * 256], &struct_trans_table[i]);

    if (((i & 0x3FFF) == 0) && user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Compact Markov tables | Struct transitions: %u%%", (i * 100) / 65536);
    }
  }

  compact_markov_start_to_bins (t->markov_start_alpha, start_row_alpha->states, 4096);
  compact_markov_start_to_bins (t->markov_start_alpha_unicode, start_row_alpha_unicode->states, 4096);
  compact_markov_start_to_bins (t->markov_start_digit, start_row_digit->states, 128);

  const u64 table_sz = 65536ULL * 256ULL;

  // Progress for Markov tables (65536 × 10)
  for (u32 s = 0; s < 65536; s++)
  {
    const u64 row_off = (u64) s * 256;

    for (int tbl = 0; tbl < 10; tbl++)
    {
      compact_markov_row_to_bins (&t->markov_table[(u64) tbl * table_sz + row_off], &markov_tables[tbl][s], table_types[tbl]);
    }

    if (((s & 0x3FFF) == 0) && user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Compact Markov tables | Terminal transitions: %u%%", (s * 100) / 65536);
    }
  }

  // char frequencies
  for (int ty = 0; ty < 256; ty++)
  {
    const u32 offset = ty * 256;

    u64 type_total = 0;

    for (int j = 0; j < 256; j++)
    {
      type_total += t->char_freq[offset + j];
    }

    if (type_total > 0)
    {
      const float inv_total = 1.0f / (float) type_total;

      for (int j = 0; j < 256; j++)
      {
        char_freq[offset + j] = (float) t->char_freq[offset + j] * inv_total;
      }
    }
  }

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Writing Markov tables ...");

  hc_fwrite (pw_len_table, sizeof (pcfg_markov_start_row_t), 1, &fp);
  hc_fwrite (struct_start_row, sizeof (pcfg_markov_start_row_t), 1, &fp);
  hc_fwrite (struct_trans_table, sizeof (pcfg_markov_row_t), 65536, &fp);

  hc_fwrite (start_row_alpha, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fwrite (start_row_alpha_unicode, sizeof (pcfg_markov_start_row_alpha_t), 1, &fp);
  hc_fwrite (start_row_digit, sizeof (pcfg_markov_start_row_digit_t), 1, &fp);

  for (int i = 0; i < 10; i++)
  {
    hc_fwrite (markov_tables[i], sizeof (pcfg_markov_row_t), 65536, &fp);
  }

  hc_fwrite (char_freq, sizeof (float), 65536, &fp);

  // free memory
  hcfree (pw_len_table);
  hcfree (struct_start_row);
  hcfree (struct_trans_table);
  hcfree (start_row_alpha);
  hcfree (start_row_alpha_unicode);
  hcfree (start_row_digit);

  for (int i = 0; i < 10; i++)
  {
    hcfree (markov_tables[i]);
  }

  hcfree (char_freq);

  // Structures

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Counting structures ...");

  u32 struct_cnt = 0;

  for (u64 i = 0; i < t->ht_size; i++)
  {
    ht_node_t *n = t->struct_ht[i];

    while (n)
    {
      struct_cnt++;

      n = n->next;
    }

    if (((i & 0xFFFFF) == 0) && user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Counting structures: %u%% (%u found)", (u32) ((i * 100) / t->ht_size), struct_cnt);
    }
  }

  hc_fwrite (&struct_cnt, 4, 1, &fp);

  if (struct_cnt > 0)
  {
    if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Collecting %u structures ...", struct_cnt);

    ht_node_t **struct_ptrs = (ht_node_t **) hcmalloc (struct_cnt * sizeof (ht_node_t *));

    u32 s_idx = 0;

    for (u64 i = 0; i < t->ht_size; i++)
    {
      ht_node_t *n = t->struct_ht[i];

      while (n)
      {
        struct_ptrs[s_idx++] = n;
        n = n->next;
      }
    }

    if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Sorting %u structures ...", struct_cnt);

    hc_qsort_r (struct_ptrs, struct_cnt, sizeof (ht_node_t *), compare_ht_node_desc, NULL);

    if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Writing structures: 0%%");

    const u32 struct_progress_step = (struct_cnt > 100) ? (struct_cnt / 100) : 1;

    u32 struct_next_progress = struct_progress_step;

    for (u32 i = 0; i < struct_cnt; i++)
    {
      ht_node_t *n = struct_ptrs[i];

      pcfg_structure_t s;

      memset (&s, 0, sizeof (s));

      s.count = n->cnt;
      s.prob = (float) n->cnt / t->struct_total;

      const char *p = n->key;

      while (*p && s.token_cnt < PCFG_TOKEN_MAX)
      {
        if (isalpha ((unsigned char) *p))
        {
          s.types[s.token_cnt] = *p++;

          u32 ln = 0;

          while (isdigit ((unsigned char) *p))
          {
            ln = ln * 10 + (*p++ - '0');
          }

          s.lengths[s.token_cnt] = (u16) ln;
          s.token_cnt++;
          // update also total_len
          s.total_len += ln;
        }
        else
        {
          p++;
        }
      }

      hc_fwrite (&s, sizeof (pcfg_structure_t), 1, &fp);

      if (i >= struct_next_progress)
      {
        if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Writing structures: %u%%", (i * 100) / struct_cnt);
        struct_next_progress += struct_progress_step;
      }
    }

    hcfree (struct_ptrs);
  }

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Written %u structures", struct_cnt);

  // Terminals

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Counting terminals ...");

  static u32 counts[256][PCFG_VALUE_MAX];

  memset (counts, 0, sizeof (counts));

  u64 term_cnt         = 0;
  u64 type_totals[256] = { 0 };

  // count by (type, length) and by type
  for (u64 i = 0; i < t->ht_size; i++)
  {
    term_node_t *n = t->global_term_ht[i];

    while (n)
    {
      if (n->len < PCFG_VALUE_MAX)
      {
        counts[n->type][n->len]++;
        type_totals[n->type]++;
        term_cnt++;
      }

      n = n->next;
    }

    if (((i & 0xFFFFF) == 0) && user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Counting terminals: %u%%", (u32) ((i * 100) / t->ht_size));
    }
  }

  if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Terminals: %" PRIu64 " total", term_cnt);

  if (term_cnt > 0)
  {
    // allocate single buffer for ALL terminals (single-pass collection)
    term_node_t **all_ptrs = (term_node_t **) hcmalloc (term_cnt * sizeof (term_node_t *));

    // compute flat offsets for each (type, length) pair
    const u32 flat_sz = 256 * PCFG_VALUE_MAX;

    u64 *flat_off  = (u64 *) hcmalloc (flat_sz * sizeof (u64));
    u64 *flat_fill = (u64 *) hcmalloc (flat_sz * sizeof (u64));

    u64 off = 0;

    for (int ty = 0; ty < 256; ty++)
    {
      for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
      {
        u32 idx = ty * PCFG_VALUE_MAX + ln;

        flat_off[idx]  = off;
        flat_fill[idx] = off;
        off += counts[ty][ln];
      }
    }

    // single pass over hash table: place each terminal into its (type, length) slot
    if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Collecting %" PRIu64 " terminals ...", term_cnt);

    for (u64 i = 0; i < t->ht_size; i++)
    {
      term_node_t *n = t->global_term_ht[i];

      while (n)
      {
        if (n->len < PCFG_VALUE_MAX)
        {
          u32 idx = (u32) n->type * PCFG_VALUE_MAX + n->len;

          all_ptrs[flat_fill[idx]++] = n;
        }

        n = n->next;
      }

      if (((i & 0xFFFFF) == 0) && user_options->quiet == false)
      {
        event_log_info_nn (hashcat_ctx, "PCFG: Collecting terminals: %u%%", (u32) ((i * 100) / t->ht_size));
      }
    }

    hcfree (flat_fill);

    u64 term_written = 0;

    // sort and write per (type, length) segment
    for (int ty = 0; ty < 256; ty++)
    {
      if (type_totals[ty] == 0)
      {
        for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
        {
          u32 zero = 0;

          hc_fwrite (&zero, sizeof (u32), 1, &fp);
        }

        continue;
      }

      for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
      {
        u32 cnt = counts[ty][ln];

        hc_fwrite (&cnt, sizeof (u32), 1, &fp);

        if (cnt > 0)
        {
          u32 idx = ty * PCFG_VALUE_MAX + ln;

          term_node_t **segment = all_ptrs + flat_off[idx];

          hc_qsort_r (segment, cnt, sizeof (term_node_t *), compare_term_node_desc, NULL);

          for (u32 k = 0; k < cnt; k++)
          {
            term_node_t *n = segment[k];

            u16 len = (u16) n->len;

            float prob = (t->term_totals[ty][ln] > 0) ? (float) n->cnt / t->term_totals[ty][ln] : 0.0f;

            u32 c32 = (u32) n->cnt;

            hc_fwrite (&len, 2, 1, &fp);
            hc_fwrite (&c32, 4, 1, &fp);
            hc_fwrite (&prob, 4, 1, &fp);
            hc_fwrite (n->val, 1, n->len, &fp);
          }

          term_written += cnt;
        }
      }

      if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Terminals: %u%% (%" PRIu64 "/%" PRIu64 ")", (u32) ((term_written * 100) / term_cnt), term_written, term_cnt);
    }

    hcfree (flat_off);
    hcfree (all_ptrs);
  }
  else
  {
    u32 zero = 0;

    for (int i = 0; i < 256 * PCFG_VALUE_MAX; i++)
    {
      hc_fwrite (&zero, 4, 1, &fp);
    }
  }

  hc_fclose (&fp);

  if (user_options->quiet == false) event_log_info (hashcat_ctx, "PCFG: Export complete - %u structures, %" PRIu64 " terminals written", struct_cnt, term_cnt);

  return true;
}
