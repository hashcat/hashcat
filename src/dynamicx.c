/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "shared.h"
#include "filehandling.h"
#include "parser.h"
#include "path.h"
#include "dynamicx.h"

// John the Ripper writes a hash of one of its dynamic formats as
//
//   $dynamic_N$<hash>[$<salt>][$$2<salt2>][$$U<user>]
//
// with a field that is not printable written as $HEX$ followed by its hex. hashcat writes the same
// hashes as <hash><separator><salt> and takes the format from -m rather than from the line, so a
// dynamic hash needs both the fields rearranged and the number turned into a hash-mode. This is
// the table that turns the number into the hash-mode.
//
// Only John's built-in formats are here. The formats in dynamic.conf are numbered from 1001 and
// what they compute is whatever that file says, which is not something hashcat can know.
//
// The expression is not what decides. dynamic_19 and dynamic_0 are both md5($p) and they are
// Cisco PIX and raw MD5; dynamic_20 and dynamic_1 are both md5($p.$s) and they are Cisco ASA and
// joomla. The name John puts after the expression is what decides, and where John and hashcat
// spell the same construction differently the entry was made by hand. Every entry in this table
// was checked by running hashcat over John's own self-test vectors for that format.

typedef struct dynamicx_map
{
  int         dynamic_num;
  u32         hash_mode;
  const char *expression;

} dynamicx_map_t;

static const dynamicx_map_t DYNAMICX_MAP[] =
{
  {    0,     0, "md5($p)" },
  {    1,    10, "md5($p.$s)" },
  {    2,  2600, "md5(md5($p))" },
  {    3,  3500, "md5(md5(md5($p)))" },
  {    4,    20, "md5($s.$p)" },
  {    5,  3800, "md5($s.$p.$s)" },
  {    6,  2611, "md5(md5($p).$s)" },
  {    9,  3710, "md5($s.md5($p))" },
  {   10,  4010, "md5($s.md5($s.$p))" },
  {   11,  4110, "md5($s.md5($p.$s))" },
  {   12,  2811, "md5(md5($s).md5($p))" },
  {   13,  3910, "md5(md5($p).md5($s))" },
  {   14, 33100, "md5($s.md5($p).$s)" },
  {   19,  2400, "md5($p)" },
  {   20,  2410, "md5($p.$s)" },
  {   22,  4400, "md5(sha1($p))" },
  {   23,  4700, "sha1(md5($p))" },
  {   24,   110, "sha1($p.$s)" },
  {   25,   120, "sha1($s.$p)" },
  {   26,   100, "sha1($p)" },
  {   29,    70, "md5(utf16($p))" },
  {   30,   900, "md4($p)" },
  {   33,  1000, "md4(utf16($p))" },
  {   38,  8400, "sha1($s.sha1($s.sha1($p)))" },
  {   41,   140, "sha1($s.utf16($p))" },
  {   50,  1300, "sha224($p)" },
  {   51,  1320, "sha224($s.$p)" },
  {   52,  1310, "sha224($p.$s)" },
  {   53, 34400, "sha224(sha224($p))" },
  {   60,  1400, "sha256($p)" },
  {   61,  1420, "sha256($s.$p)" },
  {   62,  1410, "sha256($p.$s)" },
  {   64, 21400, "sha256(sha256_raw($p))" },
  {   65, 20710, "sha256(sha256($p).$s)" },
  {   66, 20720, "sha256($s.sha256($p))" },
  {   70, 10800, "sha384($p)" },
  {   71, 10820, "sha384($s.$p)" },
  {   72, 10810, "sha384($p.$s)" },
  {   80,  1700, "sha512($p)" },
  {   81,  1720, "sha512($s.$p)" },
  {   82,  1710, "sha512($p.$s)" },
  {   84, 21000, "sha512(sha512_raw($p))" },
  {   85, 32410, "sha512(sha512($p).$s)" },
  {   90,  6900, "gost($p)" },
  {  100,  6100, "whirlpool($p)" },
  {  130,  6000, "ripemd160($p)" },
  {  150, 33600, "ripemd320($p)" },
  {  370, 17300, "sha3_224($p)" },
  {  380, 17400, "sha3_256($p)" },
  {  390, 17500, "sha3_384($p)" },
  {  400, 17600, "sha3_512($p)" },
  {  410, 17800, "keccak_256($p)" },
  {  420, 18000, "keccak_512($p)" },
  {  430, 17700, "keccak_224($p)" },
  {  440, 17900, "keccak_384($p)" },
  {  450, 31100, "sm3($p)" },
};

#define DYNAMICX_MAP_CNT (sizeof (DYNAMICX_MAP) / sizeof (dynamicx_map_t))

static const dynamicx_map_t *dynamicx_map_find (const int dynamic_num)
{
  for (size_t i = 0; i < DYNAMICX_MAP_CNT; i++)
  {
    if (DYNAMICX_MAP[i].dynamic_num == dynamic_num) return &DYNAMICX_MAP[i];
  }

  return NULL;
}

int dynamicx_hash_mode (const int dynamic_num)
{
  const dynamicx_map_t *map = dynamicx_map_find (dynamic_num);

  if (map == NULL) return -1;

  return (int) map->hash_mode;
}

const char *dynamicx_expression (const int dynamic_num)
{
  const dynamicx_map_t *map = dynamicx_map_find (dynamic_num);

  if (map == NULL) return NULL;

  return map->expression;
}

// The number in the tag, and how many bytes the tag takes. Both are wanted where the line is only
// being looked at rather than translated: choosing the hash-mode from the first line, and keeping
// the tag so that --left and --remove can write the line back the way it came in.

int dynamicx_tag_number (const char *line_buf, const int line_len, int *tag_len)
{
  u8 *hash_pos = NULL;
  int hash_len = 0;

  const int dynamic_num = extract_dynamicx_hash ((const u8 *) line_buf, line_len, &hash_pos, &hash_len);

  if (dynamic_num < 0) return -1;

  if (tag_len != NULL) *tag_len = (int) ((const char *) hash_pos - line_buf);

  return dynamic_num;
}

// Rewrite one line from John's spelling into hashcat's, in place. Every rewrite either keeps the
// line the same length or shortens it -- the $ between the fields becomes one separator byte, and
// $HEX$ turns two bytes into one -- so no second buffer is needed and the tag at the front is left
// where it is for the caller to pick up.
//
// Nothing is written until every check has passed, so a line this refuses is the line as it was
// read and an error message quoting it quotes what the user wrote.

int dynamicx_translate (char *line_buf, const int line_len, const char separator, int *tag_len, int *hash_len, const char **error)
{
  *error = NULL;

  const int dynamic_num = dynamicx_tag_number (line_buf, line_len, tag_len);

  if (dynamic_num < 0)
  {
    *error = "no $dynamic_N$ tag";

    return -1;
  }

  char *rest = line_buf + *tag_len;

  const int rest_len = line_len - *tag_len;

  // the hash runs to the first $, and whatever follows it is the salt

  int sep_pos = -1;

  for (int i = 0; i < rest_len; i++)
  {
    if (rest[i] == '$')
    {
      sep_pos = i;

      break;
    }
  }

  if (sep_pos == -1)
  {
    *hash_len = rest_len;

    return dynamic_num;
  }

  char *salt = rest + sep_pos + 1;

  int salt_len = rest_len - sep_pos - 1;

  const bool is_hex = ((salt_len > 4) && (memcmp (salt, "HEX$", 4) == 0));

  const char *src = salt;

  int src_len = salt_len;

  if (is_hex == true)
  {
    src     = salt + 4;
    src_len = salt_len - 4;

    if ((src_len & 1) || (is_valid_hex_string ((const u8 *) src, (size_t) src_len) == false))
    {
      *error = "a malformed $HEX$ salt";

      return -1;
    }

    salt_len = src_len / 2;
  }

  // $$2 introduces a second salt and $$U a user name. hashcat has one salt field per hash and no
  // field for a name that takes part in the hash, so a line carrying either is refused rather than
  // loaded without it and cracked against something else. The marker of the first field lost one $
  // to the split above and reads as a leading $2 or $U.
  //
  // The separator has to survive into the line hashcat parses, and so does the line itself.

  char win1 = 0;
  char win2 = 0;

  for (int i = 0; i < salt_len; i++)
  {
    const char c = (is_hex == true) ? (char) hex_to_u8 ((const u8 *) src + (i * 2)) : src[i];

    if (c == separator)
    {
      *error = "a salt holding the separator character";

      return -1;
    }

    if ((c == 0) || (c == '\n') || (c == '\r'))
    {
      *error = "a salt holding a null byte or a line break";

      return -1;
    }

    if ((c == '2') || (c == 'U'))
    {
      const bool at_start  = ((i == 1) && (win2 == '$'));
      const bool in_middle = ((win1 == '$') && (win2 == '$'));

      if ((at_start == true) || (in_middle == true))
      {
        *error = (c == '2') ? "a second salt ($$2), which hashcat has no field for"
                            : "a user name ($$U), which hashcat has no field for";

        return -1;
      }
    }

    win1 = win2;
    win2 = c;
  }

  // checks are done, the line may be written on now

  if (is_hex == true)
  {
    // two bytes read for every one written, so decoding a field onto itself never overtakes itself

    hex_decode ((const u8 *) src, src_len, (u8 *) salt);
  }

  rest[sep_pos] = separator;

  *hash_len = sep_pos + 1 + salt_len;

  // decoding a $HEX$ field shortens the line, and what is left behind the new end is the tail of the
  // hex. The line is what an error message about this hash quotes, so it ends here now.

  line_buf[*tag_len + *hash_len] = 0;

  return dynamic_num;
}

// The hash-mode comes from the first line of the hash list, before anything that depends on the
// hash-mode has been set up. This is the same place autodetect runs, and it is the reason the tag
// beats autodetect: autodetect cannot tell md5($p.$s) from md5($s.$p) by looking at a hash, and
// the tag says which one it is.

// The other direction: a line hashcat has just encoded, turned back into the line John wrote.
//
// out_buf holds the tag already, tag_len bytes of it, followed by hash_len bytes of hashcat's
// encoding. What is left to do is the separator between hash and salt, which is a $ again, and a
// salt that is not printable, which John writes as $HEX$ and hashcat writes as itself.
//
// Anything that got this far went through dynamicx_translate on the way in, so the salt holds no
// separator, no null byte and no line break, and it needs nothing but the hex when it is binary.
//
// Returns the new length. tag_len of 0 means this is not a --dynamic-x hash and nothing is done.

int dynamicx_encode (char *out_buf, const int tag_len, const int hash_len, const char separator, const int out_sz)
{
  if (tag_len == 0) return hash_len;

  char *rest = out_buf + tag_len;

  int sep_pos = -1;

  for (int i = 0; i < hash_len; i++)
  {
    if (rest[i] == separator)
    {
      sep_pos = i;

      break;
    }
  }

  if (sep_pos == -1) return tag_len + hash_len;

  rest[sep_pos] = '$';

  char *salt = rest + sep_pos + 1;

  const int salt_len = hash_len - sep_pos - 1;

  bool printable = true;

  for (int i = 0; i < salt_len; i++)
  {
    const u8 c = (u8) salt[i];

    if ((c < 0x20) || (c > 0x7e))
    {
      printable = false;

      break;
    }
  }

  if (printable == true) return tag_len + hash_len;

  // "$HEX$" plus two bytes for every one, and the $ of it is the separator that is already there

  if ((tag_len + sep_pos + 1 + 4 + (salt_len * 2) + 1) > out_sz) return tag_len + hash_len;

  // written from the back, because byte i ends up at 4 + (i * 2) and that is never below i

  for (int i = salt_len - 1; i >= 0; i--)
  {
    hex_encode ((const u8 *) salt + i, 1, (u8 *) salt + 4 + (i * 2));
  }

  memcpy (salt, "HEX$", 4);

  return tag_len + sep_pos + 1 + 4 + (salt_len * 2);
}

// The number in the tag of the first hash in the list, or -1 if there is none. Quiet: an unreadable
// or missing hash file is what user_options_sanity and hashes_init_stage1 report on, not this.

int dynamicx_first_number (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->benchmark    == true) return -1;
  if (user_options->keyspace     == true) return -1;
  if (user_options->stdout_flag  == true) return -1;
  if (user_options->backend_info >    0)  return -1;
  if (user_options->hash_info    >    0)  return -1;

  if (user_options_extra->hc_hash == NULL) return -1;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  if (line_buf == NULL) return -1;

  int line_len = 0;

  if (hc_path_exist (user_options_extra->hc_hash) == true)
  {
    HCFILE fp;

    if (hc_fopen (&fp, user_options_extra->hc_hash, "rb") == false)
    {
      hcfree (line_buf);

      return -1;
    }

    while (!hc_feof (&fp))
    {
      line_len = (int) fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

      if (line_len > 0) break;
    }

    hc_fclose (&fp);
  }
  else
  {
    line_len = snprintf (line_buf, HCBUFSIZ_LARGE, "%s", user_options_extra->hc_hash);
  }

  const int dynamic_num = (line_len > 0) ? dynamicx_tag_number (line_buf, line_len, NULL) : -1;

  hcfree (line_buf);

  return dynamic_num;
}

// The hash-mode comes from the first line of the hash list, before anything that depends on the
// hash-mode has been set up. This is the same place autodetect runs, and it is the reason the tag
// beats autodetect: autodetect cannot tell md5($p.$s) from md5($s.$p) by looking at a hash, and
// the tag says which one it is.

int dynamicx_session_hash_mode (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->dynamic_x == false) return 0;

  const int dynamic_num = dynamicx_first_number (hashcat_ctx);

  if (dynamic_num < 0)
  {
    if (user_options_extra->hc_hash == NULL) return 0;

    event_log_error (hashcat_ctx, "--dynamic-x was given but the first hash does not start with $dynamic_N$.");

    return -1;
  }

  user_options_extra->dynamicx_num = dynamic_num;

  const int hash_mode = dynamicx_hash_mode (dynamic_num);

  if (hash_mode == -1)
  {
    event_log_error (hashcat_ctx, "hashcat has no hash-mode for $dynamic_%d$.", dynamic_num);

    event_log_warning (hashcat_ctx, "Run 'john --list=subformats' to see what that format computes.");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  if (user_options->hash_mode_chgd == true)
  {
    if (user_options->hash_mode != hash_mode)
    {
      event_log_warning (hashcat_ctx, "$dynamic_%d$ is %s, which is hash-mode %d, but -m %d was given.", dynamic_num, dynamicx_expression (dynamic_num), hash_mode, user_options->hash_mode);
      event_log_warning (hashcat_ctx, "Continuing with -m %d.", user_options->hash_mode);
      event_log_warning (hashcat_ctx, NULL);
    }

    return 0;
  }

  user_options->hash_mode  = hash_mode;
  user_options->autodetect = false;

  return 0;
}
