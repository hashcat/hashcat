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
#include "recipe.h"
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
// A format runs in mode 4000 with the recipe that computes it, from DYNAMICX_RECIPES. DYNAMICX_MAP
// holds hash-modes. It is the route for -O, which mode 4000 has no kernels for, where a hash-mode
// with optimized kernels reads the same lines. It is the only route for the Cisco formats, whose
// hash is an encoding that mode 4000 cannot read.
//
// The formats from 1001 up are the ones that John's dynamic.conf ships with. A user can define such
// a number differently in a local copy of that file, and a hash of that local format then does not
// crack here.
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
  {   50,  1300, "sha224($p)" },
  {   60,  1400, "sha256($p)" },
  {   61,  1420, "sha256($s.$p)" },
  {   62,  1410, "sha256($p.$s)" },
  {   64, 21400, "sha256(sha256_raw($p))" },
  {   65, 20710, "sha256(sha256($p).$s)" },
  {   70, 10800, "sha384($p)" },
  {   71, 10820, "sha384($s.$p)" },
  {   72, 10810, "sha384($p.$s)" },
  {   80,  1700, "sha512($p)" },
  {   81,  1720, "sha512($s.$p)" },
  {   82,  1710, "sha512($p.$s)" },
  {   84, 21000, "sha512(sha512_raw($p))" },
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

  // dynamic.conf. The long salt formats 1014, 1016 and 1017 and XenForo's 1503 have no -O route,
  // because their salts are longer than the optimized kernels accept.

  { 1010,  9900, "md5($p null_padded_to_len_100)" },
  { 1013,    10, "md5($p.PMD5(username))" },
  { 1020, 32800, "md5(sha1(md5($p)))" },
  { 1032,   133, "sha1_64(utf16($p))" },
  { 1400,   170, "sha1(utf16($p))" },
  { 1501,  4520, "sha1($s.sha1($p))" },
  { 1502,  4510, "sha1(sha1($p).$s)" },
  { 1504,  4900, "sha1($s.$p.$s)" },
  { 1518, 20900, "md5(sha1($p).md5($p).sha1($p))" },
  { 1588, 12600, "sha256($s.sha1($p))" },
  { 1592,  8400, "sha1($s.sha1($s.sha1($p)))" },
};

#define DYNAMICX_MAP_CNT (sizeof (DYNAMICX_MAP) / sizeof (dynamicx_map_t))

// The formats as mode 4000 recipes. A format whose salt is binary in practice, such as RADIUS,
// Telegram and net-md5, reads it with fromhex (salt) and has no -O route, because a hash-mode cannot
// load a salt holding a null byte or a line break.
//
// fields names the $$2 and $$U fields the John format declares. John splits them off the end of
// the salt only for a format that declares them, because a salt can contain those characters too.

typedef struct dynamicx_recipe
{
  int         dynamic_num;
  const char *expression;
  const char *recipe;
  u32         fields;

} dynamicx_recipe_t;

// John's large hash families are 9 formats each, numbered N0 to N8 and built from one template.
// The template is the same for every family, so are the recipes.

#define DYNAMICX_FAMILY(N,J,H) \
  { (N) + 0, J "($p)",                  H "(pass)",                      0 }, \
  { (N) + 1, J "($s.$p)",               H "(salt . pass)",               0 }, \
  { (N) + 2, J "($p.$s)",               H "(pass . salt)",               0 }, \
  { (N) + 3, J "(" J "($p))",           H "(" H "(pass))",               0 }, \
  { (N) + 4, J "(" J "_raw($p))",       H "(" H "_bin(pass))",           0 }, \
  { (N) + 5, J "(" J "($p).$s)",        H "(" H "(pass) . salt)",        0 }, \
  { (N) + 6, J "($s." J "($p))",        H "(salt . " H "(pass))",        0 }, \
  { (N) + 7, J "(" J "($s)." J "($p))", H "(" H "(salt) . " H "(pass))", 0 }, \
  { (N) + 8, J "(" J "($p)." J "($p))", H "(" H "(pass) . " H "(pass))", 0 }

static const dynamicx_recipe_t DYNAMICX_RECIPES[] =
{
  {    0, "md5($p)",                                "md5(pass)",                                               0 },
  {    1, "md5($p.$s)",                             "md5(pass . salt)",                                        0 },
  {    2, "md5(md5($p))",                           "md5(md5(pass))",                                          0 },
  {    3, "md5(md5(md5($p)))",                      "md5^3(pass)",                                             0 },
  {    4, "md5($s.$p)",                             "md5(salt . pass)",                                        0 },
  {    5, "md5($s.$p.$s)",                          "md5(salt . pass . salt)",                                 0 },
  {    6, "md5(md5($p).$s)",                        "md5(md5(pass) . salt)",                                   0 },
  {    7, "md5(md5($p).$s)",                        "md5(md5(pass) . salt)",                                   0 },
  {    8, "md5(md5($s).$p)",                        "md5(md5(salt) . pass)",                                   0 },
  {    9, "md5($s.md5($p))",                        "md5(salt . md5(pass))",                                   0 },
  {   10, "md5($s.md5($s.$p))",                     "md5(salt . md5(salt . pass))",                            0 },
  {   11, "md5($s.md5($p.$s))",                     "md5(salt . md5(pass . salt))",                            0 },
  {   12, "md5(md5($s).md5($p))",                   "md5(md5(salt) . md5(pass))",                              0 },
  {   13, "md5(md5($p).md5($s))",                   "md5(md5(pass) . md5(salt))",                              0 },
  {   14, "md5($s.md5($p).$s)",                     "md5(salt . md5(pass) . salt)",                            0 },
  {   15, "md5($u.md5($p).$s)",                     "md5(user . md5(pass) . salt)",                            DYNAMICX_SPLIT_USER },
  {   16, "md5(md5(md5($p).$s).$s2)",               "md5(md5(md5(pass) . salt) . salt2)",                      DYNAMICX_SPLIT_SALT2 },
  {   18, "md5($s.Y.$p.0xF7.$s)",                   "md5(salt . \"Y\" . pass . \"\\xf7\" . salt)",             0 },
  {   22, "md5(sha1($p))",                          "md5(sha1(pass))",                                         0 },
  {   23, "sha1(md5($p))",                          "sha1(md5(pass))",                                         0 },
  {   24, "sha1($p.$s)",                            "sha1(pass . salt)",                                       0 },
  {   25, "sha1($s.$p)",                            "sha1(salt . pass)",                                       0 },
  {   26, "sha1($p)",                               "sha1(pass)",                                              0 },
  {   29, "md5(utf16($p))",                         "md5(utf16le(pass))",                                      0 },
  {   30, "md4($p)",                                "md4(pass)",                                               0 },
  {   31, "md4($s.$p)",                             "md4(salt . pass)",                                        0 },
  {   32, "md4($p.$s)",                             "md4(pass . salt)",                                        0 },
  {   33, "md4(utf16($p))",                         "md4(utf16le(pass))",                                      0 },
  {   34, "md5(md4($p))",                           "md5(md4(pass))",                                          0 },
  {   35, "sha1(uc($u).:.$p)",                      "sha1(upper(user) . \":\" . pass)",                        DYNAMICX_SPLIT_USER },
  {   36, "sha1($u.:.$p)",                          "sha1(user . \":\" . pass)",                               DYNAMICX_SPLIT_USER },
  {   37, "sha1(lc($u).$p)",                        "sha1(lower(user) . pass)",                                DYNAMICX_SPLIT_USER },
  {   38, "sha1($s.sha1($s.sha1($p)))",             "sha1(salt . sha1(salt . sha1(pass)))",                    0 },
  {   39, "md5($s.pad16($p))",                      "md5(fromhex(salt) . pad(pass, 16))",                      0 },
  {   40, "sha1($s.pad20($p))",                     "sha1(fromhex(salt) . pad(pass, 20))",                     0 },
  {   41, "sha1($s.utf16($p))",                     "sha1(fromhex(salt) . utf16le(pass))",                     0 },
  { 1001, "md5(md5(md5(md5($p))))",                 "md5^4(pass)",                                             0 },
  { 1002, "md5(md5(md5(md5(md5($p)))))",            "md5^5(pass)",                                             0 },
  { 1003, "md5(md5($p).md5($p))",                   "md5(md5(pass) . md5(pass))",                              0 },
  { 1004, "md5^6($p)",                              "md5^6(pass)",                                             0 },
  { 1005, "md5^7($p)",                              "md5^7(pass)",                                             0 },
  { 1006, "md5^8($p)",                              "md5^8(pass)",                                             0 },
  { 1007, "md5(md5($p).$s)",                        "md5(md5(pass) . salt)",                                   0 },
  { 1008, "md5($p.$s)",                             "md5(pass . fromhex(salt))",                               0 },
  { 1009, "md5($s.$p)",                             "md5(fromhex(salt) . pass)",                               0 },
  { 1010, "md5($p null_padded_to_len_100)",         "md5(pad(pass, 100))",                                     0 },
  { 1011, "md5($p.md5($s))",                        "md5(pass . md5(salt))",                                   0 },
  { 1012, "md5($p.md5($s))",                        "md5(pass . md5(salt))",                                   0 },
  { 1013, "md5($p.PMD5(username))",                 "md5(pass . salt)",                                        0 },
  { 1014, "md5($p.$s)",                             "md5(pass . salt)",                                        0 },
  { 1015, "md5(md5($p.$u).$s)",                     "md5(md5(pass . user) . salt)",                            DYNAMICX_SPLIT_USER },
  { 1016, "md5($p.$s)",                             "md5(pass . fromhex(salt))",                               0 },
  { 1017, "md5($s.$p)",                             "md5(salt . pass)",                                        0 },
  { 1018, "md5(sha1(sha1($p)))",                    "md5(sha1(sha1(pass)))",                                   0 },
  { 1019, "md5(sha1(sha1(md5($p))))",               "md5(sha1(sha1(md5(pass))))",                              0 },
  { 1020, "md5(sha1(md5($p)))",                     "md5(sha1(md5(pass)))",                                    0 },
  { 1021, "md5(sha1(md5(sha1($p))))",               "md5(sha1(md5(sha1(pass))))",                              0 },
  { 1022, "md5(sha1(md5(sha1(md5($p)))))",          "md5(sha1(md5(sha1(md5(pass)))))",                         0 },
  { 1023, "sha1($p) truncated to 32",               "trunc(sha1(pass), 32)",                                   0 },
  { 1024, "sha1(md5($p)) truncated to 32",          "trunc(sha1(md5(pass)), 32)",                              0 },
  { 1025, "sha1(md5(md5($p))) truncated to 32",     "trunc(sha1(md5(md5(pass))), 32)",                         0 },
  { 1026, "sha1(sha1($p)) truncated to 32",         "trunc(sha1(sha1(pass)), 32)",                             0 },
  { 1027, "sha1(sha1(sha1($p))) truncated to 32",   "trunc(sha1(sha1(sha1(pass))), 32)",                       0 },
  { 1028, "sha1(sha1_raw($p)) truncated to 32",     "trunc(sha1(sha1_bin(pass)), 32)",                         0 },
  { 1029, "sha256($p) truncated to 32",             "trunc(sha256(pass), 32)",                                 0 },
  { 1030, "whirlpool($p) truncated to 32",          "trunc(wrl(pass), 32)",                                    0 },
  { 1031, "gost($p) truncated to 32",               "trunc(gost(pass), 32)",                                   0 },
  { 1032, "sha1_64(utf16($p))",                     "sha1_b64(utf16le(pass))",                                 0 },
  { 1033, "sha1_64(utf16($p).$s)",                  "sha1_b64(utf16le(pass) . salt)",                          0 },
  { 1034, "md5($p.$u)",                             "md5(pass . user)",                                        DYNAMICX_SPLIT_USER },
  { 1300, "md5(md5_raw($p))",                       "md5(md5_bin(pass))",                                      0 },
  { 1350, "md5(md5($s.$p):$s)",                     "md5(md5(salt . pass) . \":\" . salt)",                    0 },
  { 1400, "sha1(utf16($p))",                        "sha1(utf16le(pass))",                                     0 },
  { 1401, "md5($u.\\nskyper\\n.$p)",                "md5(user . \"\\nskyper\\n\" . pass)",                     DYNAMICX_SPLIT_USER },
  { 1501, "sha1($s.sha1($p))",                      "sha1(salt . sha1(pass))",                                 0 },
  { 1502, "sha1(sha1($p).$s)",                      "sha1(sha1(pass) . salt)",                                 0 },
  { 1503, "sha256(sha256($p).$s)",                  "sha256(sha256(pass) . salt)",                             0 },
  { 1504, "sha1($s.$p.$s)",                         "sha1(salt . pass . salt)",                                0 },
  { 1505, "md5($p.$s.md5($p.$s))",                  "md5(pass . salt . md5(pass . salt))",                     0 },
  { 1506, "md5($u.:XDB:.$p)",                       "md5(user . \":XDB:\" . pass)",                            DYNAMICX_SPLIT_USER },
  { 1507, "sha1(utf16($const.$p))",                 "sha1(utf16le(\"\\x01\\x0f\\x0d\\x33\") . utf16le(pass))", 0 },
  { 1518, "md5(sha1($p).md5($p).sha1($p))",         "md5(sha1(pass) . md5(pass) . sha1(pass))",                0 },
  { 1528, "sha256($s.$p.$s)",                       "sha256(fromhex(salt) . pass . fromhex(salt))",            0 },
  { 1529, "sha1($p null_padded_to_len_32)",         "sha1(pad(pass, 32))",                                     0 },
  { 1550, "md5($u.:mongo:.$p)",                     "md5(user . \":mongo:\" . pass)",                          DYNAMICX_SPLIT_USER },
  { 1551, "md5($s.$u.md5($u.:mongo:.$p))",          "md5(salt . user . md5(user . \":mongo:\" . pass))",       DYNAMICX_SPLIT_USER },
  { 1552, "md5($s.$u.md5($u.:mongo:.$p))",          "md5(salt . user . md5(user . \":mongo:\" . pass))",       DYNAMICX_SPLIT_USER },
  { 1560, "md5($s.$p.$s2)",                         "md5(salt . pass . salt2)",                                DYNAMICX_SPLIT_SALT2 },
  { 1588, "sha256($s.sha1($p))",                    "sha256(salt . sha1_uc(pass))",                            0 },
  { 1590, "sha1(utf16be(space_pad_10(uc($s)).$p))", "sha1(fromhex(salt) . utf16be(pass))",                     0 },
  { 1592, "sha1($s.sha1($s.sha1($p)))",             "sha1(salt . sha1(salt . sha1(pass)))",                    0 },
  { 1600, "sha1($s.utf16le($p))",                   "sha1(fromhex(salt) . utf16le(pass))",                     0 },
  { 1602, "sha256(#.$salt.-.$pass)",                "sha256(\"#\" . salt . \"-\" . pass)",                     DYNAMICX_SPLIT_USER },
  { 1608, "sha256(sha256_raw(sha256_raw($p)))",     "sha256(sha256_bin(sha256_bin(pass)))",                    0 },

  // the large hash families

  DYNAMICX_FAMILY ( 50, "sha224",     "sha224"),
  DYNAMICX_FAMILY ( 60, "sha256",     "sha256"),
  DYNAMICX_FAMILY ( 70, "sha384",     "sha384"),
  DYNAMICX_FAMILY ( 80, "sha512",     "sha512"),
  DYNAMICX_FAMILY ( 90, "gost",       "gost"),
  DYNAMICX_FAMILY (100, "whirlpool",  "wrl"),
  DYNAMICX_FAMILY (110, "tiger",      "tiger"),
  DYNAMICX_FAMILY (120, "ripemd128",  "rmd128"),
  DYNAMICX_FAMILY (130, "ripemd160",  "rmd160"),
  DYNAMICX_FAMILY (140, "ripemd256",  "rmd256"),
  DYNAMICX_FAMILY (150, "ripemd320",  "rmd320"),
  DYNAMICX_FAMILY (160, "haval128_3", "hav128_3"),
  DYNAMICX_FAMILY (170, "haval128_4", "hav128_4"),
  DYNAMICX_FAMILY (180, "haval128_5", "hav128_5"),
  DYNAMICX_FAMILY (190, "haval160_3", "hav160_3"),
  DYNAMICX_FAMILY (200, "haval160_4", "hav160_4"),
  DYNAMICX_FAMILY (210, "haval160_5", "hav160_5"),
  DYNAMICX_FAMILY (220, "haval192_3", "hav192_3"),
  DYNAMICX_FAMILY (230, "haval192_4", "hav192_4"),
  DYNAMICX_FAMILY (240, "haval192_5", "hav192_5"),
  DYNAMICX_FAMILY (250, "haval224_3", "hav224_3"),
  DYNAMICX_FAMILY (260, "haval224_4", "hav224_4"),
  DYNAMICX_FAMILY (270, "haval224_5", "hav224_5"),
  DYNAMICX_FAMILY (280, "haval256_3", "hav256_3"),
  DYNAMICX_FAMILY (290, "haval256_4", "hav256_4"),
  DYNAMICX_FAMILY (300, "haval256_5", "hav256_5"),
  DYNAMICX_FAMILY (310, "md2",        "md2"),
  DYNAMICX_FAMILY (320, "panama",     "panama"),
  DYNAMICX_FAMILY (330, "skein224",   "skein224"),
  DYNAMICX_FAMILY (340, "skein256",   "skein256"),
  DYNAMICX_FAMILY (350, "skein384",   "skein384"),
  DYNAMICX_FAMILY (360, "skein512",   "skein512"),
  DYNAMICX_FAMILY (370, "sha3_224",   "sha3_224"),
  DYNAMICX_FAMILY (380, "sha3_256",   "sha3_256"),
  DYNAMICX_FAMILY (390, "sha3_384",   "sha3_384"),
  DYNAMICX_FAMILY (400, "sha3_512",   "sha3_512"),
  DYNAMICX_FAMILY (410, "keccak_256", "keccak256"),
  DYNAMICX_FAMILY (420, "keccak_512", "keccak512"),
  DYNAMICX_FAMILY (430, "keccak_224", "keccak224"),
  DYNAMICX_FAMILY (440, "keccak_384", "keccak384"),
  DYNAMICX_FAMILY (450, "sm3",        "sm3"),
};

#define DYNAMICX_RECIPES_CNT (sizeof (DYNAMICX_RECIPES) / sizeof (dynamicx_recipe_t))

static const dynamicx_map_t *dynamicx_map_find (const int dynamic_num)
{
  for (size_t i = 0; i < DYNAMICX_MAP_CNT; i++)
  {
    if (DYNAMICX_MAP[i].dynamic_num == dynamic_num) return &DYNAMICX_MAP[i];
  }

  return NULL;
}

static const dynamicx_recipe_t *dynamicx_recipe_find (const int dynamic_num)
{
  for (size_t i = 0; i < DYNAMICX_RECIPES_CNT; i++)
  {
    if (DYNAMICX_RECIPES[i].dynamic_num == dynamic_num) return &DYNAMICX_RECIPES[i];
  }

  return NULL;
}

// The recipe's mode 4000, or with -O the hash-mode where DYNAMICX_MAP has one. A number with only a
// hash-mode always uses it.

int dynamicx_hash_mode (const int dynamic_num, const bool optimized)
{
  const dynamicx_map_t    *map    = dynamicx_map_find    (dynamic_num);
  const dynamicx_recipe_t *recipe = dynamicx_recipe_find (dynamic_num);

  if ((map != NULL) && ((recipe == NULL) || (optimized == true))) return (int) map->hash_mode;

  if (recipe != NULL) return 4000;

  return -1;
}

const char *dynamicx_expression (const int dynamic_num)
{
  const dynamicx_recipe_t *recipe = dynamicx_recipe_find (dynamic_num);

  if (recipe != NULL) return recipe->expression;

  const dynamicx_map_t *map = dynamicx_map_find (dynamic_num);

  if (map != NULL) return map->expression;

  return NULL;
}

const char *dynamicx_recipe (const int dynamic_num)
{
  const dynamicx_recipe_t *recipe = dynamicx_recipe_find (dynamic_num);

  if (recipe == NULL) return NULL;

  return recipe->recipe;
}

static u32 dynamicx_fields (const int dynamic_num)
{
  const dynamicx_recipe_t *recipe = dynamicx_recipe_find (dynamic_num);

  if (recipe == NULL) return 0;

  return recipe->fields;
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

// John decodes the $HEX$ runs of a line before it looks for the fields: from each $HEX$ the hex
// pairs, and from a $ on the text as it is up to the next $HEX$. A line that does not decode, or
// that would decode to a null byte, is kept as it is. src starts with the $ that ended the hash.

static int dynamicx_remove_hex (const char *src, const int src_len, char *dst)
{
  int pos = -1;

  for (int i = 0; i + 5 <= src_len; i++)
  {
    if (memcmp (src + i, "$HEX$", 5) == 0)
    {
      pos = i;

      break;
    }
  }

  if (pos == -1)
  {
    memcpy (dst, src, src_len);

    return src_len;
  }

  memcpy (dst, src, pos + 1);

  int out = pos + 1;

  int i = pos + 5;

  while (i < src_len)
  {
    if (((i + 1) < src_len) && (is_valid_hex_char ((u8) src[i + 0]) == true) && (is_valid_hex_char ((u8) src[i + 1]) == true))
    {
      const u8 c = hex_to_u8 ((const u8 *) src + i);

      if (c == 0) break;

      dst[out] = (char) c;

      out += 1;
      i   += 2;

      continue;
    }

    if (src[i] != '$') break;

    while ((i < src_len) && (((i + 5) > src_len) || (memcmp (src + i, "$HEX$", 5) != 0)))
    {
      dst[out] = src[i];

      out += 1;
      i   += 1;
    }

    if (i == src_len) break;

    dst[out] = '$';

    out += 1;
    i   += 5;
  }

  if (i == src_len) return out;

  memcpy (dst, src, src_len);

  return src_len;
}

// A field that still reads HEX$ after dynamicx_remove_hex is decoded on its own, in place.

static int dynamicx_field_hex (char *field, const int field_len)
{
  if (field_len < 4) return field_len;

  if (memcmp (field, "HEX$", 4) != 0) return field_len;

  const int hex_len = field_len - 4;

  if ((hex_len & 1) || (is_valid_hex_string ((const u8 *) field + 4, (size_t) hex_len) == false)) return -1;

  hex_decode ((const u8 *) field + 4, hex_len, (u8 *) field);

  return hex_len / 2;
}

static bool dynamicx_field_ok (const char *field, const int field_len, const bool star_ok)
{
  for (int i = 0; i < field_len; i++)
  {
    const char c = field[i];

    if ((c == 0) || (c == '\n') || (c == '\r')) return false;

    if ((c == '*') && (star_ok == false)) return false;
  }

  return true;
}

static char *dynamicx_keep (const char *rest, const int rest_len)
{
  // rest_len is the line length less the tag, which the tag parser keeps inside the line. A negative
  // value would reach memcpy () as a size close to SIZE_MAX, so it is kept as nothing instead.

  const size_t len = (rest_len > 0) ? (size_t) rest_len : 0;

  char *kept = (char *) hcmalloc (len + 1);

  memcpy (kept, rest, len);

  return kept;
}

// A line for mode 4000 becomes <hash>*<salt>*<salt2>*<user>, with the salt and the fields its recipe
// reads and in that order, which is the order mode 4000 reads them in. John may write the fields in
// any order after the salt. The salt may hold a *, because mode 4000 takes the fields off the end
// of the line, and a field may not. A recipe that decodes its salt with fromhex or frombase64 gets
// the salt in that encoding, which is how a salt with a null byte in it gets through.

static int dynamicx_translate_recipe (char *line_buf, const int line_len, const int line_size, const u32 layout, const int tag_len, const int sep_pos, int *hash_len, const char **error)
{
  const u32 line_fields = DYNAMICX_LINE_SALT | DYNAMICX_LINE_SALT2 | DYNAMICX_LINE_USER;

  char *hash = line_buf + tag_len;

  const int body_len = line_len - tag_len;

  if (sep_pos == -1)
  {
    if ((layout & line_fields) == 0)
    {
      *hash_len = body_len;

      return 0;
    }

    if (layout & DYNAMICX_LINE_SALT)
    {
      *error = "no salt";
    }
    else
    {
      *error = (layout & DYNAMICX_LINE_SALT2) ? "no second salt ($$2)" : "no user name ($$U)";
    }

    return -1;
  }

  const int tail_len = body_len - sep_pos;

  char *tail = (char *) hcmalloc (tail_len + 1);
  char *buf  = (char *) hcmalloc (tail_len + 1);

  memcpy (tail, hash + sep_pos, tail_len);

  const int buf_len = dynamicx_remove_hex (tail, tail_len, buf);

  // John takes the fields off from the back, and each one ends where the one after it starts. The
  // $ that ended the hash is buf[0], and a field right after the hash shares it, as in hash$$Uuser.

  int end = buf_len;

  int salt2_pos = -1;
  int salt2_len = 0;
  int user_pos  = -1;
  int user_len  = 0;

  for (int i = buf_len - 3; i >= 0; i--)
  {
    if (buf[i + 0] != '$') continue;
    if (buf[i + 1] != '$') continue;

    if ((buf[i + 2] == '2') && (layout & DYNAMICX_SPLIT_SALT2))
    {
      salt2_pos = i + 3;
      salt2_len = end - salt2_pos;

      end = i;
    }
    else if ((buf[i + 2] == 'U') && (layout & DYNAMICX_SPLIT_USER))
    {
      user_pos = i + 3;
      user_len = end - user_pos;

      end = i;
    }
  }

  char *salt = buf + 1;

  int salt_len = (end >= 1) ? (end - 1) : 0;

  salt_len = dynamicx_field_hex (salt, salt_len);

  if (salt2_pos != -1) salt2_len = dynamicx_field_hex (buf + salt2_pos, salt2_len);
  if (user_pos  != -1) user_len  = dynamicx_field_hex (buf + user_pos,  user_len);

  if ((salt_len < 0) || (salt2_len < 0) || (user_len < 0))
  {
    *error = "a malformed $HEX$ field";
  }
  else if ((salt_len > 0) && ((layout & DYNAMICX_LINE_SALT) == 0))
  {
    *error = "a salt, which the recipe does not read";
  }
  else if ((salt2_pos == -1) && (layout & DYNAMICX_LINE_SALT2))
  {
    *error = "no second salt ($$2)";
  }
  else if ((user_pos == -1) && (layout & DYNAMICX_LINE_USER))
  {
    *error = "no user name ($$U)";
  }
  else if (((layout & (DYNAMICX_LINE_SALT_HEX | DYNAMICX_LINE_SALT_B64)) == 0) && (dynamicx_field_ok (salt, salt_len, true) == false))
  {
    *error = "a salt holding a null byte or a line break";
  }
  else if ((salt2_pos != -1) && (dynamicx_field_ok (buf + salt2_pos, salt2_len, false) == false))
  {
    *error = "a field holding a *, a null byte or a line break";
  }
  else if ((user_pos != -1) && (dynamicx_field_ok (buf + user_pos, user_len, false) == false))
  {
    *error = "a field holding a *, a null byte or a line break";
  }

  if (*error != NULL)
  {
    hcfree (tail);
    hcfree (buf);

    return -1;
  }

  // a field is never longer than its text in John's line, and a $$2 or $$U turns into one *, but a
  // salt written in hex or base64 can be longer than it was

  int salt_out = salt_len;

  if (layout & DYNAMICX_LINE_SALT_HEX) salt_out = salt_len * 2;
  if (layout & DYNAMICX_LINE_SALT_B64) salt_out = ((salt_len + 2) / 3) * 4;

  const int need = tag_len + sep_pos + 1 + salt_out + 1 + salt2_len + 1 + user_len + 1;

  if (need > line_size)
  {
    *error = "a salt too long to write as the recipe reads it";

    hcfree (tail);
    hcfree (buf);

    return -1;
  }

  int out = sep_pos;

  if (layout & line_fields)
  {
    hash[out] = '*';

    out += 1;

    if (layout & DYNAMICX_LINE_SALT_HEX)
    {
      hex_encode ((const u8 *) salt, salt_len, (u8 *) hash + out);
    }
    else if (layout & DYNAMICX_LINE_SALT_B64)
    {
      base64_encode (int_to_base64, (const u8 *) salt, (size_t) salt_len, (u8 *) hash + out);
    }
    else
    {
      memcpy (hash + out, salt, salt_len);
    }

    out += salt_out;
  }

  if (layout & DYNAMICX_LINE_SALT2)
  {
    hash[out] = '*';

    out += 1;

    memcpy (hash + out, buf + salt2_pos, salt2_len);

    out += salt2_len;
  }

  if (layout & DYNAMICX_LINE_USER)
  {
    hash[out] = '*';

    out += 1;

    memcpy (hash + out, buf + user_pos, user_len);

    out += user_len;
  }

  hash[out] = 0;

  *hash_len = out;

  hcfree (tail);
  hcfree (buf);

  return 0;
}

int dynamicx_translate (char *line_buf, const int line_len, const int line_size, const char separator, const u32 layout, int *tag_len, int *hash_len, char **kept_buf, u32 *kept_len, const char **error)
{
  *error = NULL;

  *kept_buf = NULL;
  *kept_len = 0;

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

  // John's text after the tag is kept as it was read, for the way back, see dynamicx_encode

  if (layout & DYNAMICX_LINE_RECIPE)
  {
    char *kept = dynamicx_keep (rest, rest_len);

    if (dynamicx_translate_recipe (line_buf, line_len, line_size, layout, *tag_len, sep_pos, hash_len, error) == -1)
    {
      hcfree (kept);

      return -1;
    }

    *kept_buf = kept;
    *kept_len = (u32) rest_len;

    return dynamic_num;
  }

  if (sep_pos == -1)
  {
    *hash_len = rest_len;

    *kept_buf = dynamicx_keep (rest, rest_len);
    *kept_len = (u32) rest_len;

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

  // $$2 introduces a second salt and $$U a user name. A hash-mode has one salt field per hash and no
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
        *error = (c == '2') ? "a second salt ($$2), which the hash-mode has no field for"
                            : "a user name ($$U), which the hash-mode has no field for";

        return -1;
      }
    }

    win1 = win2;
    win2 = c;
  }

  // checks are done, the line may be written on now

  *kept_buf = dynamicx_keep (rest, rest_len);
  *kept_len = (u32) rest_len;

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

// The other direction: the line John wrote, for --show, --left and --remove. Every hash kept John's
// text after the tag when it was read, see dynamicx_translate, and that text goes back behind the
// tag as it was. hashcat's own encoding of the hash is not used, because it can differ from John's:
// a digest John wrote in uppercase comes back in lowercase, and a field the recipe does not read is
// not on the line at all.
//
// Returns the new length. tag_len of 0 means this is not a --dynamic-x hash and nothing is done.

int dynamicx_encode (char *out_buf, const hashinfo_t *hash_info, const int tag_len, const int hash_len, const int out_sz)
{
  if (tag_len == 0) return hash_len;

  const dynamicx_t *dynamicx = (hash_info != NULL) ? hash_info->dynamicx : NULL;

  if (dynamicx == NULL) return tag_len + hash_len;

  if (dynamicx->dynamicx_rest == NULL) return tag_len + hash_len;

  const int rest_len = (int) dynamicx->dynamicx_rest_len;

  if ((tag_len + rest_len + 1) > out_sz) return tag_len + hash_len;

  memcpy (out_buf + tag_len, dynamicx->dynamicx_rest, rest_len);

  const int out_len = tag_len + rest_len;

  return out_len;
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

  const int   hash_mode  = dynamicx_hash_mode  (dynamic_num, user_options->optimized_kernel);
  const char *expression = dynamicx_expression (dynamic_num);
  const char *recipe     = dynamicx_recipe     (dynamic_num);

  // With -m, a number the tables do not know is loaded too. That is how a format from a local
  // dynamic.conf gets in, with -m 4000 and a recipe for what that format computes. An -m that names
  // either route of a known number needs no warning.

  if (user_options->hash_mode_chgd == true)
  {
    const dynamicx_map_t *map = dynamicx_map_find (dynamic_num);

    const bool route_recipe = (recipe != NULL) && (user_options->hash_mode == 4000);
    const bool route_map    = (map    != NULL) && (user_options->hash_mode == (int) map->hash_mode);

    if ((hash_mode != -1) && (route_recipe == false) && (route_map == false))
    {
      event_log_warning (hashcat_ctx, "$dynamic_%d$ is %s, which is hash-mode %d, but -m %d was given.", dynamic_num, expression, hash_mode, user_options->hash_mode);
      event_log_warning (hashcat_ctx, "Continuing with -m %d.", user_options->hash_mode);
      event_log_warning (hashcat_ctx, NULL);
    }
  }
  else
  {
    if (hash_mode == -1)
    {
      event_log_error (hashcat_ctx, "hashcat has no hash-mode for $dynamic_%d$.", dynamic_num);

      event_log_warning (hashcat_ctx, "Run 'john --list=subformats' to see what that format computes.");
      event_log_warning (hashcat_ctx, "A recipe for it can be given with -m 4000 and --hash-recipe.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    user_options->hash_mode  = hash_mode;
    user_options->autodetect = false;
  }

  if (user_options->hash_mode != 4000) return 0;

  // mode 4000: the recipe comes from the table unless --hash-recipe gave one

  if (user_options->hash_recipe == NULL)
  {
    if (recipe == NULL)
    {
      event_log_error (hashcat_ctx, "Hash-mode 4000 needs --hash-recipe for $dynamic_%d$.", dynamic_num);

      return -1;
    }

    user_options->hash_recipe = (char *) recipe;
  }
  else if ((recipe != NULL) && (strcmp (user_options->hash_recipe, recipe) != 0))
  {
    event_log_warning (hashcat_ctx, "$dynamic_%d$ is %s, which is the recipe '%s', but --hash-recipe '%s' was given.", dynamic_num, expression, recipe, user_options->hash_recipe);
    event_log_warning (hashcat_ctx, "Continuing with --hash-recipe.");
    event_log_warning (hashcat_ctx, NULL);
  }

  recipe_prog_t prog;

  if (recipe_compile (&prog, user_options->hash_recipe) == false)
  {
    event_log_error (hashcat_ctx, "Invalid recipe for $dynamic_%d$, %s.", dynamic_num, prog.error);

    return -1;
  }

  // John's line has a field for a second salt and one for a user name, and no field for a pepper

  if (prog.fields & (1u << RECIPE_FIELD_PEPPER))
  {
    event_log_error (hashcat_ctx, "A $dynamic_N$ line has no field for the pepper the recipe reads.");

    return -1;
  }

  u32 layout = DYNAMICX_LINE_RECIPE;

  if (prog.salt_read != 0) layout |= DYNAMICX_LINE_SALT;

  if (prog.salt_dec == RECIPE_DEC_HEX) layout |= DYNAMICX_LINE_SALT_HEX;
  if (prog.salt_dec == RECIPE_DEC_B64) layout |= DYNAMICX_LINE_SALT_B64;

  if (prog.fields & (1u << RECIPE_FIELD_SALT2)) layout |= DYNAMICX_LINE_SALT2 | DYNAMICX_SPLIT_SALT2;
  if (prog.fields & (1u << RECIPE_FIELD_USER))  layout |= DYNAMICX_LINE_USER  | DYNAMICX_SPLIT_USER;

  layout |= dynamicx_fields (dynamic_num);

  // the name is the $$U field of the line, and with --username mode 4000 would take it from the
  // hash list instead and parse the line without that field

  if ((layout & DYNAMICX_LINE_USER) && (user_options->username == true))
  {
    event_log_error (hashcat_ctx, "--username cannot be used with --dynamic-x when the recipe reads the user name.");
    event_log_error (hashcat_ctx, "The name comes from the $$U field of each hash.");

    return -1;
  }

  user_options_extra->dynamicx_layout = layout;

  return 0;
}
