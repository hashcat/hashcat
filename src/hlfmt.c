/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "hlfmt.h"

static const char HLFMT_TEXT_HASHCAT[]  = "native hashcat";
static const char HLFMT_TEXT_PWDUMP[]   = "pwdump";
static const char HLFMT_TEXT_PASSWD[]   = "passwd";
static const char HLFMT_TEXT_SHADOW[]   = "shadow";
static const char HLFMT_TEXT_DCC[]      = "DCC";
static const char HLFMT_TEXT_DCC2[]     = "DCC 2";
static const char HLFMT_TEXT_NETNTLM1[] = "NetNTLMv1";
static const char HLFMT_TEXT_NETNTLM2[] = "NetNTLMv2";
static const char HLFMT_TEXT_NSLDAP[]   = "nsldap";
static const char HLFMT_TEXT_NSLDAPS[]  = "nsldaps";

// hlfmt hashcat

static void hlfmt_hash_hashcat (char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, const hashconfig_t *hashconfig, const user_options_t *user_options)
{
  if (user_options->username == 0)
  {
    *hashbuf_pos = line_buf;
    *hashbuf_len = line_len;
  }
  else
  {
    char *pos = line_buf;
    int   len = line_len;

    for (int i = 0; i < line_len; i++, pos++, len--)
    {
      if (line_buf[i] == hashconfig->separator)
      {
        pos++;

        len--;

        break;
      }
    }

    *hashbuf_pos = pos;
    *hashbuf_len = len;
  }
}

static void hlfmt_user_hashcat (char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len, const hashconfig_t *hashconfig)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == hashconfig->separator)
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt pwdump

static int hlfmt_detect_pwdump (char *line_buf, int line_len)
{
  int sep_cnt = 0;

  int sep2_len = 0;
  int sep3_len = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 2) sep2_len++;
    if (sep_cnt == 3) sep3_len++;
  }

  if ((sep_cnt == 6) && ((sep2_len == 32) || (sep3_len == 32))) return 1;

  return 0;
}

static void hlfmt_hash_pwdump (char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, const hashconfig_t *hashconfig)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (hashconfig->hash_mode == 1000)
    {
      if (sep_cnt == 3)
      {
        if (pos == NULL) pos = line_buf + i;

        len++;
      }
    }
    else if (hashconfig->hash_mode == 3000)
    {
      if (sep_cnt == 2)
      {
        if (pos == NULL) pos = line_buf + i;

        len++;
      }
    }
  }

  *hashbuf_pos = pos;
  *hashbuf_len = len;
}

static void hlfmt_user_pwdump (char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt passwd

static int hlfmt_detect_passwd (char *line_buf, int line_len)
{
  int sep_cnt = 0;

  char sep5_first = 0;
  char sep6_first = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 5) if (sep5_first == 0) sep5_first = line_buf[i];
    if (sep_cnt == 6) if (sep6_first == 0) sep6_first = line_buf[i];
  }

  if ((sep_cnt == 6) && ((sep5_first == '/') || (sep6_first == '/'))) return 1;

  return 0;
}

static void hlfmt_hash_passwd (char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 1)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *hashbuf_pos = pos;
  *hashbuf_len = len;
}

static void hlfmt_user_passwd (char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt shadow

static int hlfmt_detect_shadow (char *line_buf, int line_len)
{
  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':') sep_cnt++;
  }

  if (sep_cnt == 8) return 1;

  return 0;
}

static void hlfmt_hash_shadow (char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  hlfmt_hash_passwd (line_buf, line_len, hashbuf_pos, hashbuf_len);
}

static void hlfmt_user_shadow (char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  hlfmt_user_passwd (line_buf, line_len, userbuf_pos, userbuf_len);
}

// hlfmt main

char *strhlfmt (const u32 hashfile_format)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT:  return ((char *) HLFMT_TEXT_HASHCAT);
    case HLFMT_PWDUMP:   return ((char *) HLFMT_TEXT_PWDUMP);
    case HLFMT_PASSWD:   return ((char *) HLFMT_TEXT_PASSWD);
    case HLFMT_SHADOW:   return ((char *) HLFMT_TEXT_SHADOW);
    case HLFMT_DCC:      return ((char *) HLFMT_TEXT_DCC);
    case HLFMT_DCC2:     return ((char *) HLFMT_TEXT_DCC2);
    case HLFMT_NETNTLM1: return ((char *) HLFMT_TEXT_NETNTLM1);
    case HLFMT_NETNTLM2: return ((char *) HLFMT_TEXT_NETNTLM2);
    case HLFMT_NSLDAP:   return ((char *) HLFMT_TEXT_NSLDAP);
    case HLFMT_NSLDAPS:  return ((char *) HLFMT_TEXT_NSLDAPS);
  }

  return ((char *) "Unknown");
}

void hlfmt_hash (u32 hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len, const hashconfig_t *hashconfig, const user_options_t *user_options)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT: hlfmt_hash_hashcat (line_buf, line_len, hashbuf_pos, hashbuf_len, hashconfig, user_options);  break;
    case HLFMT_PWDUMP:  hlfmt_hash_pwdump  (line_buf, line_len, hashbuf_pos, hashbuf_len, hashconfig);                break;
    case HLFMT_PASSWD:  hlfmt_hash_passwd  (line_buf, line_len, hashbuf_pos, hashbuf_len);                            break;
    case HLFMT_SHADOW:  hlfmt_hash_shadow  (line_buf, line_len, hashbuf_pos, hashbuf_len);                            break;
  }
}

void hlfmt_user (u32 hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len, const hashconfig_t *hashconfig)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT: hlfmt_user_hashcat (line_buf, line_len, userbuf_pos, userbuf_len, hashconfig);                break;
    case HLFMT_PWDUMP:  hlfmt_user_pwdump  (line_buf, line_len, userbuf_pos, userbuf_len);                            break;
    case HLFMT_PASSWD:  hlfmt_user_passwd  (line_buf, line_len, userbuf_pos, userbuf_len);                            break;
    case HLFMT_SHADOW:  hlfmt_user_shadow  (line_buf, line_len, userbuf_pos, userbuf_len);                            break;
  }
}

u32 hlfmt_detect (FILE *fp, u32 max_check, const hashconfig_t *hashconfig)
{
  // Exception: those formats are wrongly detected as HLFMT_SHADOW, prevent it

  if (hashconfig->hash_mode == 5300) return HLFMT_HASHCAT;
  if (hashconfig->hash_mode == 5400) return HLFMT_HASHCAT;

  u32 *formats_cnt = (u32 *) mycalloc (HLFMTS_CNT, sizeof (u32));

  u32 num_check = 0;

  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  while (!feof (fp))
  {
    int line_len = fgetl (fp, line_buf);

    if (line_len == 0) continue;

    if (hlfmt_detect_pwdump (line_buf, line_len)) formats_cnt[HLFMT_PWDUMP]++;
    if (hlfmt_detect_passwd (line_buf, line_len)) formats_cnt[HLFMT_PASSWD]++;
    if (hlfmt_detect_shadow (line_buf, line_len)) formats_cnt[HLFMT_SHADOW]++;

    if (num_check == max_check) break;

    num_check++;
  }

  myfree (line_buf);

  u32 hashlist_format = HLFMT_HASHCAT;

  for (u32 i = 1; i < HLFMTS_CNT; i++)
  {
    if (formats_cnt[i - 1] >= formats_cnt[i]) continue;

    hashlist_format = i;
  }

  free (formats_cnt);

  return hashlist_format;
}
