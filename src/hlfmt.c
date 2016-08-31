#include <hlfmt.h>
#include <hc_global.h>

// hlfmt hashcat

void hlfmt_hash_hashcat(char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  if (data.username == 0)
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
      if (line_buf[i] == data.separator)
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

void hlfmt_user_hashcat(char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
  {
    if (line_buf[i] == data.separator)
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

int hlfmt_detect_pwdump(char *line_buf, int line_len)
{
  int sep_cnt = 0;

  int sep2_len = 0;
  int sep3_len = 0;

  for (int i = 0; i < line_len; ++i)
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

void hlfmt_hash_pwdump(char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (data.hash_mode == 1000)
    {
      if (sep_cnt == 3)
      {
        if (pos == NULL) pos = line_buf + i;

        len++;
      }
    }
    else if (data.hash_mode == 3000)
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

void hlfmt_user_pwdump(char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
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

int hlfmt_detect_passwd(char *line_buf, int line_len)
{
  int sep_cnt = 0;

  char sep5_first = 0;
  char sep6_first = 0;

  for (int i = 0; i < line_len; ++i)
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

void hlfmt_hash_passwd(char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
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

void hlfmt_user_passwd(char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  char *pos = NULL;
  int   len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
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

int hlfmt_detect_shadow(char *line_buf, int line_len)
{
  int sep_cnt = 0;

  for (int i = 0; i < line_len; ++i)
  {
    if (line_buf[i] == ':') sep_cnt++;
  }

  if (sep_cnt == 8) return 1;

  return 0;
}

void hlfmt_hash_shadow(char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  hlfmt_hash_passwd(line_buf, line_len, hashbuf_pos, hashbuf_len);
}

void hlfmt_user_shadow(char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  hlfmt_user_passwd(line_buf, line_len, userbuf_pos, userbuf_len);
}

// hlfmt main

void hlfmt_hash(HLFMT hashfile_format, char *line_buf, int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  switch (hashfile_format)
  {
  case HLFMT_HASHCAT: hlfmt_hash_hashcat(line_buf, line_len, hashbuf_pos, hashbuf_len); break;
  case HLFMT_PWDUMP:  hlfmt_hash_pwdump(line_buf, line_len, hashbuf_pos, hashbuf_len); break;
  case HLFMT_PASSWD:  hlfmt_hash_passwd(line_buf, line_len, hashbuf_pos, hashbuf_len); break;
  case HLFMT_SHADOW:  hlfmt_hash_shadow(line_buf, line_len, hashbuf_pos, hashbuf_len); break;
  }
}

void hlfmt_user(HLFMT hashfile_format, char *line_buf, int line_len, char **userbuf_pos, int *userbuf_len)
{
  switch (hashfile_format)
  {
  case HLFMT_HASHCAT: hlfmt_user_hashcat(line_buf, line_len, userbuf_pos, userbuf_len); break;
  case HLFMT_PWDUMP:  hlfmt_user_pwdump(line_buf, line_len, userbuf_pos, userbuf_len); break;
  case HLFMT_PASSWD:  hlfmt_user_passwd(line_buf, line_len, userbuf_pos, userbuf_len); break;
  case HLFMT_SHADOW:  hlfmt_user_shadow(line_buf, line_len, userbuf_pos, userbuf_len); break;
  }
}

char *strhlfmt(const HLFMT hashfile_format)
{
  switch (hashfile_format)
  {
  case HLFMT_HASHCAT:  return ((char *)HLFMT_TEXT_HASHCAT);  break;
  case HLFMT_PWDUMP:   return ((char *)HLFMT_TEXT_PWDUMP);   break;
  case HLFMT_PASSWD:   return ((char *)HLFMT_TEXT_PASSWD);   break;
  case HLFMT_SHADOW:   return ((char *)HLFMT_TEXT_SHADOW);   break;
  case HLFMT_DCC:      return ((char *)HLFMT_TEXT_DCC);      break;
  case HLFMT_DCC2:     return ((char *)HLFMT_TEXT_DCC2);     break;
  case HLFMT_NETNTLM1: return ((char *)HLFMT_TEXT_NETNTLM1); break;
  case HLFMT_NETNTLM2: return ((char *)HLFMT_TEXT_NETNTLM2); break;
  case HLFMT_NSLDAP:   return ((char *)HLFMT_TEXT_NSLDAP);   break;
  case HLFMT_NSLDAPS:  return ((char *)HLFMT_TEXT_NSLDAPS);  break;
  }

  return ((char *) "Unknown");
}

HLFMT hlfmt_detect(FILE *fp, uint max_check)
{
  // Exception: those formats are wrongly detected as HLFMT_SHADOW, prevent it

  if (data.hash_mode == 5300) return HLFMT_HASHCAT;
  if (data.hash_mode == 5400) return HLFMT_HASHCAT;

  uint *formats_cnt = (uint *)mycalloc(HLFMTS_CNT, sizeof(uint));

  uint num_check = 0;

  char *line_buf = (char *)mymalloc(HCBUFSIZ);

  while (!feof(fp))
  {
    int line_len = fgetl(fp, line_buf);

    if (line_len == 0) continue;

    if (hlfmt_detect_pwdump(line_buf, line_len)) formats_cnt[HLFMT_PWDUMP]++;
    if (hlfmt_detect_passwd(line_buf, line_len)) formats_cnt[HLFMT_PASSWD]++;
    if (hlfmt_detect_shadow(line_buf, line_len)) formats_cnt[HLFMT_SHADOW]++;

    if (num_check == max_check) break;

    num_check++;
  }

  myfree(line_buf);

  HLFMT hashlist_format = HLFMT_HASHCAT;

  for (int i = 1; i < HLFMTS_CNT; ++i)
  {
    if (formats_cnt[i - 1] >= formats_cnt[i]) continue;

    hashlist_format = (HLFMT)i;
  }

  free(formats_cnt);

  return hashlist_format;
}
