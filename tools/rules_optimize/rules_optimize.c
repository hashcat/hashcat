/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <strings.h>
#include <stdlib.h>

#define MIN_FUNCTIONS 1
#define MAX_FUNCTIONS 5

int max_len = 0;

#include "cpu_rules.h"

typedef struct
{
  char rule_buf[BLOCK_SIZE];
  int  rule_len;

} rule_t;

static int cmp (const void *p1, const void *p2)
{
  rule_t *r1 = (rule_t *) p1;
  rule_t *r2 = (rule_t *) p2;

  return r1->rule_len - r2->rule_len;
}

int process_block (int o[BLOCK_SIZE], char *block_ptr[BLOCK_SIZE], int block_cnt, char *word_buf, char final_buf[BLOCK_SIZE], int final_len, char rule_buf[BLOCK_SIZE])
{
  int last_o = o[0];

  for (int i = 1; i < block_cnt; i++)
  {
    if (o[i] < last_o) return (0);
  }

  memset (rule_buf, 0, BLOCK_SIZE);

  strcat (rule_buf, block_ptr[o[0]]);

  int i;

  for (i = 1; i < block_cnt; i++)
  {
    strcat (rule_buf, " ");

    strcat (rule_buf, block_ptr[o[i]]);
  }

  char out_buf[BLOCK_SIZE];

  memset (out_buf, 0, sizeof (out_buf));

  int out_len = apply_rule_cpu (rule_buf, strlen (rule_buf), word_buf, strlen (word_buf), out_buf);

  if (out_len == final_len)
  {
    if (memcmp (final_buf, out_buf, out_len) == 0) return (1);
  }

  return 0;
}

int next_permutation (int *o, int *p, int k)
{
  p[k]--;

  int j = k % 2 * p[k];

  int tmp = o[j];

  o[j] = o[k];

  o[k] = tmp;

  for (k = 1; p[k] == 0; k++) p[k] = k;

  return k;
}

int main ()
{
  FILE *fp = stdin;

  char line_buf[BUFSIZ];

  while (!feof (fp))
  {
    /*
     * line
     */

    char *line_ptr = fgets (line_buf, BUFSIZ, fp);

    if (line_ptr == NULL) continue;

    int line_len = strlen (line_ptr);

    if (line_len && line_ptr[line_len - 1] == '\n') line_len--;
    if (line_len && line_ptr[line_len - 1] == '\r') line_len--;

    line_ptr[line_len] = 0;

    /*
     * split
     */

    char *word_buf = line_ptr;

    char *sep = strchr (line_ptr, ':');

    if (sep == NULL) continue;

    *sep = 0;

    int word_len = sep - word_buf;

    if (strstr (word_buf, "$HEX[")) continue; // not yet supported

    char *rule_buf = sep + 1;

    if (strchr (rule_buf, ':')) continue; // another one? ignore line

    /*
     * final
     */

    char final_buf[BLOCK_SIZE];

    memset (final_buf, 0, sizeof (final_buf));

    int final_len = apply_rule_cpu (rule_buf, strlen (rule_buf), word_buf, strlen (word_buf), final_buf);

    if (final_len < 0) continue;

    if ((final_len == word_len) && (memcmp (word_buf, final_buf, final_len)) == 0) continue;

    /*
     * split into blocks
     */

    char *block_ptr[BLOCK_SIZE];
    int   block_cnt = 0;

    char *ptr = rule_buf;

    for (char *next = NULL; (next = strchr (ptr, ' ')) != NULL; ptr = next + 1)
    {
      if (next[1] == ' ') next++;

      *next = 0;

      block_ptr[block_cnt] = ptr;

      block_cnt++;
    }

    block_ptr[block_cnt] = ptr;

    block_cnt++;

    if (block_cnt < MIN_FUNCTIONS) continue; // to many
    if (block_cnt > MAX_FUNCTIONS) continue; // to many

    /*
     * permute blocks, this where the real work starts..
     */

    int o[BLOCK_SIZE];
    int p[BLOCK_SIZE];

    for (int i = 0; i < block_cnt + 1; i++)
    {
      o[i] = i;
      p[i] = i;
    }

    int k = 1;

    rule_t *rules_buf = (rule_t *) calloc (120 * MAX_FUNCTIONS, sizeof (rule_t)); // 5! = 120, so its guaranteed
    int     rules_cnt = 0;

    char rule_out_buf[BLOCK_SIZE];

    for (int i0 = 0, i1 = 1; i0 < block_cnt; i0++, i1++)
    {
      if (process_block (o, block_ptr, i1, word_buf, final_buf, final_len, rule_out_buf) == 1)
      {
        memcpy (rules_buf[rules_cnt].rule_buf, rule_out_buf, BLOCK_SIZE);

        rules_buf[rules_cnt].rule_len = i1;

        rules_cnt++;
      }
    }

    if (block_cnt >= 2)
    {
      while ((k = next_permutation (o, p, k)) != block_cnt)
      {
        for (int i0 = 0, i1 = 1; i0 < block_cnt; i0++, i1++)
        {
          if (process_block (o, block_ptr, i1, word_buf, final_buf, final_len, rule_out_buf) == 1)
          {
            memcpy (rules_buf[rules_cnt].rule_buf, rule_out_buf, BLOCK_SIZE);

            rules_buf[rules_cnt].rule_len = i1;

            rules_cnt++;
          }
        }
      }

      for (int i0 = 0, i1 = 1; i0 < block_cnt; i0++, i1++)
      {
        if (process_block (o, block_ptr, i1, word_buf, final_buf, final_len, rule_out_buf) == 1)
        {
          memcpy (rules_buf[rules_cnt].rule_buf, rule_out_buf, BLOCK_SIZE);

          rules_buf[rules_cnt].rule_len = i1;

          rules_cnt++;
        }
      }
    }

    /**
     * sort and output the ones with the less length
     */

    qsort (rules_buf, rules_cnt, sizeof (rule_t), cmp);

    int first_len = rules_buf[0].rule_len;

    for (int i = 0; i < rules_cnt; i++)
    {
      rule_t *rule_buf = &rules_buf[i];

      if (rule_buf->rule_len > first_len) break;

      puts (rule_buf->rule_buf);
    }

    free (rules_buf);
  }

  return 0;
}
