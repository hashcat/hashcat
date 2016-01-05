/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define RULES_PER_PLAIN_MIN  1
#define RULES_PER_PLAIN_MAX 99
#define RP_GEN_FUNC_MIN      1
#define RP_GEN_FUNC_MAX      4
#define PW_MAX              32
#define LINE_SIG_LEN        RP_GEN_FUNC_MAX * 2 + 1

int max_len = 0;

#include "cpu_rules.h"
#include "rp_gpu_on_cpu.h"

void print_plain (char *plain, int plain_len)
{
  int need_hexifly = 0;

  unsigned char *plain_ptr = (unsigned char*) plain;

  int k;

  for (k = 0; k < plain_len; k++)
  {
    if ((plain_ptr[k] < 0x20) || (plain_ptr[k] > 0x7f))
    {
      need_hexifly = 1;

      break;
    }
  }

  if (need_hexifly)
  {
    printf ("$HEX[");

    for (k = 0; k < plain_len; k++)
    {
      printf ("%02x", plain_ptr[k]);
    }

    printf ("]");
  }
  else
  {
    for (k = 0; k < plain_len; k++)
    {
      printf ("%c", plain_ptr[k]);
    }
  }
}

int main (int argc, char **argv)
{
  FILE *fp = stdin;

  char rule_buf[BUFSIZ];

  int rp_gen_func_min = RP_GEN_FUNC_MIN;
  int rp_gen_func_max = RP_GEN_FUNC_MAX;

  while (1)
  {
    /*
     * line
     */

    if (feof (fp)) break;

    char line_buf[BUFSIZ + 1];

    char *line_ptr = fgets (line_buf, BUFSIZ, fp);

    if (line_ptr == NULL) continue;

    int line_len = strlen (line_ptr);

    line_len--;

    if (line_len <      0) continue;
    if (line_len > PW_MAX) continue;

    memset (line_ptr + line_len, 0, PW_MAX - line_len);

    /*
     * generate random rule and apply it afterwards
     */

    uint max;

    if (argc < 2)
    {
      max = get_random_num (RULES_PER_PLAIN_MIN, RULES_PER_PLAIN_MAX);
    }
    else
    {
      max = 1;
    }

    uint i;

    for (i = 0; i < max; i++)
    {
      int rule_len;

      memset (rule_buf, 0, BLOCK_SIZE);

      if (argc < 2)
      {
        rule_len = (int) generate_random_rule (rule_buf, rp_gen_func_min, rp_gen_func_max);
      }
      else
      {
        strncpy (rule_buf, argv[1], BUFSIZ);

        rule_len = strlen (rule_buf);
      }

      gpu_rule_t gpu_rule_buf;

      memset (&gpu_rule_buf, 0, sizeof (gpu_rule_t));

      if (cpu_rule_to_gpu_rule (rule_buf, rule_len, &gpu_rule_buf) == -1) continue;

      // cpu
      char rule_buf_cpu[BLOCK_SIZE];

      memset (rule_buf_cpu, 0, BLOCK_SIZE);

      max_len = 0;

      int out_len_cpu = apply_rule_cpu (rule_buf, rule_len, line_ptr, line_len, rule_buf_cpu);

      if (max_len >= 32) continue;

      // gpu
      char rule_buf_gpu[BLOCK_SIZE];

      memset (rule_buf_gpu, 0, sizeof (rule_buf_gpu));

      memcpy (rule_buf_gpu, line_buf, line_len);

      uint32_t *plain_ptr = (uint32_t *) rule_buf_gpu;

      int out_len_gpu = apply_rules (gpu_rule_buf.cmds, &plain_ptr[0], &plain_ptr[4], line_len);

      /*
       * compare
       */

      if (out_len_cpu >= 0 && out_len_cpu < 32)
      {
        int failed = 1;

        if (out_len_gpu == out_len_cpu)
        {
          if (memcmp (rule_buf_gpu, rule_buf_cpu, out_len_gpu) == 0)
          {
            failed = 0;
          }
        }

        /*
         * print if failed
         */

        if (failed == 1)
        {
          printf ("Rule: %s", rule_buf);

          // nicer output
          int spaces = LINE_SIG_LEN - rule_len;

          if (rule_len >  10) spaces++;
          if (rule_len > 100) spaces++;

          while (spaces--) printf (".");

          printf (": ");

          // initial line
          print_plain (line_buf, line_len);

          printf (" %i => ", line_len);

          // modified by cpu
          print_plain (rule_buf_cpu, out_len_cpu);

          printf (" %i vs ", out_len_cpu);

          // modified by gpu
          print_plain (rule_buf_gpu, out_len_gpu);

          printf (" %i\n", out_len_gpu);
        }
      }
    }
  }

  fclose (fp);

  return 0;
}
