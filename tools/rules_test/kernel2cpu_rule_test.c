/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define RULES_PER_PLAIN_MIN 1
#define RULES_PER_PLAIN_MAX 99
#define RP_GEN_FUNC_MIN     1
#define RP_GEN_FUNC_MAX     4
#define PW_MAX              32
#define LINE_SIG_LEN        RP_GEN_FUNC_MAX * 2 + 1

int max_len = 0;

#include "cpu_rules.h"
#include "rp_kernel_on_cpu.h"

void print_plain (char *plain, int plain_len)
{
  int need_hexifly = 0;

  u8 *plain_ptr = (u8*) plain;

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

  char *rule_buf = (char *) malloc (HCBUFSIZ);

  char *line_buf = (char *) malloc (HCBUFSIZ);

  int rp_gen_func_min = RP_GEN_FUNC_MIN;
  int rp_gen_func_max = RP_GEN_FUNC_MAX;

  while (1)
  {
    /*
     * line
     */

    if (feof (fp)) break;

    char *line_ptr = fgets (line_buf, HCBUFSIZ - 1, fp);

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
        strncpy (rule_buf, argv[1], HCBUFSIZ - 1);

        rule_len = strlen (rule_buf);
      }

      kernel_rule_t kernel_rule_buf;

      memset (&kernel_rule_buf, 0, sizeof (kernel_rule_t));

      if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rule_buf) == -1) continue;

      // cpu
      char rule_buf_cpu[BLOCK_SIZE];

      memset (rule_buf_cpu, 0, BLOCK_SIZE);

      max_len = 0;

      int out_len_cpu = apply_rule_cpu (rule_buf, rule_len, line_ptr, line_len, rule_buf_cpu);

      if (max_len >= 32) continue;

      // gpu
      char rule_buf_kernel[BLOCK_SIZE];

      memset (rule_buf_kernel, 0, sizeof (rule_buf_kernel));

      memcpy (rule_buf_kernel, line_buf, line_len);

      u32 *plain_ptr = (u32 *) rule_buf_kernel;

      int out_len_kernel = apply_rules (kernel_rule_buf.cmds, &plain_ptr[0], &plain_ptr[4], line_len);

      /*
       * compare
       */

      if (out_len_cpu >= 0 && out_len_cpu < 32)
      {
        int failed = 1;

        if (out_len_kernel == out_len_cpu)
        {
          if (memcmp (rule_buf_kernel, rule_buf_cpu, out_len_kernel) == 0)
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
          print_plain (rule_buf_kernel, out_len_kernel);

          printf (" %i\n", out_len_kernel);
        }
      }
    }
  }

  fclose (fp);

  free (line_buf);

  free (rule_buf);

  return 0;
}
