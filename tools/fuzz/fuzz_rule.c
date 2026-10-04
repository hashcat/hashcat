/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * libFuzzer entry point for the rule compiler.
 *
 * cpu_rule_to_kernel_rule () turns one line of a rule file into the command
 * list the kernels run. Rule files are as attacker controlled as hash files
 * are: they are downloaded, passed around and fed to -r without review, and
 * the compiler walks the line by hand with a lot of rule_pos arithmetic.
 *
 * The input is the rule, byte for byte. It is copied into an allocation of
 * exactly that length, so a read past rule_len is a read past the allocation
 * and AddressSanitizer reports it. hashcat's own callers hand the compiler a
 * NUL terminated line buffer, so such a read lands on the terminator there
 * rather than off the end. That makes it a correctness finding rather than a
 * crash, and it still has to be fixed, because the byte read is not part of
 * the rule. Build with -DFUZZ_NUL_TERMINATE to reproduce the caller's buffer
 * instead and report only reads past the terminator.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "rp.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0) return 0;

  // longer than RP_RULE_SIZE is rejected by every caller before the compiler
  // sees it, so fuzzing past that length only wastes executions

  if (size > RP_RULE_SIZE) return 0;

  #ifdef FUZZ_NUL_TERMINATE
  char *rule_buf = (char *) malloc (size + 1);

  rule_buf[size] = 0;
  #else
  char *rule_buf = (char *) malloc (size);
  #endif

  memcpy (rule_buf, data, size);

  kernel_rule_t rule;

  memset (&rule, 0, sizeof (rule));

  cpu_rule_to_kernel_rule (rule_buf, (u32) size, &rule);

  free (rule_buf);

  return 0;
}
