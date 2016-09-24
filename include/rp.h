/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _RP_H
#define _RP_H

#include <string.h>

#define RP_RULE_BUFSIZ 0x100

#define INCR_RULES 10000

#define MAX_KERNEL_RULES 31

bool class_num   (const u8 c);
bool class_lower (const u8 c);
bool class_upper (const u8 c);
bool class_alpha (const u8 c);

int conv_ctoi (const u8 c);
int conv_itoc (const u8 c);

int generate_random_rule (char rule_buf[RP_RULE_BUFSIZ], u32 rp_gen_func_min, u32 rp_gen_func_max);

int cpu_rule_to_kernel_rule (char *rule_buf, uint rule_len, kernel_rule_t *rule);
int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule);

#endif // _RP_H
