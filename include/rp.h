/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _RP_H
#define _RP_H

#include <string.h>

#define RP_RULE_BUFSIZ 0x100

#define INCR_RULES 10000

#define RULES_MAX 32
#define MAX_KERNEL_RULES (RULES_MAX - 1)

bool class_num   (const u8 c);
bool class_lower (const u8 c);
bool class_upper (const u8 c);
bool class_alpha (const u8 c);

int conv_ctoi (const u8 c);
int conv_itoc (const u8 c);

int generate_random_rule (char rule_buf[RP_RULE_BUFSIZ], const u32 rp_gen_func_min, const u32 rp_gen_func_max);

int cpu_rule_to_kernel_rule (char *rule_buf, u32 rule_len, kernel_rule_t *rule);
int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule);

bool kernel_rules_has_noop (const kernel_rule_t *kernel_rules_buf, const u32 kernel_rules_cnt);

int kernel_rules_load     (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt);
int kernel_rules_generate (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt);

#endif // _RP_H
