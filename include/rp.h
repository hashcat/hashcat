/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _RP_H
#define _RP_H

#include <string.h>

#define RP_RULE_SIZE      256
#define RP_PASSWORD_SIZE  256

#define INCR_RULES 10000

#define RULES_MAX 32
#define MAX_KERNEL_RULES (RULES_MAX - 1)

typedef struct
{
  char *grp_op_nop_selection;
  char *grp_op_pos_p0_selection;
  char *grp_op_pos_p1_selection;
  char *grp_op_chr_selection;
  char *grp_op_chr_chr_selection;
  char *grp_op_pos_chr_selection;
  char *grp_op_pos_pos0_selection;
  char *grp_op_pos_pos1_selection;

  int grp_op_nop_cnt;
  int grp_op_pos_p0_cnt;
  int grp_op_pos_p1_cnt;
  int grp_op_chr_cnt;
  int grp_op_chr_chr_cnt;
  int grp_op_pos_chr_cnt;
  int grp_op_pos_pos0_cnt;
  int grp_op_pos_pos1_cnt;

  // 8 if all operator group types used, but can be lower if user is using operator selection options

  int grp_op_alias_buf[8];
  int grp_op_alias_cnt;

} rp_gen_ops_t;

bool class_num   (const u8 c);
bool class_lower (const u8 c);
bool class_upper (const u8 c);
bool class_alpha (const u8 c);

int conv_ctoi (const u8 c);
int conv_itoc (const u8 c);

int generate_random_rule (char rule_buf[RP_RULE_SIZE], const u32 rp_gen_func_min, const u32 rp_gen_func_max, const rp_gen_ops_t *rp_gen_ops);

bool is_hex_notation (const char *rule_buf, u32 rule_len, u32 rule_pos);

int cpu_rule_to_kernel_rule (char *rule_buf, u32 rule_len, kernel_rule_t *rule);
int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule);

bool kernel_rules_has_noop (const kernel_rule_t *kernel_rules_buf, const u32 kernel_rules_cnt);

int kernel_rules_load     (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt);
int kernel_rules_generate (hashcat_ctx_t *hashcat_ctx, kernel_rule_t **out_buf, u32 *out_cnt, const char *rp_gen_func_selection);

#endif // _RP_H
