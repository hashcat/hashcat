#pragma once
#include "common.h"
#include "types.h"
u64 sp_get_sum(uint start, uint stop, cs_t *root_css_buf);
void sp_exec(u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint start, uint stop);
int sp_comp_val(const void *p1, const void *p2);
void sp_setup_tbl(const char *install_dir, char *hcstat, uint disable, uint classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf);
void sp_tbl_to_css(hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint threshold, uint uniq_tbls[SP_PW_MAX][CHARSIZ]);
void sp_stretch_markov(hcstat_table_t *in, hcstat_table_t *out);
void sp_stretch_root(hcstat_table_t *in, hcstat_table_t *out);
