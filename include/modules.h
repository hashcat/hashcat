
#ifndef _MODULES_H
#define _MODULES_H

const char *module_hash_name    ();
u32         module_salt_type    ();
u32         module_attack_exec  ();
u64         module_opts_type    ();
u32         module_dgst_size    ();
u32         module_opti_type    ();
u32         module_dgst_pos0    ();
u32         module_dgst_pos1    ();
u32         module_dgst_pos2    ();
u32         module_dgst_pos3    ();
const char *module_st_hash      ();
const char *module_st_pass      ();
u32         module_pw_min       (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         module_pw_max       (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         module_salt_min     (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
u32         module_salt_max     (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra);
int         module_hash_decode  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED       void *digest_buf, MAYBE_UNUSED       salt_t *salt, MAYBE_UNUSED       void *esalt_buf, const char *line_buf, const int line_len);
int         module_hash_encode  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf,       char *line_buf, const int line_size);
void        module_register     (module_ctx_t *module_ctx);

#endif // _MODULES_H
