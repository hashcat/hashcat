
#ifndef _MODULES_H
#define _MODULES_H

typedef struct hashcat_module
{
  const char *(*module_hash_name)    ();
  u32         (*module_salt_type)    ();
  u32         (*module_attack_exec)  ();
  u64         (*module_opts_type)    ();
  u32         (*module_dgst_size)    ();
  u32         (*module_opti_type)    ();
  u32         (*module_dgst_pos0)    ();
  u32         (*module_dgst_pos1)    ();
  u32         (*module_dgst_pos2)    ();
  u32         (*module_dgst_pos3)    ();
  const char *(*module_st_hash)      ();
  const char *(*module_st_pass)      ();
  u32         (*module_pw_min)       (const hashcat_ctx_t *);
  u32         (*module_pw_max)       (const hashcat_ctx_t *);
  u32         (*module_salt_min)     (const hashcat_ctx_t *);
  u32         (*module_salt_max)     (const hashcat_ctx_t *);
  int         (*module_hash_decode)  (const hashcat_ctx_t *, const u8 *, const int, hash_t *);
  int         (*module_hash_encode)  (const hashcat_ctx_t *, const void *, const salt_t *, const void *, u8 *, const size_t);

} hashcat_module_t;

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
u32         module_pw_min       (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx);
u32         module_pw_max       (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx);
u32         module_salt_min     (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx);
u32         module_salt_max     (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx);
int         module_hash_decode  (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx, const u8 *input_buf, const int input_len, hash_t *hash_buf);
int         module_hash_encode  (MAYBE_UNUSED const hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *digest, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt, u8 *output_buf, const size_t output_size);
void        module_register     (hashcat_module_t *hashcat_module);

#endif // _MODULES_H
