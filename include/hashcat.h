/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASHCAT_H
#define _HASHCAT_H

int hashcat (hashcat_ctx_t *hashcat_ctx, char *install_folder, char *shared_folder, int argc, char **argv, const int comptime);

void hashcat_ctx_init    (hashcat_ctx_t *hashcat_ctx, void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t));
void hashcat_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _HASHCAT_H
