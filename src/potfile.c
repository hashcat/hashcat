/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "convert.h"
#include "memory.h"
#include "event.h"
#include "hashes.h"
#include "filehandling.h"
#include "loopback.h"
#include "outfile.h"
#include "locking.h"
#include "shared.h"
#include "potfile.h"

static const char MASKED_PLAIN[] = "[notfound]";

// get rid of this later
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);
// get rid of this later

// this function is for potfile comparison where the potfile does not contain all the
// information requires to do a true sort_by_hash() bsearch
/*
static int sort_by_hash_t_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  const int res1 = (int) s1->salt_len - (int) s2->salt_len;

  if (res1 != 0) return (res1);

  //const int res2 = (int) s1->salt_iter - (int) s2->salt_iter;
  //
  //if (res2 != 0) return (res2);

  for (int n = 0; n < 16; n++)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return  1;
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  for (int n = 0; n < 8; n++)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return  1;
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}
*/

// this function is special and only used whenever --username and --show are used together:
// it will sort all tree entries according to the settings stored in hashconfig

int sort_pot_tree_by_hash (const void *v1, const void *v2)
{
  const pot_tree_entry_t *t1 = (const pot_tree_entry_t *) v1;
  const pot_tree_entry_t *t2 = (const pot_tree_entry_t *) v2;

  const hash_t *h1 = (const hash_t *) t1->nodes->hash_buf;
  const hash_t *h2 = (const hash_t *) t2->nodes->hash_buf;

  hashconfig_t *hc = t1->hashconfig; // is same as t2->hashconfig

  return sort_by_hash (h1, h2, hc);
}

// the problem with the GNU tdestroy () function is that it doesn't work with mingw etc
// there are 2 alternatives:
// 1. recursively delete the entries with entry->left and entry->right
// 2. use tdelete () <- this is what we currently use, but this could be slower!

void pot_tree_destroy (pot_tree_entry_t *tree)
{
  pot_tree_entry_t *entry = tree;

  while (tree != NULL)
  {
    entry = *(pot_tree_entry_t **) tree;

    tdelete (entry, (void **) &tree, sort_pot_tree_by_hash);
  }
}

int potfile_init (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
        potfile_ctx_t   *potfile_ctx   = hashcat_ctx->potfile_ctx;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  potfile_ctx->enabled = false;

  if (user_options->benchmark       == true) return 0;
  if (user_options->example_hashes  == true) return 0;
  if (user_options->keyspace        == true) return 0;
  if (user_options->backend_info    == true) return 0;
  if (user_options->stdout_flag     == true) return 0;
  if (user_options->speed_only      == true) return 0;
  if (user_options->progress_only   == true) return 0;
  if (user_options->usage           == true) return 0;
  if (user_options->version         == true) return 0;
  if (user_options->potfile_disable == true) return 0;

  if (hashconfig->potfile_disable == true) return 0;

  potfile_ctx->enabled = true;

  if (user_options->potfile_path == NULL)
  {
    potfile_ctx->fp.pfp   = NULL;

    hc_asprintf (&potfile_ctx->filename, "%s/hashcat.potfile", folder_config->profile_dir);
  }
  else
  {
    potfile_ctx->filename = hcstrdup (user_options->potfile_path);
    potfile_ctx->fp.pfp   = NULL;
  }

  // starting from here, we should allocate some scratch buffer for later use

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  potfile_ctx->out_buf = out_buf;

  // we need two buffers in parallel

  u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  potfile_ctx->tmp_buf = tmp_buf;

  // old potfile detection

  if (user_options->potfile_path == NULL)
  {
    char *potfile_old;

    hc_asprintf (&potfile_old, "%s/hashcat.pot", folder_config->profile_dir);

    if (hc_path_exist (potfile_old) == true)
    {
      event_log_warning (hashcat_ctx, "Old potfile detected: %s", potfile_old);
      event_log_warning (hashcat_ctx, "New potfile is: %s ", potfile_ctx->filename);
      event_log_warning (hashcat_ctx, NULL);
    }

    hcfree (potfile_old);
  }

  return 0;
}

void potfile_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  if (hashconfig->potfile_disable == true) return;

  hcfree (potfile_ctx->out_buf);
  hcfree (potfile_ctx->tmp_buf);

  memset (potfile_ctx, 0, sizeof (potfile_ctx_t));
}

int potfile_read_open (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  if (hc_fopen (&potfile_ctx->fp, potfile_ctx->filename, "rb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_read_close (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  if (hashconfig->potfile_disable == true) return;

  if (potfile_ctx->fp.pfp == NULL) return;

  hc_fclose (&potfile_ctx->fp);
}

int potfile_write_open (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  if (hc_fopen (&potfile_ctx->fp, potfile_ctx->filename, "ab") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_write_close (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  if (hashconfig->potfile_disable == true) return;

  hc_fclose (&potfile_ctx->fp);
}

void potfile_write_append (hashcat_ctx_t *hashcat_ctx, const char *out_buf, const int out_len, u8 *plain_ptr, unsigned int plain_len)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;
  potfile_ctx_t        *potfile_ctx  = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  if (hashconfig->potfile_disable == true) return;

  u8 *tmp_buf = potfile_ctx->tmp_buf;

  int tmp_len = 0;

  if (1)
  {
    memcpy (tmp_buf + tmp_len, out_buf, out_len);

    tmp_len += out_len;

    tmp_buf[tmp_len] = hashconfig->separator;

    tmp_len += 1;
  }

  if ((hashconfig->opts_type & OPTS_TYPE_POTFILE_NOPASS) == 0)
  {
    const bool always_ascii = (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_ASCII) ? true : false;

    if ((user_options->outfile_autohex == true) && (need_hexify (plain_ptr, plain_len, hashconfig->separator, always_ascii) == true))
    {
      tmp_buf[tmp_len++] = '$';
      tmp_buf[tmp_len++] = 'H';
      tmp_buf[tmp_len++] = 'E';
      tmp_buf[tmp_len++] = 'X';
      tmp_buf[tmp_len++] = '[';

      exec_hexify ((const u8 *) plain_ptr, plain_len, tmp_buf + tmp_len);

      tmp_len += plain_len * 2;

      tmp_buf[tmp_len++] = ']';
    }
    else
    {
      memcpy (tmp_buf + tmp_len, plain_ptr, plain_len);

      tmp_len += plain_len;
    }
  }

  tmp_buf[tmp_len] = 0;

  hc_lockfile (&potfile_ctx->fp);

  hc_fprintf (&potfile_ctx->fp, "%s" EOL, tmp_buf);

  hc_fflush (&potfile_ctx->fp);

  if (hc_unlockfile (&potfile_ctx->fp))
  {
    event_log_error (hashcat_ctx, "%s: Failed to unlock file.", potfile_ctx->filename);
  }
}

void potfile_update_hash (hashcat_ctx_t *hashcat_ctx, hash_t *found, char *line_pw_buf, int line_pw_len)
{
  const loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (found == NULL) return;

  char *pw_buf = line_pw_buf;
  int   pw_len = line_pw_len;

  found->pw_buf = (char *) hcmalloc (pw_len + 1);
  found->pw_len = pw_len;

  if (pw_buf)
  {
    memcpy (found->pw_buf, pw_buf, pw_len);

    found->pw_buf[found->pw_len] = 0;
  }

  found->cracked = 1;

  // if enabled, update also the loopback file

  if (loopback_ctx->fp.pfp != NULL)
  {
    loopback_write_append (hashcat_ctx, (u8 *) pw_buf, (unsigned int) pw_len);
  }
}

void potfile_update_hashes (hashcat_ctx_t *hashcat_ctx, hash_t *hash_buf, char *line_pw_buf, int line_pw_len, pot_tree_entry_t *tree)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  // the linked list node:

  pot_hash_node_t search_node;

  search_node.hash_buf = hash_buf;
  search_node.next     = NULL;

  // the search entry:

  pot_tree_entry_t search_entry;

  search_entry.nodes      = &search_node;
  search_entry.hashconfig = hashconfig;

  // the main search function is this:

  void **found = tfind (&search_entry, (void **) &tree, sort_pot_tree_by_hash);

  if (found)
  {
    pot_tree_entry_t *found_entry = (pot_tree_entry_t *) *found;

    pot_hash_node_t *node = found_entry->nodes;

    while (node)
    {
      potfile_update_hash (hashcat_ctx, node->hash_buf, line_pw_buf, line_pw_len);

      node = node->next;
    }
  }
}

int potfile_remove_parse (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;
  potfile_ctx_t        *potfile_ctx  = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  if (hashconfig->potfile_disable == true) return 0;

  if (hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) return 0;

  // if no potfile exists yet we don't need to do anything here

  if (hc_path_exist (potfile_ctx->filename) == false) return 0;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  // no solution for these special hash types (for instane because they use hashfile in output etc)

  hash_t hash_buf;

  hash_buf.digest    = hcmalloc (hashconfig->dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hook_salt = NULL;
  hash_buf.cracked   = 0;
  hash_buf.hash_info = NULL;
  hash_buf.pw_buf    = NULL;
  hash_buf.pw_len    = 0;

  if (hashconfig->is_salted == true)
  {
    hash_buf.salt = (salt_t *) hcmalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    hash_buf.esalt = hcmalloc (hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hash_buf.hook_salt = hcmalloc (hashconfig->hook_salt_size);
  }

  // we only need this variable in a very specific situation:
  // whenever we use --username and --show together we want to keep all hashes sorted within a nice structure

  pot_tree_entry_t *all_hashes_tree  = NULL;
  pot_tree_entry_t *tree_entry_cache = NULL;
  pot_hash_node_t  *tree_nodes_cache = NULL;

  if (hashconfig->potfile_keep_all_hashes == true)
  {
    // we need *at most* one entry for every hash
    // (if there are no hashes with the same keys (hash + salt), a counter example would be: same hash but different user name)
    tree_entry_cache = (pot_tree_entry_t *) hccalloc (hashes_cnt, sizeof (pot_tree_entry_t));

    // we need *always exactly* one linked list for every hash
    tree_nodes_cache = (pot_hash_node_t  *) hccalloc (hashes_cnt, sizeof (pot_hash_node_t));

    for (u32 hash_pos = 0; hash_pos < hashes_cnt; hash_pos++)
    {
      // initialize the linked list node:
      // we always need to create a new one and add it, because we want to keep and later update all hashes:

      pot_hash_node_t *new_node = &tree_nodes_cache[hash_pos];

      new_node->hash_buf = &hashes_buf[hash_pos];
      new_node->next     = NULL;

      // initialize the entry:

      pot_tree_entry_t *new_entry = &tree_entry_cache[hash_pos];

      // note: the "key" (hash + salt) is indirectly accessible via the first nodes "hash_buf"

      new_entry->nodes      = new_node;
      // the hashconfig is needed here because we need to be able to check within the sort function if we also need
      // to sort by salt and we also need to have the correct order of dgst_pos0...dgst_pos3:
      new_entry->hashconfig = (hashconfig_t *) hashconfig; // "const hashconfig_t" gives a warning

      // the following function searches if the "key" is already present and if not inserts the new entry:

      void **found = tsearch (new_entry, (void **) &all_hashes_tree, sort_pot_tree_by_hash);

      pot_tree_entry_t *found_entry = (pot_tree_entry_t *) *found;

      // we now need to check these cases; tsearch () could return:
      // 1. NULL : if we have a memory allocation problem (not enough memory for the tree structure)
      // 2. found_entry == new_entry: if we successfully insert a new key (which was not present yet)
      // 3. found_entry != new_entry: if the key was already present

      // case 1: memory allocation error

      if (found_entry == NULL)
      {
        fprintf (stderr, "Error while allocating memory for the potfile search: %s\n", MSG_ENOMEM);

        return -1;
      }

      // case 2: this means it was a new insert (and the insert was successful)

      if (found_entry == new_entry)
      {
        // no updates to the linked list required (since it is the first one!)
      }
      // case 3: if we have found an already existing entry
      else
      {
        new_node->next = found_entry->nodes;
      }

      // we always insert the new node at the very beginning
      // (or in other words: the head of the linked list always points to *this* new inserted node)

      found_entry->nodes = new_node;
    }
  }

  // do not use this unless really needed, for example as in LM

  if (module_ctx->module_hash_decode_zero_hash != MODULE_DEFAULT)
  {
    module_ctx->module_hash_decode_zero_hash (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info);

    if (hashconfig->potfile_keep_all_hashes == true)
    {
      potfile_update_hashes (hashcat_ctx, &hash_buf, NULL, 0, all_hashes_tree);
    }
    else
    {
      hash_t *found = (hash_t *) hc_bsearch_r (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);

      potfile_update_hash (hashcat_ctx, found, NULL, 0);
    }
  }

  const int rc = potfile_read_open (hashcat_ctx);

  if (rc == -1) return -1;

  void *tmps = NULL;

  if (hashconfig->tmp_size > 0)
  {
    tmps = hcmalloc (hashconfig->tmp_size);
  }

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  while (!hc_feof (&potfile_ctx->fp))
  {
    size_t line_len = fgetl (&potfile_ctx->fp, line_buf, HCBUFSIZ_LARGE);

    if (line_len == 0) continue;

    char *last_separator = strrchr (line_buf, hashconfig->separator);

    if (last_separator == NULL) continue; // ??

    char *line_pw_buf = last_separator + 1;

    size_t line_pw_len = line_buf + line_len - line_pw_buf;

    char *line_hash_buf = line_buf;

    int line_hash_len = last_separator - line_buf;

    line_hash_buf[line_hash_len] = 0;

    if (line_hash_len == 0) continue;

    if (hash_buf.salt)
    {
      memset (hash_buf.salt, 0, sizeof (salt_t));
    }

    if (hash_buf.esalt)
    {
      memset (hash_buf.esalt, 0, hashconfig->esalt_size);
    }

    if (hash_buf.hook_salt)
    {
      memset (hash_buf.hook_salt, 0, hashconfig->hook_salt_size);
    }

    if (module_ctx->module_hash_decode_potfile != MODULE_DEFAULT)
    {
      if (module_ctx->module_potfile_custom_check != MODULE_DEFAULT)
      {
        const int parser_status = module_ctx->module_hash_decode_potfile (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info, line_hash_buf, line_hash_len, tmps);

        if (parser_status != PARSER_OK) continue;

        for (u32 hashes_pos = 0; hashes_pos < hashes_cnt; hashes_pos++)
        {
          const bool cracked = module_ctx->module_potfile_custom_check (hashconfig, &hashes_buf[hashes_pos], &hash_buf, tmps);

          if (cracked == true)
          {
            potfile_update_hash (hashcat_ctx, &hashes_buf[hashes_pos], line_pw_buf, (u32) line_pw_len);
          }
        }

        continue;
      }

      // should be rejected?
      //const int parser_status = module_ctx->module_hash_decode_potfile (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info, line_hash_buf, line_hash_len, NULL);
      //if (parser_status != PARSER_OK) continue;
    }
    else
    {
      const int parser_status = module_ctx->module_hash_decode (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info, line_hash_buf, line_hash_len);

      if (parser_status != PARSER_OK) continue;

      if (hashconfig->potfile_keep_all_hashes == true)
      {
        potfile_update_hashes (hashcat_ctx, &hash_buf, line_pw_buf, (u32) line_pw_len, all_hashes_tree);

        continue;
      }

      hash_t *found = (hash_t *) hc_bsearch_r (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash, (void *) hashconfig);

      potfile_update_hash (hashcat_ctx, found, line_pw_buf, (u32) line_pw_len);
    }
  }

  hcfree (line_buf);

  if (hashconfig->tmp_size > 0)
  {
    hcfree (tmps);
  }

  potfile_read_close (hashcat_ctx);

  if (hashconfig->potfile_keep_all_hashes == true)
  {
    pot_tree_destroy (all_hashes_tree); // this could be slow (should we just skip it?)

    hcfree (tree_nodes_cache);
    hcfree (tree_entry_cache);
  }

  if (hashconfig->esalt_size > 0)
  {
    hcfree (hash_buf.esalt);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hcfree (hash_buf.hook_salt);
  }

  if (hashconfig->is_salted == true)
  {
    hcfree (hash_buf.salt);
  }

  hcfree (hash_buf.digest);

  return 0;
}

int potfile_handle_show (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  hash_t *hashes_buf  = hashes->hashes_buf;

  u32     salts_cnt = hashes->salts_cnt;
  salt_t *salts_buf = hashes->salts_buf;

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
  {
    // this implementation will work for LM only
    // however, LM is the only hash support which splits the password into multiple hashes

    for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
    {
      salt_t *salt_buf = salts_buf + salt_idx;

      u32 digests_cnt = salt_buf->digests_cnt;

      for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
      {
        const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

        u32 *digests_shown = hashes->digests_shown;

        hash_t *hash1 = &hashes_buf[hashes_idx];
        hash_t *hash2 = NULL;

        int split_neighbor = -1;

        // find out if at least one of the parts has been cracked

        if (hash1->hash_info->split->split_origin == SPLIT_ORIGIN_LEFT)
        {
          split_neighbor = hash1->hash_info->split->split_neighbor;

          hash2 = &hashes_buf[split_neighbor];

          if ((digests_shown[hashes_idx] == 0) && (digests_shown[split_neighbor] == 0)) continue;
        }
        else if (hash1->hash_info->split->split_origin == SPLIT_ORIGIN_NONE)
        {
          if (digests_shown[hashes_idx] == 0) continue;
        }
        else
        {
          // SPLIT_ORIGIN_RIGHT are not handled this way

          continue;
        }

        u8 *out_buf = potfile_ctx->out_buf;

        int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf + 0, HCBUFSIZ_LARGE - 0, salt_idx, digest_idx);

        if (hash2)
        {
          out_len += hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf + 16, HCBUFSIZ_LARGE - 16, salt_idx, split_neighbor);
        }

        out_buf[out_len] = 0;

        // user
        unsigned char *username = NULL;

        u32 user_len = 0;

        user_t *user = hash1->hash_info->user;

        if (user)
        {
          username = (unsigned char *) (user->user_name);

          user_len = user->user_len;

          username[user_len] = 0;
        }

        u8 *tmp_buf = potfile_ctx->tmp_buf;

        tmp_buf[0] = 0;

        u8 mixed_buf[20] = { 0 };

        u8 mixed_len = 0;

        if (digests_shown[hashes_idx] == 1)
        {
          memcpy (mixed_buf + mixed_len, hash1->pw_buf, hash1->pw_len);

          mixed_len += hash1->pw_len;
        }
        else
        {
          memcpy (mixed_buf + mixed_len, MASKED_PLAIN, strlen (MASKED_PLAIN));

          mixed_len += strlen (MASKED_PLAIN);
        }

        if (hash2)
        {
          if (digests_shown[split_neighbor] == 1)
          {
            memcpy (mixed_buf + mixed_len, hash2->pw_buf, hash2->pw_len);

            mixed_len += hash2->pw_len;
          }
          else
          {
            memcpy (mixed_buf + mixed_len, MASKED_PLAIN, strlen (MASKED_PLAIN));

            mixed_len += strlen (MASKED_PLAIN);
          }
        }

        const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, (u8 *) mixed_buf, mixed_len, 0, username, user_len, (char *) tmp_buf);

        EVENT_DATA (EVENT_POTFILE_HASH_SHOW, tmp_buf, tmp_len);
      }
    }
  }
  else
  {
    for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
    {
      salt_t *salt_buf = salts_buf + salt_idx;

      u32 digests_cnt = salt_buf->digests_cnt;

      for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
      {
        const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

        u32 *digests_shown = hashes->digests_shown;

        if (digests_shown[hashes_idx] == 0) continue;

        hash_t *hash = &hashes_buf[hashes_idx];

        u8 *out_buf = potfile_ctx->out_buf;

        const int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_idx, digest_idx);

        out_buf[out_len] = 0;

        // user
        unsigned char *username = NULL;

        u32 user_len = 0;

        if (hash->hash_info != NULL)
        {
          user_t *user = hash->hash_info->user;

          if (user)
          {
            username = (unsigned char *) (user->user_name);

            user_len = user->user_len;

            username[user_len] = 0;
          }
        }

        u8 *tmp_buf = potfile_ctx->tmp_buf;

        tmp_buf[0] = 0;


        // special case for collider modes: we do not use the $HEX[] format within the hash itself
        // therefore we need to convert the $HEX[] password into hexadecimal (without "$HEX[" and "]")

        bool is_collider_hex_password = false;

        if (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_HEXIFY)
        {
          if (is_hexify ((u8 *) hash->pw_buf, hash->pw_len) == true)
          {
            is_collider_hex_password = true;
          }
        }

        int tmp_len = 0;

        if (is_collider_hex_password == true)
        {
          u8 pass_unhexified[HCBUFSIZ_SMALL] = { 0 };

          const size_t pass_unhexified_len = exec_unhexify ((u8 *) hash->pw_buf, hash->pw_len, pass_unhexified, sizeof (pass_unhexified));

          tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, pass_unhexified, (u32) pass_unhexified_len, 0, username, user_len, (char *) tmp_buf);
        }
        else
        {
          tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, (u8 *) hash->pw_buf, hash->pw_len, 0, username, user_len, (char *) tmp_buf);
        }

        EVENT_DATA (EVENT_POTFILE_HASH_SHOW, tmp_buf, tmp_len);
      }
    }
  }

  return 0;
}

int potfile_handle_left (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;
  module_ctx_t  *module_ctx  = hashcat_ctx->module_ctx;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  hash_t *hashes_buf = hashes->hashes_buf;

  u32     salts_cnt = hashes->salts_cnt;
  salt_t *salts_buf = hashes->salts_buf;

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
  {
    // this implementation will work for LM only
    // however, LM is the only hash support which splits the password into multiple hashes

    for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
    {
      salt_t *salt_buf = salts_buf + salt_idx;

      u32 digests_cnt = salt_buf->digests_cnt;

      for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
      {
        const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

        u32 *digests_shown = hashes->digests_shown;

        hash_t *hash1 = &hashes_buf[hashes_idx];
        hash_t *hash2 = NULL;

        int split_neighbor = -1;

        // find out if at least one of the parts has been cracked

        if (hash1->hash_info->split->split_origin == SPLIT_ORIGIN_LEFT)
        {
          split_neighbor = hash1->hash_info->split->split_neighbor;

          hash2 = &hashes_buf[split_neighbor];

          if ((digests_shown[hashes_idx] == 1) && (digests_shown[split_neighbor] == 1)) continue;
        }
        else if (hash1->hash_info->split->split_origin == SPLIT_ORIGIN_NONE)
        {
          if (digests_shown[hashes_idx] == 1) continue;
        }
        else
        {
          // SPLIT_ORIGIN_RIGHT are not handled this way

          continue;
        }

        u8 *out_buf = potfile_ctx->out_buf;

        int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf + 0, HCBUFSIZ_LARGE - 0, salt_idx, digest_idx);

        if (hash2)
        {
          out_len += hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf + 16, HCBUFSIZ_LARGE - 16, salt_idx, split_neighbor);
        }

        out_buf[out_len] = 0;

        // user
        unsigned char *username = NULL;

        u32 user_len = 0;

        user_t *user = hash1->hash_info->user;

        if (user)
        {
          username = (unsigned char *) (user->user_name);

          user_len = user->user_len;

          username[user_len] = 0;
        }

        u8 *tmp_buf = potfile_ctx->tmp_buf;

        tmp_buf[0] = 0;

        const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, NULL, 0, 0, username, user_len, (char *) tmp_buf);

        EVENT_DATA (EVENT_POTFILE_HASH_LEFT, tmp_buf, tmp_len);
      }
    }
  }
  else
  {
    for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
    {
      salt_t *salt_buf = salts_buf + salt_idx;

      u32 digests_cnt = salt_buf->digests_cnt;

      for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
      {
        const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

        u32 *digests_shown = hashes->digests_shown;

        if (digests_shown[hashes_idx] == 1) continue;

        u8 *out_buf = potfile_ctx->out_buf;

        int out_len;

        if (module_ctx->module_hash_binary_save != MODULE_DEFAULT)
        {
          char *binary_buf = NULL;

          int binary_len = module_ctx->module_hash_binary_save (hashes, salt_idx, digest_idx, &binary_buf);

          if ((hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE) == 0)
          {
            binary_len--; // no need for the newline
          }

          memcpy (out_buf, binary_buf, binary_len);

          out_len = binary_len;

          hcfree (binary_buf);
        }
        else
        {
          out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_idx, digest_idx);
        }

        out_buf[out_len] = 0;

        hash_t *hash = &hashes_buf[hashes_idx];

        // user
        unsigned char *username = NULL;

        u32 user_len = 0;

        if (hash->hash_info != NULL)
        {
          user_t *user = hash->hash_info->user;

          if (user)
          {
            username = (unsigned char *) (user->user_name);

            user_len = user->user_len;

            username[user_len] = 0;
          }
        }

        u8 *tmp_buf = potfile_ctx->tmp_buf;

        tmp_buf[0] = 0;

        const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, NULL, 0, 0, username, user_len, (char *) tmp_buf);

        EVENT_DATA (EVENT_POTFILE_HASH_LEFT, tmp_buf, tmp_len);
      }
    }
  }

  return 0;
}
