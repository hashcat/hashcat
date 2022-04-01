/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "timer.h"
#include "memory.h"
#include "thread.h"
#include "convert.h"
#include "shared.h"
#include "hashes.h"
#include "brain.h"

static bool keep_running = true;

static hc_timer_t timer_logging;

static hc_thread_mutex_t mux_display;

int brain_logging (FILE *stream, const int client_idx, const char *format, ...)
{
  const double ms = hc_timer_get (timer_logging);

  hc_timer_set (&timer_logging);

  hc_thread_mutex_lock (mux_display);

  struct timeval v;

  gettimeofday (&v, NULL);

  fprintf (stream, "%u.%06u | %6.2fs | %3d | ", (u32) v.tv_sec, (u32) v.tv_usec, ms / 1000, client_idx);

  va_list ap;

  va_start (ap, format);

  const int len = vfprintf (stream, format, ap);

  va_end (ap);

  hc_thread_mutex_unlock (mux_display);

  return len;
}

u32 brain_compute_session (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes       = hashcat_ctx->hashes;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->brain_session != 0) return user_options->brain_session;

  const u64 seed = (const u64) hashconfig->hash_mode;

  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, seed);

  if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
  {
    // digest

    u32  digests_cnt = hashes->digests_cnt;
    u32 *digests_buf = (u32 *) hashes->digests_buf;

    XXH64_update (state, digests_buf, digests_cnt * hashconfig->dgst_size);

    // salt

    u32     salts_cnt = hashes->salts_cnt;
    salt_t *salts_buf = hashes->salts_buf;

    for (u32 salts_idx = 0; salts_idx < salts_cnt; salts_idx++)
    {
      salt_t *salt = salts_buf + salts_idx;

      XXH64_update (state, &salt->salt_iter, sizeof (salt->salt_iter));
      XXH64_update (state,  salt->salt_buf,  sizeof (salt->salt_buf));
    }

    // esalt

    if (hashconfig->esalt_size > 0)
    {
      void *esalts_buf = hashes->esalts_buf;

      XXH64_update (state, esalts_buf, digests_cnt * hashconfig->esalt_size);
    }
  }
  else
  {
    // using hash_encode is an easy workaround for dealing with optimizations
    // like OPTI_TYPE_PRECOMPUTE_MERKLE which cause different hashes in digests_buf
    // in case -O is used

    string_sized_t *string_sized_buf = (string_sized_t *) hccalloc (hashes->digests_cnt, sizeof (string_sized_t));

    int string_sized_cnt = 0;

    u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

    u32 salts_cnt = hashes->salts_cnt;

    for (u32 salts_idx = 0; salts_idx < salts_cnt; salts_idx++)
    {
      salt_t *salt_buf = &hashes->salts_buf[salts_idx];

      for (u32 digest_idx = 0; digest_idx < salt_buf->digests_cnt; digest_idx++)
      {
        const int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salts_idx, digest_idx);

        string_sized_buf[string_sized_cnt].buf = (char *) hcmalloc (out_len + 1);
        string_sized_buf[string_sized_cnt].len = out_len;

        memcpy (string_sized_buf[string_sized_cnt].buf, out_buf, out_len);

        string_sized_cnt++;
      }
    }

    hcfree (out_buf);

    qsort (string_sized_buf, string_sized_cnt, sizeof (string_sized_t), sort_by_string_sized);

    for (int i = 0; i < string_sized_cnt; i++)
    {
      XXH64_update (state, string_sized_buf[i].buf, string_sized_buf[i].len);

      hcfree (string_sized_buf[i].buf);
    }

    hcfree (string_sized_buf);
  }

  const u32 session = (const u32) XXH64_digest (state);

  XXH64_freeState (state);

  return session;
}

u32 brain_compute_attack (hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  const hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  const user_options_t   *user_options   = hashcat_ctx->user_options;

  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, user_options->brain_session);

  const int hash_mode   = hashconfig->hash_mode;
  const int attack_mode = user_options->attack_mode;

  XXH64_update (state, &hash_mode,   sizeof (hash_mode));
  XXH64_update (state, &attack_mode, sizeof (attack_mode));

  const int skip  = user_options->skip;
  const int limit = user_options->limit;

  XXH64_update (state, &skip,  sizeof (skip));
  XXH64_update (state, &limit, sizeof (limit));

  const int hex_salt = user_options->hex_salt;

  XXH64_update (state, &hex_salt, sizeof (hex_salt));

  const u32 opti_type = hashconfig->opti_type;

  XXH64_update (state, &opti_type, sizeof (opti_type));

  const u64 opts_type = hashconfig->opts_type;

  XXH64_update (state, &opts_type, sizeof (opts_type));

  const int hccapx_message_pair = user_options->hccapx_message_pair;

  XXH64_update (state, &hccapx_message_pair, sizeof (hccapx_message_pair));

  const int nonce_error_corrections = user_options->nonce_error_corrections;

  XXH64_update (state, &nonce_error_corrections, sizeof (nonce_error_corrections));

  const int veracrypt_pim_start = user_options->veracrypt_pim_start;

  XXH64_update (state, &veracrypt_pim_start, sizeof (veracrypt_pim_start));

  const int veracrypt_pim_stop = user_options->veracrypt_pim_stop;

  XXH64_update (state, &veracrypt_pim_stop, sizeof (veracrypt_pim_stop));

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (straight_ctx->dict)
    {
      const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

      XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex_disable = user_options->wordlist_autohex_disable;

    XXH64_update (state, &wordlist_autohex_disable, sizeof (wordlist_autohex_disable));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }

    const int loopback = user_options->loopback;

    XXH64_update (state, &loopback, sizeof (loopback));

    XXH64_update (state, straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt * sizeof (kernel_rule_t));
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const u64 wordlist1_hash = brain_compute_attack_wordlist (combinator_ctx->dict1);
    const u64 wordlist2_hash = brain_compute_attack_wordlist (combinator_ctx->dict2);

    XXH64_update (state, &wordlist1_hash, sizeof (wordlist1_hash));
    XXH64_update (state, &wordlist2_hash, sizeof (wordlist2_hash));

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex_disable = user_options->wordlist_autohex_disable;

    XXH64_update (state, &wordlist_autohex_disable, sizeof (wordlist_autohex_disable));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov_disable   = user_options->markov_disable;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov_disable,   sizeof (markov_disable));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

    XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));

    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov_disable   = user_options->markov_disable;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov_disable,   sizeof (markov_disable));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex_disable = user_options->wordlist_autohex_disable;

    XXH64_update (state, &wordlist_autohex_disable, sizeof (wordlist_autohex_disable));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

    XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov_disable   = user_options->markov_disable;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov_disable,   sizeof (markov_disable));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex_disable = user_options->wordlist_autohex_disable;

    XXH64_update (state, &wordlist_autohex_disable, sizeof (wordlist_autohex_disable));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    if (straight_ctx->dict)
    {
      const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

      XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex_disable = user_options->wordlist_autohex_disable;

    XXH64_update (state, &wordlist_autohex_disable, sizeof (wordlist_autohex_disable));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    XXH64_update (state, straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt * sizeof (kernel_rule_t));
  }

  const u32 brain_attack = (const u32) XXH64_digest (state);

  XXH64_freeState (state);

  return brain_attack;
}

u64 brain_compute_attack_wordlist (const char *filename)
{
  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, 0);

  #define FBUFSZ 8192

  char buf[FBUFSZ];

  HCFILE fp;

  hc_fopen (&fp, filename, "rb");

  while (!hc_feof (&fp))
  {
    memset (buf, 0, sizeof (buf));

    const size_t nread = hc_fread (buf, 1, FBUFSZ, &fp);

    XXH64_update (state, buf, nread);
  }

  hc_fclose (&fp);

  const u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  return hash;
}

u64 brain_auth_hash (const u32 challenge, const char *pw_buf, const int pw_len)
{
  // nothing for production but good enough for testing

  u64 response = XXH64 (pw_buf, pw_len, challenge);

  for (int i = 0; i < 100000; i++)
  {
    response = XXH64 (&response, 8, 0);
  }

  return response;
}

u32 brain_auth_challenge (void)
{
  srand (time (NULL));

  u32 val = rand (); // just a fallback value

  #if defined (_WIN)

  // from

  HCRYPTPROV hCryptProv;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == true)
  {
    if (CryptGenRandom (hCryptProv, sizeof (val), (BYTE *) &val) == true)
    {
      // all good
    }
    else
    {
      brain_logging (stderr, 0, "CryptGenRandom: %d\n", (int) GetLastError ());

      return val;
    }

    CryptReleaseContext (hCryptProv, 0);
  }
  else
  {
    brain_logging (stderr, 0, "CryptAcquireContext: %d\n", (int) GetLastError ());

    return val;
  }

  #else

  static const char *const urandom = "/dev/urandom";

  HCFILE fp;

  if (hc_fopen (&fp, urandom, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", urandom, strerror (errno));

    return val;
  }

  if (hc_fread (&val, sizeof (val), 1, &fp) != 1)
  {
    brain_logging (stderr, 0, "%s: %s\n", urandom, strerror (errno));

    hc_fclose (&fp);

    return val;
  }

  hc_fclose (&fp);

  #endif

  return val;
}

int brain_connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen, const int timeout)
{
  #if defined (_WIN)

  if (timeout == 99999999)
  {
    // timeout not support on windows
  }

  if (connect (sockfd, addr, addrlen) == SOCKET_ERROR)
  {
    int err = WSAGetLastError ();

    char msg[256];

    memset (msg, 0, sizeof (msg));

    FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,   // flags
                   NULL,                // lpsource
                   err,                 // message id
                   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),    // languageid
                   msg,                 // output buffer
                   sizeof (msg),        // size of msgbuf, bytes
                   NULL);               // va_list of arguments

    brain_logging (stderr, 0, "connect: %s\n", msg);

    return -1;
  }

  #else

  const int old_mode = fcntl (sockfd, F_GETFL, 0);

  if (fcntl (sockfd, F_SETFL, old_mode | O_NONBLOCK) == -1)
  {
    brain_logging (stderr, 0, "fcntl: %s\n", strerror (errno));

    return -1;
  }

  connect (sockfd, addr, addrlen);

  const int rc_select = select_write_timeout (sockfd, timeout);

  if (rc_select == -1) return -1;

  if (rc_select == 0)
  {
    brain_logging (stderr, 0, "connect: timeout\n");

    return -1;
  }

  int so_error = 0;

  socklen_t len = sizeof (so_error);

  if (getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == -1)
  {
    brain_logging (stderr, 0, "getsockopt: %s\n", strerror (errno));

    return -1;
  }

  if (fcntl (sockfd, F_SETFL, old_mode) == -1)
  {
    brain_logging (stderr, 0, "fcntl: %s\n", strerror (errno));

    return -1;
  }

  if (so_error != 0)
  {
    brain_logging (stderr, 0, "connect: %s\n", strerror (so_error));

    return -1;
  }

  #endif

  return 0;
}

bool brain_send (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *ptr = (char *) buf;

  ssize_t s_pos;
  ssize_t s_len = len;

  for (s_pos = 0; s_pos < s_len - BRAIN_LINK_CHUNK_SIZE; s_pos += BRAIN_LINK_CHUNK_SIZE)
  {
    if (brain_send_all (sockfd, ptr + s_pos, BRAIN_LINK_CHUNK_SIZE, flags, device_param, status_ctx) == false) return false;

    if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;
  }

  if (brain_send_all (sockfd, ptr + s_pos, s_len - s_pos, flags, device_param, status_ctx) == false) return false;

  if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;

  return true;
}

bool brain_recv (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *ptr = (char *) buf;

  ssize_t s_pos;
  ssize_t s_len = len;

  for (s_pos = 0; s_pos < s_len - BRAIN_LINK_CHUNK_SIZE; s_pos += BRAIN_LINK_CHUNK_SIZE)
  {
    if (brain_recv_all (sockfd, ptr + s_pos, BRAIN_LINK_CHUNK_SIZE, flags, device_param, status_ctx) == false) return false;

    if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;
  }

  if (brain_recv_all (sockfd, ptr + s_pos, s_len - s_pos, flags, device_param, status_ctx) == false) return false;

  if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;

  return true;
}

bool brain_send_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  link_speed_t *link_speed = &device_param->brain_link_send_speed;

  if (device_param)
  {
    device_param->brain_link_send_active = true;

    hc_timer_set (&link_speed->timer[link_speed->pos]);
  }

  ssize_t nsend = send (sockfd, buf, len, flags);

  if (device_param)
  {
    link_speed->bytes[link_speed->pos] = nsend;

    if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

    device_param->brain_link_send_bytes += nsend;
  }

  if (nsend <= 0) return false;

  if (status_ctx && status_ctx->run_thread_level1 == false) return false;

  while (nsend < (ssize_t) len)
  {
    char *buf_new = (char *) buf;

    if (device_param)
    {
      hc_timer_set (&link_speed->timer[link_speed->pos]);
    }

    ssize_t nsend_new = send (sockfd, buf_new + nsend, len - nsend, flags);

    if (device_param)
    {
      link_speed->bytes[link_speed->pos] = nsend_new;

      if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

      device_param->brain_link_send_bytes += nsend_new;
    }

    if (nsend_new <= 0) return false;

    if (status_ctx && status_ctx->run_thread_level1 == false) break;

    nsend += nsend_new;
  }

  if (device_param)
  {
    device_param->brain_link_send_active = false;
  }

  return true;
}

bool brain_recv_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  link_speed_t *link_speed = &device_param->brain_link_recv_speed;

  if (device_param)
  {
    device_param->brain_link_recv_active = true;

    hc_timer_set (&link_speed->timer[link_speed->pos]);
  }

  ssize_t nrecv = recv (sockfd, buf, len, flags);

  if (device_param)
  {
    link_speed->bytes[link_speed->pos] = nrecv;

    if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

    device_param->brain_link_recv_bytes += nrecv;
  }

  if (nrecv <= 0) return false;

  if (status_ctx && status_ctx->run_thread_level1 == false) return false;

  while (nrecv < (ssize_t) len)
  {
    char *buf_new = (char *) buf;

    if (device_param)
    {
      hc_timer_set (&link_speed->timer[link_speed->pos]);
    }

    ssize_t nrecv_new = recv (sockfd, buf_new + nrecv, len - nrecv, flags);

    if (device_param)
    {
      link_speed->bytes[link_speed->pos] = nrecv_new;

      if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

      device_param->brain_link_recv_bytes += nrecv_new;
    }

    if (nrecv_new <= 0) return false;

    if (status_ctx && status_ctx->run_thread_level1 == false) break;

    nrecv += nrecv_new;
  }

  if (device_param)
  {
    device_param->brain_link_recv_active = false;
  }

  return true;
}

bool brain_client_connect (hc_device_param_t *device_param, const status_ctx_t *status_ctx, const char *host, const int port, const char *password, u32 brain_session, u32 brain_attack, i64 passwords_max, u64 *highest)
{
  device_param->brain_link_client_fd   = 0;
  device_param->brain_link_recv_bytes  = 0;
  device_param->brain_link_send_bytes  = 0;
  device_param->brain_link_recv_active = false;
  device_param->brain_link_send_active = false;

  memset (&device_param->brain_link_recv_speed, 0, sizeof (link_speed_t));
  memset (&device_param->brain_link_send_speed, 0, sizeof (link_speed_t));

  const int brain_link_client_fd = socket (AF_INET, SOCK_STREAM, 0);

  if (brain_link_client_fd == -1)
  {
    brain_logging (stderr, 0, "socket: %s\n", strerror (errno));

    return false;
  }

  #if defined (__linux__)
  const int one = 1;

  if (setsockopt (brain_link_client_fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, 0, "setsockopt: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }
  #else

  #endif

  struct addrinfo hints;

  memset (&hints, 0, sizeof (hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[8];

  memset (port_str, 0, sizeof (port_str));

  snprintf (port_str, sizeof (port_str), "%i", port);

  const char *host_real = (host == NULL) ? "127.0.0.1" : host;

  bool connected = false;

  struct addrinfo *address_info;

  const int rc_getaddrinfo = getaddrinfo (host_real, port_str, &hints, &address_info);

  if (rc_getaddrinfo == 0)
  {
    struct addrinfo *address_info_ptr;

    for (address_info_ptr = address_info; address_info_ptr != NULL; address_info_ptr = address_info_ptr->ai_next)
    {
      if (brain_connect (brain_link_client_fd, address_info_ptr->ai_addr, address_info_ptr->ai_addrlen, BRAIN_CLIENT_CONNECT_TIMEOUT) == 0)
      {
        connected = true;

        break;
      }
    }

    freeaddrinfo (address_info);
  }
  else
  {
    brain_logging (stderr, 0, "%s: %s\n", host_real, gai_strerror (rc_getaddrinfo));

    close (brain_link_client_fd);

    return false;
  }

  if (connected == false)
  {
    close (brain_link_client_fd);

    return false;
  }

  device_param->brain_link_client_fd = brain_link_client_fd;

  u32 brain_link_version = BRAIN_LINK_VERSION_CUR;

  if (brain_send (brain_link_client_fd, &brain_link_version, sizeof (brain_link_version), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  u32 brain_link_version_ok = 0;

  if (brain_recv (brain_link_client_fd, &brain_link_version_ok, sizeof (brain_link_version_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  if (brain_link_version_ok == 0)
  {
    brain_logging (stderr, 0, "Invalid brain server version\n");

    close (brain_link_client_fd);

    return false;
  }

  u32 challenge = 0;

  if (brain_recv (brain_link_client_fd, &challenge, sizeof (challenge), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  u64 response = brain_auth_hash (challenge, password, strlen (password));

  if (brain_send (brain_link_client_fd, &response, sizeof (response), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  u32 password_ok = 0;

  if (brain_recv (brain_link_client_fd, &password_ok, sizeof (password_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  if (password_ok == 0)
  {
    brain_logging (stderr, 0, "Invalid brain server password\n");

    close (brain_link_client_fd);

    return false;
  }

  if (brain_send (brain_link_client_fd, &brain_session, sizeof (brain_session), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  if (brain_send (brain_link_client_fd, &brain_attack, sizeof (brain_attack), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  if (brain_send (brain_link_client_fd, &passwords_max, sizeof (passwords_max), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  if (brain_recv (brain_link_client_fd, highest, sizeof (u64), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));

    close (brain_link_client_fd);

    return false;
  }

  return true;
}

void brain_client_disconnect (hc_device_param_t *device_param)
{
  if (device_param->brain_link_client_fd > 2)
  {
    close (device_param->brain_link_client_fd);
  }

  device_param->brain_link_client_fd = -1;
}

bool brain_client_reserve (hc_device_param_t *device_param, const status_ctx_t *status_ctx, u64 words_off, u64 work, u64 *overlap)
{
  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  u8 operation = BRAIN_OPERATION_ATTACK_RESERVE;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &words_off, sizeof (words_off),          0, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &work,           sizeof (work),          0, device_param, status_ctx) == false) return false;

  if (brain_recv (brain_link_client_fd, overlap,          sizeof (u64),          0, device_param, status_ctx) == false) return false;

  return true;
}

bool brain_client_commit (hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  if (device_param->pws_cnt == 0) return true;

  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  u8 operation = BRAIN_OPERATION_COMMIT;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;

  return true;
}

bool brain_client_lookup (hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  if (device_param->pws_pre_cnt == 0) return true;

  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  char *recvbuf = (char *) device_param->brain_link_in_buf;
  char *sendbuf = (char *) device_param->brain_link_out_buf;

  int in_size  = 0;
  int out_size = device_param->pws_pre_cnt * BRAIN_HASH_SIZE;

  u8 operation = BRAIN_OPERATION_HASH_LOOKUP;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &out_size,   sizeof (out_size), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, sendbuf,              out_size, SEND_FLAGS, device_param, status_ctx) == false) return false;

  if (brain_recv (brain_link_client_fd, &in_size,     sizeof (in_size),          0, device_param, status_ctx) == false) return false;

  if (in_size > (int) device_param->size_brain_link_in) return false;

  if (brain_recv (brain_link_client_fd, recvbuf,      (size_t) in_size,          0, device_param, status_ctx) == false) return false;

  return true;
}

void brain_client_generate_hash (u64 *hash, const char *line_buf, const size_t line_len)
{
  const u64 seed = 0;

  hash[0] = XXH64 (line_buf, line_len, seed);
}

void brain_server_db_hash_init (brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session)
{
  brain_server_db_hash->brain_session = brain_session;

  brain_server_db_hash->hb           = 0;
  brain_server_db_hash->long_cnt     = 0;
  brain_server_db_hash->long_buf     = NULL;
  brain_server_db_hash->long_alloc   = 0;
  brain_server_db_hash->write_hashes = false;

  hc_thread_mutex_init (brain_server_db_hash->mux_hr);
  hc_thread_mutex_init (brain_server_db_hash->mux_hg);
}

bool brain_server_db_hash_realloc (brain_server_db_hash_t *brain_server_db_hash, const i64 new_long_cnt)
{
  if ((brain_server_db_hash->long_cnt + new_long_cnt) > brain_server_db_hash->long_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_long_cnt, (const u64) BRAIN_SERVER_REALLOC_HASH_SIZE) * BRAIN_SERVER_REALLOC_HASH_SIZE;

    brain_server_hash_long_t *long_buf = (brain_server_hash_long_t *) hcrealloc (brain_server_db_hash->long_buf, brain_server_db_hash->long_alloc * sizeof (brain_server_hash_long_t), realloc_size_total * sizeof (brain_server_hash_long_t));

    if (long_buf == NULL) return false;

    brain_server_db_hash->long_buf    = long_buf;
    brain_server_db_hash->long_alloc += realloc_size_total;
  }

  return true;
}

void brain_server_db_hash_free (brain_server_db_hash_t *brain_server_db_hash)
{
  hc_thread_mutex_delete (brain_server_db_hash->mux_hg);
  hc_thread_mutex_delete (brain_server_db_hash->mux_hr);

  hcfree (brain_server_db_hash->long_buf);

  brain_server_db_hash->hb            = 0;
  brain_server_db_hash->long_cnt      = 0;
  brain_server_db_hash->long_buf      = NULL;
  brain_server_db_hash->long_alloc    = 0;
  brain_server_db_hash->write_hashes  = false;
  brain_server_db_hash->brain_session = 0;
}

void brain_server_db_attack_init (brain_server_db_attack_t *brain_server_db_attack, const u32 brain_attack)
{
  brain_server_db_attack->brain_attack = brain_attack;

  brain_server_db_attack->ab            = 0;
  brain_server_db_attack->short_cnt     = 0;
  brain_server_db_attack->short_buf     = NULL;
  brain_server_db_attack->short_alloc   = 0;
  brain_server_db_attack->long_cnt      = 0;
  brain_server_db_attack->long_buf      = NULL;
  brain_server_db_attack->long_alloc    = 0;
  brain_server_db_attack->write_attacks = false;

  hc_thread_mutex_init (brain_server_db_attack->mux_ar);
  hc_thread_mutex_init (brain_server_db_attack->mux_ag);
}

bool brain_server_db_attack_realloc (brain_server_db_attack_t *brain_server_db_attack, const i64 new_long_cnt, const i64 new_short_cnt)
{
  if ((brain_server_db_attack->long_cnt + new_long_cnt) > brain_server_db_attack->long_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_long_cnt, (const u64) BRAIN_SERVER_REALLOC_ATTACK_SIZE) * BRAIN_SERVER_REALLOC_ATTACK_SIZE;

    brain_server_attack_long_t *long_buf = (brain_server_attack_long_t *) hcrealloc (brain_server_db_attack->long_buf, brain_server_db_attack->long_alloc * sizeof (brain_server_attack_long_t), realloc_size_total * sizeof (brain_server_attack_long_t));

    if (long_buf == NULL) return false;

    brain_server_db_attack->long_buf    = long_buf;
    brain_server_db_attack->long_alloc += realloc_size_total;
  }

  if ((brain_server_db_attack->short_cnt + new_short_cnt) > brain_server_db_attack->short_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_short_cnt, (const u64) BRAIN_SERVER_REALLOC_ATTACK_SIZE) * BRAIN_SERVER_REALLOC_ATTACK_SIZE;

    brain_server_attack_short_t *short_buf = (brain_server_attack_short_t *) hcrealloc (brain_server_db_attack->short_buf, brain_server_db_attack->short_alloc * sizeof (brain_server_attack_short_t), realloc_size_total * sizeof (brain_server_attack_short_t));

    if (short_buf == NULL) return false;

    brain_server_db_attack->short_buf    = short_buf;
    brain_server_db_attack->short_alloc += realloc_size_total;
  }

  return true;
}

void brain_server_db_attack_free (brain_server_db_attack_t *brain_server_db_attack)
{
  hc_thread_mutex_delete (brain_server_db_attack->mux_ag);
  hc_thread_mutex_delete (brain_server_db_attack->mux_ar);

  hcfree (brain_server_db_attack->long_buf);
  hcfree (brain_server_db_attack->short_buf);

  brain_server_db_attack->ab            = 0;
  brain_server_db_attack->long_cnt      = 0;
  brain_server_db_attack->long_buf      = NULL;
  brain_server_db_attack->long_alloc    = 0;
  brain_server_db_attack->short_cnt     = 0;
  brain_server_db_attack->short_buf     = NULL;
  brain_server_db_attack->short_alloc   = 0;
  brain_server_db_attack->brain_attack  = 0;
  brain_server_db_attack->write_attacks = false;
}

u64 brain_server_highest_attack (const brain_server_db_attack_t *buf)
{
  const brain_server_attack_long_t  *long_buf  = buf->long_buf;
  const brain_server_attack_short_t *short_buf = buf->short_buf;

  const u64 long_cnt  = buf->long_cnt;
  const u64 short_cnt = buf->short_cnt;

  u64 highest_long  = brain_server_highest_attack_long  (long_buf,  long_cnt,  0);
  u64 highest_short = brain_server_highest_attack_short (short_buf, short_cnt, 0);

  u64 highest = MAX (highest_long, highest_short);

  highest_long  = brain_server_highest_attack_long  (long_buf,  long_cnt,  highest);
  highest_short = brain_server_highest_attack_short (short_buf, short_cnt, highest);

  highest = MAX (highest_long, highest_short);

  return highest;
}

u64 brain_server_highest_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 start)
{
  u64 highest = start;

  for (i64 idx = 0; idx < cnt; idx++)
  {
    const u64 offset = buf[idx].offset;
    const u64 length = buf[idx].length;

    if (offset > highest) break;

    const u64 next = offset + length;

    highest = MAX (highest, next);
  }

  return highest;
}

u64 brain_server_highest_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 start)
{
  u64 highest = start;

  for (i64 idx = 0; idx < cnt; idx++)
  {
    const u64 offset = buf[idx].offset;
    const u64 length = buf[idx].length;

    if (offset > highest) break;

    const u64 next = offset + length;

    highest = MAX (highest, next);
  }

  return highest;
}

u64 brain_server_find_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  const u64 end = offset + length;

  u64 overlap = 0;

  for (i64 idx = 0; idx < cnt; idx++)
  {
    const u64 element_length = buf[idx].length;

    if (element_length == 0) continue;

    const u64 element_start = buf[idx].offset;
    const u64 element_end   = element_start + element_length;

    const u64 start = offset + overlap;

    if (element_start > start) break; // we can't ever do it since this list is sorted

    if (element_end > start)
    {
      const u64 limited_end = MIN (end, element_end);

      overlap += limited_end - start;

      if (overlap == length) break;
    }
  }

  return overlap;
}

u64 brain_server_find_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  const u64 end = offset + length;

  u64 overlap = 0;

  for (i64 idx = 0; idx < cnt; idx++)
  {
    const u64 element_length = buf[idx].length;

    if (element_length == 0) continue;

    const u64 element_start = buf[idx].offset;
    const u64 element_end   = element_start + element_length;

    const u64 start = offset + overlap;

    if (element_start > start) break; // we can't ever do it since this list is sorted

    if (element_end > start)
    {
      const u64 limited_end = MIN (end, element_end);

      overlap += limited_end - start;

      if (overlap == length) break;
    }
  }

  return overlap;
}

int brain_server_sort_db_hash (const void *v1, const void *v2)
{
  const brain_server_db_hash_t *d1 = (const brain_server_db_hash_t *) v1;
  const brain_server_db_hash_t *d2 = (const brain_server_db_hash_t *) v2;

  if (d1->brain_session > d2->brain_session) return  1;
  if (d1->brain_session < d2->brain_session) return -1;

  return 0;
}

int brain_server_sort_db_attack (const void *v1, const void *v2)
{
  const brain_server_db_attack_t *d1 = (const brain_server_db_attack_t *) v1;
  const brain_server_db_attack_t *d2 = (const brain_server_db_attack_t *) v2;

  if (d1->brain_attack > d2->brain_attack) return  1;
  if (d1->brain_attack < d2->brain_attack) return -1;

  return 0;
}

int brain_server_sort_hash (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  if (d1[1] > d2[1]) return  1;
  if (d1[1] < d2[1]) return -1;
  if (d1[0] > d2[0]) return  1;
  if (d1[0] < d2[0]) return -1;

  return 0;
}

int brain_server_sort_attack_long (const void *v1, const void *v2)
{
  const brain_server_attack_long_t *d1 = (const brain_server_attack_long_t *) v1;
  const brain_server_attack_long_t *d2 = (const brain_server_attack_long_t *) v2;

  if (d1->offset > d2->offset) return  1;
  if (d1->offset < d2->offset) return -1;

  return 0;
}

int brain_server_sort_attack_short (const void *v1, const void *v2)
{
  const brain_server_attack_short_t *d1 = (const brain_server_attack_short_t *) v1;
  const brain_server_attack_short_t *d2 = (const brain_server_attack_short_t *) v2;

  if (d1->offset > d2->offset) return  1;
  if (d1->offset < d2->offset) return -1;

  return 0;
}

int brain_server_sort_hash_long (const void *v1, const void *v2)
{
  const brain_server_hash_long_t *d1 = (const brain_server_hash_long_t *) v1;
  const brain_server_hash_long_t *d2 = (const brain_server_hash_long_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

int brain_server_sort_hash_short (const void *v1, const void *v2)
{
  const brain_server_hash_short_t *d1 = (const brain_server_hash_short_t *) v1;
  const brain_server_hash_short_t *d2 = (const brain_server_hash_short_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

int brain_server_sort_hash_unique (const void *v1, const void *v2)
{
  const brain_server_hash_unique_t *d1 = (const brain_server_hash_unique_t *) v1;
  const brain_server_hash_unique_t *d2 = (const brain_server_hash_unique_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

bool brain_server_read_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  brain_server_dbs->hash_cnt = 0;

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (chdir (path) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }
  */

  DIR *dirp = opendir (path);

  if (dirp == NULL)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }

  struct dirent *entry;

  while ((entry = readdir (dirp)) != NULL)
  {
    char *file = entry->d_name;

    const size_t len = strlen (file);

    if (len != 19) continue;

    if (file[ 0] != 'b') continue;
    if (file[ 1] != 'r') continue;
    if (file[ 2] != 'a') continue;
    if (file[ 3] != 'i') continue;
    if (file[ 4] != 'n') continue;
    if (file[ 5] != '.') continue;

    if (file[14] != '.') continue;
    if (file[15] != 'l') continue;
    if (file[16] != 'd') continue;
    if (file[17] != 'm') continue;
    if (file[18] != 'p') continue;

    const u32 brain_session = byte_swap_32 (hex_to_u32 ((const u8 *) file + 6));

    brain_server_db_hash_t *brain_server_db_hash = &brain_server_dbs->hash_buf[brain_server_dbs->hash_cnt];

    brain_server_db_hash_init (brain_server_db_hash, brain_session);

    if (brain_server_read_hash_dump (brain_server_db_hash, file) == false) continue;

    brain_server_dbs->hash_cnt++;
  }

  closedir (dirp);

  return true;
}

bool brain_server_write_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  for (i64 idx = 0; idx < brain_server_dbs->hash_cnt; idx++)
  {
    brain_server_db_hash_t *brain_server_db_hash = &brain_server_dbs->hash_buf[idx];

    hc_thread_mutex_lock (brain_server_db_hash->mux_hg);

    char file[100];

    memset (file, 0, sizeof (file));

    snprintf (file, sizeof (file), "%s/brain.%08x.ldmp", path, brain_server_db_hash->brain_session);

    brain_server_write_hash_dump (brain_server_db_hash, file);

    hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);
  }

  return true;
}

bool brain_server_read_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file)
{
  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // read from file

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  HCFILE fp;

  if (hc_fopen (&fp, file, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  i64 temp_cnt = (u64) sb.st_size / sizeof (brain_server_hash_long_t);

  if (brain_server_db_hash_realloc (brain_server_db_hash, temp_cnt) == false)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    hc_fclose (&fp);

    return false;
  }

  const size_t nread = hc_fread (brain_server_db_hash->long_buf, sizeof (brain_server_hash_long_t), temp_cnt, &fp);

  if (nread != (size_t) temp_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes read\n", file, (u64) nread * sizeof (brain_server_hash_long_t));

    hc_fclose (&fp);

    return false;
  }

  brain_server_db_hash->long_cnt     = temp_cnt;
  brain_server_db_hash->write_hashes = false;

  hc_fclose (&fp);

  const double ms = hc_timer_get (timer_dump);

  brain_logging (stdout, 0, "Read %" PRIu64 " bytes from session 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_hash->brain_session, ms);

  return true;
}

bool brain_server_write_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file)
{
  if (brain_server_db_hash->write_hashes == false) return true;

  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // write to file

  HCFILE fp;

  if (hc_fopen (&fp, file, "wb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  const size_t nwrite = hc_fwrite (brain_server_db_hash->long_buf, sizeof (brain_server_hash_long_t), brain_server_db_hash->long_cnt, &fp);

  if (nwrite != (size_t) brain_server_db_hash->long_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes written\n", file, (u64) nwrite * sizeof (brain_server_hash_long_t));

    hc_fclose (&fp);

    return false;
  }

  hc_fclose (&fp);

  brain_server_db_hash->write_hashes = false;

  // stats

  const double ms = hc_timer_get (timer_dump);

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  brain_logging (stdout, 0, "Wrote %" PRIu64 " bytes from session 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_hash->brain_session, ms);

  return true;
}

bool brain_server_read_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  brain_server_dbs->attack_cnt = 0;

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (chdir (path) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }
  */

  DIR *dirp = opendir (path);

  if (dirp == NULL)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }

  struct dirent *entry = NULL;

  while ((entry = readdir (dirp)) != NULL)
  {
    char *file = entry->d_name;

    const size_t len = strlen (file);

    if (len != 19) continue;

    if (file[ 0] != 'b') continue;
    if (file[ 1] != 'r') continue;
    if (file[ 2] != 'a') continue;
    if (file[ 3] != 'i') continue;
    if (file[ 4] != 'n') continue;
    if (file[ 5] != '.') continue;

    if (file[14] != '.') continue;
    if (file[15] != 'a') continue;
    if (file[16] != 'd') continue;
    if (file[17] != 'm') continue;
    if (file[18] != 'p') continue;

    const u32 brain_attack = byte_swap_32 (hex_to_u32 ((const u8 *) file + 6));

    brain_server_db_attack_t *brain_server_db_attack = &brain_server_dbs->attack_buf[brain_server_dbs->attack_cnt];

    brain_server_db_attack_init (brain_server_db_attack, brain_attack);

    if (brain_server_read_attack_dump (brain_server_db_attack, file) == false) continue;

    brain_server_dbs->attack_cnt++;
  }

  closedir (dirp);

  return true;
}

bool brain_server_write_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  for (i64 idx = 0; idx < brain_server_dbs->attack_cnt; idx++)
  {
    brain_server_db_attack_t *brain_server_db_attack = &brain_server_dbs->attack_buf[idx];

    hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

    char file[100];

    memset (file, 0, sizeof (file));

    snprintf (file, sizeof (file), "%s/brain.%08x.admp", path, brain_server_db_attack->brain_attack);

    brain_server_write_attack_dump (brain_server_db_attack, file);

    hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);
  }

  return true;
}

bool brain_server_read_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file)
{
  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // read from file

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  HCFILE fp;

  if (hc_fopen (&fp, file, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  i64 temp_cnt = (u64) sb.st_size / sizeof (brain_server_attack_long_t);

  if (brain_server_db_attack_realloc (brain_server_db_attack, temp_cnt, 0) == false)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    hc_fclose (&fp);

    return false;
  }

  const size_t nread = hc_fread (brain_server_db_attack->long_buf, sizeof (brain_server_attack_long_t), temp_cnt, &fp);

  if (nread != (size_t) temp_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes read\n", file, (u64) nread * sizeof (brain_server_attack_long_t));

    hc_fclose (&fp);

    return false;
  }

  brain_server_db_attack->long_cnt      = temp_cnt;
  brain_server_db_attack->write_attacks = false;

  hc_fclose (&fp);

  const double ms = hc_timer_get (timer_dump);

  brain_logging (stdout, 0, "Read %" PRIu64 " bytes from attack 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_attack->brain_attack, ms);

  return true;
}

bool brain_server_write_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file)
{
  if (brain_server_db_attack->write_attacks == false) return true;

  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // write to file

  HCFILE fp;

  if (hc_fopen (&fp, file, "wb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  // storing should not include reserved attacks only finished

  const size_t nwrite = hc_fwrite (brain_server_db_attack->long_buf, sizeof (brain_server_attack_long_t), brain_server_db_attack->long_cnt, &fp);

  if (nwrite != (size_t) brain_server_db_attack->long_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes written\n", file, (u64) nwrite * sizeof (brain_server_attack_long_t));

    hc_fclose (&fp);

    return false;
  }

  hc_fclose (&fp);

  brain_server_db_attack->write_attacks = false;

  // stats

  const double ms = hc_timer_get (timer_dump);

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  brain_logging (stdout, 0, "Wrote %" PRIu64 " bytes from attack 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_attack->brain_attack, ms);

  return true;
}

int brain_server_get_client_idx (brain_server_dbs_t *brain_server_dbs)
{
  for (int i = 1; i < BRAIN_SERVER_CLIENTS_MAX; i++)
  {
    if (brain_server_dbs->client_slots[i] == 0)
    {
      brain_server_dbs->client_slots[i] = 1;

      return i;
    }
  }

  return -1;
}

i64 brain_server_find_hash_long (const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt)
{
  for (i64 l = 0, r = cnt; r; r >>= 1)
  {
    const i64 m = r >> 1;
    const i64 c = l + m;

    const int cmp = brain_server_sort_hash_long (search, buf + c);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return c;
  }

  return -1;
}

i64 brain_server_find_hash_short (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt)
{
  for (i64 l = 0, r = cnt; r; r >>= 1)
  {
    const i64 m = r >> 1;
    const i64 c = l + m;

    const int cmp = brain_server_sort_hash_short (search, buf + c);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return c;
  }

  return -1;
}

void brain_server_handle_signal (int signo)
{
  if (signo == SIGINT)
  {
    keep_running = false;
  }
}

void *brain_server_handle_dumps (void *p)
{
  brain_server_dumper_options_t *brain_server_dumper_options = (brain_server_dumper_options_t *) p;

  brain_server_dbs_t *brain_server_dbs = brain_server_dumper_options->brain_server_dbs;

  u32 brain_server_timer = brain_server_dumper_options->brain_server_timer;

  if (brain_server_timer == 0) return NULL;

  u32 i = 0;

  while (keep_running == true)
  {
    if (i == brain_server_timer)
    {
      brain_server_write_hash_dumps   (brain_server_dbs, ".");
      brain_server_write_attack_dumps (brain_server_dbs, ".");

      i = 0;
    }
    else
    {
      i++;
    }

    sleep (1);
  }

  return NULL;
}

void *brain_server_handle_client (void *p)
{
  brain_server_client_options_t *brain_server_client_options = (brain_server_client_options_t *) p;

  const int   client_idx            = brain_server_client_options->client_idx;
  const int   client_fd             = brain_server_client_options->client_fd;
  const char *auth_password         = brain_server_client_options->auth_password;
  const u32  *session_whitelist_buf = brain_server_client_options->session_whitelist_buf;
  const int   session_whitelist_cnt = brain_server_client_options->session_whitelist_cnt;

  brain_server_dbs_t *brain_server_dbs = brain_server_client_options->brain_server_dbs;

  // client configuration

  #if defined (__linux__)
  const int one = 1;

  if (setsockopt (client_fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, client_idx, "setsockopt: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }
  #else

  #endif

  u32 brain_link_version = 0;

  if (brain_recv (client_fd, &brain_link_version, sizeof (brain_link_version), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 brain_link_version_ok = (brain_link_version >= (u32) BRAIN_LINK_VERSION_MIN) ? 1 : 0;

  if (brain_send (client_fd, &brain_link_version_ok, sizeof (brain_link_version_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (brain_link_version_ok == 0)
  {
    brain_logging (stderr, client_idx, "Invalid version\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 challenge = brain_auth_challenge ();

  if (brain_send (client_fd, &challenge, sizeof (challenge), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u64 response = 0;

  if (brain_recv (client_fd, &response, sizeof (response), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u64 auth_hash = brain_auth_hash (challenge, auth_password, strlen (auth_password));

  u32 password_ok = (auth_hash == response) ? 1 : 0;

  if (brain_send (client_fd, &password_ok, sizeof (password_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (password_ok == 0)
  {
    brain_logging (stderr, client_idx, "Invalid password\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 brain_session = 0;

  if (brain_recv (client_fd, &brain_session, sizeof (brain_session), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (session_whitelist_cnt > 0)
  {
    bool found = false;

    for (int idx = 0; idx < session_whitelist_cnt; idx++)
    {
      if (session_whitelist_buf[idx] == brain_session)
      {
        found = true;

        break;
      }
    }

    if (found == false)
    {
      brain_logging (stderr, client_idx, "Invalid brain session: 0x%08x\n", brain_session);

      brain_server_dbs->client_slots[client_idx] = 0;

      close (client_fd);

      return NULL;
    }
  }

  u32 brain_attack = 0;

  if (brain_recv (client_fd, &brain_attack, sizeof (brain_attack), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  i64 passwords_max = 0;

  if (brain_recv (client_fd, &passwords_max, sizeof (passwords_max), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (passwords_max >= BRAIN_LINK_CANDIDATES_MAX)
  {
    brain_logging (stderr, client_idx, "Too large candidate allocation buffer size\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  brain_logging (stdout, client_idx, "Session: 0x%08x, Attack: 0x%08x, Kernel-power: %" PRIu64 "\n", brain_session, brain_attack, passwords_max);

  // so far so good

  hc_thread_mutex_lock (brain_server_dbs->mux_dbs);

  // long term memory

  brain_server_db_hash_t key_hash;

  key_hash.brain_session = brain_session;

  #if defined (_WIN)
  unsigned int find_hash_cnt = (unsigned int) brain_server_dbs->hash_cnt;
  #else
  size_t find_hash_cnt = (size_t) brain_server_dbs->hash_cnt;
  #endif

  brain_server_db_hash_t *brain_server_db_hash = (brain_server_db_hash_t *) lfind (&key_hash, brain_server_dbs->hash_buf, &find_hash_cnt, sizeof (brain_server_db_hash_t), brain_server_sort_db_hash);

  if (brain_server_db_hash == NULL)
  {
    if (brain_server_dbs->hash_cnt >= BRAIN_SERVER_SESSIONS_MAX)
    {
      brain_logging (stderr, 0, "too many sessions\n");

      brain_server_dbs->client_slots[client_idx] = 0;

      hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

      close (client_fd);

      return NULL;
    }

    brain_server_db_hash = &brain_server_dbs->hash_buf[brain_server_dbs->hash_cnt];

    brain_server_db_hash_init (brain_server_db_hash, brain_session);

    brain_server_dbs->hash_cnt++;
  }

  // attack memory

  brain_server_db_attack_t key_attack;

  key_attack.brain_attack = brain_attack;

  #if defined (_WIN)
  unsigned int find_attack_cnt = (unsigned int) brain_server_dbs->attack_cnt;
  #else
  size_t find_attack_cnt = (size_t) brain_server_dbs->attack_cnt;
  #endif

  brain_server_db_attack_t *brain_server_db_attack = (brain_server_db_attack_t *) lfind (&key_attack, brain_server_dbs->attack_buf, &find_attack_cnt, sizeof (brain_server_db_attack_t), brain_server_sort_db_attack);

  if (brain_server_db_attack == NULL)
  {
    if (brain_server_dbs->attack_cnt >= BRAIN_SERVER_ATTACKS_MAX)
    {
      brain_logging (stderr, 0, "too many attacks\n");

      brain_server_dbs->client_slots[client_idx] = 0;

      hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

      close (client_fd);

      return NULL;
    }

    brain_server_db_attack = &brain_server_dbs->attack_buf[brain_server_dbs->attack_cnt];

    brain_server_db_attack_init (brain_server_db_attack, brain_attack);

    brain_server_dbs->attack_cnt++;
  }

  hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

  // higest position of that attack

  u64 highest = brain_server_highest_attack (brain_server_db_attack);

  if (brain_send (client_fd, &highest, sizeof (highest), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // recv

  const size_t recv_size = passwords_max * BRAIN_HASH_SIZE;

  u32 *recv_buf = (u32 *) hcmalloc (recv_size);

  if (recv_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // send

  const size_t send_size = passwords_max * sizeof (char);

  u8 *send_buf = (u8  *) hcmalloc (send_size); // we can reduce this to 1/8 if we use bits instead of bytes

  if (send_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // temp

  brain_server_hash_unique_t *temp_buf = (brain_server_hash_unique_t *) hccalloc (passwords_max, sizeof (brain_server_hash_unique_t));

  if (temp_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // short global alloc

  brain_server_db_short_t *brain_server_db_short = (brain_server_db_short_t *) hcmalloc (sizeof (brain_server_db_short_t));

  brain_server_db_short->short_cnt = 0;
  brain_server_db_short->short_buf = (brain_server_hash_short_t *) hccalloc (passwords_max, sizeof (brain_server_hash_short_t));

  if (brain_server_db_short->short_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // main loop

  while (keep_running == true)
  {
    // wait for client to send data, but not too long

    const int rc_select = select_read_timeout (client_fd, 1);

    if (rc_select == -1) break;

    if (rc_select == 0) continue;

    // there's data

    u8 operation = 0;

    if (brain_recv (client_fd, &operation, sizeof (operation), 0, NULL, NULL) == false) break;

    // U = update
    // R = request
    // C = commit

    /**
     * L = lookup
     *
     * In this section the client sends a number of password hashes (max = passwords_max).
     * The goal is to check them against the long-term memory
     * to find out if the password is either reserved by any client (can be the same, too)
     * or if it was already checked in the past and then to send a reject.
     * This is a complicated process as we have to deal with lots of duplicate data
     * and with lots of clients both at the same time.
     * We also have to be very fast in looking up the information otherwise the clients
     * lose too much performance.
     * Once a client sends a commit message, all short-term data related to the client
     * is moved to the long-term memory.
     * To do that in the commit section, we're storing each hash in the short-term memory
     * along with client_fd.
     * The short-term memory itself is limited in size. That's possible because each client
     * tells the server in the handshake the maximum number of passwords it will send
     * before it will either disconnect or send a commit signal.
     * The first procedure for each package of hashes sent by the client is to sort them.
     * This is done in the client thread and without any mutex barriers, therefore the server
     * is able to use multiple threads for this action.
     * This is the only time in the entire process when data is being sorted because
     * of a smart way of using the data in the following process up to
     * and later even in the commit process.
     * We need to make sure that a hash which is stored in the short-term memory is not
     * already in both the short-term and the long-term memory otherwise we end up in a
     * corrupted database.
     * Therefor, as a first step after the data has been sorted, we need to remove all duplicates.
     * Such duplicates can occur easily in hashcat, for example if hashcat uses a 's' rule.
     * If such a 's' rule searches for a character which does not exist in the base word
     * the password is not changed.
     * If we have multiple of such rules we create lots of duplicates.
     * As to this point there was no need to use any mutex.
     * But from now on we need a mutex because we will access two shared memory regions
     * which both can be written to from any other client.
     * We'll check the both databases and remove any existing hashes before the go into
     * the short-term memory but at the same time, update the send[] buffer in case we
     * need to reject the hash.
     * This is possible because along with the hash, we also keep track of its original position
     * in the client stream.
     * No we ne'll add the remaining hashes to the short-term memory.
     * This process needs no additional sorting, but we need to update the hashes
     * at the correct position because this is important for the binary tree search.
     * So we can not simply append it to the end.
     * We do not need to care about the short-term memory size because it was preallocated
     * and it is safe the client does not send more hashes that max_passwords.
     * The trick here is, since all data at this point is sorted, to merge them in a reverse order.
     * Using the reverse order allows us to reuse the existing memory, we do not need to
     * have two buffer allocated. This is more important to the long-term memory which is
     * using the same technique but has an always growing size.
     * Basically what we do is that we will use the hashes of the current one of the new hash array
     * and the current one of the short-term memory as a representation of a pure number.
     * We take the larger on (a comparison can always be only smaller or larger, not equal)
     * and store it at the highest array index. We repeat this process till both buffers
     * have iterate through all of their elements.
     * It's like a broken zipper.
     */

    if (operation == BRAIN_OPERATION_ATTACK_RESERVE)
    {
      u64 offset = 0;
      u64 length = 0;

      if (brain_recv (client_fd, &offset, sizeof (offset), 0, NULL, NULL) == false) break;
      if (brain_recv (client_fd, &length, sizeof (length), 0, NULL, NULL) == false) break;

      // time the lookups for debugging

      hc_timer_t timer_reserved;

      hc_timer_set (&timer_reserved);

      hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

      u64 overlap = 0;

      overlap += brain_server_find_attack_short (brain_server_db_attack->short_buf, brain_server_db_attack->short_cnt, offset, length);
      overlap += brain_server_find_attack_long  (brain_server_db_attack->long_buf,  brain_server_db_attack->long_cnt,  offset + overlap, length - overlap);

      if (overlap < length)
      {
        if (brain_server_db_attack_realloc (brain_server_db_attack, 0, 1) == true)
        {
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].offset     = offset + overlap;
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].length     = length - overlap;
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].client_idx = client_idx;

          brain_server_db_attack->short_cnt++;

          qsort (brain_server_db_attack->short_buf, brain_server_db_attack->short_cnt, sizeof (brain_server_attack_short_t), brain_server_sort_attack_short);
        }
      }

      hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

      if (brain_send (client_fd, &overlap, sizeof (overlap), SEND_FLAGS, NULL, NULL) == false) break;

      const double ms = hc_timer_get (timer_reserved);

      brain_logging (stdout, client_idx, "R | %8.2f ms | Offset: %" PRIu64 ", Length: %" PRIu64 ", Overlap: %" PRIu64 "\n", ms, offset, length, overlap);
    }
    else if (operation == BRAIN_OPERATION_COMMIT)
    {
      // time the lookups for debugging

      hc_timer_t timer_commit;

      hc_timer_set (&timer_commit);

      hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

      i64 new_attacks = 0;

      for (i64 idx = 0; idx < brain_server_db_attack->short_cnt; idx++)
      {
        if (brain_server_db_attack->short_buf[idx].client_idx == client_idx)
        {
          if (brain_server_db_attack_realloc (brain_server_db_attack, 1, 0) == true)
          {
            brain_server_db_attack->long_buf[brain_server_db_attack->long_cnt].offset = brain_server_db_attack->short_buf[idx].offset;
            brain_server_db_attack->long_buf[brain_server_db_attack->long_cnt].length = brain_server_db_attack->short_buf[idx].length;

            brain_server_db_attack->long_cnt++;

            qsort (brain_server_db_attack->long_buf, brain_server_db_attack->long_cnt, sizeof (brain_server_attack_long_t), brain_server_sort_attack_long);
          }
          else
          {
            brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);
          }

          brain_server_db_attack->short_buf[idx].offset     = 0;
          brain_server_db_attack->short_buf[idx].length     = 0;
          brain_server_db_attack->short_buf[idx].client_idx = 0;

          new_attacks++;
        }
      }

      brain_server_db_attack->write_attacks = true;

      hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

      if (new_attacks)
      {
        const double ms_attacks = hc_timer_get (timer_commit);

        brain_logging (stdout, client_idx, "C | %8.2f ms | Attacks: %" PRIi64 "\n", ms_attacks, new_attacks);
      }

      // time the lookups for debugging

      hc_timer_set (&timer_commit);

      hc_thread_mutex_lock (brain_server_db_hash->mux_hg);

      // long-term memory merge

      if (brain_server_db_short->short_cnt)
      {
        if (brain_server_db_hash_realloc (brain_server_db_hash, brain_server_db_short->short_cnt) == true)
        {
          if (brain_server_db_hash->long_cnt == 0)
          {
            for (i64 idx = 0; idx < brain_server_db_short->short_cnt; idx++)
            {
              brain_server_db_hash->long_buf[idx].hash[0] = brain_server_db_short->short_buf[idx].hash[0];
              brain_server_db_hash->long_buf[idx].hash[1] = brain_server_db_short->short_buf[idx].hash[1];
            }

            brain_server_db_hash->long_cnt = brain_server_db_short->short_cnt;
          }
          else
          {
            const i64 cnt_total = brain_server_db_hash->long_cnt + brain_server_db_short->short_cnt;

            i64 long_left  = brain_server_db_hash->long_cnt - 1;
            i64 short_left = brain_server_db_short->short_cnt - 1;
            i64 long_dupes = 0;

            for (i64 idx = cnt_total - 1; idx >= long_dupes; idx--)
            {
              const brain_server_hash_long_t  *long_entry  = &brain_server_db_hash->long_buf[long_left];
              const brain_server_hash_short_t *short_entry = &brain_server_db_short->short_buf[short_left];

              int rc = 0;

              if ((long_left >= 0) && (short_left >= 0))
              {
                rc = brain_server_sort_hash (long_entry->hash, short_entry->hash);
              }
              else if (long_left >= 0)
              {
                rc = 1;
              }
              else if (short_left >= 0)
              {
                rc = -1;
              }
              else
              {
                brain_logging (stderr, client_idx, "unexpected remaining buffers in compare: %" PRIi64 " - %" PRIi64 "\n", long_left, short_left);
              }

              brain_server_hash_long_t *next = &brain_server_db_hash->long_buf[idx];

              if (rc == -1)
              {
                next->hash[0] = short_entry->hash[0];
                next->hash[1] = short_entry->hash[1];

                short_left--;
              }
              else if (rc == 1)
              {
                next->hash[0] = long_entry->hash[0];
                next->hash[1] = long_entry->hash[1];

                long_left--;
              }
              else
              {
                next->hash[0] = long_entry->hash[0];
                next->hash[1] = long_entry->hash[1];

                short_left--;
                long_left--;

                long_dupes++;
              }
            }

            if ((long_left != -1) || (short_left != -1))
            {
              brain_logging (stderr, client_idx, "unexpected remaining buffers in commit: %" PRIi64 " - %" PRIi64 "\n", long_left, short_left);
            }

            brain_server_db_hash->long_cnt = cnt_total - long_dupes;

            if (long_dupes)
            {
              for (i64 idx = 0; idx < brain_server_db_hash->long_cnt; idx++)
              {
                brain_server_db_hash->long_buf[idx].hash[0] = brain_server_db_hash->long_buf[long_dupes + idx].hash[0];
                brain_server_db_hash->long_buf[idx].hash[1] = brain_server_db_hash->long_buf[long_dupes + idx].hash[1];
              }
            }
          }
        }
        else
        {
          brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);
        }

        brain_server_db_hash->write_hashes = true;
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);

      if (brain_server_db_short->short_cnt)
      {
        const double ms_hashes = hc_timer_get (timer_commit);

        brain_logging (stdout, client_idx, "C | %8.2f ms | Hashes: %" PRIi64 "\n", ms_hashes, brain_server_db_short->short_cnt);
      }

      brain_server_db_short->short_cnt = 0;
    }
    else if (operation == BRAIN_OPERATION_HASH_LOOKUP)
    {
      int in_size = 0;

      if (brain_recv (client_fd, &in_size, sizeof (in_size), 0, NULL, NULL) == false) break;

      if (in_size == 0)
      {
        brain_logging (stderr, client_idx, "Zero in_size value\n");

        break;
      }

      if (in_size > (int) recv_size) break;

      if (brain_recv (client_fd, recv_buf, (size_t) in_size, 0, NULL, NULL) == false) break;

      const int hashes_cnt = in_size / BRAIN_HASH_SIZE;

      if (hashes_cnt == 0)
      {
        brain_logging (stderr, client_idx, "Zero passwords\n");

        break;
      }

      if ((brain_server_db_short->short_cnt + hashes_cnt) > passwords_max)
      {
        brain_logging (stderr, client_idx, "Too many passwords\n");

        break;
      }

      // time the lookups for debugging

      hc_timer_t timer_lookup;

      hc_timer_set (&timer_lookup);

      // make it easier to work with

      for (int hash_idx = 0, recv_idx = 0; hash_idx < hashes_cnt; hash_idx += 1, recv_idx += 2)
      {
        temp_buf[hash_idx].hash[0] = recv_buf[recv_idx + 0];
        temp_buf[hash_idx].hash[1] = recv_buf[recv_idx + 1];

        temp_buf[hash_idx].hash_idx = hash_idx;

        send_buf[hash_idx] = 0;
      }

      // unique temp memory

      i64 temp_cnt = 0;

      qsort (temp_buf, hashes_cnt, sizeof (brain_server_hash_unique_t), brain_server_sort_hash_unique);

      brain_server_hash_unique_t *prev = temp_buf + temp_cnt;

      for (i64 temp_idx = 1; temp_idx < hashes_cnt; temp_idx++)
      {
        brain_server_hash_unique_t *cur = temp_buf + temp_idx;

        if ((cur->hash[0] == prev->hash[0]) && (cur->hash[1] == prev->hash[1]))
        {
          send_buf[cur->hash_idx] = 1;
        }
        else
        {
          temp_cnt++;

          prev = temp_buf + temp_cnt;

          prev->hash[0] = cur->hash[0];
          prev->hash[1] = cur->hash[1];

          prev->hash_idx = cur->hash_idx; // we need this in a later stage
        }
      }

      temp_cnt++;

      // check if they are in long term memory

      hc_thread_mutex_lock (brain_server_db_hash->mux_hr);

      brain_server_db_hash->hb++;

      if (brain_server_db_hash->hb == 1)
      {
        hc_thread_mutex_lock (brain_server_db_hash->mux_hg);
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hr);

      if (temp_cnt > 0)
      {
        i64 temp_idx_new = 0;

        for (i64 temp_idx = 0; temp_idx < temp_cnt; temp_idx++)
        {
          brain_server_hash_unique_t *cur = &temp_buf[temp_idx];

          const i64 r = brain_server_find_hash_long (cur->hash, brain_server_db_hash->long_buf, brain_server_db_hash->long_cnt);

          if (r != -1)
          {
            send_buf[cur->hash_idx] = 1;
          }
          else
          {
            brain_server_hash_unique_t *save = temp_buf + temp_idx_new;

            temp_idx_new++;

            save->hash[0] = cur->hash[0];
            save->hash[1] = cur->hash[1];

            save->hash_idx = cur->hash_idx; // we need this in a later stage
          }
        }

        temp_cnt = temp_idx_new;
      }

      hc_thread_mutex_lock (brain_server_db_hash->mux_hr);

      brain_server_db_hash->hb--;

      if (brain_server_db_hash->hb == 0)
      {
        hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hr);

      // check if they are in short term memory

      if (temp_cnt > 0)
      {
        i64 temp_idx_new = 0;

        for (i64 temp_idx = 0; temp_idx < temp_cnt; temp_idx++)
        {
          brain_server_hash_unique_t *cur = &temp_buf[temp_idx];

          const i64 r = brain_server_find_hash_short (cur->hash, brain_server_db_short->short_buf, brain_server_db_short->short_cnt);

          if (r != -1)
          {
            send_buf[cur->hash_idx] = 1;
          }
          else
          {
            brain_server_hash_unique_t *save = temp_buf + temp_idx_new;

            temp_idx_new++;

            save->hash[0] = cur->hash[0];
            save->hash[1] = cur->hash[1];

            save->hash_idx = cur->hash_idx; // we need this in a later stage
          }
        }

        temp_cnt = temp_idx_new;
      }

      // update remaining

      if (temp_cnt > 0)
      {
        if (brain_server_db_short->short_cnt == 0)
        {
          for (i64 idx = 0; idx < temp_cnt; idx++)
          {
            brain_server_db_short->short_buf[idx].hash[0] = temp_buf[idx].hash[0];
            brain_server_db_short->short_buf[idx].hash[1] = temp_buf[idx].hash[1];
          }

          brain_server_db_short->short_cnt = temp_cnt;
        }
        else
        {
          const i64 cnt_total = brain_server_db_short->short_cnt + temp_cnt;

          i64 short_left  = brain_server_db_short->short_cnt - 1;
          i64 unique_left = temp_cnt - 1;

          for (i64 idx = cnt_total - 1; idx >= 0; idx--)
          {
            const brain_server_hash_short_t  *short_entry  = brain_server_db_short->short_buf + short_left;
            const brain_server_hash_unique_t *unique_entry = temp_buf + unique_left;

            int rc = 0;

            if ((short_left >= 0) && (unique_left >= 0))
            {
              rc = brain_server_sort_hash (short_entry->hash, unique_entry->hash);
            }
            else if (short_left >= 0)
            {
              rc = 1;
            }
            else if (unique_left >= 0)
            {
              rc = -1;
            }
            else
            {
              brain_logging (stderr, client_idx, "unexpected remaining buffers in compare: %" PRIi64 " - %" PRIi64 "\n", short_left, unique_left);
            }

            brain_server_hash_short_t *next = brain_server_db_short->short_buf + idx;

            if (rc == -1)
            {
              next->hash[0] = unique_entry->hash[0];
              next->hash[1] = unique_entry->hash[1];

              unique_left--;
            }
            else if (rc == 1)
            {
              next->hash[0] = short_entry->hash[0];
              next->hash[1] = short_entry->hash[1];

              short_left--;
            }
            else
            {
              brain_logging (stderr, client_idx, "unexpected zero comparison in commit\n");
            }
          }

          if ((short_left != -1) || (unique_left != -1))
          {
            brain_logging (stderr, client_idx, "unexpected remaining buffers in commit: %" PRIi64 " - %" PRIi64 "\n", short_left, unique_left);
          }

          brain_server_db_short->short_cnt = cnt_total;
        }
      }

      // opportunity to set counters for stats

      int local_lookup_new = 0;

      for (i64 hashes_idx = 0; hashes_idx < hashes_cnt; hashes_idx++)
      {
        if (send_buf[hashes_idx] == 0)
        {
          local_lookup_new++;
        }
      }

      // needs anti-flood fix

      const double ms = hc_timer_get (timer_lookup);

      brain_logging (stdout, client_idx, "L | %8.2f ms | Long: %" PRIi64 ", Inc: %d, New: %d\n", ms, brain_server_db_hash->long_cnt, hashes_cnt, local_lookup_new);

      // send

      int out_size = hashes_cnt;

      if (brain_send (client_fd, &out_size, sizeof (out_size), SEND_FLAGS, NULL, NULL) == false) break;
      if (brain_send (client_fd, send_buf,           out_size, SEND_FLAGS, NULL, NULL) == false) break;
    }
    else
    {
      break;
    }
  }

  // client reservations

  hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

  for (i64 idx = 0; idx < brain_server_db_attack->short_cnt; idx++)
  {
    if (brain_server_db_attack->short_buf[idx].client_idx == client_idx)
    {
      brain_server_db_attack->short_buf[idx].offset     = 0;
      brain_server_db_attack->short_buf[idx].length     = 0;
      brain_server_db_attack->short_buf[idx].client_idx = 0;
    }
  }

  hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

  // short free

  hcfree (brain_server_db_short->short_buf);
  hcfree (brain_server_db_short);

  // free local memory

  hcfree (send_buf);
  hcfree (temp_buf);
  hcfree (recv_buf);

  brain_logging (stdout, client_idx, "Disconnected\n");

  brain_server_dbs->client_slots[client_idx] = 0;

  close (client_fd);

  return NULL;
}

int brain_server (const char *listen_host, const int listen_port, const char *brain_password, const char *brain_session_whitelist, const u32 brain_server_timer)
{
  #if defined (_WIN)
  WSADATA wsaData;

  WORD wVersionRequested = MAKEWORD (2,2);

  if (WSAStartup (wVersionRequested, &wsaData) != NO_ERROR)
  {
    fprintf (stderr, "WSAStartup: %s\n", strerror (errno));

    return -1;
  }
  #endif

  hc_timer_set (&timer_logging);

  hc_thread_mutex_init (mux_display);

  // generate random brain password if not specified by user

  char *auth_password = NULL;

  if (brain_password == NULL)
  {
    #define BRAIN_PASSWORD_SZ 20

    auth_password = (char *) hcmalloc (BRAIN_PASSWORD_SZ);

    snprintf (auth_password, BRAIN_PASSWORD_SZ, "%08x%08x", brain_auth_challenge (), brain_auth_challenge ());

    brain_logging (stdout, 0, "Generated authentication password: %s\n", auth_password);
  }
  else
  {
    auth_password = (char *) brain_password;
  }

  // socket stuff

  const int server_fd = socket (AF_INET, SOCK_STREAM, 0);

  if (server_fd == -1)
  {
    brain_logging (stderr, 0, "socket: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  #if defined (__linux__)
  const int one = 1;

  if (setsockopt (server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, 0, "setsockopt: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  if (setsockopt (server_fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, 0, "setsockopt: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }
  #else

  #endif

  struct sockaddr_in sa;

  memset (&sa, 0, sizeof (sa));

  size_t salen = sizeof (sa);

  sa.sin_family = AF_INET;
  sa.sin_port = htons (listen_port);
  sa.sin_addr.s_addr = INADDR_ANY;

  if (listen_host)
  {
    struct addrinfo hints;

    memset (&hints, 0, sizeof (hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *address_info = NULL;

    const int rc_getaddrinfo = getaddrinfo (listen_host, NULL, &hints, &address_info);

    if (rc_getaddrinfo == 0)
    {
      struct sockaddr_in *tmp = (struct sockaddr_in *) address_info->ai_addr;

      sa.sin_addr.s_addr = tmp->sin_addr.s_addr;

      freeaddrinfo (address_info);
    }
    else
    {
      brain_logging (stderr, 0, "%s: %s\n", listen_host, gai_strerror (rc_getaddrinfo));

      if (brain_password == NULL) hcfree (auth_password);

      return -1;
    }
  }

  if (bind (server_fd, (struct sockaddr *) &sa, salen) == -1)
  {
    brain_logging (stderr, 0, "bind: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  if (listen (server_fd, 5) == -1)
  {
    brain_logging (stderr, 0, "listen: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  brain_server_dbs_t *brain_server_dbs = (brain_server_dbs_t *) hcmalloc (sizeof (brain_server_dbs_t));

  if (brain_server_dbs == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  hc_thread_mutex_init (brain_server_dbs->mux_dbs);

  brain_server_dbs->hash_buf = (brain_server_db_hash_t *) hccalloc (BRAIN_SERVER_SESSIONS_MAX, sizeof (brain_server_db_hash_t));
  brain_server_dbs->hash_cnt = 0;

  if (brain_server_dbs->hash_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  if (brain_server_read_hash_dumps (brain_server_dbs, ".") == false)
  {
    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  brain_server_dbs->attack_buf = (brain_server_db_attack_t *) hccalloc (BRAIN_SERVER_ATTACKS_MAX, sizeof (brain_server_db_attack_t));
  brain_server_dbs->attack_cnt = 0;

  if (brain_server_dbs->attack_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  if (brain_server_read_attack_dumps (brain_server_dbs, ".") == false)
  {
    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  brain_server_dbs->client_slots = (int *) hccalloc (BRAIN_SERVER_CLIENTS_MAX, sizeof (int));

  if (brain_server_dbs->client_slots == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  // session whitelists

  u32 *session_whitelist_buf = (u32 *) hccalloc (BRAIN_SERVER_SESSIONS_MAX, sizeof (u32));
  int  session_whitelist_cnt = 0;

  if (brain_session_whitelist != NULL)
  {
    char *sessions = hcstrdup (brain_session_whitelist);

    if (sessions == NULL)
    {
      brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

      if (brain_password == NULL) hcfree (auth_password);

      return -1;
    }

    char *saveptr = NULL;

    char *next = strtok_r (sessions, ",", &saveptr);

    do
    {
      const int session = (const int) hc_strtoul (next, NULL, 16);

      session_whitelist_buf[session_whitelist_cnt] = session;

      session_whitelist_cnt++;

    } while ((next = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

    hcfree (sessions);
  }

  // client options

  brain_server_client_options_t *brain_server_client_options = (brain_server_client_options_t *) hccalloc (BRAIN_SERVER_CLIENTS_MAX, sizeof (brain_server_client_options_t));

  if (brain_server_client_options == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  for (int client_idx = 0; client_idx < BRAIN_SERVER_CLIENTS_MAX; client_idx++)
  {
    // none of these value change

    brain_server_client_options[client_idx].client_idx            = client_idx;
    brain_server_client_options[client_idx].auth_password         = auth_password;
    brain_server_client_options[client_idx].brain_server_dbs      = brain_server_dbs;
    brain_server_client_options[client_idx].session_whitelist_buf = session_whitelist_buf;
    brain_server_client_options[client_idx].session_whitelist_cnt = session_whitelist_cnt;
  }

  // ready to serve

  brain_logging (stdout, 0, "Brain server started\n");

  if (signal (SIGINT, brain_server_handle_signal) == SIG_ERR)
  {
    brain_logging (stderr, 0, "signal: %s\n", strerror (errno));

    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  brain_server_dumper_options_t brain_server_dumper_options;

  brain_server_dumper_options.brain_server_dbs   = brain_server_dbs;
  brain_server_dumper_options.brain_server_timer = brain_server_timer;

  hc_thread_t dump_thr;

  hc_thread_create (dump_thr, brain_server_handle_dumps, &brain_server_dumper_options);

  while (keep_running == true)
  {
    // wait for a client to connect, but not too long

    const int rc_select = select_read_timeout (server_fd, 1);

    if (rc_select == -1)
    {
      keep_running = false;

      break;
    }

    if (rc_select == 0) continue;

    // there's a client!

    struct sockaddr_in ca;

    memset (&ca, 0, sizeof (ca));

    size_t calen = sizeof (ca);

    const int client_fd = accept (server_fd, (struct sockaddr *) &ca, (socklen_t *) &calen);

    brain_logging (stdout, 0, "Connection from %s:%d\n", inet_ntoa (ca.sin_addr), ntohs (ca.sin_port));

    const int client_idx = brain_server_get_client_idx (brain_server_dbs);

    if (client_idx == -1)
    {
      brain_logging (stderr, client_idx, "Too many clients\n");

      close (client_fd);

      continue;
    }

    brain_server_client_options[client_idx].client_fd = client_fd;

    hc_thread_t client_thr;

    hc_thread_create (client_thr, brain_server_handle_client, &brain_server_client_options[client_idx]);

    if (client_thr == 0)
    {
      brain_logging (stderr, 0, "pthread_create: %s\n", strerror (errno));

      close (client_fd);

      continue;
    }

    hc_thread_detach (client_thr);
  }

  brain_logging (stdout, 0, "Brain server stopping\n");

  hc_thread_wait (1, &dump_thr);

  if (brain_server_write_hash_dumps (brain_server_dbs, ".") == false)
  {
    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  if (brain_server_write_attack_dumps (brain_server_dbs, ".") == false)
  {
    if (brain_password == NULL) hcfree (auth_password);

    return -1;
  }

  for (i64 idx = 0; idx < brain_server_dbs->hash_cnt; idx++)
  {
    brain_server_db_hash_t *brain_server_db_hash = &brain_server_dbs->hash_buf[idx];

    brain_server_db_hash_free (brain_server_db_hash);
  }

  for (i64 idx = 0; idx < brain_server_dbs->attack_cnt; idx++)
  {
    brain_server_db_attack_t *brain_server_db_attack = &brain_server_dbs->attack_buf[idx];

    brain_server_db_attack_free (brain_server_db_attack);
  }

  hcfree (brain_server_dbs->hash_buf);
  hcfree (brain_server_dbs->attack_buf);
  hcfree (brain_server_dbs);
  hcfree (brain_server_client_options);

  if (brain_password == NULL) hcfree (auth_password);

  close (server_fd);

  #if defined (_WIN)
  WSACleanup ();
  #endif

  return 0;
}

int brain_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  brain_ctx_t    *brain_ctx    = hashcat_ctx->brain_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  #ifdef WITH_BRAIN
  brain_ctx->support = true;
  #else
  brain_ctx->support = false;
  #endif

  if (brain_ctx->support == false) return 0;

  if (user_options->brain_client == true)
  {
    brain_ctx->enabled = true;
  }

  if (user_options->brain_server == true)
  {
    brain_ctx->enabled = true;
  }

  return 0;
}

void brain_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  brain_ctx_t *brain_ctx = hashcat_ctx->brain_ctx;

  if (brain_ctx->support == false) return;

  memset (brain_ctx, 0, sizeof (brain_ctx_t));
}
