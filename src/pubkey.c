/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "shared.h"
#include "ext_openssl.h"
#include "pubkey.h"

#include <time.h>
#include <inttypes.h>

// --encrypt-with-pubkey encrypts every recovered plain with the recipient's public key before it
// reaches any sink, so an operator running the job never sees the password on screen, in the
// outfile, or in the potfile. Only the holder of the private key can read the result.
//
// What is encrypted is not the bare password but a payload bound to the hash it belongs to:
//
//   v1\n<sha256 hex of the hash line>\n<unix timestamp>\n<password bytes>
//
// RSA-OAEP gives confidentiality but nothing that ties a ciphertext to the line it sits on, and the
// operator holds the public key, so without the binding they could move a ciphertext onto a
// different hash or replay one from an earlier run. The recipient recomputes the digest of the hash
// line the entry appeared on and rejects a mismatch. The timestamp lets them tell a fresh result
// from a replayed one.
//
// The password is placed last and copied verbatim, so it may contain any byte, including newlines.

static void pubkey_log_ssl_error (hashcat_ctx_t *hashcat_ctx, hc_openssl_lib_t *ossl, const char *what)
{
  const unsigned long e = ossl->ERR_get_error ();

  if (e == 0)
  {
    event_log_error (hashcat_ctx, "%s.", what);

    return;
  }

  char buf[256] = { 0 };

  ossl->ERR_error_string_n (e, buf, sizeof (buf));

  event_log_error (hashcat_ctx, "%s: %s", what, buf);
}

static int pubkey_compute_keyid (hashcat_ctx_t *hashcat_ctx, pubkey_ctx_t *pubkey_ctx)
{
  hc_openssl_lib_t *ossl  = (hc_openssl_lib_t *) pubkey_ctx->openssl;
  EVP_PKEY         *pkey  = (EVP_PKEY *)         pubkey_ctx->pubkey;

  const int der_len = ossl->i2d_PUBKEY (pkey, NULL);

  if (der_len <= 0)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to serialize the public key");

    return -1;
  }

  u8 *der = (u8 *) hcmalloc ((size_t) der_len);

  u8 *der_ptr = der;

  if (ossl->i2d_PUBKEY (pkey, &der_ptr) != der_len)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to serialize the public key");

    hcfree (der);

    return -1;
  }

  u8 md[32] = { 0 };

  unsigned int md_len = 0;

  if (ossl->EVP_Digest (der, (size_t) der_len, md, &md_len, ossl->EVP_sha256 (), NULL) != 1)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to digest the public key");

    hcfree (der);

    return -1;
  }

  hcfree (der);

  for (int i = 0; i < PUBKEY_KEYID_LEN / 2; i++)
  {
    snprintf (pubkey_ctx->keyid + (i * 2), 3, "%02x", md[i]);
  }

  return 0;
}

int pubkey_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  pubkey_ctx_t   *pubkey_ctx   = hashcat_ctx->pubkey_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  pubkey_ctx->enabled = false;

  if (user_options->encrypt_with_pubkey == NULL) return 0;

  hc_openssl_lib_t *ossl = (hc_openssl_lib_t *) hcmalloc (sizeof (hc_openssl_lib_t));

  pubkey_ctx->openssl = ossl;

  if (openssl_init (hashcat_ctx, ossl) == -1)
  {
    event_log_error (hashcat_ctx, "Cannot find the OpenSSL 3 crypto library, which --encrypt-with-pubkey requires.");

    event_log_warning (hashcat_ctx, "Install OpenSSL 3 (for instance the libssl3 or openssl package) and try again.");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  BIO *bio = ossl->BIO_new_file (user_options->encrypt_with_pubkey, "r");

  if (bio == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", user_options->encrypt_with_pubkey, strerror (errno));

    return -1;
  }

  EVP_PKEY *pkey = ossl->PEM_read_bio_PUBKEY (bio, NULL, NULL, NULL);

  ossl->BIO_free (bio);

  if (pkey == NULL)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to read a PEM public key from the given file");

    event_log_warning (hashcat_ctx, "The file must hold a PEM public key, that is a file starting with -----BEGIN PUBLIC KEY-----.");
    event_log_warning (hashcat_ctx, "Create one from a private key with: openssl rsa -in private.pem -pubout -out public.pem");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  pubkey_ctx->pubkey = pkey;

  if (ossl->EVP_PKEY_get_base_id (pkey) != HC_EVP_PKEY_RSA)
  {
    event_log_error (hashcat_ctx, "%s: not an RSA public key.", user_options->encrypt_with_pubkey);

    event_log_warning (hashcat_ctx, "--encrypt-with-pubkey uses RSA-OAEP. Elliptic curve and Ed25519 keys are not supported.");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  const int key_size = ossl->EVP_PKEY_get_size (pkey);
  const int key_bits = ossl->EVP_PKEY_get_bits (pkey);

  if (key_size <= PUBKEY_OAEP_OVERHEAD)
  {
    event_log_error (hashcat_ctx, "%s: the key is far too small to encrypt anything.", user_options->encrypt_with_pubkey);

    return -1;
  }

  const size_t capacity = (size_t) key_size - PUBKEY_OAEP_OVERHEAD;

  // The key has to be able to carry the longest password hashcat can ever produce, not just the one
  // we happen to recover. Checking that here, once, is what makes it impossible to reach the
  // encrypt call with a plain that does not fit: a seed phrase silently truncated to the modulus
  // would be worth exactly nothing to whoever is waiting for it.

  const size_t needed = PUBKEY_HEADER_MAX + PW_MAX;

  if (capacity < needed)
  {
    const int needed_bits = (int) ((needed + PUBKEY_OAEP_OVERHEAD) * 8);

    event_log_error (hashcat_ctx, "%s: the key is too small.", user_options->encrypt_with_pubkey);

    event_log_warning (hashcat_ctx, "The key is %d bits and can carry %" PRIu64 " bytes, but a password of up to %d bytes plus %d bytes of binding must fit.", key_bits, (u64) capacity, PW_MAX, PUBKEY_HEADER_MAX);
    event_log_warning (hashcat_ctx, "Use a key of at least %d bits. A 4096 bit key is recommended:", needed_bits);
    event_log_warning (hashcat_ctx, "  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out private.pem");
    event_log_warning (hashcat_ctx, "  openssl rsa -in private.pem -pubout -out public.pem");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  pubkey_ctx->key_size = (size_t) key_size;
  pubkey_ctx->key_bits = key_bits;
  pubkey_ctx->capacity = capacity;

  if (pubkey_compute_keyid (hashcat_ctx, pubkey_ctx) == -1) return -1;

  pubkey_ctx->run_time = (u64) time (NULL);

  pubkey_ctx->enabled = true;

  return 0;
}

void pubkey_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  pubkey_ctx_t *pubkey_ctx = hashcat_ctx->pubkey_ctx;

  hc_openssl_lib_t *ossl = (hc_openssl_lib_t *) pubkey_ctx->openssl;

  if (ossl != NULL)
  {
    if (pubkey_ctx->pubkey != NULL)
    {
      ossl->EVP_PKEY_free ((EVP_PKEY *) pubkey_ctx->pubkey);
    }

    openssl_close (hashcat_ctx, ossl);

    hcfree (ossl);
  }

  memset (pubkey_ctx, 0, sizeof (pubkey_ctx_t));
}

int pubkey_encrypt_plain (hashcat_ctx_t *hashcat_ctx, const u8 *hash_buf, const int hash_len, const u8 *plain_buf, const int plain_len, u8 *out_buf, const size_t out_size, int *out_len)
{
  pubkey_ctx_t *pubkey_ctx = hashcat_ctx->pubkey_ctx;

  hc_openssl_lib_t *ossl = (hc_openssl_lib_t *) pubkey_ctx->openssl;

  // bind the payload to the hash line it belongs to

  u8 hash_md[32] = { 0 };

  unsigned int hash_md_len = 0;

  if (ossl->EVP_Digest (hash_buf, (size_t) hash_len, hash_md, &hash_md_len, ossl->EVP_sha256 (), NULL) != 1)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to digest the hash line");

    return -1;
  }

  char hash_hex[65] = { 0 };

  for (int i = 0; i < 32; i++)
  {
    snprintf (hash_hex + (i * 2), 3, "%02x", hash_md[i]);
  }

  u8 payload[PUBKEY_HEADER_MAX + PW_MAX];

  const int header_len = snprintf ((char *) payload, PUBKEY_HEADER_MAX, "v1\n%s\n%" PRIu64 "\n", hash_hex, pubkey_ctx->run_time);

  if ((header_len <= 0) || (header_len >= PUBKEY_HEADER_MAX))
  {
    event_log_error (hashcat_ctx, "Failed to build the encrypted payload header.");

    return -1;
  }

  if ((size_t) plain_len > sizeof (payload) - (size_t) header_len)
  {
    event_log_error (hashcat_ctx, "Recovered password of %d bytes does not fit the encrypted payload.", plain_len);

    return -1;
  }

  memcpy (payload + header_len, plain_buf, (size_t) plain_len);

  const size_t payload_len = (size_t) header_len + (size_t) plain_len;

  // The key size was validated at startup against PW_MAX, so this cannot legitimately trip. It is
  // kept because the alternative to a hard error here is writing a truncated or empty result.

  if (payload_len > pubkey_ctx->capacity)
  {
    event_log_error (hashcat_ctx, "Encrypted payload of %" PRIu64 " bytes exceeds the %" PRIu64 " bytes the key can carry.", (u64) payload_len, (u64) pubkey_ctx->capacity);

    return -1;
  }

  // encrypt

  EVP_PKEY_CTX *ctx = ossl->EVP_PKEY_CTX_new ((EVP_PKEY *) pubkey_ctx->pubkey, NULL);

  if (ctx == NULL)
  {
    pubkey_log_ssl_error (hashcat_ctx, ossl, "Failed to create an encryption context");

    return -1;
  }

  u8 *ct_buf = (u8 *) hcmalloc (pubkey_ctx->key_size);

  size_t ct_len = pubkey_ctx->key_size;

  #define PUBKEY_ENCRYPT_FAIL(msg)                          \
  do {                                                      \
    pubkey_log_ssl_error (hashcat_ctx, ossl, (msg));        \
    ossl->EVP_PKEY_CTX_free (ctx);                          \
    hcfree (ct_buf);                                        \
    return -1;                                              \
  } while (0)

  if (ossl->EVP_PKEY_encrypt_init (ctx) != 1)                                          PUBKEY_ENCRYPT_FAIL ("Failed to initialize encryption");
  if (ossl->EVP_PKEY_CTX_set_rsa_padding (ctx, HC_RSA_PKCS1_OAEP_PADDING) <= 0)        PUBKEY_ENCRYPT_FAIL ("Failed to select OAEP padding");
  if (ossl->EVP_PKEY_CTX_set_rsa_oaep_md (ctx, ossl->EVP_sha256 ()) <= 0)              PUBKEY_ENCRYPT_FAIL ("Failed to select the OAEP digest");
  if (ossl->EVP_PKEY_CTX_set_rsa_mgf1_md (ctx, ossl->EVP_sha256 ()) <= 0)              PUBKEY_ENCRYPT_FAIL ("Failed to select the MGF1 digest");
  if (ossl->EVP_PKEY_encrypt (ctx, ct_buf, &ct_len, payload, payload_len) != 1)        PUBKEY_ENCRYPT_FAIL ("Failed to encrypt the recovered password");

  #undef PUBKEY_ENCRYPT_FAIL

  ossl->EVP_PKEY_CTX_free (ctx);

  if (ct_len > pubkey_ctx->key_size)
  {
    event_log_error (hashcat_ctx, "Ciphertext of %" PRIu64 " bytes exceeds the key size.", (u64) ct_len);

    hcfree (ct_buf);

    return -1;
  }

  // format

  const size_t need = PUBKEY_MARKER_LEN + PUBKEY_KEYID_LEN + 1 + (((ct_len + 2) / 3) * 4) + 1;

  if (need > out_size)
  {
    event_log_error (hashcat_ctx, "Encrypted output of %" PRIu64 " bytes does not fit the output buffer.", (u64) need);

    hcfree (ct_buf);

    return -1;
  }

  int len = 0;

  memcpy (out_buf + len, PUBKEY_MARKER, PUBKEY_MARKER_LEN);   len += PUBKEY_MARKER_LEN;
  memcpy (out_buf + len, pubkey_ctx->keyid, PUBKEY_KEYID_LEN); len += PUBKEY_KEYID_LEN;

  out_buf[len] = '$'; len += 1;

  len += (int) base64_encode (int_to_base64, ct_buf, ct_len, out_buf + len);

  out_buf[len] = 0;

  hcfree (ct_buf);

  *out_len = len;

  return 0;
}
