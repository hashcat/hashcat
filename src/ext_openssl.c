/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "dynloader.h"
#include "ext_openssl.h"

// We target the OpenSSL 3 ABI. 1.1.1 went end-of-life in September 2023, and on it several of the
// RSA parameter setters we need are macros over EVP_PKEY_CTX_ctrl rather than exported functions,
// so loading it would only fail later with a confusing missing-symbol message. If an unversioned
// soname resolves to a 1.1 build the symbol load below fails and the user is told exactly that.

static const char *const OPENSSL_SONAMES[] =
{
  #if   defined (_WIN) || defined (__CYGWIN__)
  "libcrypto-3-x64.dll",
  "libcrypto-3.dll",
  "libcrypto.dll",
  #elif defined (__APPLE__)
  "libcrypto.3.dylib",
  "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
  "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
  "libcrypto.dylib",
  #else
  "libcrypto.so.3",
  "libcrypto.so",
  #endif
};

int openssl_init (void *hashcat_ctx, void *openssl)
{
  hc_openssl_lib_t *ossl = (hc_openssl_lib_t *) openssl;

  memset (ossl, 0, sizeof (hc_openssl_lib_t));

  for (size_t i = 0; i < sizeof (OPENSSL_SONAMES) / sizeof (OPENSSL_SONAMES[0]); i++)
  {
    ossl->lib = hc_dlopen (OPENSSL_SONAMES[i]);

    if (ossl->lib) break;
  }

  if (ossl->lib == NULL) return -1;

  HC_LOAD_FUNC (ossl, BIO_new_file,                 OPENSSL_BIO_NEW_FILE,                 OpenSSL, 1);
  HC_LOAD_FUNC (ossl, BIO_free,                     OPENSSL_BIO_FREE,                     OpenSSL, 1);
  HC_LOAD_FUNC (ossl, PEM_read_bio_PUBKEY,          OPENSSL_PEM_READ_BIO_PUBKEY,          OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_free,                OPENSSL_EVP_PKEY_FREE,                OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_get_size,            OPENSSL_EVP_PKEY_GET_SIZE,            OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_get_bits,            OPENSSL_EVP_PKEY_GET_BITS,            OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_get_base_id,         OPENSSL_EVP_PKEY_GET_BASE_ID,         OpenSSL, 1);
  HC_LOAD_FUNC (ossl, i2d_PUBKEY,                   OPENSSL_I2D_PUBKEY,                   OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_CTX_new,             OPENSSL_EVP_PKEY_CTX_NEW,             OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_CTX_free,            OPENSSL_EVP_PKEY_CTX_FREE,            OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_encrypt_init,        OPENSSL_EVP_PKEY_ENCRYPT_INIT,        OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_encrypt,             OPENSSL_EVP_PKEY_ENCRYPT,             OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_CTX_set_rsa_padding, OPENSSL_EVP_PKEY_CTX_SET_RSA_PADDING, OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_CTX_set_rsa_oaep_md, OPENSSL_EVP_PKEY_CTX_SET_RSA_OAEP_MD, OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_PKEY_CTX_set_rsa_mgf1_md, OPENSSL_EVP_PKEY_CTX_SET_RSA_MGF1_MD, OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_sha256,                   OPENSSL_EVP_SHA256,                   OpenSSL, 1);
  HC_LOAD_FUNC (ossl, EVP_Digest,                   OPENSSL_EVP_DIGEST,                   OpenSSL, 1);
  HC_LOAD_FUNC (ossl, ERR_get_error,                OPENSSL_ERR_GET_ERROR,                OpenSSL, 1);
  HC_LOAD_FUNC (ossl, ERR_error_string_n,           OPENSSL_ERR_ERROR_STRING_N,           OpenSSL, 1);

  return 0;
}

void openssl_close (void *hashcat_ctx, void *openssl)
{
  hc_openssl_lib_t *ossl = (hc_openssl_lib_t *) openssl;

  if (ossl == NULL) return;

  if (ossl->lib)
  {
    hc_dlclose (ossl->lib);
  }

  memset (ossl, 0, sizeof (hc_openssl_lib_t));

  (void) hashcat_ctx;
}
