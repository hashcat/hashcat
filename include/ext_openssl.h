/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_OPENSSL_H
#define HC_EXT_OPENSSL_H

#include <stdlib.h>
#include <stdint.h>

#include "dynloader.h"

// libcrypto is loaded at runtime, never linked. That keeps hashcat buildable and shippable on hosts
// that have no OpenSSL development files, and keeps the OpenSSL DLL out of the binary packages. The
// types below are the handful of opaque handles we pass around; we only ever hold pointers to them,
// so forward declarations are enough and no OpenSSL header is needed to build hashcat.

typedef struct evp_pkey_st     EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_st       EVP_MD;
typedef struct bio_st          BIO;
typedef struct engine_st       ENGINE;

// From OpenSSL's rsa.h and obj_mac.h. These are ABI constants and have not changed across OpenSSL
// releases, so hardcoding them is safe and avoids the header dependency.

#define HC_RSA_PKCS1_OAEP_PADDING 4
#define HC_EVP_PKEY_RSA           6

typedef BIO          *(*OPENSSL_BIO_NEW_FILE)                  (const char *, const char *);
typedef int           (*OPENSSL_BIO_FREE)                      (BIO *);
typedef EVP_PKEY     *(*OPENSSL_PEM_READ_BIO_PUBKEY)           (BIO *, EVP_PKEY **, void *, void *);
typedef void          (*OPENSSL_EVP_PKEY_FREE)                 (EVP_PKEY *);
typedef int           (*OPENSSL_EVP_PKEY_GET_SIZE)             (const EVP_PKEY *);
typedef int           (*OPENSSL_EVP_PKEY_GET_BITS)             (const EVP_PKEY *);
typedef int           (*OPENSSL_EVP_PKEY_GET_BASE_ID)          (const EVP_PKEY *);
typedef int           (*OPENSSL_I2D_PUBKEY)                    (const EVP_PKEY *, unsigned char **);
typedef EVP_PKEY_CTX *(*OPENSSL_EVP_PKEY_CTX_NEW)              (EVP_PKEY *, ENGINE *);
typedef void          (*OPENSSL_EVP_PKEY_CTX_FREE)             (EVP_PKEY_CTX *);
typedef int           (*OPENSSL_EVP_PKEY_ENCRYPT_INIT)         (EVP_PKEY_CTX *);
typedef int           (*OPENSSL_EVP_PKEY_ENCRYPT)              (EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
typedef int           (*OPENSSL_EVP_PKEY_CTX_SET_RSA_PADDING)  (EVP_PKEY_CTX *, int);
typedef int           (*OPENSSL_EVP_PKEY_CTX_SET_RSA_OAEP_MD)  (EVP_PKEY_CTX *, const EVP_MD *);
typedef int           (*OPENSSL_EVP_PKEY_CTX_SET_RSA_MGF1_MD)  (EVP_PKEY_CTX *, const EVP_MD *);
typedef const EVP_MD *(*OPENSSL_EVP_SHA256)                    (void);
typedef int           (*OPENSSL_EVP_DIGEST)                    (const void *, size_t, unsigned char *, unsigned int *, const EVP_MD *, ENGINE *);
typedef unsigned long (*OPENSSL_ERR_GET_ERROR)                 (void);
typedef void          (*OPENSSL_ERR_ERROR_STRING_N)            (unsigned long, char *, size_t);

typedef struct hc_openssl_lib
{
  hc_dynlib_t lib;

  OPENSSL_BIO_NEW_FILE                 BIO_new_file;
  OPENSSL_BIO_FREE                     BIO_free;
  OPENSSL_PEM_READ_BIO_PUBKEY          PEM_read_bio_PUBKEY;
  OPENSSL_EVP_PKEY_FREE                EVP_PKEY_free;
  OPENSSL_EVP_PKEY_GET_SIZE            EVP_PKEY_get_size;
  OPENSSL_EVP_PKEY_GET_BITS            EVP_PKEY_get_bits;
  OPENSSL_EVP_PKEY_GET_BASE_ID         EVP_PKEY_get_base_id;
  OPENSSL_I2D_PUBKEY                   i2d_PUBKEY;
  OPENSSL_EVP_PKEY_CTX_NEW             EVP_PKEY_CTX_new;
  OPENSSL_EVP_PKEY_CTX_FREE            EVP_PKEY_CTX_free;
  OPENSSL_EVP_PKEY_ENCRYPT_INIT        EVP_PKEY_encrypt_init;
  OPENSSL_EVP_PKEY_ENCRYPT             EVP_PKEY_encrypt;
  OPENSSL_EVP_PKEY_CTX_SET_RSA_PADDING EVP_PKEY_CTX_set_rsa_padding;
  OPENSSL_EVP_PKEY_CTX_SET_RSA_OAEP_MD EVP_PKEY_CTX_set_rsa_oaep_md;
  OPENSSL_EVP_PKEY_CTX_SET_RSA_MGF1_MD EVP_PKEY_CTX_set_rsa_mgf1_md;
  OPENSSL_EVP_SHA256                   EVP_sha256;
  OPENSSL_EVP_DIGEST                   EVP_Digest;
  OPENSSL_ERR_GET_ERROR                ERR_get_error;
  OPENSSL_ERR_ERROR_STRING_N           ERR_error_string_n;

} hc_openssl_lib_t;

int  openssl_init  (void *hashcat_ctx, void *openssl);
void openssl_close (void *hashcat_ctx, void *openssl);

#endif // HC_EXT_OPENSSL_H
