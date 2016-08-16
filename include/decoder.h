#pragma once
#include "numeric_types_abbreviations.h"

static void AES128_decrypt_cbc(const u32 key[4], const u32 iv[4], const u32 in[16], u32 out[16]);

void juniper_decrypt_hash(char * in, char * out);

void phpass_decode(u8 digest[16], u8 buf[22]);
void phpass_encode(u8 digest[16], u8 buf[22]);
void md5crypt_decode(u8 digest[16], u8 buf[22]);
void md5crypt_encode(u8 digest[16], u8 buf[22]);
void sha512crypt_decode(u8 digest[64], u8 buf[86]);
void sha512crypt_encode(u8 digest[64], u8 buf[86]);
void sha1aix_decode(u8 digest[20], u8 buf[27]);
void sha1aix_encode(u8 digest[20], u8 buf[27]);
void sha256aix_decode(u8 digest[32], u8 buf[43]);
void sha256aix_encode(u8 digest[32], u8 buf[43]);
void sha512aix_decode(u8 digest[64], u8 buf[86]);
void sha512aix_encode(u8 digest[64], u8 buf[86]);
void sha256crypt_decode(u8 digest[32], u8 buf[43]);
void sha256crypt_encode(u8 digest[32], u8 buf[43]);
void drupal7_decode(u8 digest[64], u8 buf[44]);
void drupal7_encode(u8 digest[64], u8 buf[43]);
