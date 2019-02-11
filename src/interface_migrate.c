
  "  10100 | SipHash                                          | Raw Hash",
  "   6000 | RIPEMD-160                                       | Raw Hash",
  "   6100 | Whirlpool                                        | Raw Hash",
  "  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian | Raw Hash",
  "  11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian | Raw Hash",
  "     30 | md5(utf16le($pass).$salt)                        | Raw Hash, Salted and/or Iterated",
  "   3800 | md5($salt.$pass.$salt)                           | Raw Hash, Salted and/or Iterated",
  "   3710 | md5($salt.md5($pass))                            | Raw Hash, Salted and/or Iterated",
  "   4010 | md5($salt.md5($salt.$pass))                      | Raw Hash, Salted and/or Iterated",
  "   4110 | md5($salt.md5($pass.$salt))                      | Raw Hash, Salted and/or Iterated",
  "   2600 | md5(md5($pass))                                  | Raw Hash, Salted and/or Iterated",
  "   4300 | md5(strtoupper(md5($pass)))                      | Raw Hash, Salted and/or Iterated",
  "   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated",
  "    120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated",
  "    130 | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated",
  "    140 | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated",
  "   4500 | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated",
  "   4520 | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated",
  "   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated",
  "   4900 | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated",
  "   1410 | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated",
  "   1420 | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated",
  "   1430 | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated",
  "   1440 | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated",
  "   1710 | sha512($pass.$salt)                              | Raw Hash, Salted and/or Iterated",
  "   1720 | sha512($salt.$pass)                              | Raw Hash, Salted and/or Iterated",
  "   1730 | sha512(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated",
  "   1740 | sha512($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated",
  "     50 | HMAC-MD5 (key = $pass)                           | Raw Hash, Authenticated",
  "     60 | HMAC-MD5 (key = $salt)                           | Raw Hash, Authenticated",
  "    150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated",
  "    160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated",
  "   1450 | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated",
  "   1460 | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated",
  "   1750 | HMAC-SHA512 (key = $pass)                        | Raw Hash, Authenticated",
  "   1760 | HMAC-SHA512 (key = $salt)                        | Raw Hash, Authenticated",
  "  11750 | HMAC-Streebog-256 (key = $pass), big-endian      | Raw Hash, Authenticated",
  "  11760 | HMAC-Streebog-256 (key = $salt), big-endian      | Raw Hash, Authenticated",
  "  11850 | HMAC-Streebog-512 (key = $pass), big-endian      | Raw Hash, Authenticated",
  "  11860 | HMAC-Streebog-512 (key = $salt), big-endian      | Raw Hash, Authenticated",
  "    121 | SMF (Simple Machines Forum) > v1.1               | Forums, CMS, E-Commerce, Frameworks",
  "   2611 | vBulletin < v3.8.5                               | Forums, CMS, E-Commerce, Frameworks",
  "   2711 | vBulletin >= v3.8.5                              | Forums, CMS, E-Commerce, Frameworks",
  "   2612 | PHPS                                             | Forums, CMS, E-Commerce, Frameworks",
  "    124 | Django (SHA-1)                                   | Forums, CMS, E-Commerce, Frameworks",
  "   3711 | MediaWiki B type                                 | Forums, CMS, E-Commerce, Frameworks",
  "  13900 | OpenCart                                         | Forums, CMS, E-Commerce, Frameworks",
  "   4521 | Redmine                                          | Forums, CMS, E-Commerce, Frameworks",
  "   4522 | PunBB                                            | Forums, CMS, E-Commerce, Frameworks",
  "    141 | Episerver 6.x < .NET 4                           | HTTP, SMTP, LDAP Server",
  "   1441 | Episerver 6.x >= .NET 4                          | HTTP, SMTP, LDAP Server",
  "   1421 | hMailServer                                      | HTTP, SMTP, LDAP Server",
  "   1411 | SSHA-256(Base64), LDAP {SSHA256}                 | HTTP, SMTP, LDAP Server",
  "   1711 | SSHA-512(Base64), LDAP {SSHA512}                 | HTTP, SMTP, LDAP Server",
  "   1722 | macOS v10.7                                      | Operating Systems",
  "     22 | Juniper NetScreen/SSG (ScreenOS)                 | Operating Systems",

static const char *ST_HASH_00021 = "e983672a03adcc9767b24584338eb378:00";
static const char *ST_HASH_00022 = "nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173";
static const char *ST_HASH_00030 = "1169500a7dfece72e1f7fc9c9410867a:687430237020";
static const char *ST_HASH_00050 = "e28e4e37e972a945e464b5226053bac0:40";
static const char *ST_HASH_00060 = "7f51edecfa6fb401a0b5e63d33fc8c0e:84143";
static const char *ST_HASH_00120 = "a428863972744b16afef28e0087fc094b44bb7b1:465727565";
static const char *ST_HASH_00121 = "d27c0a627a45db487af161fcc3a4005d88eb8a1f:25551135";
static const char *ST_HASH_00124 = "sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013";
static const char *ST_HASH_00130 = "0a9e4591f539a77cd3af67bae207d250bc86bac6:23240710432";
static const char *ST_HASH_00140 = "03b83421e2aa6d872d1f8dee001dc226ef01722b:818436";
static const char *ST_HASH_00141 = "$episerver$*0*MjEwNA==*ZUgAmuaYTqAvisD0A427FA3oaWU";
static const char *ST_HASH_00150 = "02b256705348a28b1d6c0f063907979f7e0c82f8:10323";
static const char *ST_HASH_00160 = "8d7cb4d4a27a438059bb83a34d1e6cc439669168:2134817";
static const char *ST_HASH_01410 = "5bb7456f43e3610363f68ad6de82b8b96f3fc9ad24e9d1f1f8d8bd89638db7c0:12480864321";
static const char *ST_HASH_01411 = "{SSHA256}L5Wk0zPY2lmoR5pH20zngq37KkxFwgTquEhx95rxfVk3Ng==";
static const char *ST_HASH_01420 = "816d1ded1d621873595048912ea3405d9d42afd3b57665d9f5a2db4d89720854:36176620";
static const char *ST_HASH_01421 = "8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3";
static const char *ST_HASH_01430 = "b2d0db162e30dfef1bfd606689a3acbc213c47ef3fd11968394191886075249d:32002";
static const char *ST_HASH_01440 = "84ebe1bc3d59919a8c4f9337d66bd163661586c828b24b8067a27a6dc4228c64:05662";
static const char *ST_HASH_01441 = "$episerver$*1*NDg1NTIz*8BFCg/YJBAuZs/wjbH3OWKe69BLr5Lao26ybpnD48Zk";
static const char *ST_HASH_01450 = "b435ffbacea34d5eb0dbc4d69a92f0152f2cf4cd364d34c2ece322ca22d8b334:21217";
static const char *ST_HASH_01460 = "8b9472281c36c3a693703de0e0f1ffab8fc0ecdd3bc5ead04c76dd74ef431e49:70108387805";
static const char *ST_HASH_01600 = "$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/";
static const char *ST_HASH_01710 = "3f749c84d00c6f94a6651b5c195c71dacae08f3cea6fed760232856cef701f7bf60d7f38a587f69f159d4e4cbe00435aeb9c8c0a4927b252d76a744e16e87e91:388026522082";
static const char *ST_HASH_01711 = "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg==";
static const char *ST_HASH_01720 = "efc5dd0e4145970917abdc311e1d4e23ba0afa9426d960cb28569f4d585cb031af5c936f57fbcb0a08368a1b302573cf582100d40bd7c632f3d8aecd1a1a8eb1:812";
static const char *ST_HASH_01730 = "eefb67342d62a5d8ac84e8ae89d0f157f03749bd0427c80637003a4760feefdb36cbe11ba35ab2015b3691e2e83803178c986aa85f29e6f56938b469a31ccd7a:6576666";
static const char *ST_HASH_01740 = "ce77bf8a8ca9b9cf0ed67edde58ed7fafd4542ce1378fc8bd87b05656ebf92e5711517d5930c18de93a71990e77e1037423e5b64c2f293be7d859d7b6921622e:1512373";
static const char *ST_HASH_01722 = "07543781b07e905f6f947db8ae305c248b9e12f509b41097e852e2f450e824790e677ea7397b8a9a552b1c19ecf6a6e1dd3844fa5ee5db23976962859676f7d2fb85ca94";
static const char *ST_HASH_01750 = "138c00f17a1a0363f274817c91118f019aff09f937bfdaea844280a0c0e7811267cc4735d967d8640eed1218268c1c4a76fec8f7aa551491b353829f3a654270:885142";
static const char *ST_HASH_01760 = "7d02921299935179d509e6dd4f3d0f2944e3451ea9de3af16baead6a7297e5653577d2473a0fff743d9fe78a89bd49296114319989dc7e7870fc7f62bc96accb:114";
static const char *ST_HASH_02600 = "a936af92b0ae20b1ff6c3347a72e5fbe";
static const char *ST_HASH_02611 = "28f9975808ae2bdc5847b1cda26033ea:308";
static const char *ST_HASH_02612 = "$PHPS$30353031383437363132$f02b0b2f25e5754edb04522c346ba243";
static const char *ST_HASH_02711 = "0844fbb2fdeda31884a7a45ec2010bb6:324410183853308365427804872426";
static const char *ST_HASH_03710 = "a3aa0ae2b4a102a9974cdf40edeabee0:242812778074";
static const char *ST_HASH_03711 = "$B$2152187716$8c8b39c3602b194eeeb6cac78eea2742";
static const char *ST_HASH_03800 = "78274b1105fb8a7c415b43ffe35ec4a9:6";
static const char *ST_HASH_04010 = "82422514daaa8253be0aa43f3e263af5:7530326651137";
static const char *ST_HASH_04110 = "45b1005214e2d9472a7ad681578b2438:64268771004";
static const char *ST_HASH_04300 = "b8c385461bb9f9d733d3af832cf60b27";
static const char *ST_HASH_04400 = "288496df99b33f8f75a7ce4837d1b480";
static const char *ST_HASH_04500 = "3db9184f5da4e463832b086211af8d2314919951";
static const char *ST_HASH_04520 = "59b80a295392eedb677ca377ad7bf3487928df96:136472340404074825440760227553028141804855170538";
static const char *ST_HASH_04521 = "c18e826af2a78c7b9b7261452613233417e65817:28246535720688452723483475753333";
static const char *ST_HASH_04522 = "9038129c474caa3f0de56f38db84033d0fe1d4b8:365563602032";
static const char *ST_HASH_04700 = "92d85978d884eb1d99a51652b1139c8279fa8663";
static const char *ST_HASH_04900 = "75d280ca9a0c2ee18729603104ead576d9ca6285:347070";
static const char *ST_HASH_06000 = "012cb9b334ec1aeb71a9c8ce85586082467f7eb6";
static const char *ST_HASH_06100 = "7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258";
static const char *ST_HASH_10100 = "583e6f51e52ba296:2:4:47356410265714355482333327356688";
static const char *ST_HASH_11700 = "57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36";
static const char *ST_HASH_11750 = "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337";
static const char *ST_HASH_11760 = "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337";
static const char *ST_HASH_11800 = "5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3";
static const char *ST_HASH_11850 = "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337";
static const char *ST_HASH_11860 = "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337";
static const char *ST_HASH_13900 = "058c1c3773340c8563421e2b17e60eb7c916787e:827500576";

static const char *HT_00030 = "md5(utf16le($pass).$salt)";
static const char *HT_00050 = "HMAC-MD5 (key = $pass)";
static const char *HT_00060 = "HMAC-MD5 (key = $salt)";
static const char *HT_00100 = "SHA1";
static const char *HT_00110 = "sha1($pass.$salt)";
static const char *HT_00120 = "sha1($salt.$pass)";
static const char *HT_00130 = "sha1(utf16le($pass).$salt)";
static const char *HT_00140 = "sha1($salt.utf16le($pass))";
static const char *HT_00150 = "HMAC-SHA1 (key = $pass)";
static const char *HT_00160 = "HMAC-SHA1 (key = $salt)";
static const char *HT_01410 = "sha256($pass.$salt)";
static const char *HT_01420 = "sha256($salt.$pass)";
static const char *HT_01430 = "sha256(utf16le($pass).$salt)";
static const char *HT_01440 = "sha256($salt.utf16le($pass))";
static const char *HT_01450 = "HMAC-SHA256 (key = $pass)";
static const char *HT_01460 = "HMAC-SHA256 (key = $salt)";
static const char *HT_01600 = "Apache $apr1$ MD5, md5apr1, MD5 (APR)";
static const char *HT_01710 = "sha512($pass.$salt)";
static const char *HT_01720 = "sha512($salt.$pass)";
static const char *HT_01730 = "sha512(utf16le($pass).$salt)";
static const char *HT_01740 = "sha512($salt.utf16le($pass))";
static const char *HT_01750 = "HMAC-SHA512 (key = $pass)";
static const char *HT_01760 = "HMAC-SHA512 (key = $salt)";
static const char *HT_02600 = "md5(md5($pass))";
static const char *HT_03710 = "md5($salt.md5($pass))";
static const char *HT_03711 = "MediaWiki B type";
static const char *HT_03800 = "md5($salt.$pass.$salt)";
static const char *HT_04010 = "md5($salt.md5($salt.$pass))";
static const char *HT_04110 = "md5($salt.md5($pass.$salt))";
static const char *HT_04300 = "md5(strtoupper(md5($pass)))";
static const char *HT_04400 = "md5(sha1($pass))";
static const char *HT_04500 = "sha1(sha1($pass))";
static const char *HT_04520 = "sha1($salt.sha1($pass))";
static const char *HT_04700 = "sha1(md5($pass))";
static const char *HT_04900 = "sha1($salt.$pass.$salt)";
static const char *HT_06000 = "RIPEMD-160";
static const char *HT_06100 = "Whirlpool";
static const char *HT_10100 = "SipHash";
static const char *HT_11700 = "GOST R 34.11-2012 (Streebog) 256-bit, big-endian";
static const char *HT_11750 = "HMAC-Streebog-256 (key = $pass), big-endian";
static const char *HT_11760 = "HMAC-Streebog-256 (key = $salt), big-endian";
static const char *HT_11800 = "GOST R 34.11-2012 (Streebog) 512-bit, big-endian";
static const char *HT_11850 = "HMAC-Streebog-512 (key = $pass), big-endian";
static const char *HT_11860 = "HMAC-Streebog-512 (key = $salt), big-endian";
static const char *HT_13900 = "OpenCart";

static const char *HT_00022 = "Juniper NetScreen/SSG (ScreenOS)";
static const char *HT_00101 = "nsldap, SHA-1(Base64), Netscape LDAP SHA";
static const char *HT_00121 = "SMF (Simple Machines Forum) > v1.1";
static const char *HT_00124 = "Django (SHA-1)";
static const char *HT_00141 = "Episerver 6.x < .NET 4";
static const char *HT_01411 = "SSHA-256(Base64), LDAP {SSHA256}";
static const char *HT_01421 = "hMailServer";
static const char *HT_01441 = "Episerver 6.x >= .NET 4";
static const char *HT_01711 = "SSHA-512(Base64), LDAP {SSHA512}";
static const char *HT_01722 = "macOS v10.7";
static const char *HT_02611 = "vBulletin < v3.8.5";
static const char *HT_02612 = "PHPS";
static const char *HT_02711 = "vBulletin >= v3.8.5";
static const char *HT_04521 = "Redmine";
static const char *HT_04522 = "PunBB";

static const char *SIGNATURE_DJANGOSHA1         = "sha1$";
static const char *SIGNATURE_EPISERVER          = "$episerver$";
static const char *SIGNATURE_MEDIAWIKI_B        = "$B$";
static const char *SIGNATURE_PHPS               = "$PHPS$";
static const char *SIGNATURE_SHA1B64            = "{SHA}";
static const char *SIGNATURE_SHA256B64S         = "{SSHA256}";
static const char *SIGNATURE_SHA512B64S         = "{SSHA512}";

/**
 * decoder / encoder
 */

int macos1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 40;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int macos512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 128;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int netscreen_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 30;
  token.len_max[0] = 30;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[1] = 1;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  // unscramble

  u8 clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = {   0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != hash_pos[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = hash_pos[i];

      k++;
    }
  }

  // base64 decode

  u32 a, b, c, d, e, f;

  a = base64_to_int (clean_input_buf[ 0] & 0x7f);
  b = base64_to_int (clean_input_buf[ 1] & 0x7f);
  c = base64_to_int (clean_input_buf[ 2] & 0x7f);
  d = base64_to_int (clean_input_buf[ 3] & 0x7f);
  e = base64_to_int (clean_input_buf[ 4] & 0x7f);
  f = base64_to_int (clean_input_buf[ 5] & 0x7f);

  digest[0] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[ 6] & 0x7f);
  b = base64_to_int (clean_input_buf[ 7] & 0x7f);
  c = base64_to_int (clean_input_buf[ 8] & 0x7f);
  d = base64_to_int (clean_input_buf[ 9] & 0x7f);
  e = base64_to_int (clean_input_buf[10] & 0x7f);
  f = base64_to_int (clean_input_buf[11] & 0x7f);

  digest[1] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[12] & 0x7f);
  b = base64_to_int (clean_input_buf[13] & 0x7f);
  c = base64_to_int (clean_input_buf[14] & 0x7f);
  d = base64_to_int (clean_input_buf[15] & 0x7f);
  e = base64_to_int (clean_input_buf[16] & 0x7f);
  f = base64_to_int (clean_input_buf[17] & 0x7f);

  digest[2] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[18] & 0x7f);
  b = base64_to_int (clean_input_buf[19] & 0x7f);
  c = base64_to_int (clean_input_buf[20] & 0x7f);
  d = base64_to_int (clean_input_buf[21] & 0x7f);
  e = base64_to_int (clean_input_buf[22] & 0x7f);
  f = base64_to_int (clean_input_buf[23] & 0x7f);

  digest[3] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32
  // 32 - 4 bytes (to fit w0lr for all attack modes) = 28

  if (salt->salt_len > 28) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  static const char *adm = ":Administration Tools:";

  memcpy (salt_buf_ptr + salt->salt_len, adm, strlen (adm));

  salt->salt_len += strlen (adm);

  return (PARSER_OK);
}

int episerver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EPISERVER;

  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 0;
  token.len_max[2] = 44;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[3] = 27;
  token.len_max[3] = 27;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int md4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  return (PARSER_OK);
}

int md4s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  return (PARSER_OK);
}

int md5s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  if (hashconfig->opts_type & OPTS_TYPE_ST_HASH_MD5)
  {
    // precompute md5 of the salt

    precompute_salt_md5 (salt->salt_buf, salt->salt_len, (u8 *) salt->salt_buf_pc);
  }

  return (PARSER_OK);
}

int md5md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  /**
   * This is a virtual salt. While the algorithm is basically not salted
   * we can exploit the salt buffer to set the 0x80 and the w[14] value.
   * This way we can save a special md5md5 kernel and reuse the one from vbull.
   */

  static const u8 *zero = (const u8*) "";

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, zero, 0, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int vb30_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 23;
  token.len_max[1] = 31;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int sha1s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha224_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 56;
  token.len_max[0] = 56;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA224M_A;
    digest[1] -= SHA224M_B;
    digest[2] -= SHA224M_C;
    digest[3] -= SHA224M_D;
    digest[4] -= SHA224M_E;
    digest[5] -= SHA224M_F;
    digest[6] -= SHA224M_G;
  }

  return (PARSER_OK);
}

int sha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  return (PARSER_OK);
}

int sha256s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha384_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 96;
  token.len_max[0] = 96;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +  0);
  digest[1] = hex_to_u64 (hash_pos + 16);
  digest[2] = hex_to_u64 (hash_pos + 32);
  digest[3] = hex_to_u64 (hash_pos + 48);
  digest[4] = hex_to_u64 (hash_pos + 64);
  digest[5] = hex_to_u64 (hash_pos + 80);
  digest[6] = 0;
  digest[7] = 0;

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = 0;
  digest[7] = 0;

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA384M_A;
    digest[1] -= SHA384M_B;
    digest[2] -= SHA384M_C;
    digest[3] -= SHA384M_D;
    digest[4] -= SHA384M_E;
    digest[5] -= SHA384M_F;
    digest[6] -= 0;
    digest[7] -= 0;
  }

  return (PARSER_OK);
}

int sha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  return (PARSER_OK);
}

int sha512s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int ripemd160_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  return (PARSER_OK);
}

int whirlpool_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  digest[ 0] = byte_swap_32 (digest[ 0]);
  digest[ 1] = byte_swap_32 (digest[ 1]);
  digest[ 2] = byte_swap_32 (digest[ 2]);
  digest[ 3] = byte_swap_32 (digest[ 3]);
  digest[ 4] = byte_swap_32 (digest[ 4]);
  digest[ 5] = byte_swap_32 (digest[ 5]);
  digest[ 6] = byte_swap_32 (digest[ 6]);
  digest[ 7] = byte_swap_32 (digest[ 7]);
  digest[ 8] = byte_swap_32 (digest[ 8]);
  digest[ 9] = byte_swap_32 (digest[ 9]);
  digest[10] = byte_swap_32 (digest[10]);
  digest[11] = byte_swap_32 (digest[11]);
  digest[12] = byte_swap_32 (digest[12]);
  digest[13] = byte_swap_32 (digest[13]);
  digest[14] = byte_swap_32 (digest[14]);
  digest[15] = byte_swap_32 (digest[15]);

  return (PARSER_OK);
}

int episerver4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EPISERVER;

  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 0;
  token.len_max[2] = 24;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[3] = 43;
  token.len_max[3] = 43;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha512b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA512B64S;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 88;
  token.len_max[1] = 428; // 428 = 64 + 256 where 64 is digest length and 256 is SALT_MAX
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[512] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (tmp_len < 64) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf;

  memcpy (digest, hash_pos, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  // salt

  u8 *salt_pos = tmp_buf + 64;
  int salt_len = tmp_len - 64;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, salt_pos, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int mysql323_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 16;
  token.len_max[0] = 16;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int opencart_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 9;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int hmailserver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len_min[1] = 64;
  token.len_max[1] = 64;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int phps_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PHPS;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int mediawiki_b_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MEDIAWIKI_B;

  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_buf_ptr[salt_len] = 0x2d;

  salt->salt_len = salt_len + 1;

  return (PARSER_OK);
}

int djangosha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DJANGOSHA1;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int siphash_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.sep[0]     = ':';
  token.len_min[0] = 16;
  token.len_max[0] = 16;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 iter_c = token.buf[1][0];
  const u8 iter_d = token.buf[2][0];

  // atm only defaults, let's see if there's more request
  if (iter_c != '2') return (PARSER_SALT_ITERATION);
  if (iter_d != '4') return (PARSER_SALT_ITERATION);

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  // salt

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int redmine_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 32;
  token.len_max[1] = 32;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int punbb_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 12;
  token.len_max[1] = 12;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int streebog_256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len[0]  = 64;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  return (PARSER_OK);
}

int streebog_256s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = ':';
  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int streebog_512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len[0]  = 128;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  return (PARSER_OK);
}

int streebog_512s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = ':';
  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha256b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA256B64S;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 44;
  token.len_max[1] = 385; // 385 = 32 + 256 where 32 is digest length and 256 is SALT_MAX
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[512] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (tmp_len < 32) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf;

  memcpy (digest, hash_pos, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  // salt

  u8 *salt_pos = tmp_buf + 32;
  int salt_len = tmp_len - 32;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, salt_pos, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  if (hash_mode == 22)
  {
    char username[30] = { 0 };

    memcpy (username, salt.salt_buf, salt.salt_len - 22);

    char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };

    u16 *ptr = (u16 *) digest_buf;

    tmp_buf[ 0] = sig[0];
    tmp_buf[ 1] = int_to_base64 (((ptr[1]) >> 12) & 0x3f);
    tmp_buf[ 2] = int_to_base64 (((ptr[1]) >>  6) & 0x3f);
    tmp_buf[ 3] = int_to_base64 (((ptr[1]) >>  0) & 0x3f);
    tmp_buf[ 4] = int_to_base64 (((ptr[0]) >> 12) & 0x3f);
    tmp_buf[ 5] = int_to_base64 (((ptr[0]) >>  6) & 0x3f);
    tmp_buf[ 6] = sig[1];
    tmp_buf[ 7] = int_to_base64 (((ptr[0]) >>  0) & 0x3f);
    tmp_buf[ 8] = int_to_base64 (((ptr[3]) >> 12) & 0x3f);
    tmp_buf[ 9] = int_to_base64 (((ptr[3]) >>  6) & 0x3f);
    tmp_buf[10] = int_to_base64 (((ptr[3]) >>  0) & 0x3f);
    tmp_buf[11] = int_to_base64 (((ptr[2]) >> 12) & 0x3f);
    tmp_buf[12] = sig[2];
    tmp_buf[13] = int_to_base64 (((ptr[2]) >>  6) & 0x3f);
    tmp_buf[14] = int_to_base64 (((ptr[2]) >>  0) & 0x3f);
    tmp_buf[15] = int_to_base64 (((ptr[5]) >> 12) & 0x3f);
    tmp_buf[16] = int_to_base64 (((ptr[5]) >>  6) & 0x3f);
    tmp_buf[17] = sig[3];
    tmp_buf[18] = int_to_base64 (((ptr[5]) >>  0) & 0x3f);
    tmp_buf[19] = int_to_base64 (((ptr[4]) >> 12) & 0x3f);
    tmp_buf[20] = int_to_base64 (((ptr[4]) >>  6) & 0x3f);
    tmp_buf[21] = int_to_base64 (((ptr[4]) >>  0) & 0x3f);
    tmp_buf[22] = int_to_base64 (((ptr[7]) >> 12) & 0x3f);
    tmp_buf[23] = sig[4];
    tmp_buf[24] = int_to_base64 (((ptr[7]) >>  6) & 0x3f);
    tmp_buf[25] = int_to_base64 (((ptr[7]) >>  0) & 0x3f);
    tmp_buf[26] = int_to_base64 (((ptr[6]) >> 12) & 0x3f);
    tmp_buf[27] = int_to_base64 (((ptr[6]) >>  6) & 0x3f);
    tmp_buf[28] = int_to_base64 (((ptr[6]) >>  0) & 0x3f);
    tmp_buf[29] = sig[5];

    snprintf (out_buf, out_size, "%s:%s",
      tmp_buf,
      username);
  }
  else if (hash_mode == 101)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "{SHA}%s", ptr_plain);
  }
  else if (hash_mode == 124)
  {
    snprintf (out_buf, out_size, "sha1$%s$%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 141)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, ptr_salt);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    memset (tmp_buf + 20, 0, sizeof (tmp_buf) - 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    ptr_plain[27] = 0;

    snprintf (out_buf, out_size, "%s*0*%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1411)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);
    memcpy (tmp_buf + 32, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 32 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "%s%s", SIGNATURE_SHA256B64S, ptr_plain);
  }
  else if (hash_mode == 1421)
  {
    u8 *salt_ptr = (u8 *) salt.salt_buf;

    snprintf (out_buf, out_size, "%c%c%c%c%c%c%08x%08x%08x%08x%08x%08x%08x%08x",
      salt_ptr[0],
      salt_ptr[1],
      salt_ptr[2],
      salt_ptr[3],
      salt_ptr[4],
      salt_ptr[5],
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 1441)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, ptr_salt);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);

    memset (tmp_buf + 32, 0, sizeof (tmp_buf) - 32);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

    ptr_plain[43] = 0;

    snprintf (out_buf, out_size, "%s*1*%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1711)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
    digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
    digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
    digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
    digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
    digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
    digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
    digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

    memcpy (tmp_buf, digest_buf, 64);
    memcpy (tmp_buf + 64, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 64 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "%s%s", SIGNATURE_SHA512B64S, ptr_plain);
  }
  else if (hash_mode == 1722)
  {
    u32 *ptr = digest_buf;

    snprintf (out_buf, out_size, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      ptr[ 1], ptr[ 0],
      ptr[ 3], ptr[ 2],
      ptr[ 5], ptr[ 4],
      ptr[ 7], ptr[ 6],
      ptr[ 9], ptr[ 8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 4400)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if (hash_mode == 4700)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 4900)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 2612)
  {
    snprintf (out_buf, out_size, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_PHPS,
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 3711)
  {
    char *salt_ptr = (char *) salt.salt_buf;

    salt_ptr[salt.salt_len - 1] = 0;

    snprintf (out_buf, out_size, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_MEDIAWIKI_B,
      salt_ptr,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 10100)
  {
    snprintf (out_buf, out_size, "%08x%08x:%d:%d:%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      2,
      4,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]));
  }
  else if (hash_mode == 11700 || hash_mode == 11750 || hash_mode == 11760)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 11800 || hash_mode == 11850 || hash_mode == 11860)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[ 0]),
      byte_swap_32 (digest_buf[ 1]),
      byte_swap_32 (digest_buf[ 2]),
      byte_swap_32 (digest_buf[ 3]),
      byte_swap_32 (digest_buf[ 4]),
      byte_swap_32 (digest_buf[ 5]),
      byte_swap_32 (digest_buf[ 6]),
      byte_swap_32 (digest_buf[ 7]),
      byte_swap_32 (digest_buf[ 8]),
      byte_swap_32 (digest_buf[ 9]),
      byte_swap_32 (digest_buf[10]),
      byte_swap_32 (digest_buf[11]),
      byte_swap_32 (digest_buf[12]),
      byte_swap_32 (digest_buf[13]),
      byte_swap_32 (digest_buf[14]),
      byte_swap_32 (digest_buf[15]));
  }
  else
  {
    if (hash_type == HASH_TYPE_MD4)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_MD5)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_SHA1)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_SHA224)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6]);
    }
    else if (hash_type == HASH_TYPE_SHA256)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_SHA384)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10]);
    }
    else if (hash_type == HASH_TYPE_SHA512)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
    }
    else if (hash_type == HASH_TYPE_RIPEMD160)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_WHIRLPOOL)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[ 0],
        digest_buf[ 1],
        digest_buf[ 2],
        digest_buf[ 3],
        digest_buf[ 4],
        digest_buf[ 5],
        digest_buf[ 6],
        digest_buf[ 7],
        digest_buf[ 8],
        digest_buf[ 9],
        digest_buf[10],
        digest_buf[11],
        digest_buf[12],
        digest_buf[13],
        digest_buf[14],
        digest_buf[15]);
    }
    else if (hash_type == HASH_TYPE_MYSQL)
    {
      snprintf (out_buf, out_size, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
  }
}

int hashconfig_init (hashcat_ctx_t *hashcat_ctx)
{
    case    22:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = netscreen_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00022;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    30:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00030;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    50:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00050;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    60:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00060;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   120:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00120;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   121:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_LOWER;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00121;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   124:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = djangosha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00124;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   130:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00130;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   140:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00140;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   141:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_BASE64;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = episerver_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00141;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   150:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00150;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   160:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00160;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1410:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01410;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1411:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256b64s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01411;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1420:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01420;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1421:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = hmailserver_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01421;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1430:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01430;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1440:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01440;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1441:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_BASE64;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = episerver4_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01441;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1450:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01450;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1460:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01460;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PREFERED_THREAD;
                 hashconfig->kern_type      = KERN_TYPE_APR1CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5apr1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_01600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1710:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01710;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1711:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512b64s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1720:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01720;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1722:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = macos512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01722;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1730:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLTU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01730;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1740:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01740;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1750:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_PW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01750;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1760:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01760;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_VIRTUAL;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2611:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02611;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2612:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = phps_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02612;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2711:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = vb30_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3710:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03710;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3711:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = mediawiki_b_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3800:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4010:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_SLT_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04010;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4110:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04110;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4300:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_VIRTUAL;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD5U5_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4500:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA11;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04500;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4520:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04520;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4521:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = redmine_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04521;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4522:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = punbb_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04522;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4700:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  6000:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_RIPEMD160;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = ripemd160_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_06000;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  6100:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_WHIRLPOOL;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = whirlpool_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_06100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10100:  hashconfig->hash_type      = HASH_TYPE_SIPHASH;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SIPHASH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = siphash_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11700:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_STREEBOG_256;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11750:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_256_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11750;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11760:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_256_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11760;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11800:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_STREEBOG_512;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11850:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_512_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11850;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11860:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_512_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11860;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_OPENCART;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = opencart_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_13900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

  }

}
