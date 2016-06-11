/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define COMBINATOR_MODE_BASE_LEFT  10001
#define COMBINATOR_MODE_BASE_RIGHT 10002

#ifdef SHARED_H
#define _BCRYPT_
#define _SHA1_
#define _SHA256_
#define _SHA384_
#define _SHA512_
#define _MD4_
#define _MD5_
#define _MD5H_
#define _KECCAK_
#define _RIPEMD160_
#define _WHIRLPOOL_
#define _SAPB_
#define _CLOUDKEY_
#define _OFFICE2013_
#define _SIPHASH_
#define _PDF17L8_
#define _PBKDF2_MD5_
#define _PBKDF2_SHA1_
#define _PBKDF2_SHA256_
#define _PBKDF2_SHA512_
#define _RAR3_
#define _ZIP2_
#define _AXCRYPT_
#endif

#ifdef _SIPHASH_
/**
 * SipHash Constants
 */

#define SIPHASHM_0 0x736f6d6570736575
#define SIPHASHM_1 0x646f72616e646f6d
#define SIPHASHM_2 0x6c7967656e657261
#define SIPHASHM_3 0x7465646279746573
#endif

#if defined _BCRYPT_ || defined _PSAFE2_
/**
 * bcrypt Constants
 */

#define BCRYPTM_0 0x4F727068u
#define BCRYPTM_1 0x65616E42u
#define BCRYPTM_2 0x65686F6Cu
#define BCRYPTM_3 0x64657253u
#define BCRYPTM_4 0x63727944u
#define BCRYPTM_5 0x6F756274u
#endif

#if defined _SHA1_ || defined _SAPG_ || defined _OFFICE2007_ || defined _OFFICE2010_ || defined _OLDOFFICE34_ || defined _ANDROIDFDE_ || defined _DCC2_ || defined _WPA_ || defined _MD5_SHA1_ || defined _SHA1_MD5_ || defined _PSAFE2_ || defined _LOTUS8_ || defined _PBKDF2_SHA1_ || defined _RAR3_ || defined _SHA256_SHA1_ || defined _ZIP2_ || defined _AXCRYPT_
/**
 * SHA1 Constants
 */

#define SHA1M_A 0x67452301u
#define SHA1M_B 0xefcdab89u
#define SHA1M_C 0x98badcfeu
#define SHA1M_D 0x10325476u
#define SHA1M_E 0xc3d2e1f0u

#define SHA1C00 0x5a827999u
#define SHA1C01 0x6ed9eba1u
#define SHA1C02 0x8f1bbcdcu
#define SHA1C03 0xca62c1d6u
#endif

#if defined _SHA256_ || defined _PDF17L8_ || defined _SEVEN_ZIP_ || defined _ANDROIDFDE_ || defined _CLOUDKEY_ || defined _SCRYPT_ || defined _PBKDF2_SHA256_ || defined _SHA256_SHA1_ || defined _MS_DRSR_ || defined _ANDROIDFDE_SAMSUNG_ || defined _RAR5_ || defined _KEEPASS_
/**
 * SHA256 Constants
 */

#define SHA256M_A 0x6a09e667u
#define SHA256M_B 0xbb67ae85u
#define SHA256M_C 0x3c6ef372u
#define SHA256M_D 0xa54ff53au
#define SHA256M_E 0x510e527fu
#define SHA256M_F 0x9b05688cu
#define SHA256M_G 0x1f83d9abu
#define SHA256M_H 0x5be0cd19u

#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u
#endif

#if defined _MD4_ || defined _DCC2_ || defined _NETNTLMV2_ || defined _KRB5PA_ || defined _MS_DRSR_ || defined _KRB5TGS_
/**
 * MD4 Constants
 */

#define MD4M_A 0x67452301u
#define MD4M_B 0xefcdab89u
#define MD4M_C 0x98badcfeu
#define MD4M_D 0x10325476u

#define MD4S00  3u
#define MD4S01  7u
#define MD4S02 11u
#define MD4S03 19u
#define MD4S10  3u
#define MD4S11  5u
#define MD4S12  9u
#define MD4S13 13u
#define MD4S20  3u
#define MD4S21  9u
#define MD4S22 11u
#define MD4S23 15u

#define MD4C00 0x00000000u
#define MD4C01 0x5a827999u
#define MD4C02 0x6ed9eba1u
#endif

#if defined _MD5_ || defined _MD5H_ || defined _SAPB_ || defined _OLDOFFICE01_ || defined _WPA_ || defined _MD5_SHA1_ || defined _SHA1_MD5_ || defined _NETNTLMV2_ || defined _KRB5PA_  || defined _PBKDF2_MD5_ || defined _KRB5TGS_
/**
 * MD5 Constants
 */

#define MD5M_A 0x67452301u
#define MD5M_B 0xefcdab89u
#define MD5M_C 0x98badcfeu
#define MD5M_D 0x10325476u

#define MD5S00  7u
#define MD5S01 12u
#define MD5S02 17u
#define MD5S03 22u
#define MD5S10  5u
#define MD5S11  9u
#define MD5S12 14u
#define MD5S13 20u
#define MD5S20  4u
#define MD5S21 11u
#define MD5S22 16u
#define MD5S23 23u
#define MD5S30  6u
#define MD5S31 10u
#define MD5S32 15u
#define MD5S33 21u

#define MD5C00 0xd76aa478u
#define MD5C01 0xe8c7b756u
#define MD5C02 0x242070dbu
#define MD5C03 0xc1bdceeeu
#define MD5C04 0xf57c0fafu
#define MD5C05 0x4787c62au
#define MD5C06 0xa8304613u
#define MD5C07 0xfd469501u
#define MD5C08 0x698098d8u
#define MD5C09 0x8b44f7afu
#define MD5C0a 0xffff5bb1u
#define MD5C0b 0x895cd7beu
#define MD5C0c 0x6b901122u
#define MD5C0d 0xfd987193u
#define MD5C0e 0xa679438eu
#define MD5C0f 0x49b40821u
#define MD5C10 0xf61e2562u
#define MD5C11 0xc040b340u
#define MD5C12 0x265e5a51u
#define MD5C13 0xe9b6c7aau
#define MD5C14 0xd62f105du
#define MD5C15 0x02441453u
#define MD5C16 0xd8a1e681u
#define MD5C17 0xe7d3fbc8u
#define MD5C18 0x21e1cde6u
#define MD5C19 0xc33707d6u
#define MD5C1a 0xf4d50d87u
#define MD5C1b 0x455a14edu
#define MD5C1c 0xa9e3e905u
#define MD5C1d 0xfcefa3f8u
#define MD5C1e 0x676f02d9u
#define MD5C1f 0x8d2a4c8au
#define MD5C20 0xfffa3942u
#define MD5C21 0x8771f681u
#define MD5C22 0x6d9d6122u
#define MD5C23 0xfde5380cu
#define MD5C24 0xa4beea44u
#define MD5C25 0x4bdecfa9u
#define MD5C26 0xf6bb4b60u
#define MD5C27 0xbebfbc70u
#define MD5C28 0x289b7ec6u
#define MD5C29 0xeaa127fau
#define MD5C2a 0xd4ef3085u
#define MD5C2b 0x04881d05u
#define MD5C2c 0xd9d4d039u
#define MD5C2d 0xe6db99e5u
#define MD5C2e 0x1fa27cf8u
#define MD5C2f 0xc4ac5665u
#define MD5C30 0xf4292244u
#define MD5C31 0x432aff97u
#define MD5C32 0xab9423a7u
#define MD5C33 0xfc93a039u
#define MD5C34 0x655b59c3u
#define MD5C35 0x8f0ccc92u
#define MD5C36 0xffeff47du
#define MD5C37 0x85845dd1u
#define MD5C38 0x6fa87e4fu
#define MD5C39 0xfe2ce6e0u
#define MD5C3a 0xa3014314u
#define MD5C3b 0x4e0811a1u
#define MD5C3c 0xf7537e82u
#define MD5C3d 0xbd3af235u
#define MD5C3e 0x2ad7d2bbu
#define MD5C3f 0xeb86d391u
#endif

#if defined _SHA384_ || defined _PDF17L8_
/**
 * SHA384 Constants (64 bits)
 */

#define SHA384M_A 0xcbbb9d5dc1059ed8
#define SHA384M_B 0x629a292a367cd507
#define SHA384M_C 0x9159015a3070dd17
#define SHA384M_D 0x152fecd8f70e5939
#define SHA384M_E 0x67332667ffc00b31
#define SHA384M_F 0x8eb44a8768581511
#define SHA384M_G 0xdb0c2e0d64f98fa7
#define SHA384M_H 0x47b5481dbefa4fa4

#define SHA384C00 0x428a2f98d728ae22
#define SHA384C01 0x7137449123ef65cd
#define SHA384C02 0xb5c0fbcfec4d3b2f
#define SHA384C03 0xe9b5dba58189dbbc
#define SHA384C04 0x3956c25bf348b538
#define SHA384C05 0x59f111f1b605d019
#define SHA384C06 0x923f82a4af194f9b
#define SHA384C07 0xab1c5ed5da6d8118
#define SHA384C08 0xd807aa98a3030242
#define SHA384C09 0x12835b0145706fbe
#define SHA384C0a 0x243185be4ee4b28c
#define SHA384C0b 0x550c7dc3d5ffb4e2
#define SHA384C0c 0x72be5d74f27b896f
#define SHA384C0d 0x80deb1fe3b1696b1
#define SHA384C0e 0x9bdc06a725c71235
#define SHA384C0f 0xc19bf174cf692694
#define SHA384C10 0xe49b69c19ef14ad2
#define SHA384C11 0xefbe4786384f25e3
#define SHA384C12 0x0fc19dc68b8cd5b5
#define SHA384C13 0x240ca1cc77ac9c65
#define SHA384C14 0x2de92c6f592b0275
#define SHA384C15 0x4a7484aa6ea6e483
#define SHA384C16 0x5cb0a9dcbd41fbd4
#define SHA384C17 0x76f988da831153b5
#define SHA384C18 0x983e5152ee66dfab
#define SHA384C19 0xa831c66d2db43210
#define SHA384C1a 0xb00327c898fb213f
#define SHA384C1b 0xbf597fc7beef0ee4
#define SHA384C1c 0xc6e00bf33da88fc2
#define SHA384C1d 0xd5a79147930aa725
#define SHA384C1e 0x06ca6351e003826f
#define SHA384C1f 0x142929670a0e6e70
#define SHA384C20 0x27b70a8546d22ffc
#define SHA384C21 0x2e1b21385c26c926
#define SHA384C22 0x4d2c6dfc5ac42aed
#define SHA384C23 0x53380d139d95b3df
#define SHA384C24 0x650a73548baf63de
#define SHA384C25 0x766a0abb3c77b2a8
#define SHA384C26 0x81c2c92e47edaee6
#define SHA384C27 0x92722c851482353b
#define SHA384C28 0xa2bfe8a14cf10364
#define SHA384C29 0xa81a664bbc423001
#define SHA384C2a 0xc24b8b70d0f89791
#define SHA384C2b 0xc76c51a30654be30
#define SHA384C2c 0xd192e819d6ef5218
#define SHA384C2d 0xd69906245565a910
#define SHA384C2e 0xf40e35855771202a
#define SHA384C2f 0x106aa07032bbd1b8
#define SHA384C30 0x19a4c116b8d2d0c8
#define SHA384C31 0x1e376c085141ab53
#define SHA384C32 0x2748774cdf8eeb99
#define SHA384C33 0x34b0bcb5e19b48a8
#define SHA384C34 0x391c0cb3c5c95a63
#define SHA384C35 0x4ed8aa4ae3418acb
#define SHA384C36 0x5b9cca4f7763e373
#define SHA384C37 0x682e6ff3d6b2b8a3
#define SHA384C38 0x748f82ee5defb2fc
#define SHA384C39 0x78a5636f43172f60
#define SHA384C3a 0x84c87814a1f0ab72
#define SHA384C3b 0x8cc702081a6439ec
#define SHA384C3c 0x90befffa23631e28
#define SHA384C3d 0xa4506cebde82bde9
#define SHA384C3e 0xbef9a3f7b2c67915
#define SHA384C3f 0xc67178f2e372532b
#define SHA384C40 0xca273eceea26619c
#define SHA384C41 0xd186b8c721c0c207
#define SHA384C42 0xeada7dd6cde0eb1e
#define SHA384C43 0xf57d4f7fee6ed178
#define SHA384C44 0x06f067aa72176fba
#define SHA384C45 0x0a637dc5a2c898a6
#define SHA384C46 0x113f9804bef90dae
#define SHA384C47 0x1b710b35131c471b
#define SHA384C48 0x28db77f523047d84
#define SHA384C49 0x32caab7b40c72493
#define SHA384C4a 0x3c9ebe0a15c9bebc
#define SHA384C4b 0x431d67c49c100d4c
#define SHA384C4c 0x4cc5d4becb3e42b6
#define SHA384C4d 0x597f299cfc657e2a
#define SHA384C4e 0x5fcb6fab3ad6faec
#define SHA384C4f 0x6c44198c4a475817

#endif

#if defined _SHA512_ || defined _CLOUDKEY_ || defined _OFFICE2013_ || defined _PDF17L8_ || defined _PBKDF2_SHA512_
/**
 * SHA512 Constants (64 bits)
 */

#define SHA512M_A 0x6a09e667f3bcc908
#define SHA512M_B 0xbb67ae8584caa73b
#define SHA512M_C 0x3c6ef372fe94f82b
#define SHA512M_D 0xa54ff53a5f1d36f1
#define SHA512M_E 0x510e527fade682d1
#define SHA512M_F 0x9b05688c2b3e6c1f
#define SHA512M_G 0x1f83d9abfb41bd6b
#define SHA512M_H 0x5be0cd19137e2179

#define SHA512C00 0x428a2f98d728ae22
#define SHA512C01 0x7137449123ef65cd
#define SHA512C02 0xb5c0fbcfec4d3b2f
#define SHA512C03 0xe9b5dba58189dbbc
#define SHA512C04 0x3956c25bf348b538
#define SHA512C05 0x59f111f1b605d019
#define SHA512C06 0x923f82a4af194f9b
#define SHA512C07 0xab1c5ed5da6d8118
#define SHA512C08 0xd807aa98a3030242
#define SHA512C09 0x12835b0145706fbe
#define SHA512C0a 0x243185be4ee4b28c
#define SHA512C0b 0x550c7dc3d5ffb4e2
#define SHA512C0c 0x72be5d74f27b896f
#define SHA512C0d 0x80deb1fe3b1696b1
#define SHA512C0e 0x9bdc06a725c71235
#define SHA512C0f 0xc19bf174cf692694
#define SHA512C10 0xe49b69c19ef14ad2
#define SHA512C11 0xefbe4786384f25e3
#define SHA512C12 0x0fc19dc68b8cd5b5
#define SHA512C13 0x240ca1cc77ac9c65
#define SHA512C14 0x2de92c6f592b0275
#define SHA512C15 0x4a7484aa6ea6e483
#define SHA512C16 0x5cb0a9dcbd41fbd4
#define SHA512C17 0x76f988da831153b5
#define SHA512C18 0x983e5152ee66dfab
#define SHA512C19 0xa831c66d2db43210
#define SHA512C1a 0xb00327c898fb213f
#define SHA512C1b 0xbf597fc7beef0ee4
#define SHA512C1c 0xc6e00bf33da88fc2
#define SHA512C1d 0xd5a79147930aa725
#define SHA512C1e 0x06ca6351e003826f
#define SHA512C1f 0x142929670a0e6e70
#define SHA512C20 0x27b70a8546d22ffc
#define SHA512C21 0x2e1b21385c26c926
#define SHA512C22 0x4d2c6dfc5ac42aed
#define SHA512C23 0x53380d139d95b3df
#define SHA512C24 0x650a73548baf63de
#define SHA512C25 0x766a0abb3c77b2a8
#define SHA512C26 0x81c2c92e47edaee6
#define SHA512C27 0x92722c851482353b
#define SHA512C28 0xa2bfe8a14cf10364
#define SHA512C29 0xa81a664bbc423001
#define SHA512C2a 0xc24b8b70d0f89791
#define SHA512C2b 0xc76c51a30654be30
#define SHA512C2c 0xd192e819d6ef5218
#define SHA512C2d 0xd69906245565a910
#define SHA512C2e 0xf40e35855771202a
#define SHA512C2f 0x106aa07032bbd1b8
#define SHA512C30 0x19a4c116b8d2d0c8
#define SHA512C31 0x1e376c085141ab53
#define SHA512C32 0x2748774cdf8eeb99
#define SHA512C33 0x34b0bcb5e19b48a8
#define SHA512C34 0x391c0cb3c5c95a63
#define SHA512C35 0x4ed8aa4ae3418acb
#define SHA512C36 0x5b9cca4f7763e373
#define SHA512C37 0x682e6ff3d6b2b8a3
#define SHA512C38 0x748f82ee5defb2fc
#define SHA512C39 0x78a5636f43172f60
#define SHA512C3a 0x84c87814a1f0ab72
#define SHA512C3b 0x8cc702081a6439ec
#define SHA512C3c 0x90befffa23631e28
#define SHA512C3d 0xa4506cebde82bde9
#define SHA512C3e 0xbef9a3f7b2c67915
#define SHA512C3f 0xc67178f2e372532b
#define SHA512C40 0xca273eceea26619c
#define SHA512C41 0xd186b8c721c0c207
#define SHA512C42 0xeada7dd6cde0eb1e
#define SHA512C43 0xf57d4f7fee6ed178
#define SHA512C44 0x06f067aa72176fba
#define SHA512C45 0x0a637dc5a2c898a6
#define SHA512C46 0x113f9804bef90dae
#define SHA512C47 0x1b710b35131c471b
#define SHA512C48 0x28db77f523047d84
#define SHA512C49 0x32caab7b40c72493
#define SHA512C4a 0x3c9ebe0a15c9bebc
#define SHA512C4b 0x431d67c49c100d4c
#define SHA512C4c 0x4cc5d4becb3e42b6
#define SHA512C4d 0x597f299cfc657e2a
#define SHA512C4e 0x5fcb6fab3ad6faec
#define SHA512C4f 0x6c44198c4a475817

#define SHA512REV0 0x5218a97a1b97e8a0
#define SHA512REV1 0x4334c1bea164f555

#endif

#ifdef _RIPEMD160_
/**
 * RIPEMD160 Constants
 */

#define RIPEMD160M_A 0x67452301u
#define RIPEMD160M_B 0xefcdab89u
#define RIPEMD160M_C 0x98badcfeu
#define RIPEMD160M_D 0x10325476u
#define RIPEMD160M_E 0xc3d2e1f0u

#define RIPEMD160C00 0x00000000u
#define RIPEMD160C10 0x5a827999u
#define RIPEMD160C20 0x6ed9eba1u
#define RIPEMD160C30 0x8f1bbcdcu
#define RIPEMD160C40 0xa953fd4eu
#define RIPEMD160C50 0x50a28be6u
#define RIPEMD160C60 0x5c4dd124u
#define RIPEMD160C70 0x6d703ef3u
#define RIPEMD160C80 0x7a6d76e9u
#define RIPEMD160C90 0x00000000u

#define RIPEMD160S00 11u
#define RIPEMD160S01 14u
#define RIPEMD160S02 15u
#define RIPEMD160S03 12u
#define RIPEMD160S04  5u
#define RIPEMD160S05  8u
#define RIPEMD160S06  7u
#define RIPEMD160S07  9u
#define RIPEMD160S08 11u
#define RIPEMD160S09 13u
#define RIPEMD160S0A 14u
#define RIPEMD160S0B 15u
#define RIPEMD160S0C  6u
#define RIPEMD160S0D  7u
#define RIPEMD160S0E  9u
#define RIPEMD160S0F  8u

#define RIPEMD160S10  7u
#define RIPEMD160S11  6u
#define RIPEMD160S12  8u
#define RIPEMD160S13 13u
#define RIPEMD160S14 11u
#define RIPEMD160S15  9u
#define RIPEMD160S16  7u
#define RIPEMD160S17 15u
#define RIPEMD160S18  7u
#define RIPEMD160S19 12u
#define RIPEMD160S1A 15u
#define RIPEMD160S1B  9u
#define RIPEMD160S1C 11u
#define RIPEMD160S1D  7u
#define RIPEMD160S1E 13u
#define RIPEMD160S1F 12u

#define RIPEMD160S20 11u
#define RIPEMD160S21 13u
#define RIPEMD160S22  6u
#define RIPEMD160S23  7u
#define RIPEMD160S24 14u
#define RIPEMD160S25  9u
#define RIPEMD160S26 13u
#define RIPEMD160S27 15u
#define RIPEMD160S28 14u
#define RIPEMD160S29  8u
#define RIPEMD160S2A 13u
#define RIPEMD160S2B  6u
#define RIPEMD160S2C  5u
#define RIPEMD160S2D 12u
#define RIPEMD160S2E  7u
#define RIPEMD160S2F  5u

#define RIPEMD160S30 11u
#define RIPEMD160S31 12u
#define RIPEMD160S32 14u
#define RIPEMD160S33 15u
#define RIPEMD160S34 14u
#define RIPEMD160S35 15u
#define RIPEMD160S36  9u
#define RIPEMD160S37  8u
#define RIPEMD160S38  9u
#define RIPEMD160S39 14u
#define RIPEMD160S3A  5u
#define RIPEMD160S3B  6u
#define RIPEMD160S3C  8u
#define RIPEMD160S3D  6u
#define RIPEMD160S3E  5u
#define RIPEMD160S3F 12u

#define RIPEMD160S40  9u
#define RIPEMD160S41 15u
#define RIPEMD160S42  5u
#define RIPEMD160S43 11u
#define RIPEMD160S44  6u
#define RIPEMD160S45  8u
#define RIPEMD160S46 13u
#define RIPEMD160S47 12u
#define RIPEMD160S48  5u
#define RIPEMD160S49 12u
#define RIPEMD160S4A 13u
#define RIPEMD160S4B 14u
#define RIPEMD160S4C 11u
#define RIPEMD160S4D  8u
#define RIPEMD160S4E  5u
#define RIPEMD160S4F  6u

#define RIPEMD160S50  8u
#define RIPEMD160S51  9u
#define RIPEMD160S52  9u
#define RIPEMD160S53 11u
#define RIPEMD160S54 13u
#define RIPEMD160S55 15u
#define RIPEMD160S56 15u
#define RIPEMD160S57  5u
#define RIPEMD160S58  7u
#define RIPEMD160S59  7u
#define RIPEMD160S5A  8u
#define RIPEMD160S5B 11u
#define RIPEMD160S5C 14u
#define RIPEMD160S5D 14u
#define RIPEMD160S5E 12u
#define RIPEMD160S5F  6u

#define RIPEMD160S60  9u
#define RIPEMD160S61 13u
#define RIPEMD160S62 15u
#define RIPEMD160S63  7u
#define RIPEMD160S64 12u
#define RIPEMD160S65  8u
#define RIPEMD160S66  9u
#define RIPEMD160S67 11u
#define RIPEMD160S68  7u
#define RIPEMD160S69  7u
#define RIPEMD160S6A 12u
#define RIPEMD160S6B  7u
#define RIPEMD160S6C  6u
#define RIPEMD160S6D 15u
#define RIPEMD160S6E 13u
#define RIPEMD160S6F 11u

#define RIPEMD160S70  9u
#define RIPEMD160S71  7u
#define RIPEMD160S72 15u
#define RIPEMD160S73 11u
#define RIPEMD160S74  8u
#define RIPEMD160S75  6u
#define RIPEMD160S76  6u
#define RIPEMD160S77 14u
#define RIPEMD160S78 12u
#define RIPEMD160S79 13u
#define RIPEMD160S7A  5u
#define RIPEMD160S7B 14u
#define RIPEMD160S7C 13u
#define RIPEMD160S7D 13u
#define RIPEMD160S7E  7u
#define RIPEMD160S7F  5u

#define RIPEMD160S80 15u
#define RIPEMD160S81  5u
#define RIPEMD160S82  8u
#define RIPEMD160S83 11u
#define RIPEMD160S84 14u
#define RIPEMD160S85 14u
#define RIPEMD160S86  6u
#define RIPEMD160S87 14u
#define RIPEMD160S88  6u
#define RIPEMD160S89  9u
#define RIPEMD160S8A 12u
#define RIPEMD160S8B  9u
#define RIPEMD160S8C 12u
#define RIPEMD160S8D  5u
#define RIPEMD160S8E 15u
#define RIPEMD160S8F  8u

#define RIPEMD160S90  8u
#define RIPEMD160S91  5u
#define RIPEMD160S92 12u
#define RIPEMD160S93  9u
#define RIPEMD160S94 12u
#define RIPEMD160S95  5u
#define RIPEMD160S96 14u
#define RIPEMD160S97  6u
#define RIPEMD160S98  8u
#define RIPEMD160S99 13u
#define RIPEMD160S9A  6u
#define RIPEMD160S9B  5u
#define RIPEMD160S9C 15u
#define RIPEMD160S9D 13u
#define RIPEMD160S9E 11u
#define RIPEMD160S9F 11u

#endif

#ifdef _KECCAK_
/**
 * KECCAK Constants
 */

#define KECCAK_RNDC_00 0x0000000000000001
#define KECCAK_RNDC_01 0x0000000000008082
#define KECCAK_RNDC_02 0x000000000000808a
#define KECCAK_RNDC_03 0x0000000080008000
#define KECCAK_RNDC_04 0x000000000000808b
#define KECCAK_RNDC_05 0x0000000080000001
#define KECCAK_RNDC_06 0x0000000080008081
#define KECCAK_RNDC_07 0x0000000000008009
#define KECCAK_RNDC_08 0x000000000000008a
#define KECCAK_RNDC_09 0x0000000000000088
#define KECCAK_RNDC_10 0x0000000080008009
#define KECCAK_RNDC_11 0x000000008000000a
#define KECCAK_RNDC_12 0x000000008000808b
#define KECCAK_RNDC_13 0x000000000000008b
#define KECCAK_RNDC_14 0x0000000000008089
#define KECCAK_RNDC_15 0x0000000000008003
#define KECCAK_RNDC_16 0x0000000000008002
#define KECCAK_RNDC_17 0x0000000000000080
#define KECCAK_RNDC_18 0x000000000000800a
#define KECCAK_RNDC_19 0x000000008000000a
#define KECCAK_RNDC_20 0x0000000080008081
#define KECCAK_RNDC_21 0x0000000000008080
#define KECCAK_RNDC_22 0x0000000080000001
#define KECCAK_RNDC_23 0x0000000080008008

#define KECCAK_PILN_00 10
#define KECCAK_PILN_01  7
#define KECCAK_PILN_02 11
#define KECCAK_PILN_03 17
#define KECCAK_PILN_04 18
#define KECCAK_PILN_05  3
#define KECCAK_PILN_06  5
#define KECCAK_PILN_07 16
#define KECCAK_PILN_08  8
#define KECCAK_PILN_09 21
#define KECCAK_PILN_10 24
#define KECCAK_PILN_11  4
#define KECCAK_PILN_12 15
#define KECCAK_PILN_13 23
#define KECCAK_PILN_14 19
#define KECCAK_PILN_15 13
#define KECCAK_PILN_16 12
#define KECCAK_PILN_17  2
#define KECCAK_PILN_18 20
#define KECCAK_PILN_19 14
#define KECCAK_PILN_20 22
#define KECCAK_PILN_21  9
#define KECCAK_PILN_22  6
#define KECCAK_PILN_23  1

#define KECCAK_ROTC_00  1
#define KECCAK_ROTC_01  3
#define KECCAK_ROTC_02  6
#define KECCAK_ROTC_03 10
#define KECCAK_ROTC_04 15
#define KECCAK_ROTC_05 21
#define KECCAK_ROTC_06 28
#define KECCAK_ROTC_07 36
#define KECCAK_ROTC_08 45
#define KECCAK_ROTC_09 55
#define KECCAK_ROTC_10  2
#define KECCAK_ROTC_11 14
#define KECCAK_ROTC_12 27
#define KECCAK_ROTC_13 41
#define KECCAK_ROTC_14 56
#define KECCAK_ROTC_15  8
#define KECCAK_ROTC_16 25
#define KECCAK_ROTC_17 43
#define KECCAK_ROTC_18 62
#define KECCAK_ROTC_19 18
#define KECCAK_ROTC_20 39
#define KECCAK_ROTC_21 61
#define KECCAK_ROTC_22 20
#define KECCAK_ROTC_23 44


#endif

#ifdef _MYSQL323_
/**
 * MYSQL323 Constants
 */

#define MYSQL323_A 0x50305735
#define MYSQL323_B 0x12345671

#endif
