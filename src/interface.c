/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "common.h"
#include "types.h"
#include "bitops.h"
#include "memory.h"
#include "convert.h"
#include "event.h"
#include "inc_hash_constants.h"
#include "cpu_aes.h"
#include "cpu_crc32.h"
#include "cpu_des.h"
#include "cpu_md4.h"
#include "cpu_md5.h"
#include "cpu_sha1.h"
#include "cpu_sha256.h"
#include "cpu_blake2.h"
#include "interface.h"
#include "ext_lzma.h"

static const char OPTI_STR_ZERO_BYTE[]         = "Zero-Byte";
static const char OPTI_STR_PRECOMPUTE_INIT[]   = "Precompute-Init";
static const char OPTI_STR_PRECOMPUTE_MERKLE[] = "Precompute-Merkle-Demgard";
static const char OPTI_STR_PRECOMPUTE_PERMUT[] = "Precompute-Final-Permutation";
static const char OPTI_STR_MEET_IN_MIDDLE[]    = "Meet-In-The-Middle";
static const char OPTI_STR_EARLY_SKIP[]        = "Early-Skip";
static const char OPTI_STR_NOT_SALTED[]        = "Not-Salted";
static const char OPTI_STR_NOT_ITERATED[]      = "Not-Iterated";
static const char OPTI_STR_PREPENDED_SALT[]    = "Prepended-Salt";
static const char OPTI_STR_APPENDED_SALT[]     = "Appended-Salt";
static const char OPTI_STR_SINGLE_HASH[]       = "Single-Hash";
static const char OPTI_STR_SINGLE_SALT[]       = "Single-Salt";
static const char OPTI_STR_BRUTE_FORCE[]       = "Brute-Force";
static const char OPTI_STR_RAW_HASH[]          = "Raw-Hash";
static const char OPTI_STR_SLOW_HASH_SIMD[]    = "Slow-Hash-SIMD";
static const char OPTI_STR_USES_BITS_8[]       = "Uses-8-Bit";
static const char OPTI_STR_USES_BITS_16[]      = "Uses-16-Bit";
static const char OPTI_STR_USES_BITS_32[]      = "Uses-32-Bit";
static const char OPTI_STR_USES_BITS_64[]      = "Uses-64-Bit";

static const char PA_000[] = "OK";
static const char PA_001[] = "Ignored due to comment";
static const char PA_002[] = "Ignored due to zero length";
static const char PA_003[] = "Line-length exception";
static const char PA_004[] = "Hash-length exception";
static const char PA_005[] = "Hash-value exception";
static const char PA_006[] = "Salt-length exception";
static const char PA_007[] = "Salt-value exception";
static const char PA_008[] = "Salt-iteration count exception";
static const char PA_009[] = "Separator unmatched";
static const char PA_010[] = "Signature unmatched";
static const char PA_011[] = "Invalid hccapx file size";
static const char PA_012[] = "Invalid hccapx eapol size";
static const char PA_013[] = "Invalid psafe2 filesize";
static const char PA_014[] = "Invalid psafe3 filesize";
static const char PA_015[] = "Invalid truecrypt filesize";
static const char PA_016[] = "Invalid veracrypt filesize";
static const char PA_017[] = "Invalid SIP directive, only MD5 is supported";
static const char PA_018[] = "Hash-file exception";
static const char PA_019[] = "Hash-encoding exception";
static const char PA_020[] = "Salt-encoding exception";
static const char PA_021[] = "Invalid LUKS filesize";
static const char PA_022[] = "Invalid LUKS identifier";
static const char PA_023[] = "Invalid LUKS version";
static const char PA_024[] = "Invalid or unsupported LUKS cipher type";
static const char PA_025[] = "Invalid or unsupported LUKS cipher mode";
static const char PA_026[] = "Invalid or unsupported LUKS hash type";
static const char PA_027[] = "Invalid LUKS key size";
static const char PA_028[] = "Disabled LUKS key detected";
static const char PA_029[] = "Invalid LUKS key AF stripes count";
static const char PA_030[] = "Invalid combination of LUKS hash type and cipher type";
static const char PA_031[] = "Invalid hccapx signature";
static const char PA_032[] = "Invalid hccapx version";
static const char PA_033[] = "Invalid hccapx message pair";
static const char PA_255[] = "Unknown error";

static const char HT_00000[] = "MD5";
static const char HT_00010[] = "md5($pass.$salt)";
static const char HT_00020[] = "md5($salt.$pass)";
static const char HT_00030[] = "md5(utf16le($pass).$salt)";
static const char HT_00040[] = "md5($salt.utf16le($pass))";
static const char HT_00050[] = "HMAC-MD5 (key = $pass)";
static const char HT_00060[] = "HMAC-MD5 (key = $salt)";
static const char HT_00100[] = "SHA1";
static const char HT_00110[] = "sha1($pass.$salt)";
static const char HT_00120[] = "sha1($salt.$pass)";
static const char HT_00130[] = "sha1(utf16le($pass).$salt)";
static const char HT_00140[] = "sha1($salt.utf16le($pass))";
static const char HT_00150[] = "HMAC-SHA1 (key = $pass)";
static const char HT_00160[] = "HMAC-SHA1 (key = $salt)";
static const char HT_00200[] = "MySQL323";
static const char HT_00300[] = "MySQL4.1/MySQL5";
static const char HT_00400[] = "phpass, WordPress (MD5), phpBB3 (MD5), Joomla (MD5)";
static const char HT_00500[] = "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)";
static const char HT_00501[] = "Juniper IVE";
static const char HT_00600[] = "BLAKE2-512";
static const char HT_00900[] = "MD4";
static const char HT_01000[] = "NTLM";
static const char HT_01100[] = "Domain Cached Credentials (DCC), MS Cache";
static const char HT_01300[] = "SHA-224";
static const char HT_01400[] = "SHA-256";
static const char HT_01410[] = "sha256($pass.$salt)";
static const char HT_01420[] = "sha256($salt.$pass)";
static const char HT_01430[] = "sha256(utf16le($pass).$salt)";
static const char HT_01440[] = "sha256($salt.utf16le($pass))";
static const char HT_01450[] = "HMAC-SHA256 (key = $pass)";
static const char HT_01460[] = "HMAC-SHA256 (key = $salt)";
static const char HT_01500[] = "descrypt, DES (Unix), Traditional DES";
static const char HT_01600[] = "Apache $apr1$ MD5, md5apr1, MD5 (APR)";
static const char HT_01700[] = "SHA-512";
static const char HT_01710[] = "sha512($pass.$salt)";
static const char HT_01720[] = "sha512($salt.$pass)";
static const char HT_01730[] = "sha512(utf16le($pass).$salt)";
static const char HT_01740[] = "sha512($salt.utf16le($pass))";
static const char HT_01750[] = "HMAC-SHA512 (key = $pass)";
static const char HT_01760[] = "HMAC-SHA512 (key = $salt)";
static const char HT_01800[] = "sha512crypt $6$, SHA512 (Unix)";
static const char HT_02100[] = "Domain Cached Credentials 2 (DCC2), MS Cache 2";
static const char HT_02400[] = "Cisco-PIX MD5";
static const char HT_02410[] = "Cisco-ASA MD5";
static const char HT_02500[] = "WPA/WPA2";
static const char HT_02600[] = "md5(md5($pass))";
static const char HT_03000[] = "LM";
static const char HT_03100[] = "Oracle H: Type (Oracle 7+)";
static const char HT_03200[] = "bcrypt $2*$, Blowfish (Unix)";
static const char HT_03710[] = "md5($salt.md5($pass))";
static const char HT_03711[] = "MediaWiki B type";
static const char HT_03800[] = "md5($salt.$pass.$salt)";
static const char HT_03910[] = "md5(md5($pass).md5($salt))";
static const char HT_04010[] = "md5($salt.md5($salt.$pass))";
static const char HT_04110[] = "md5($salt.md5($pass.$salt))";
static const char HT_04300[] = "md5(strtoupper(md5($pass)))";
static const char HT_04400[] = "md5(sha1($pass))";
static const char HT_04500[] = "sha1(sha1($pass))";
static const char HT_04520[] = "sha1($salt.sha1($pass))";
static const char HT_04700[] = "sha1(md5($pass))";
static const char HT_04800[] = "iSCSI CHAP authentication, MD5(CHAP)";
static const char HT_04900[] = "sha1($salt.$pass.$salt)";
static const char HT_05000[] = "SHA-3 (Keccak)";
static const char HT_05100[] = "Half MD5";
static const char HT_05200[] = "Password Safe v3";
static const char HT_05300[] = "IKE-PSK MD5";
static const char HT_05400[] = "IKE-PSK SHA1";
static const char HT_05500[] = "NetNTLMv1 / NetNTLMv1+ESS";
static const char HT_05600[] = "NetNTLMv2";
static const char HT_05700[] = "Cisco-IOS type 4 (SHA256)";
static const char HT_05800[] = "Samsung Android Password/PIN";
static const char HT_06000[] = "RIPEMD-160";
static const char HT_06100[] = "Whirlpool";
static const char HT_06300[] = "AIX {smd5}";
static const char HT_06400[] = "AIX {ssha256}";
static const char HT_06500[] = "AIX {ssha512}";
static const char HT_06600[] = "1Password, agilekeychain";
static const char HT_06700[] = "AIX {ssha1}";
static const char HT_06800[] = "LastPass + LastPass sniffed";
static const char HT_06900[] = "GOST R 34.11-94";
static const char HT_07000[] = "FortiGate (FortiOS)";
static const char HT_07100[] = "OSX v10.8+ (PBKDF2-SHA512)";
static const char HT_07200[] = "GRUB 2";
static const char HT_07300[] = "IPMI2 RAKP HMAC-SHA1";
static const char HT_07400[] = "sha256crypt $5$, SHA256 (Unix)";
static const char HT_07500[] = "Kerberos 5 AS-REQ Pre-Auth etype 23";
static const char HT_07700[] = "SAP CODVN B (BCODE)";
static const char HT_07800[] = "SAP CODVN F/G (PASSCODE)";
static const char HT_07900[] = "Drupal7";
static const char HT_08000[] = "Sybase ASE";
static const char HT_08100[] = "Citrix NetScaler";
static const char HT_08200[] = "1Password, cloudkeychain";
static const char HT_08300[] = "DNSSEC (NSEC3)";
static const char HT_08400[] = "WBB3 (Woltlab Burning Board)";
static const char HT_08500[] = "RACF";
static const char HT_08600[] = "Lotus Notes/Domino 5";
static const char HT_08700[] = "Lotus Notes/Domino 6";
static const char HT_08800[] = "Android FDE <= 4.3";
static const char HT_08900[] = "scrypt";
static const char HT_09000[] = "Password Safe v2";
static const char HT_09100[] = "Lotus Notes/Domino 8";
static const char HT_09200[] = "Cisco-IOS $8$ (PBKDF2-SHA256)";
static const char HT_09300[] = "Cisco-IOS $9$ (scrypt)";
static const char HT_09400[] = "MS Office 2007";
static const char HT_09500[] = "MS Office 2010";
static const char HT_09600[] = "MS Office 2013";
static const char HT_09700[] = "MS Office <= 2003 $0/$1, MD5 + RC4";
static const char HT_09710[] = "MS Office <= 2003 $0/$1, MD5 + RC4, collider #1";
static const char HT_09720[] = "MS Office <= 2003 $0/$1, MD5 + RC4, collider #2";
static const char HT_09800[] = "MS Office <= 2003 $3/$4, SHA1 + RC4";
static const char HT_09810[] = "MS Office <= 2003 $3, SHA1 + RC4, collider #1";
static const char HT_09820[] = "MS Office <= 2003 $3, SHA1 + RC4, collider #2";
static const char HT_09900[] = "Radmin2";
static const char HT_10000[] = "Django (PBKDF2-SHA256)";
static const char HT_10100[] = "SipHash";
static const char HT_10200[] = "CRAM-MD5";
static const char HT_10300[] = "SAP CODVN H (PWDSALTEDHASH) iSSHA-1";
static const char HT_10400[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4)";
static const char HT_10410[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1";
static const char HT_10420[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2";
static const char HT_10500[] = "PDF 1.4 - 1.6 (Acrobat 5 - 8)";
static const char HT_10600[] = "PDF 1.7 Level 3 (Acrobat 9)";
static const char HT_10700[] = "PDF 1.7 Level 8 (Acrobat 10 - 11)";
static const char HT_10800[] = "SHA-384";
static const char HT_10900[] = "PBKDF2-HMAC-SHA256";
static const char HT_11000[] = "PrestaShop";
static const char HT_11100[] = "PostgreSQL CRAM (MD5)";
static const char HT_11200[] = "MySQL CRAM (SHA1)";
static const char HT_11300[] = "Bitcoin/Litecoin wallet.dat";
static const char HT_11400[] = "SIP digest authentication (MD5)";
static const char HT_11500[] = "CRC32";
static const char HT_11600[] = "7-Zip";
static const char HT_11700[] = "GOST R 34.11-2012 (Streebog) 256-bit";
static const char HT_11800[] = "GOST R 34.11-2012 (Streebog) 512-bit";
static const char HT_11900[] = "PBKDF2-HMAC-MD5";
static const char HT_12000[] = "PBKDF2-HMAC-SHA1";
static const char HT_12100[] = "PBKDF2-HMAC-SHA512";
static const char HT_12200[] = "eCryptfs";
static const char HT_12300[] = "Oracle T: Type (Oracle 12+)";
static const char HT_12400[] = "BSDi Crypt, Extended DES";
static const char HT_12500[] = "RAR3-hp";
static const char HT_12600[] = "ColdFusion 10+";
static const char HT_12700[] = "Blockchain, My Wallet";
static const char HT_12800[] = "MS-AzureSync PBKDF2-HMAC-SHA256";
static const char HT_12900[] = "Android FDE (Samsung DEK)";
static const char HT_13000[] = "RAR5";
static const char HT_13100[] = "Kerberos 5 TGS-REP etype 23";
static const char HT_13200[] = "AxCrypt";
static const char HT_13300[] = "AxCrypt in-memory SHA1";
static const char HT_13400[] = "KeePass 1 (AES/Twofish) and KeePass 2 (AES)";
static const char HT_13500[] = "PeopleSoft PS_TOKEN";
static const char HT_13600[] = "WinZip";
static const char HT_13800[] = "Windows Phone 8+ PIN/password";
static const char HT_13900[] = "OpenCart";
static const char HT_14000[] = "DES (PT = $salt, key = $pass)";
static const char HT_14100[] = "3DES (PT = $salt, key = $pass)";
static const char HT_14400[] = "sha1(CX)";
static const char HT_14600[] = "LUKS";
static const char HT_14700[] = "iTunes backup < 10.0";
static const char HT_14800[] = "iTunes backup >= 10.0";
static const char HT_14900[] = "Skip32 (PT = $salt, key = $pass)";
static const char HT_15000[] = "FileZilla Server >= 0.9.55";
static const char HT_15100[] = "Juniper/NetBSD sha1crypt";
static const char HT_15200[] = "Blockchain, My Wallet, V2";
static const char HT_15300[] = "DPAPI masterkey file v1 and v2";
static const char HT_15400[] = "ChaCha20";
static const char HT_15500[] = "JKS Java Key Store Private Keys (SHA1)";
static const char HT_15600[] = "Ethereum Wallet, PBKDF2-HMAC-SHA256";
static const char HT_15700[] = "Ethereum Wallet, SCRYPT";
static const char HT_99999[] = "Plaintext";

static const char HT_00011[] = "Joomla < 2.5.18";
static const char HT_00012[] = "PostgreSQL";
static const char HT_00021[] = "osCommerce, xt:Commerce";
static const char HT_00022[] = "Juniper NetScreen/SSG (ScreenOS)";
static const char HT_00023[] = "Skype";
static const char HT_00101[] = "nsldap, SHA-1(Base64), Netscape LDAP SHA";
static const char HT_00111[] = "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA";
static const char HT_00112[] = "Oracle S: Type (Oracle 11+)";
static const char HT_00121[] = "SMF (Simple Machines Forum) > v1.1";
static const char HT_00122[] = "OSX v10.4, OSX v10.5, OSX v10.6";
static const char HT_00124[] = "Django (SHA-1)";
static const char HT_00125[] = "ArubaOS";
static const char HT_00131[] = "MSSQL (2000)";
static const char HT_00132[] = "MSSQL (2005)";
static const char HT_00133[] = "PeopleSoft";
static const char HT_00141[] = "Episerver 6.x < .NET 4";
static const char HT_01411[] = "SSHA-256(Base64), LDAP {SSHA256}";
static const char HT_01421[] = "hMailServer";
static const char HT_01441[] = "Episerver 6.x >= .NET 4";
static const char HT_01711[] = "SSHA-512(Base64), LDAP {SSHA512}";
static const char HT_01722[] = "OSX v10.7";
static const char HT_01731[] = "MSSQL (2012, 2014)";
static const char HT_02611[] = "vBulletin < v3.8.5";
static const char HT_02612[] = "PHPS";
static const char HT_02711[] = "vBulletin >= v3.8.5";
static const char HT_02811[] = "IPB2+ (Invision Power Board), MyBB 1.2+";
static const char HT_04521[] = "Redmine";
static const char HT_04522[] = "PunBB";
static const char HT_06211[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit";
static const char HT_06212[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1024 bit";
static const char HT_06213[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1536 bit";
static const char HT_06221[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit";
static const char HT_06222[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 1024 bit";
static const char HT_06223[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 1536 bit";
static const char HT_06231[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit";
static const char HT_06232[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 1024 bit";
static const char HT_06233[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 1536 bit";
static const char HT_06241[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit + boot-mode";
static const char HT_06242[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1024 bit + boot-mode";
static const char HT_06243[] = "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1536 bit + boot-mode";
static const char HT_13711[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit";
static const char HT_13712[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1024 bit";
static const char HT_13713[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1536 bit";
static const char HT_13721[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit";
static const char HT_13722[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 1024 bit";
static const char HT_13723[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 1536 bit";
static const char HT_13731[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit";
static const char HT_13732[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 1024 bit";
static const char HT_13733[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 1536 bit";
static const char HT_13741[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit + boot-mode";
static const char HT_13742[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1024 bit + boot-mode";
static const char HT_13743[] = "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 1536 bit + boot-mode";
static const char HT_13751[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit";
static const char HT_13752[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1024 bit";
static const char HT_13753[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1536 bit";
static const char HT_13761[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit + boot-mode";
static const char HT_13762[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1024 bit + boot-mode";
static const char HT_13763[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1536 bit + boot-mode";
static const char HT_12001[] = "Atlassian (PBKDF2-HMAC-SHA1)";

static const char SIGNATURE_ANDROIDFDE[]       = "$fde$";
static const char SIGNATURE_AXCRYPT[]          = "$axcrypt$*1";
static const char SIGNATURE_AXCRYPT_SHA1[]     = "$axcrypt_sha1";
static const char SIGNATURE_BCRYPT1[]          = "$2a$";
static const char SIGNATURE_BCRYPT2[]          = "$2b$";
static const char SIGNATURE_BCRYPT3[]          = "$2x$";
static const char SIGNATURE_BCRYPT4[]          = "$2y$";
static const char SIGNATURE_BITCOIN_WALLET[]   = "$bitcoin$";
static const char SIGNATURE_BSDICRYPT[]        = "_";
static const char SIGNATURE_CISCO8[]           = "$8$";
static const char SIGNATURE_CISCO9[]           = "$9$";
static const char SIGNATURE_CRAM_MD5[]         = "$cram_md5$";
static const char SIGNATURE_DCC2[]             = "$DCC2$";
static const char SIGNATURE_DJANGOPBKDF2[]     = "pbkdf2_sha256$";
static const char SIGNATURE_DJANGOSHA1[]       = "sha1$";
static const char SIGNATURE_DPAPIMK[]          = "$DPAPImk$";
static const char SIGNATURE_DRUPAL7[]          = "$S$";
static const char SIGNATURE_ECRYPTFS[]         = "$ecryptfs$";
static const char SIGNATURE_EPISERVER4[]       = "$episerver$*1*";
static const char SIGNATURE_EPISERVER[]        = "$episerver$*0*";
static const char SIGNATURE_KEEPASS[]          = "$keepass$";
static const char SIGNATURE_KRB5PA[]           = "$krb5pa$23";
static const char SIGNATURE_KRB5TGS[]          = "$krb5tgs$23";
static const char SIGNATURE_MD5AIX[]           = "{smd5}";
static const char SIGNATURE_MD5APR1[]          = "$apr1$";
static const char SIGNATURE_MD5CRYPT[]         = "$1$";
static const char SIGNATURE_MEDIAWIKI_B[]      = "$B$";
static const char SIGNATURE_MS_DRSR[]          = "v1;PPH1_MD4";
static const char SIGNATURE_MSSQL[]            = "0x0100";
static const char SIGNATURE_MSSQL2012[]        = "0x0200";
static const char SIGNATURE_MYSQL_AUTH[]       = "$mysqlna$";
static const char SIGNATURE_MYWALLET[]         = "$blockchain$";
static const char SIGNATURE_MYWALLETV2[]       = "$blockchain$v2$";
static const char SIGNATURE_NETSCALER[]        = "1";
static const char SIGNATURE_OFFICE2007[]       = "$office$";
static const char SIGNATURE_OFFICE2010[]       = "$office$";
static const char SIGNATURE_OFFICE2013[]       = "$office$";
static const char SIGNATURE_OLDOFFICE0[]       = "$oldoffice$0";
static const char SIGNATURE_OLDOFFICE1[]       = "$oldoffice$1";
static const char SIGNATURE_OLDOFFICE3[]       = "$oldoffice$3";
static const char SIGNATURE_OLDOFFICE4[]       = "$oldoffice$4";
static const char SIGNATURE_PBKDF2_MD5[]       = "md5:";
static const char SIGNATURE_PBKDF2_SHA1[]      = "sha1:";
static const char SIGNATURE_PBKDF2_SHA256[]    = "sha256:";
static const char SIGNATURE_PBKDF2_SHA512[]    = "sha512:";
static const char SIGNATURE_PDF[]              = "$pdf$";
static const char SIGNATURE_PHPASS1[]          = "$P$";
static const char SIGNATURE_PHPASS2[]          = "$H$";
static const char SIGNATURE_PHPS[]             = "$PHPS$";
static const char SIGNATURE_POSTGRESQL_AUTH[]  = "$postgres$";
static const char SIGNATURE_PSAFE3[]           = "PWS3";
static const char SIGNATURE_RACF[]             = "$racf$";
static const char SIGNATURE_RAR3[]             = "$RAR3$";
static const char SIGNATURE_RAR5[]             = "$rar5$";
static const char SIGNATURE_SAPH_SHA1[]        = "{x-issha, ";
static const char SIGNATURE_SCRYPT[]           = "SCRYPT";
static const char SIGNATURE_SEVEN_ZIP[]        = "$7z$";
static const char SIGNATURE_SHA1AIX[]          = "{ssha1}";
static const char SIGNATURE_SHA1B64[]          = "{SHA}";
static const char SIGNATURE_SHA256AIX[]        = "{ssha256}";
static const char SIGNATURE_SHA256B64S[]       = "{SSHA256}";
static const char SIGNATURE_SHA256CRYPT[]      = "$5$";
static const char SIGNATURE_SHA512AIX[]        = "{ssha512}";
static const char SIGNATURE_SHA512B64S[]       = "{SSHA512}";
static const char SIGNATURE_SHA512CRYPT[]      = "$6$";
static const char SIGNATURE_SHA512GRUB[]       = "grub.pbkdf2.sha512.";
static const char SIGNATURE_SHA512OSX[]        = "$ml$";
static const char SIGNATURE_SIP_AUTH[]         = "$sip$*";
static const char SIGNATURE_SSHA1B64_lower[]   = "{ssha}";
static const char SIGNATURE_SSHA1B64_upper[]   = "{SSHA}";
static const char SIGNATURE_SYBASEASE[]        = "0xc007";
static const char SIGNATURE_ZIP2_START[]       = "$zip2$";
static const char SIGNATURE_ZIP2_STOP[]        = "$/zip2$";
static const char SIGNATURE_ITUNES_BACKUP[]    = "$itunes_backup$";
static const char SIGNATURE_FORTIGATE[]        = "AK1";
static const char SIGNATURE_ATLASSIAN[]        = "{PKCS5S2}";
static const char SIGNATURE_NETBSD_SHA1CRYPT[] = "$sha1$";
static const char SIGNATURE_BLAKE2B[]          = "$BLAKE2$";
static const char SIGNATURE_CHACHA20[]         = "$chacha20$";
static const char SIGNATURE_JKS_SHA1[]         = "$jksprivk$";
static const char SIGNATURE_ETHEREUM_PBKDF2[]  = "$ethereum$p";
static const char SIGNATURE_ETHEREUM_SCRYPT[]  = "$ethereum$s";

/**
 * decoder / encoder
 */

static void juniper_decrypt_hash (u8 *in, u8 *out)
{
  // base64 decode

  u8 base64_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) in, DISPLAY_LEN_MIN_501, base64_buf);

  // iv stuff

  u32 juniper_iv[4] = { 0 };

  memcpy (juniper_iv, base64_buf, 12);

  memcpy (out, juniper_iv, 12);

  // reversed key

  u32 juniper_key[4] = { 0 };

  juniper_key[0] = byte_swap_32 (0xa6707a7e);
  juniper_key[1] = byte_swap_32 (0x8df91059);
  juniper_key[2] = byte_swap_32 (0xdea70ae5);
  juniper_key[3] = byte_swap_32 (0x2f9c2442);

  // AES decrypt

  u32 *in_ptr  = (u32 *) (base64_buf + 12);
  u32 *out_ptr = (u32 *) (out        + 12);

  AES128_decrypt_cbc (juniper_key, juniper_iv, in_ptr, out_ptr);
}

static void phpass_decode (u8 digest[16], u8 buf[22])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;

  digest[15] = (l >>  0) & 0xff;
}

static void phpass_encode (u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[15] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f);
}

static void md5crypt_decode (u8 digest[16], u8 buf[22])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

static void md5crypt_encode (u8 digest[16], u8 buf[22])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[11] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); //l >>= 6;
}

static void sha512crypt_decode (u8 digest[64], u8 buf[86])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[21] = (l >>  8) & 0xff;
  digest[42] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[ 1] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[ 2] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[24] = (l >>  8) & 0xff;
  digest[45] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[ 4] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[ 5] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[27] = (l >>  8) & 0xff;
  digest[48] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[ 7] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[30] = (l >>  8) & 0xff;
  digest[51] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[10] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[44]) <<  0;
  l |= itoa64_to_int (buf[45]) <<  6;
  l |= itoa64_to_int (buf[46]) << 12;
  l |= itoa64_to_int (buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >>  8) & 0xff;
  digest[32] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[48]) <<  0;
  l |= itoa64_to_int (buf[49]) <<  6;
  l |= itoa64_to_int (buf[50]) << 12;
  l |= itoa64_to_int (buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >>  8) & 0xff;
  digest[54] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[52]) <<  0;
  l |= itoa64_to_int (buf[53]) <<  6;
  l |= itoa64_to_int (buf[54]) << 12;
  l |= itoa64_to_int (buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[56]) <<  0;
  l |= itoa64_to_int (buf[57]) <<  6;
  l |= itoa64_to_int (buf[58]) << 12;
  l |= itoa64_to_int (buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >>  8) & 0xff;
  digest[35] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[60]) <<  0;
  l |= itoa64_to_int (buf[61]) <<  6;
  l |= itoa64_to_int (buf[62]) << 12;
  l |= itoa64_to_int (buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >>  8) & 0xff;
  digest[57] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[64]) <<  0;
  l |= itoa64_to_int (buf[65]) <<  6;
  l |= itoa64_to_int (buf[66]) << 12;
  l |= itoa64_to_int (buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[16] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[68]) <<  0;
  l |= itoa64_to_int (buf[69]) <<  6;
  l |= itoa64_to_int (buf[70]) << 12;
  l |= itoa64_to_int (buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >>  8) & 0xff;
  digest[38] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[72]) <<  0;
  l |= itoa64_to_int (buf[73]) <<  6;
  l |= itoa64_to_int (buf[74]) << 12;
  l |= itoa64_to_int (buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >>  8) & 0xff;
  digest[60] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[76]) <<  0;
  l |= itoa64_to_int (buf[77]) <<  6;
  l |= itoa64_to_int (buf[78]) << 12;
  l |= itoa64_to_int (buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[19] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[80]) <<  0;
  l |= itoa64_to_int (buf[81]) <<  6;
  l |= itoa64_to_int (buf[82]) << 12;
  l |= itoa64_to_int (buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >>  8) & 0xff;
  digest[41] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[84]) <<  0;
  l |= itoa64_to_int (buf[85]) <<  6;

  digest[63] = (l >>  0) & 0xff;
}

static void sha512crypt_encode (u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[ 0] << 16) | (digest[21] << 8) | (digest[42] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[22] << 16) | (digest[43] << 8) | (digest[ 1] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[44] << 16) | (digest[ 2] << 8) | (digest[23] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 3] << 16) | (digest[24] << 8) | (digest[45] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[25] << 16) | (digest[46] << 8) | (digest[ 4] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[47] << 16) | (digest[ 5] << 8) | (digest[26] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 6] << 16) | (digest[27] << 8) | (digest[48] << 0);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[28] << 16) | (digest[49] << 8) | (digest[ 7] << 0);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[50] << 16) | (digest[ 8] << 8) | (digest[29] << 0);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 9] << 16) | (digest[30] << 8) | (digest[51] << 0);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[31] << 16) | (digest[52] << 8) | (digest[10] << 0);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[53] << 16) | (digest[11] << 8) | (digest[32] << 0);

  buf[44] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[12] << 16) | (digest[33] << 8) | (digest[54] << 0);

  buf[48] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[34] << 16) | (digest[55] << 8) | (digest[13] << 0);

  buf[52] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[56] << 16) | (digest[14] << 8) | (digest[35] << 0);

  buf[56] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[15] << 16) | (digest[36] << 8) | (digest[57] << 0);

  buf[60] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[37] << 16) | (digest[58] << 8) | (digest[16] << 0);

  buf[64] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[59] << 16) | (digest[17] << 8) | (digest[38] << 0);

  buf[68] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[18] << 16) | (digest[39] << 8) | (digest[60] << 0);

  buf[72] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[40] << 16) | (digest[61] << 8) | (digest[19] << 0);

  buf[76] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[62] << 16) | (digest[20] << 8) | (digest[41] << 0);

  buf[80] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l =                                          (digest[63] << 0);

  buf[84] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64 (l & 0x3f); //l >>= 6;
}

static void sha1aix_decode (u8 digest[20], u8 buf[27])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

static void sha1aix_encode (u8 digest[20], u8 buf[27])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l =                 0 | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f);
}

static void sha256aix_decode (u8 digest[32], u8 buf[43])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;

  //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

static void sha256aix_encode (u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l =                 0 | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); //l >>= 6;
}

static void sha512aix_decode (u8 digest[64], u8 buf[86])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[44]) <<  0;
  l |= itoa64_to_int (buf[45]) <<  6;
  l |= itoa64_to_int (buf[46]) << 12;
  l |= itoa64_to_int (buf[47]) << 18;

  digest[35] = (l >>  0) & 0xff;
  digest[34] = (l >>  8) & 0xff;
  digest[33] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[48]) <<  0;
  l |= itoa64_to_int (buf[49]) <<  6;
  l |= itoa64_to_int (buf[50]) << 12;
  l |= itoa64_to_int (buf[51]) << 18;

  digest[38] = (l >>  0) & 0xff;
  digest[37] = (l >>  8) & 0xff;
  digest[36] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[52]) <<  0;
  l |= itoa64_to_int (buf[53]) <<  6;
  l |= itoa64_to_int (buf[54]) << 12;
  l |= itoa64_to_int (buf[55]) << 18;

  digest[41] = (l >>  0) & 0xff;
  digest[40] = (l >>  8) & 0xff;
  digest[39] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[56]) <<  0;
  l |= itoa64_to_int (buf[57]) <<  6;
  l |= itoa64_to_int (buf[58]) << 12;
  l |= itoa64_to_int (buf[59]) << 18;

  digest[44] = (l >>  0) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[42] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[60]) <<  0;
  l |= itoa64_to_int (buf[61]) <<  6;
  l |= itoa64_to_int (buf[62]) << 12;
  l |= itoa64_to_int (buf[63]) << 18;

  digest[47] = (l >>  0) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[45] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[64]) <<  0;
  l |= itoa64_to_int (buf[65]) <<  6;
  l |= itoa64_to_int (buf[66]) << 12;
  l |= itoa64_to_int (buf[67]) << 18;

  digest[50] = (l >>  0) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[48] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[68]) <<  0;
  l |= itoa64_to_int (buf[69]) <<  6;
  l |= itoa64_to_int (buf[70]) << 12;
  l |= itoa64_to_int (buf[71]) << 18;

  digest[53] = (l >>  0) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[51] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[72]) <<  0;
  l |= itoa64_to_int (buf[73]) <<  6;
  l |= itoa64_to_int (buf[74]) << 12;
  l |= itoa64_to_int (buf[75]) << 18;

  digest[56] = (l >>  0) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[54] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[76]) <<  0;
  l |= itoa64_to_int (buf[77]) <<  6;
  l |= itoa64_to_int (buf[78]) << 12;
  l |= itoa64_to_int (buf[79]) << 18;

  digest[59] = (l >>  0) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[57] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[80]) <<  0;
  l |= itoa64_to_int (buf[81]) <<  6;
  l |= itoa64_to_int (buf[82]) << 12;
  l |= itoa64_to_int (buf[83]) << 18;

  digest[62] = (l >>  0) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[60] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[84]) <<  0;
  l |= itoa64_to_int (buf[85]) <<  6;

  digest[63] = (l >> 16) & 0xff;
}

static void sha512aix_encode (u8 digest[64], u8 buf[86])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l = (digest[32] << 0) | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[43] = int_to_itoa64 (l & 0x3f);

  l = (digest[35] << 0) | (digest[34] << 8) | (digest[33] << 16);

  buf[44] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[45] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[46] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[47] = int_to_itoa64 (l & 0x3f);

  l = (digest[38] << 0) | (digest[37] << 8) | (digest[36] << 16);

  buf[48] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[49] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[50] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[51] = int_to_itoa64 (l & 0x3f);

  l = (digest[41] << 0) | (digest[40] << 8) | (digest[39] << 16);

  buf[52] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[53] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[54] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[55] = int_to_itoa64 (l & 0x3f);

  l = (digest[44] << 0) | (digest[43] << 8) | (digest[42] << 16);

  buf[56] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[57] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[58] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[59] = int_to_itoa64 (l & 0x3f);

  l = (digest[47] << 0) | (digest[46] << 8) | (digest[45] << 16);

  buf[60] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[61] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[62] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[63] = int_to_itoa64 (l & 0x3f);

  l = (digest[50] << 0) | (digest[49] << 8) | (digest[48] << 16);

  buf[64] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[65] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[66] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[67] = int_to_itoa64 (l & 0x3f);

  l = (digest[53] << 0) | (digest[52] << 8) | (digest[51] << 16);

  buf[68] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[69] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[70] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[71] = int_to_itoa64 (l & 0x3f);

  l = (digest[56] << 0) | (digest[55] << 8) | (digest[54] << 16);

  buf[72] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[73] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[74] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[75] = int_to_itoa64 (l & 0x3f);

  l = (digest[59] << 0) | (digest[58] << 8) | (digest[57] << 16);

  buf[76] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[77] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[78] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[79] = int_to_itoa64 (l & 0x3f);

  l = (digest[62] << 0) | (digest[61] << 8) | (digest[60] << 16);

  buf[80] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[81] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[82] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[83] = int_to_itoa64 (l & 0x3f);

  l =                                         (digest[63] << 16);

  buf[84] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[85] = int_to_itoa64 (l & 0x3f); //l >>= 6;
}

static void netbsd_sha1crypt_decode (u8 digest[20], u8 buf[28], u8 *additional_byte)
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  additional_byte[0] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

static void netbsd_sha1crypt_encode (u8 digest[20], u8 additional_byte, u8 buf[30])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (additional_byte << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);
  buf[28] = 0;
}

static void sha256crypt_decode (u8 digest[32], u8 buf[43])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[20] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[21] = (l >> 16) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[11] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[ 2] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[24] = (l >> 16) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[27] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[17] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[ 8] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;

  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >>  0) & 0xff;
}

static void sha256crypt_encode (u8 digest[32], u8 buf[43])
{
  int l;

  l = (digest[ 0] << 16) | (digest[10] << 8) | (digest[20] << 0);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[21] << 16) | (digest[ 1] << 8) | (digest[11] << 0);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[12] << 16) | (digest[22] << 8) | (digest[ 2] << 0);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 3] << 16) | (digest[13] << 8) | (digest[23] << 0);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[24] << 16) | (digest[ 4] << 8) | (digest[14] << 0);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[15] << 16) | (digest[25] << 8) | (digest[ 5] << 0);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 6] << 16) | (digest[16] << 8) | (digest[26] << 0);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[27] << 16) | (digest[ 7] << 8) | (digest[17] << 0);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[18] << 16) | (digest[28] << 8) | (digest[ 8] << 0);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l = (digest[ 9] << 16) | (digest[19] << 8) | (digest[29] << 0);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f); //l >>= 6;

  l =                  0 | (digest[31] << 8) | (digest[30] << 0);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); //l >>= 6;
}

static void drupal7_decode (u8 digest[64], u8 buf[44])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[15] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[18] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[21] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[24] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[27] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[30] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[32] = (l >> 16) & 0xff;

  digest[33] = 0;
  digest[34] = 0;
  digest[35] = 0;
  digest[36] = 0;
  digest[37] = 0;
  digest[38] = 0;
  digest[39] = 0;
  digest[40] = 0;
  digest[41] = 0;
  digest[42] = 0;
  digest[43] = 0;
  digest[44] = 0;
  digest[45] = 0;
  digest[46] = 0;
  digest[47] = 0;
  digest[48] = 0;
  digest[49] = 0;
  digest[50] = 0;
  digest[51] = 0;
  digest[52] = 0;
  digest[53] = 0;
  digest[54] = 0;
  digest[55] = 0;
  digest[56] = 0;
  digest[57] = 0;
  digest[58] = 0;
  digest[59] = 0;
  digest[60] = 0;
  digest[61] = 0;
  digest[62] = 0;
  digest[63] = 0;
}

static void drupal7_encode (u8 digest[64], u8 buf[43])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); //l >>= 6;
  //buf[43] = int_to_itoa64 (l & 0x3f);
}

/**
 * parser
 */

static u32 parse_and_store_salt (u8 *out, u8 *in, u32 salt_len, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 tmp_u32[64] = { 0 };

  u8 *tmp = (u8 *) tmp_u32;

  if (salt_len > sizeof (tmp_u32))
  {
    return UINT_MAX;
  }

  memset (tmp, 0, sizeof (tmp_u32));

  memcpy (tmp, in, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((salt_len % 2) == 0)
    {
      u32 new_salt_len = salt_len / 2;

      for (u32 i = 0, j = 0; i < new_salt_len; i += 1, j += 2)
      {
        u8 p0 = tmp[j + 0];
        u8 p1 = tmp[j + 1];

        tmp[i]  = hex_convert (p1) << 0;
        tmp[i] |= hex_convert (p0) << 4;
      }

      salt_len = new_salt_len;
    }
    else
    {
      return UINT_MAX;
    }
  }
  else if (hashconfig->opts_type & OPTS_TYPE_ST_BASE64)
  {
    salt_len = base64_decode (base64_to_int, (const u8 *) in, salt_len, (u8 *) tmp);
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE)
  {
    if (salt_len < 20)
    {
      tmp_u32[9] = ((tmp_u32[4] >> 8) & 0x00FF0000) | ((tmp_u32[4] >> 16) & 0x000000FF);
      tmp_u32[8] = ((tmp_u32[4] << 8) & 0x00FF0000) | ((tmp_u32[4] >>  0) & 0x000000FF);
      tmp_u32[7] = ((tmp_u32[3] >> 8) & 0x00FF0000) | ((tmp_u32[3] >> 16) & 0x000000FF);
      tmp_u32[6] = ((tmp_u32[3] << 8) & 0x00FF0000) | ((tmp_u32[3] >>  0) & 0x000000FF);
      tmp_u32[5] = ((tmp_u32[2] >> 8) & 0x00FF0000) | ((tmp_u32[2] >> 16) & 0x000000FF);
      tmp_u32[4] = ((tmp_u32[2] << 8) & 0x00FF0000) | ((tmp_u32[2] >>  0) & 0x000000FF);
      tmp_u32[3] = ((tmp_u32[1] >> 8) & 0x00FF0000) | ((tmp_u32[1] >> 16) & 0x000000FF);
      tmp_u32[2] = ((tmp_u32[1] << 8) & 0x00FF0000) | ((tmp_u32[1] >>  0) & 0x000000FF);
      tmp_u32[1] = ((tmp_u32[0] >> 8) & 0x00FF0000) | ((tmp_u32[0] >> 16) & 0x000000FF);
      tmp_u32[0] = ((tmp_u32[0] << 8) & 0x00FF0000) | ((tmp_u32[0] >>  0) & 0x000000FF);

      salt_len = salt_len * 2;
    }
    else
    {
      return UINT_MAX;
    }
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_LOWER)
  {
    lowercase (tmp, salt_len);
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_UPPER)
  {
    uppercase (tmp, salt_len);
  }

  u32 len = salt_len;

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    if (len >= 256) return UINT_MAX;

    tmp[len++] = 0x80;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD01)
  {
    if (len >= 256) return UINT_MAX;

    tmp[len++] = 0x01;
  }

  if (hashconfig->opts_type & OPTS_TYPE_ST_GENERATE_LE)
  {
    u32 max = len / 4;

    if (len % 4) max++;

    for (u32 i = 0; i < max; i++)
    {
      tmp_u32[i] = byte_swap_32 (tmp_u32[i]);
    }

    // Important: we may need to increase the length of memcpy since
    // we don't want to "loose" some swapped bytes (could happen if
    // they do not perfectly fit in the 4-byte blocks)
    // Memcpy does always copy the bytes in the BE order, but since
    // we swapped them, some important bytes could be in positions
    // we normally skip with the original len

    if (len % 4) len += 4 - (len % 4);
  }

  memcpy (out, tmp, len);

  return (salt_len);
}

static void precompute_salt_md5 (u8 *salt, u32 salt_len, u8 *salt_pc)
{
  u32 salt_pc_block[16] = { 0 };

  u8 *salt_pc_block_ptr = (u8 *) salt_pc_block;

  memcpy (salt_pc_block_ptr, salt, salt_len);

  salt_pc_block_ptr[salt_len] = 0x80;

  salt_pc_block[14] = salt_len * 8;

  u32 salt_pc_digest[4] = { MD5M_A, MD5M_B, MD5M_C, MD5M_D };

  md5_64 (salt_pc_block, salt_pc_digest);

  u8 *salt_buf_pc_ptr = salt_pc;

  u32_to_hex_lower (salt_pc_digest[0], salt_buf_pc_ptr +  0);
  u32_to_hex_lower (salt_pc_digest[1], salt_buf_pc_ptr +  8);
  u32_to_hex_lower (salt_pc_digest[2], salt_buf_pc_ptr + 16);
  u32_to_hex_lower (salt_pc_digest[3], salt_buf_pc_ptr + 24);
}

int bcrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_3200) || (input_len > DISPLAY_LEN_MAX_3200)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_BCRYPT1, input_buf, 4)) && (memcmp (SIGNATURE_BCRYPT2, input_buf, 4)) && (memcmp (SIGNATURE_BCRYPT3, input_buf, 4)) && (memcmp (SIGNATURE_BCRYPT4, input_buf, 4))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  memcpy ((char *) salt->salt_sign, input_buf, 6);

  u8 *iter_pos = input_buf + 4;

  salt->salt_iter = 1u << atoll ((const char *) iter_pos);

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u32 salt_len = 16;

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (bf64_to_int, (const u8 *) salt_pos, 22, tmp_buf);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, tmp_buf, 16);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  u8 *hash_pos = salt_pos + 22;

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, (const u8 *) hash_pos, 31, tmp_buf);

  memcpy (digest, tmp_buf, 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);

  digest[5] &= ~0xffu; // its just 23 not 24 !

  return (PARSER_OK);
}

int cisco4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5700) || (input_len > DISPLAY_LEN_MAX_5700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf, 43, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int lm_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_3000) || (input_len > DISPLAY_LEN_MAX_3000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);

  u32 tt;

  IP (digest[0], digest[1], tt);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int arubaos_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_125) || (input_len > DISPLAY_LEN_MAX_125)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[8] != '0') || (input_buf[9] != '1')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *hash_pos = input_buf + 10;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  u32 salt_len = 10;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_122) || (input_len > DISPLAY_LEN_MAX_122)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *hash_pos = input_buf + 8;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osx512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1722) || (input_len > DISPLAY_LEN_MAX_1722)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *hash_pos = input_buf + 8;

  if (is_valid_hex_string (hash_pos, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, input_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int osc_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_21H) || (input_len > DISPLAY_LEN_MAX_21H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_21) || (input_len > DISPLAY_LEN_MAX_21)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int netscreen_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_22H) || (input_len > DISPLAY_LEN_MAX_22H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_22) || (input_len > DISPLAY_LEN_MAX_22)) return (PARSER_GLOBAL_LENGTH);
  }

  // unscramble

  u8 clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = {   0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != input_buf[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = input_buf[i];

      k++;
    }
  }

  // base64 decode

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

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

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[30] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 30 - 1;

  u8 *salt_buf = input_buf + 30 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32
  // 32 - 4 bytes (to fit w0lr for all attack modes) = 28

  if (salt_len > 28) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  memcpy (salt_buf_ptr + salt_len, ":Administration Tools:", 22);

  salt->salt_len += 22;

  return (PARSER_OK);
}

int smf_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_121H) || (input_len > DISPLAY_LEN_MAX_121H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_121) || (input_len > DISPLAY_LEN_MAX_121)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2100H) || (input_len > DISPLAY_LEN_MAX_2100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2100) || (input_len > DISPLAY_LEN_MAX_2100)) return (PARSER_GLOBAL_LENGTH);
  }

  if (memcmp (SIGNATURE_DCC2, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u8 *iter_pos = input_buf + 6;

  salt_t *salt = hash_buf->salt;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter < 1)
  {
    iter = ROUNDS_DCC2;
  }

  salt->salt_iter = iter - 1;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '#');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *digest_pos = (u8 *) strchr ((const char *) salt_pos, '#');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  digest_pos++;

  u32 salt_len = digest_pos - salt_pos - 1;

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (digest_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dpapimk_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15300) || (input_len > DISPLAY_LEN_MAX_15300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DPAPIMK, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest        = (u32 *) hash_buf->digest;

  salt_t *salt       = hash_buf->salt;

  dpapimk_t *dpapimk = (dpapimk_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8  *version_pos;
  u8  *context_pos;
  u8  *SID_pos;
  u8  *cipher_algo_pos; // here just for possible forward compatibilities
  u8  *hash_algo_pos;   // same
  u8  *rounds_pos;
  u32 iv_len                 = 32;
  u32 effective_iv_len       =  0;
  u32 effective_contents_len =  0;
  u8  *iv_pos;
  u8  *contents_len_pos;
  u8  *contents_pos;

  version_pos = input_buf + 8 + 1;

  context_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (context_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  context_pos++;

  SID_pos = (u8 *) strchr ((const char *) context_pos, '*');

  if (SID_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  SID_pos++;

  cipher_algo_pos = (u8 *) strchr ((const char *) SID_pos, '*');

  if (cipher_algo_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  cipher_algo_pos++;

  hash_algo_pos = (u8 *) strchr ((const char *) cipher_algo_pos, '*');

  if (hash_algo_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_algo_pos++;

  rounds_pos = (u8 *) strchr ((const char *) hash_algo_pos, '*');

  if (rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  rounds_pos++;

  iv_pos = (u8 *) strchr ((const char *) rounds_pos, '*');

  if (iv_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  iv_pos++;

  contents_len_pos = (u8 *) strchr ((const char *) iv_pos, '*');

  if (contents_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  effective_iv_len = (u32) (contents_len_pos - iv_pos);

  if (effective_iv_len != iv_len) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (iv_pos, 32) == false) return (PARSER_SALT_ENCODING);

  contents_len_pos++;

  contents_pos = (u8 *) strchr ((const char *) contents_len_pos, '*');

  if (contents_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  contents_pos++;

  u32 version      = atoll ((const char *) version_pos);
  u32 contents_len = atoll ((const char *) contents_len_pos);

  if (version == 1 && contents_len != 208) return (PARSER_SALT_LENGTH);
  if (version == 2 && contents_len != 288) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (contents_pos, contents_len) == false) return (PARSER_SALT_ENCODING);

  u8 *end_line  = (u8 *) strchr ((const char *) contents_pos, 0);

  effective_contents_len = (u32) (end_line - contents_pos);

  if (effective_contents_len != contents_len) return (PARSER_SALT_LENGTH);

  dpapimk->version = version;

  dpapimk->context = atoll ((const char *) context_pos);

  salt->salt_iter = (atoll ((const char *) rounds_pos)) - 1;

  dpapimk->iv[0] = hex_to_u32 ((const u8 *) &iv_pos[ 0]);
  dpapimk->iv[1] = hex_to_u32 ((const u8 *) &iv_pos[ 8]);
  dpapimk->iv[2] = hex_to_u32 ((const u8 *) &iv_pos[16]);
  dpapimk->iv[3] = hex_to_u32 ((const u8 *) &iv_pos[24]);

  dpapimk->iv[0] = byte_swap_32 (dpapimk->iv[0]);
  dpapimk->iv[1] = byte_swap_32 (dpapimk->iv[1]);
  dpapimk->iv[2] = byte_swap_32 (dpapimk->iv[2]);
  dpapimk->iv[3] = byte_swap_32 (dpapimk->iv[3]);

  dpapimk->contents_len = contents_len;

  for (u32 i = 0; i < dpapimk->contents_len / 4; i++)
  {
    dpapimk->contents[i] = hex_to_u32 ((const u8 *) &contents_pos[i * 8]);

    dpapimk->contents[i] = byte_swap_32 (dpapimk->contents[i]);
  }

  u32 SID_len = cipher_algo_pos - 1 - SID_pos;

  /* maximum size of SID supported */
  u8 *SID_utf16le = (u8 *) hcmalloc (32 * 4);
  memset (SID_utf16le, 0, 32 * 4);

  for (u32 i = 0; i < SID_len; i += 1)
  {
    SID_utf16le[i * 2] = SID_pos[i];
  }

  SID_utf16le[(SID_len + 1) * 2] = 0x80;

  /* Specific to DPAPI: needs trailing '\0' while computing hash */
  dpapimk->SID_len = (SID_len + 1) * 2;

  memcpy ((u8 *) dpapimk->SID, SID_utf16le, 32 * 4);

  for (u32 i = 0; i < 32; i++)
  {
    dpapimk->SID[i] = byte_swap_32 (dpapimk->SID[i]);
  }

  digest[0] = dpapimk->iv[0];
  digest[1] = dpapimk->iv[1];
  digest[2] = dpapimk->iv[2];
  digest[3] = dpapimk->iv[3];

  salt->salt_buf[0] = dpapimk->iv[0];
  salt->salt_buf[1] = dpapimk->iv[1];
  salt->salt_buf[2] = dpapimk->iv[2];
  salt->salt_buf[3] = dpapimk->iv[3];

  salt->salt_len = 16;

  hcfree(SID_utf16le);

  return (PARSER_OK);
}

int wpa_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  wpa_t *wpa = (wpa_t *) hash_buf->esalt;

  hccapx_t in;

  memcpy (&in, input_buf, input_len);

  if (in.signature != HCCAPX_SIGNATURE) return (PARSER_HCCAPX_SIGNATURE);

  if (in.version != HCCAPX_VERSION) return (PARSER_HCCAPX_VERSION);

  if (in.eapol_len < 1 || in.eapol_len > 255) return (PARSER_HCCAPX_EAPOL_LEN);

  memcpy (wpa->keymic, in.keymic, 16);

  /*
    http://www.one-net.eu/jsw/j_sec/m_ptype.html
    The phrase "Pairwise key expansion"
    Access Point Address (referred to as Authenticator Address AA)
    Supplicant Address (referred to as Supplicant Address SA)
    Access Point Nonce (referred to as Authenticator Anonce)
    Wireless Device Nonce (referred to as Supplicant Nonce Snonce)
  */

  u32 salt_len = in.essid_len;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, in.essid, in.essid_len);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_WPA2 - 1;

  memcpy (wpa->essid, in.essid, in.essid_len);

  wpa->essid_len = in.essid_len;

  u8 *pke_ptr = (u8 *) wpa->pke;

  memcpy (pke_ptr, "Pairwise key expansion", 23);

  if (memcmp (in.mac_ap, in.mac_sta, 6) < 0)
  {
    memcpy (pke_ptr + 23, in.mac_ap,  6);
    memcpy (pke_ptr + 29, in.mac_sta, 6);
  }
  else
  {
    memcpy (pke_ptr + 23, in.mac_sta, 6);
    memcpy (pke_ptr + 29, in.mac_ap,  6);
  }

  wpa->nonce_compare = memcmp (in.nonce_ap, in.nonce_sta, 32);

  if (wpa->nonce_compare < 0)
  {
    memcpy (pke_ptr + 35, in.nonce_ap,  32);
    memcpy (pke_ptr + 67, in.nonce_sta, 32);
  }
  else
  {
    memcpy (pke_ptr + 35, in.nonce_sta, 32);
    memcpy (pke_ptr + 67, in.nonce_ap,  32);
  }

  for (int i = 0; i < 25; i++)
  {
    wpa->pke[i] = byte_swap_32 (wpa->pke[i]);
  }

  memcpy (wpa->orig_mac_ap,    in.mac_ap,    6);
  memcpy (wpa->orig_mac_sta,   in.mac_sta,   6);
  memcpy (wpa->orig_nonce_ap,  in.nonce_ap,  32);
  memcpy (wpa->orig_nonce_sta, in.nonce_sta, 32);

  u8 message_pair_orig = in.message_pair;

  in.message_pair &= 0x7f; // ignore the highest bit (it is used to indicate if the replay counters did match)

  if (wpa->message_pair_chgd == true)
  {
    if (wpa->message_pair != in.message_pair) return (PARSER_HCCAPX_MESSAGE_PAIR);
  }

  wpa->message_pair = message_pair_orig;

  if ((in.message_pair == MESSAGE_PAIR_M32E3) || (in.message_pair == MESSAGE_PAIR_M34E3))
  {
    wpa->nonce_error_corrections = 0;
  }

  wpa->keyver = in.keyver;

  if (wpa->keyver & ~7) return (PARSER_SALT_VALUE);

  wpa->eapol_len = in.eapol_len;

  u8 *eapol_ptr = (u8 *) wpa->eapol;

  memcpy (eapol_ptr, in.eapol, wpa->eapol_len);

  memset (eapol_ptr + wpa->eapol_len, 0, (256 + 64) - wpa->eapol_len);

  eapol_ptr[wpa->eapol_len] = 0x80;

  if (wpa->keyver == 1)
  {
    // nothing to do
  }
  else
  {
    wpa->keymic[0] = byte_swap_32 (wpa->keymic[0]);
    wpa->keymic[1] = byte_swap_32 (wpa->keymic[1]);
    wpa->keymic[2] = byte_swap_32 (wpa->keymic[2]);
    wpa->keymic[3] = byte_swap_32 (wpa->keymic[3]);

    for (int i = 0; i < 64; i++)
    {
      wpa->eapol[i] = byte_swap_32 (wpa->eapol[i]);
    }
  }

  // Create a hash of the nonce as ESSID is not unique enough
  // Not a regular MD5 but good enough
  // We can also ignore cases where we should bzero the work buffer

  u32 hash[4];

  hash[0] = 0;
  hash[1] = 1;
  hash[2] = 2;
  hash[3] = 3;

  u32 block[16];

  memset (block, 0, sizeof (block));

  u8 *block_ptr = (u8 *) block;

  for (int i = 0; i < 16; i++) block[i] = salt->salt_buf[i];

  md5_64 (block, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->pke[i +  0];

  md5_64 (block, hash);

  for (int i = 0; i <  9; i++) block[i] = wpa->pke[i + 16];

  md5_64 (block, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i +  0];

  md5_64 (block, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 16];

  md5_64 (block, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 32];

  md5_64 (block, hash);

  for (int i = 0; i < 16; i++) block[i] = wpa->eapol[i + 48];

  md5_64 (block, hash);

  for (int i = 0; i <  6; i++) block_ptr[i + 0] = wpa->orig_mac_ap[i];
  for (int i = 0; i <  6; i++) block_ptr[i + 6] = wpa->orig_mac_sta[i];

  md5_64 (block, hash);

  for (int i = 0; i < 32; i++) block_ptr[i +  0] = wpa->orig_nonce_ap[i];
  for (int i = 0; i < 32; i++) block_ptr[i + 32] = wpa->orig_nonce_sta[i];

  md5_64 (block, hash);

  block[0] = wpa->keymic[0];
  block[1] = wpa->keymic[1];
  block[2] = wpa->keymic[2];
  block[3] = wpa->keymic[3];

  md5_64 (block, hash);

  wpa->hash[0] = hash[0];
  wpa->hash[1] = hash[1];
  wpa->hash[2] = hash[2];
  wpa->hash[3] = hash[3];

  // make all this stuff unique

  digest[0] = wpa->hash[0];
  digest[1] = wpa->hash[1];
  digest[2] = wpa->hash[2];
  digest[3] = wpa->hash[3];

  return (PARSER_OK);
}

int psafe2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  psafe2_hdr buf;

  memset (&buf, 0, sizeof (psafe2_hdr));

  const size_t n = fread (&buf, sizeof (psafe2_hdr), 1, fp);

  fclose (fp);

  if (n != 1) return (PARSER_PSAFE2_FILE_SIZE);

  salt->salt_buf[0] = buf.random[0];
  salt->salt_buf[1] = buf.random[1];

  salt->salt_len  = 8;
  salt->salt_iter = 1000;

  digest[0] = byte_swap_32 (buf.hash[0]);
  digest[1] = byte_swap_32 (buf.hash[1]);
  digest[2] = byte_swap_32 (buf.hash[2]);
  digest[3] = byte_swap_32 (buf.hash[3]);
  digest[4] = byte_swap_32 (buf.hash[4]);

  return (PARSER_OK);
}

int psafe3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  psafe3_t in;

  memset (&in, 0, sizeof (psafe3_t));

  const size_t n = fread (&in, sizeof (psafe3_t), 1, fp);

  fclose (fp);

  if (n != 1) return (PARSER_PSAFE3_FILE_SIZE);

  if (memcmp (SIGNATURE_PSAFE3, in.signature, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  salt->salt_iter = in.iterations + 1;

  salt->salt_buf[0] = in.salt_buf[0];
  salt->salt_buf[1] = in.salt_buf[1];
  salt->salt_buf[2] = in.salt_buf[2];
  salt->salt_buf[3] = in.salt_buf[3];
  salt->salt_buf[4] = in.salt_buf[4];
  salt->salt_buf[5] = in.salt_buf[5];
  salt->salt_buf[6] = in.salt_buf[6];
  salt->salt_buf[7] = in.salt_buf[7];

  salt->salt_len = 32;

  digest[0] = in.hash_buf[0];
  digest[1] = in.hash_buf[1];
  digest[2] = in.hash_buf[2];
  digest[3] = in.hash_buf[3];
  digest[4] = in.hash_buf[4];
  digest[5] = in.hash_buf[5];
  digest[6] = in.hash_buf[6];
  digest[7] = in.hash_buf[7];

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int phpass_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_400) || (input_len > DISPLAY_LEN_MAX_400)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_PHPASS1, input_buf, 3)) && (memcmp (SIGNATURE_PHPASS2, input_buf, 3))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 3;

  u32 salt_iter = 1u << itoa64_to_int (iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy ((u8 *) salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  u8 *salt_pos = iter_pos + 1;

  u32 salt_len = 8;

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  u8 *hash_pos = salt_pos + salt_len;

  phpass_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int md5crypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (input_len < DISPLAY_LEN_MIN_500) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MD5CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 3;

  u32 iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoll ((const char *) (salt_pos - iterations_len));

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if (input_len > (DISPLAY_LEN_MAX_500 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  u32 hash_len = input_len - 3 - iterations_len - salt_len - 1;

  if (hash_len != 22) return (PARSER_HASH_LENGTH);

  md5crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int md5apr1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (memcmp (SIGNATURE_MD5APR1, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 6;

  u32 iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoll ((const char *) (salt_pos - iterations_len));

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_MD5CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1600) || (input_len > DISPLAY_LEN_MAX_1600 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  md5crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int episerver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_141) || (input_len > DISPLAY_LEN_MAX_141)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_EPISERVER, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 14;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  u32 salt_len = hash_pos - salt_pos - 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) hash_pos, 27, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int descrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1500) || (input_len > DISPLAY_LEN_MAX_1500)) return (PARSER_GLOBAL_LENGTH);

  unsigned char c12 = itoa64_to_int (input_buf[12]);

  if (c12 & 3) return (PARSER_HASH_VALUE);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // for ascii_digest
  salt->salt_sign[0] = input_buf[0];
  salt->salt_sign[1] = input_buf[1];

  salt->salt_buf[0] = itoa64_to_int (input_buf[0])
                    | itoa64_to_int (input_buf[1]) << 6;

  salt->salt_len = 2;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf + 2, 11, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  u32 tt;

  IP (digest[0], digest[1], tt);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int md4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_900) || (input_len > DISPLAY_LEN_MAX_900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  return (PARSER_OK);
}

int md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_0) || (input_len > DISPLAY_LEN_MAX_0)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int md5half_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5100) || (input_len > DISPLAY_LEN_MAX_5100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int md5s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_10H) || (input_len > DISPLAY_LEN_MAX_10H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_10) || (input_len > DISPLAY_LEN_MAX_10)) return (PARSER_GLOBAL_LENGTH);
  }

  const u32 opti_type = hashconfig->opti_type;

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  if (opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HASH_MD5)
  {
    // precompute md5 of the salt

    precompute_salt_md5 (salt_buf_ptr, salt_len, (u8 *) salt->salt_buf_pc);
  }

  return (PARSER_OK);
}

int md5pix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_2400) || (input_len > DISPLAY_LEN_MAX_2400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  digest[0] = itoa64_to_int (input_buf[ 0]) <<  0
            | itoa64_to_int (input_buf[ 1]) <<  6
            | itoa64_to_int (input_buf[ 2]) << 12
            | itoa64_to_int (input_buf[ 3]) << 18;
  digest[1] = itoa64_to_int (input_buf[ 4]) <<  0
            | itoa64_to_int (input_buf[ 5]) <<  6
            | itoa64_to_int (input_buf[ 6]) << 12
            | itoa64_to_int (input_buf[ 7]) << 18;
  digest[2] = itoa64_to_int (input_buf[ 8]) <<  0
            | itoa64_to_int (input_buf[ 9]) <<  6
            | itoa64_to_int (input_buf[10]) << 12
            | itoa64_to_int (input_buf[11]) << 18;
  digest[3] = itoa64_to_int (input_buf[12]) <<  0
            | itoa64_to_int (input_buf[13]) <<  6
            | itoa64_to_int (input_buf[14]) << 12
            | itoa64_to_int (input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  return (PARSER_OK);
}

int md5asa_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2410H) || (input_len > DISPLAY_LEN_MAX_2410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2410) || (input_len > DISPLAY_LEN_MAX_2410)) return (PARSER_GLOBAL_LENGTH);
  }

  int *digest = (int *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] = itoa64_to_int (input_buf[ 0]) <<  0
            | itoa64_to_int (input_buf[ 1]) <<  6
            | itoa64_to_int (input_buf[ 2]) << 12
            | itoa64_to_int (input_buf[ 3]) << 18;
  digest[1] = itoa64_to_int (input_buf[ 4]) <<  0
            | itoa64_to_int (input_buf[ 5]) <<  6
            | itoa64_to_int (input_buf[ 6]) << 12
            | itoa64_to_int (input_buf[ 7]) << 18;
  digest[2] = itoa64_to_int (input_buf[ 8]) <<  0
            | itoa64_to_int (input_buf[ 9]) <<  6
            | itoa64_to_int (input_buf[10]) << 12
            | itoa64_to_int (input_buf[11]) << 18;
  digest[3] = itoa64_to_int (input_buf[12]) <<  0
            | itoa64_to_int (input_buf[13]) <<  6
            | itoa64_to_int (input_buf[14]) << 12
            | itoa64_to_int (input_buf[15]) << 18;

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  if (input_buf[16] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 16 - 1;

  u8 *salt_buf = input_buf + 16 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

static void transform_netntlmv1_key (const u8 *nthash, u8 *key)
{
  key[0] =                    (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}

int netntlmv1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5500) || (input_len > DISPLAY_LEN_MAX_5500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *user_pos = input_buf;

  u8 *unused_pos = (u8 *) strchr ((const char *) user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  u8 *domain_pos = (u8 *) strchr ((const char *) unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  u8 *srvchall_pos = (u8 *) strchr ((const char *) domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 srvchall_len = hash_pos - srvchall_pos;

  // if (srvchall_len != 0) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u8 *clichall_pos = (u8 *) strchr ((const char *) hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 hash_len = clichall_pos - hash_pos;

  if (hash_len != 48) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  u32 clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len != 16) return (PARSER_SALT_LENGTH);

  /**
   * store some data for later use
   */

  netntlm->user_len     = user_len     * 2;
  netntlm->domain_len   = domain_len   * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  u8 *userdomain_ptr = (u8 *) netntlm->userdomain_buf;
  u8 *chall_ptr      = (u8 *) netntlm->chall_buf;

  /**
   * handle username and domainname
   */

  for (u32 i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = user_pos[i];
    *userdomain_ptr++ = 0;
  }

  for (u32 i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  /**
   * handle server challenge encoding
   */

  for (u32 i = 0; i < srvchall_len; i += 2)
  {
    const u8 p0 = srvchall_pos[i + 0];
    const u8 p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * handle client challenge encoding
   */

  for (u32 i = 0; i < clichall_len; i += 2)
  {
    const u8 p0 = clichall_pos[i + 0];
    const u8 p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * store data
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  u32 salt_len = parse_and_store_salt (salt_buf_ptr, clichall_pos, clichall_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  if (is_valid_hex_string (hash_pos, 48) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  /* special case, last 8 byte do not need to be checked since they are brute-forced next */

  u32 digest_tmp[2] = { 0 };

  digest_tmp[0] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest_tmp[1] = hex_to_u32 ((const u8 *) &hash_pos[40]);

  /* special case 2: ESS */

  if (srvchall_len == 48)
  {
    if ((netntlm->chall_buf[2] == 0) && (netntlm->chall_buf[3] == 0) && (netntlm->chall_buf[4] == 0) && (netntlm->chall_buf[5] == 0))
    {
      u32 w[16] = { 0 };

      w[ 0] = salt->salt_buf[0];
      w[ 1] = salt->salt_buf[1];
      w[ 2] = netntlm->chall_buf[0];
      w[ 3] = netntlm->chall_buf[1];
      w[ 4] = 0x80;
      w[14] = 16 * 8;

      u32 dgst[4] = { 0 };

      dgst[0] = MD5M_A;
      dgst[1] = MD5M_B;
      dgst[2] = MD5M_C;
      dgst[3] = MD5M_D;

      md5_64 (w, dgst);

      salt->salt_buf[0] = dgst[0];
      salt->salt_buf[1] = dgst[1];
    }
  }

  /* precompute netntlmv1 exploit start */

  for (u32 i = 0; i < 0x10000; i++)
  {
    u32 key_md4[2] = { i, 0 };
    u32 key_des[2] = { 0, 0 };

    transform_netntlmv1_key ((u8 *) key_md4, (u8 *) key_des);

    u32 Kc[16] = { 0 };
    u32 Kd[16] = { 0 };

    _des_keysetup (key_des, Kc, Kd);

    u32 data3[2] = { salt->salt_buf[0], salt->salt_buf[1] };

    _des_encrypt (data3, Kc, Kd);

    if (data3[0] != digest_tmp[0]) continue;
    if (data3[1] != digest_tmp[1]) continue;

    salt->salt_buf[2] = i;

    salt->salt_len = 24;

    break;
  }

  salt->salt_buf_pc[0] = digest_tmp[0];
  salt->salt_buf_pc[1] = digest_tmp[1];

  /* precompute netntlmv1 exploit stop */

  u32 tt;

  IP (digest[0], digest[1], tt);
  IP (digest[2], digest[3], tt);

  digest[0] = rotr32 (digest[0], 29);
  digest[1] = rotr32 (digest[1], 29);
  digest[2] = rotr32 (digest[2], 29);
  digest[3] = rotr32 (digest[3], 29);

  IP (salt->salt_buf[0], salt->salt_buf[1], tt);

  salt->salt_buf[0] = rotl32 (salt->salt_buf[0], 3);
  salt->salt_buf[1] = rotl32 (salt->salt_buf[1], 3);

  return (PARSER_OK);
}

int netntlmv2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5600) || (input_len > DISPLAY_LEN_MAX_5600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  netntlm_t *netntlm = (netntlm_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *user_pos = input_buf;

  u8 *unused_pos = (u8 *) strchr ((const char *) user_pos, ':');

  if (unused_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 user_len = unused_pos - user_pos;

  if (user_len > 60) return (PARSER_SALT_LENGTH);

  unused_pos++;

  u8 *domain_pos = (u8 *) strchr ((const char *) unused_pos, ':');

  if (domain_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 unused_len = domain_pos - unused_pos;

  if (unused_len != 0) return (PARSER_SALT_LENGTH);

  domain_pos++;

  u8 *srvchall_pos = (u8 *) strchr ((const char *) domain_pos, ':');

  if (srvchall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 domain_len = srvchall_pos - domain_pos;

  if (domain_len > 45) return (PARSER_SALT_LENGTH);

  srvchall_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) srvchall_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 srvchall_len = hash_pos - srvchall_pos;

  if (srvchall_len != 16) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u8 *clichall_pos = (u8 *) strchr ((const char *) hash_pos, ':');

  if (clichall_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 hash_len = clichall_pos - hash_pos;

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  clichall_pos++;

  u32 clichall_len = input_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

  if (clichall_len > 1024) return (PARSER_SALT_LENGTH);

  if (clichall_len % 2) return (PARSER_SALT_VALUE);

  /**
   * store some data for later use
   */

  netntlm->user_len     = user_len     * 2;
  netntlm->domain_len   = domain_len   * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  u8 *userdomain_ptr = (u8 *) netntlm->userdomain_buf;
  u8 *chall_ptr      = (u8 *) netntlm->chall_buf;

  /**
   * handle username and domainname
   */

  for (u32 i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = toupper (user_pos[i]);
    *userdomain_ptr++ = 0;
  }

  for (u32 i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  *userdomain_ptr++ = 0x80;

  /**
   * handle server challenge encoding
   */

  for (u32 i = 0; i < srvchall_len; i += 2)
  {
    const u8 p0 = srvchall_pos[i + 0];
    const u8 p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * handle client challenge encoding
   */

  for (u32 i = 0; i < clichall_len; i += 2)
  {
    const u8 p0 = clichall_pos[i + 0];
    const u8 p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  *chall_ptr++ = 0x80;

  /**
   * handle hash itself
   */

  if (is_valid_hex_string (hash_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  /**
   * reuse challange data as salt_buf, its the buffer that is most likely unique
   */

  salt->salt_buf[0] = 0;
  salt->salt_buf[1] = 0;
  salt->salt_buf[2] = 0;
  salt->salt_buf[3] = 0;
  salt->salt_buf[4] = 0;
  salt->salt_buf[5] = 0;
  salt->salt_buf[6] = 0;
  salt->salt_buf[7] = 0;

  u32 *uptr;

  uptr = (u32 *) netntlm->userdomain_buf;

  for (u32 i = 0; i < 16; i += 16)
  {
    md5_64 (uptr, salt->salt_buf);
  }

  uptr = (u32 *) netntlm->chall_buf;

  for (u32 i = 0; i < 256; i += 16)
  {
    md5_64 (uptr, salt->salt_buf);
  }

  salt->salt_len = 16;

  return (PARSER_OK);
}

int joomla_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_11H) || (input_len > DISPLAY_LEN_MAX_11H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_11) || (input_len > DISPLAY_LEN_MAX_11)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_12H) || (input_len > DISPLAY_LEN_MAX_12H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_12) || (input_len > DISPLAY_LEN_MAX_12)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int md5md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_2600) || (input_len > DISPLAY_LEN_MAX_2600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /**
   * This is a virtual salt. While the algorithm is basically not salted
   * we can exploit the salt buffer to set the 0x80 and the w[14] value.
   * This way we can save a special md5md5 kernel and reuse the one from vbull.
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  u32 salt_len = parse_and_store_salt (salt_buf_ptr, (u8 *) "", 0, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2611H) || (input_len > DISPLAY_LEN_MAX_2611H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2611) || (input_len > DISPLAY_LEN_MAX_2611)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int vb30_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2711H) || (input_len > DISPLAY_LEN_MAX_2711H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2711) || (input_len > DISPLAY_LEN_MAX_2711)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int dcc_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1100H) || (input_len > DISPLAY_LEN_MAX_1100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1100) || (input_len > DISPLAY_LEN_MAX_1100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD4M_A;
  digest[1] -= MD4M_B;
  digest[2] -= MD4M_C;
  digest[3] -= MD4M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int ipb2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_2811H) || (input_len > DISPLAY_LEN_MAX_2811H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_2811) || (input_len > DISPLAY_LEN_MAX_2811)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  // precompute md5 of the salt

  precompute_salt_md5 (salt_buf_ptr, salt_len, (u8 *) salt->salt_buf_pc);

  return (PARSER_OK);
}

int sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_100) || (input_len > DISPLAY_LEN_MAX_100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1axcrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13300) || (input_len > DISPLAY_LEN_MAX_13300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_AXCRYPT_SHA1, input_buf, 13)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  input_buf += 14;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = 0;

  return (PARSER_OK);
}

int sha1s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_110H) || (input_len > DISPLAY_LEN_MAX_110H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_110) || (input_len > DISPLAY_LEN_MAX_110)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha1sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_4520) || (input_len > DISPLAY_LEN_MAX_4520)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pstoken_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13500) || (input_len > DISPLAY_LEN_MAX_13500)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pstoken_t *pstoken = (pstoken_t *) hash_buf->esalt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  if (salt_len == UINT_MAX || salt_len % 2 != 0) return (PARSER_SALT_LENGTH);

  u8 *pstoken_ptr = (u8 *) pstoken->salt_buf;

  if (is_valid_hex_string (salt_buf, salt_len) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; i < salt_len; i += 2, j += 1)
  {
    pstoken_ptr[j] = hex_to_u8 ((const u8 *) &salt_buf[i]);
  }

  pstoken->salt_len = salt_len / 2;

  /* some fake salt for the sorting mechanisms */

  salt->salt_buf[0] = pstoken->salt_buf[0];
  salt->salt_buf[1] = pstoken->salt_buf[1];
  salt->salt_buf[2] = pstoken->salt_buf[2];
  salt->salt_buf[3] = pstoken->salt_buf[3];
  salt->salt_buf[4] = pstoken->salt_buf[4];
  salt->salt_buf[5] = pstoken->salt_buf[5];
  salt->salt_buf[6] = pstoken->salt_buf[6];
  salt->salt_buf[7] = pstoken->salt_buf[7];

  salt->salt_len = 32;

  /* we need to check if we can precompute some of the data --
     this is possible since the scheme is badly designed */

  pstoken->pc_digest[0] = SHA1M_A;
  pstoken->pc_digest[1] = SHA1M_B;
  pstoken->pc_digest[2] = SHA1M_C;
  pstoken->pc_digest[3] = SHA1M_D;
  pstoken->pc_digest[4] = SHA1M_E;

  pstoken->pc_offset = 0;

  for (int i = 0; i < (int) pstoken->salt_len - 63; i += 64)
  {
    u32 w[16];

    w[ 0] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  0]);
    w[ 1] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  1]);
    w[ 2] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  2]);
    w[ 3] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  3]);
    w[ 4] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  4]);
    w[ 5] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  5]);
    w[ 6] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  6]);
    w[ 7] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  7]);
    w[ 8] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  8]);
    w[ 9] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset +  9]);
    w[10] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 10]);
    w[11] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 11]);
    w[12] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 12]);
    w[13] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 13]);
    w[14] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 14]);
    w[15] = byte_swap_32 (pstoken->salt_buf[pstoken->pc_offset + 15]);

    sha1_64 (w, pstoken->pc_digest);

    pstoken->pc_offset += 16;
  }

  return (PARSER_OK);
}

int sha1b64_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_101) || (input_len > DISPLAY_LEN_MAX_101)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA1B64, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) input_buf + 5, input_len - 5, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha1b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_111) || (input_len > DISPLAY_LEN_MAX_111)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SSHA1B64_lower, input_buf, 6) && memcmp (SIGNATURE_SSHA1B64_upper, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, (const u8 *) input_buf + 6, input_len - 6, tmp_buf);

  if (tmp_len < 20) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 20);

  const int salt_len = tmp_len - 20;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, tmp_buf + 20, salt->salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2000_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_131) || (input_len > DISPLAY_LEN_MAX_131)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 6;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 *hash_pos = input_buf + 6 + 8 + 40;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2005_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_132) || (input_len > DISPLAY_LEN_MAX_132)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 6;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 *hash_pos = input_buf + 6 + 8;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int mssql2012_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1731) || (input_len > DISPLAY_LEN_MAX_1731)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MSSQL2012, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 6;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 *hash_pos = input_buf + 6 + 8;

  if (is_valid_hex_string (hash_pos, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int oracleh_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_3100H) || (input_len > DISPLAY_LEN_MAX_3100H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_3100) || (input_len > DISPLAY_LEN_MAX_3100)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  if (input_buf[16] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 16 - 1;

  u8 *salt_buf = input_buf + 16 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oracles_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_112) || (input_len > DISPLAY_LEN_MAX_112)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int oraclet_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12300) || (input_len > DISPLAY_LEN_MAX_12300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *hash_pos = input_buf;

  if (is_valid_hex_string (hash_pos, 128) == false) return (PARSER_HASH_ENCODING);

  digest[ 0] = hex_to_u32 ((const u8 *) &hash_pos[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &hash_pos[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &hash_pos[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &hash_pos[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &hash_pos[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &hash_pos[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &hash_pos[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &hash_pos[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &hash_pos[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &hash_pos[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &hash_pos[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &hash_pos[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &hash_pos[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &hash_pos[104]);
  digest[14] = hex_to_u32 ((const u8 *) &hash_pos[112]);
  digest[15] = hex_to_u32 ((const u8 *) &hash_pos[120]);

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

  u8 *salt_pos = input_buf + 128;

  if (is_valid_hex_string (salt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_iter = ROUNDS_ORACLET - 1;
  salt->salt_len  = 16;

  return (PARSER_OK);
}

int sha224_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1300) || (input_len > DISPLAY_LEN_MAX_1300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 56) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);

  digest[0] -= SHA224M_A;
  digest[1] -= SHA224M_B;
  digest[2] -= SHA224M_C;
  digest[3] -= SHA224M_D;
  digest[4] -= SHA224M_E;
  digest[5] -= SHA224M_F;
  digest[6] -= SHA224M_G;

  return (PARSER_OK);
}

int sha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1400) || (input_len > DISPLAY_LEN_MAX_1400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha256s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1410H) || (input_len > DISPLAY_LEN_MAX_1410H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1410) || (input_len > DISPLAY_LEN_MAX_1410)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  if (input_buf[64] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 64 - 1;

  u8 *salt_buf = input_buf + 64 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha384_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10800) || (input_len > DISPLAY_LEN_MAX_10800)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 96) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
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

  digest[0] -= SHA384M_A;
  digest[1] -= SHA384M_B;
  digest[2] -= SHA384M_C;
  digest[3] -= SHA384M_D;
  digest[4] -= SHA384M_E;
  digest[5] -= SHA384M_F;
  digest[6] -= 0;
  digest[7] -= 0;

  return (PARSER_OK);
}

int sha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1700) || (input_len > DISPLAY_LEN_MAX_1700)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  return (PARSER_OK);
}

int sha512s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1710H) || (input_len > DISPLAY_LEN_MAX_1710H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1710) || (input_len > DISPLAY_LEN_MAX_1710)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  if (input_buf[128] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 128 - 1;

  u8 *salt_buf = input_buf + 128 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sha512crypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (memcmp (SIGNATURE_SHA512CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 3;

  u32 iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoll ((const char *) (salt_pos - iterations_len));

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA512CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_1800) || (input_len > DISPLAY_LEN_MAX_1800 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha512crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int keccak_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5000) || (input_len > DISPLAY_LEN_MAX_5000)) return (PARSER_GLOBAL_LENGTH);

  if (input_len % 16) return (PARSER_GLOBAL_LENGTH);

  if (is_valid_hex_string (input_buf, input_len) == false) return (PARSER_HASH_ENCODING);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u32 keccak_mdlen = input_len / 2;

  for (u32 i = 0; i < keccak_mdlen / 8; i++)
  {
    digest[i] = hex_to_u64 ((const u8 *) &input_buf[i * 16]);
  }

  salt->keccak_mdlen = keccak_mdlen;

  return (PARSER_OK);
}

int blake2b_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_600) || (input_len > DISPLAY_LEN_MAX_600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_BLAKE2B, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  if (is_valid_hex_string (input_buf + 8, 128) == false) return (PARSER_HASH_ENCODING);

  u64 *digest = (u64 *) hash_buf->digest;

  u8 *input_hash_buf = input_buf + 8;

  digest[0] = hex_to_u64 ((const u8 *) &input_hash_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_hash_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_hash_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_hash_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_hash_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_hash_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_hash_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_hash_buf[112]);

  // Initialize BLAKE2 Params and State

  blake2_t  *S = (blake2_t *) hash_buf->esalt;

  memset(S,  0, sizeof (blake2_t));

  S->h[0] = blake2b_IV[0];
  S->h[1] = blake2b_IV[1];
  S->h[2] = blake2b_IV[2];
  S->h[3] = blake2b_IV[3];
  S->h[4] = blake2b_IV[4];
  S->h[5] = blake2b_IV[5];
  S->h[6] = blake2b_IV[6];
  S->h[7] = blake2b_IV[7];

  // S->h[0] ^= 0x0000000001010040; // digest_lenght = 0x40, depth = 0x01, fanout = 0x01
  S->h[0] ^= 0x40 <<  0;
  S->h[0] ^= 0x01 << 16;
  S->h[0] ^= 0x01 << 24;

  return (PARSER_OK);
}

int chacha20_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15400) || (input_len > DISPLAY_LEN_MAX_15400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CHACHA20, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  chacha20_t *chacha20 = (chacha20_t *) hash_buf->esalt;

  salt_t *salt = (salt_t *) hash_buf->salt;

  u8 *position_marker = (u8 *) strchr ((const char *) input_buf, '*');
  if (position_marker == NULL) return (PARSER_SEPARATOR_UNMATCHED);
  position_marker++;
  if (is_valid_hex_string (position_marker, 16) == false) return (PARSER_SALT_ENCODING);

  u8 *offset_marker = (u8 *) strchr ((const char *) position_marker, '*');
  if (offset_marker == NULL) return (PARSER_SEPARATOR_UNMATCHED);
  offset_marker++;

  int offset = atoi ((char*) offset_marker);
  if (offset > 63) return (PARSER_SALT_VALUE);

  u8 *iv_marker = (u8 *) strchr ((const char *) offset_marker, '*');
  if (iv_marker == NULL) return (PARSER_SEPARATOR_UNMATCHED);
  iv_marker++;
  if (is_valid_hex_string (iv_marker, 16) == false) return (PARSER_SALT_ENCODING);

  u8 *plain_marker = (u8 *) strchr ((const char *) iv_marker, '*');
  if (plain_marker == NULL) return (PARSER_SEPARATOR_UNMATCHED);
  plain_marker++;
  if (is_valid_hex_string (plain_marker, 16) == false) return (PARSER_SALT_ENCODING);

  u8 *cipher_marker = (u8 *) strchr ((const char *) plain_marker, '*');
  if (cipher_marker == NULL) return (PARSER_SEPARATOR_UNMATCHED);
  cipher_marker++;
  if (is_valid_hex_string (cipher_marker, 16) == false) return (PARSER_SALT_ENCODING);

  chacha20->iv[0] = hex_to_u32 ((const u8 *) iv_marker + 8);
  chacha20->iv[1] = hex_to_u32 ((const u8 *) iv_marker + 0);

  chacha20->plain[0] = hex_to_u32 ((const u8 *) plain_marker + 0);
  chacha20->plain[1] = hex_to_u32 ((const u8 *) plain_marker + 8);

  chacha20->position[0] = hex_to_u32 ((const u8 *) position_marker + 0);
  chacha20->position[1] = hex_to_u32 ((const u8 *) position_marker + 8);

  chacha20->offset = offset;

  /* some fake salt for the sorting mechanisms */

  salt->salt_buf[0] = chacha20->iv[0];
  salt->salt_buf[1] = chacha20->iv[1];
  salt->salt_buf[2] = chacha20->plain[0];
  salt->salt_buf[3] = chacha20->plain[1];
  salt->salt_buf[4] = chacha20->position[0];
  salt->salt_buf[5] = chacha20->position[1];
  salt->salt_buf[6] = chacha20->offset;
  salt->salt_buf[7] = 0;
  salt->salt_len    = 32;

  /* Store cipher for search mechanism */
  digest[0] = hex_to_u32 ((const u8 *) cipher_marker + 8);
  digest[1] = hex_to_u32 ((const u8 *) cipher_marker + 0);

  return (PARSER_OK);
}

int ikepsk_md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5300) || (input_len > DISPLAY_LEN_MAX_5300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *) hash_buf->esalt;

  /**
   * Parse that strange long line
   */

  u8 *in_off[9];

  size_t in_len[9] = { 0 };

  if (input_buf == NULL) return (PARSER_HASH_VALUE);

  char *saveptr;

  in_off[0] = (u8 *) strtok_r ((char *) input_buf, ":", &saveptr);

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen ((const char *) in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = (u8 *) strtok_r ((char *) NULL, ":", &saveptr);

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen ((const char *) in_off[i]);
  }

  u8 *ptr = (u8 *) ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (u8 *) ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
   * Store to database
   */

  ptr = in_off[8];

  if (is_valid_hex_string (ptr, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &ptr[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &ptr[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &ptr[16]);
  digest[3] = hex_to_u32 ((const u8 *) &ptr[24]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ikepsk_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5400) || (input_len > DISPLAY_LEN_MAX_5400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ikepsk_t *ikepsk = (ikepsk_t *) hash_buf->esalt;

  /**
   * Parse that strange long line
   */

  u8 *in_off[9];

  size_t in_len[9] = { 0 };

  if (input_buf == NULL) return (PARSER_HASH_VALUE);

  char *saveptr;

  in_off[0] = (u8 *) strtok_r ((char *) input_buf, ":", &saveptr);

  if (in_off[0] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  in_len[0] = strlen ((const char *) in_off[0]);

  size_t i;

  for (i = 1; i < 9; i++)
  {
    in_off[i] = (u8 *) strtok_r ((char *) NULL, ":", &saveptr);

    if (in_off[i] == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    in_len[i] = strlen ((const char *) in_off[i]);
  }

  u8 *ptr = (u8 *) ikepsk->msg_buf;

  for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[0] + i);
  for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[1] + i);
  for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[2] + i);
  for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[3] + i);
  for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[4] + i);
  for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[5] + i);

  *ptr = 0x80;

  ikepsk->msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

  ptr = (u8 *) ikepsk->nr_buf;

  for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[6] + i);
  for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_u8 ((const u8 *) in_off[7] + i);

  *ptr = 0x80;

  ikepsk->nr_len = (in_len[6] + in_len[7]) / 2;

  /**
   * Store to database
   */

  ptr = in_off[8];

  if (is_valid_hex_string (ptr, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &ptr[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &ptr[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &ptr[16]);
  digest[3] = hex_to_u32 ((const u8 *) &ptr[24]);
  digest[4] = hex_to_u32 ((const u8 *) &ptr[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  salt->salt_len = 32;

  salt->salt_buf[0] = ikepsk->nr_buf[0];
  salt->salt_buf[1] = ikepsk->nr_buf[1];
  salt->salt_buf[2] = ikepsk->nr_buf[2];
  salt->salt_buf[3] = ikepsk->nr_buf[3];
  salt->salt_buf[4] = ikepsk->nr_buf[4];
  salt->salt_buf[5] = ikepsk->nr_buf[5];
  salt->salt_buf[6] = ikepsk->nr_buf[6];
  salt->salt_buf[7] = ikepsk->nr_buf[7];

  return (PARSER_OK);
}

int ripemd160_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6000) || (input_len > DISPLAY_LEN_MAX_6000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  return (PARSER_OK);
}

int whirlpool_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6100) || (input_len > DISPLAY_LEN_MAX_6100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[ 0] = hex_to_u32 ((const u8 *) &input_buf[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &input_buf[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &input_buf[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &input_buf[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &input_buf[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &input_buf[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &input_buf[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &input_buf[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &input_buf[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &input_buf[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &input_buf[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &input_buf[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &input_buf[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &input_buf[104]);
  digest[14] = hex_to_u32 ((const u8 *) &input_buf[112]);
  digest[15] = hex_to_u32 ((const u8 *) &input_buf[120]);

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

int androidpin_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_5800) || (input_len > DISPLAY_LEN_MAX_5800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = ROUNDS_ANDROIDPIN - 1;

  return (PARSER_OK);
}

int truecrypt_parse_hash_1k (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_TC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_1K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int truecrypt_parse_hash_2k (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_TC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_TRUECRYPT_2K - 1;

  tc->signature = 0x45555254; // "TRUE"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_200000 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_200000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_500000 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_500000 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_327661 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_327661 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int veracrypt_parse_hash_655331 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tc_t *tc = (tc_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  char buf[512] = { 0 };

  const size_t n = fread (buf, 1, sizeof (buf), fp);

  fclose (fp);

  if (n != sizeof (buf)) return (PARSER_VC_FILE_SIZE);

  memcpy (tc->salt_buf, buf, 64);

  memcpy (tc->data_buf, buf + 64, 512 - 64);

  salt->salt_buf[0] = tc->salt_buf[0];

  salt->salt_len = 4;

  salt->salt_iter = ROUNDS_VERACRYPT_655331 - 1;

  tc->signature = 0x41524556; // "VERA"

  digest[0] = tc->data_buf[0];

  return (PARSER_OK);
}

int md5aix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6300) || (input_len > DISPLAY_LEN_MAX_6300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MD5AIX, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 6;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len < 8) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  salt->salt_iter = 1000;

  hash_pos++;

  md5crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int sha1aix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6700) || (input_len > DISPLAY_LEN_MAX_6700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA1AIX, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 7;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  u8 salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoll ((const char *) salt_iter);

  salt->salt_iter = (1u << atoll ((const char *) salt_iter)) - 1;

  hash_pos++;

  sha1aix_decode ((u8 *) digest, (u8 *) hash_pos);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int sha256aix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6400) || (input_len > DISPLAY_LEN_MAX_6400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA256AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 9;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoll ((const char *) salt_iter);

  salt->salt_iter = (1u << atoll ((const char *) salt_iter)) - 1;

  hash_pos++;

  sha256aix_decode ((u8 *) digest, (u8 *) hash_pos);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int sha512aix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6500) || (input_len > DISPLAY_LEN_MAX_6500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512AIX, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 9;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len < 16) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  char salt_iter[3] = { iter_pos[0], iter_pos[1], 0 };

  salt->salt_sign[0] = atoll ((const char *) salt_iter);

  salt->salt_iter = (1u << atoll ((const char *) salt_iter)) - 1;

  hash_pos++;

  sha512aix_decode ((u8 *) digest, (u8 *) hash_pos);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int agilekey_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6600) || (input_len > DISPLAY_LEN_MAX_6600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  agilekey_t *agilekey = (agilekey_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *iterations_pos = input_buf;

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iterations_len = saltbuf_pos - iterations_pos;

  if (iterations_len > 6) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  u8 *cipherbuf_pos = (u8 *) strchr ((const char *) saltbuf_pos, ':');

  if (cipherbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltbuf_len = cipherbuf_pos - saltbuf_pos;

  if (saltbuf_len != 16) return (PARSER_SALT_LENGTH);

  u32 cipherbuf_len = input_len - iterations_len - 1 - saltbuf_len - 1;

  if (cipherbuf_len != 2080) return (PARSER_HASH_LENGTH);

  cipherbuf_pos++;

  /**
   * pbkdf2 iterations
   */

  salt->salt_iter = atoll ((const char *) iterations_pos) - 1;

  /**
   * handle salt encoding
   */

  u8 *saltbuf_ptr = (u8 *) salt->salt_buf;

  for (u32 i = 0; i < saltbuf_len; i += 2)
  {
    const u8 p0 = saltbuf_pos[i + 0];
    const u8 p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  salt->salt_len = saltbuf_len / 2;

  /**
   * handle cipher encoding
   */

  u32 tmp[32];

  u8 *cipherbuf_ptr = (u8 *) tmp;

  for (u32 i = 2016; i < cipherbuf_len; i += 2)
  {
    const u8 p0 = cipherbuf_pos[i + 0];
    const u8 p1 = cipherbuf_pos[i + 1];

    *cipherbuf_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  // iv   is stored at salt_buf 4 (length 16)
  // data is stored at salt_buf 8 (length 16)

  salt->salt_buf[ 4] = byte_swap_32 (tmp[0]);
  salt->salt_buf[ 5] = byte_swap_32 (tmp[1]);
  salt->salt_buf[ 6] = byte_swap_32 (tmp[2]);
  salt->salt_buf[ 7] = byte_swap_32 (tmp[3]);

  salt->salt_buf[ 8] = byte_swap_32 (tmp[4]);
  salt->salt_buf[ 9] = byte_swap_32 (tmp[5]);
  salt->salt_buf[10] = byte_swap_32 (tmp[6]);
  salt->salt_buf[11] = byte_swap_32 (tmp[7]);

  for (u32 i = 0, j = 0; i < 1040; i += 1, j += 2)
  {
    const u8 p0 = cipherbuf_pos[j + 0];
    const u8 p1 = cipherbuf_pos[j + 1];

    agilekey->cipher[i] = hex_convert (p1) << 0
                        | hex_convert (p0) << 4;
  }

  /**
   * digest buf
   */

  digest[0] = 0x10101010;
  digest[1] = 0x10101010;
  digest[2] = 0x10101010;
  digest[3] = 0x10101010;

  return (PARSER_OK);
}

int lastpass_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6800) || (input_len > DISPLAY_LEN_MAX_6800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *hashbuf_pos = input_buf;

  u8 *iterations_pos = (u8 *) strchr ((const char *) hashbuf_pos, ':');

  if (iterations_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 hash_len = iterations_pos - hashbuf_pos;

  if ((hash_len != 32) && (hash_len != 64)) return (PARSER_HASH_LENGTH);

  iterations_pos++;

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) iterations_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iterations_len = saltbuf_pos - iterations_pos;

  saltbuf_pos++;

  u32 salt_len = input_len - hash_len - 1 - iterations_len - 1;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, saltbuf_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  salt->salt_iter = atoll ((const char *) iterations_pos) - 1;

  if (is_valid_hex_string (hashbuf_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int gost_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_6900) || (input_len > DISPLAY_LEN_MAX_6900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  return (PARSER_OK);
}

int sha256crypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (memcmp (SIGNATURE_SHA256CRYPT, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 3;

  u32 iterations_len = 0;

  if (memcmp (salt_pos, "rounds=", 7) == 0)
  {
    salt_pos += 7;

    for (iterations_len = 0; salt_pos[0] >= '0' && salt_pos[0] <= '9' && iterations_len < 7; iterations_len++, salt_pos += 1) continue;

    if (iterations_len ==  0 ) return (PARSER_SALT_ITERATION);
    if (salt_pos[0]    != '$') return (PARSER_SIGNATURE_UNMATCHED);

    salt_pos[0] = 0x0;

    salt->salt_iter = atoll ((const char *) (salt_pos - iterations_len));

    salt_pos += 1;

    iterations_len += 8;
  }
  else
  {
    salt->salt_iter = ROUNDS_SHA256CRYPT;
  }

  if ((input_len < DISPLAY_LEN_MIN_7400) || (input_len > DISPLAY_LEN_MAX_7400 + iterations_len)) return (PARSER_GLOBAL_LENGTH);

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  hash_pos++;

  sha256crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int sha512osx_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 max_len = DISPLAY_LEN_MAX_7100 + (2 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7100) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512OSX, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  u8 *iter_pos = input_buf + 4;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  if (is_valid_hex_string (hash_pos, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  u32 salt_len = hash_pos - salt_pos - 1;

  if ((salt_len % 2) != 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len / 2;

  if (is_valid_hex_string (salt_pos, 64) == false) return (PARSER_HASH_ENCODING);

  pbkdf2_sha512->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  pbkdf2_sha512->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  pbkdf2_sha512->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  pbkdf2_sha512->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);
  pbkdf2_sha512->salt_buf[4] = hex_to_u32 ((const u8 *) &salt_pos[32]);
  pbkdf2_sha512->salt_buf[5] = hex_to_u32 ((const u8 *) &salt_pos[40]);
  pbkdf2_sha512->salt_buf[6] = hex_to_u32 ((const u8 *) &salt_pos[48]);
  pbkdf2_sha512->salt_buf[7] = hex_to_u32 ((const u8 *) &salt_pos[56]);
  pbkdf2_sha512->salt_buf[8] = 0x01000000;
  pbkdf2_sha512->salt_buf[9] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_iter = atoll ((const char *) iter_pos) - 1;

  return (PARSER_OK);
}

int episerver4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1441) || (input_len > DISPLAY_LEN_MAX_1441)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_EPISERVER4, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 14;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  u32 salt_len = hash_pos - salt_pos - 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) hash_pos, 43, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  return (PARSER_OK);
}

int sha512grub_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  u32 max_len = DISPLAY_LEN_MAX_7200 + (8 * 128);

  if ((input_len < DISPLAY_LEN_MIN_7200) || (input_len > max_len)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512GRUB, input_buf, 19)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  u8 *iter_pos = input_buf + 19;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '.');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '.');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (((input_len - (hash_pos - input_buf) - 1) % 128) != 0) return (PARSER_GLOBAL_LENGTH);

  hash_pos++;

  if (is_valid_hex_string (hash_pos, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &hash_pos[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &hash_pos[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &hash_pos[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &hash_pos[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &hash_pos[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &hash_pos[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &hash_pos[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &hash_pos[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  u32 salt_len = hash_pos - salt_pos - 1;

  salt_len /= 2;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha512->salt_buf;

  if (is_valid_hex_string (salt_pos, salt_len) == false) return (PARSER_SALT_ENCODING);

  u32 i;

  for (i = 0; i < salt_len; i++)
  {
    salt_buf_ptr[i] = hex_to_u8 ((const u8 *) &salt_pos[i * 2]);
  }

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];

  salt->salt_len = salt_len;

  salt->salt_iter = atoll ((const char *) iter_pos) - 1;

  return (PARSER_OK);
}

int sha512b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1711) || (input_len > DISPLAY_LEN_MAX_1711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA512B64S, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, (const u8 *) input_buf + 9, input_len - 9, tmp_buf);

  if (tmp_len < 64) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  const int salt_len = tmp_len - 64;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, tmp_buf + 64, salt->salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int hmacmd5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_50H) || (input_len > DISPLAY_LEN_MAX_50H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_50) || (input_len > DISPLAY_LEN_MAX_50)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_150H) || (input_len > DISPLAY_LEN_MAX_150H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_150) || (input_len > DISPLAY_LEN_MAX_150)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1450H) || (input_len > DISPLAY_LEN_MAX_1450H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1450) || (input_len > DISPLAY_LEN_MAX_1450)) return (PARSER_GLOBAL_LENGTH);
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (input_buf[64] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 64 - 1;

  u8 *salt_buf = input_buf + 64 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int hmacsha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    if ((input_len < DISPLAY_LEN_MIN_1750H) || (input_len > DISPLAY_LEN_MAX_1750H)) return (PARSER_GLOBAL_LENGTH);
  }
  else
  {
    if ((input_len < DISPLAY_LEN_MIN_1750) || (input_len > DISPLAY_LEN_MAX_1750)) return (PARSER_GLOBAL_LENGTH);
  }

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (input_buf[128] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 128 - 1;

  u8 *salt_buf = input_buf + 128 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int krb5pa_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_7500) || (input_len > DISPLAY_LEN_MAX_7500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KRB5PA, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5pa_t *krb5pa = (krb5pa_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *user_pos = input_buf + 10 + 1;

  u8 *realm_pos = (u8 *) strchr ((const char *) user_pos, '$');

  if (realm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 user_len = realm_pos - user_pos;

  if (user_len >= 64) return (PARSER_SALT_LENGTH);

  realm_pos++;

  u8 *salt_pos = (u8 *) strchr ((const char *) realm_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 realm_len = salt_pos - realm_pos;

  if (realm_len >= 64) return (PARSER_SALT_LENGTH);

  salt_pos++;

  u8 *data_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = data_pos - salt_pos;

  if (salt_len >= 128) return (PARSER_SALT_LENGTH);

  data_pos++;

  u32 data_len = input_len - 10 - 1 - user_len - 1 - realm_len - 1 - salt_len - 1;

  if (data_len != ((36 + 16) * 2)) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  memcpy (krb5pa->user,  user_pos,  user_len);
  memcpy (krb5pa->realm, realm_pos, realm_len);
  memcpy (krb5pa->salt,  salt_pos,  salt_len);

  u8 *timestamp_ptr = (u8 *) krb5pa->timestamp;

  for (u32 i = 0; i < (36 * 2); i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *timestamp_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  u8 *checksum_ptr = (u8 *) krb5pa->checksum;

  for (u32 i = (36 * 2); i < ((36 + 16) * 2); i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

  /**
   * copy some data to generic buffers to make sorting happy
   */

  salt->salt_buf[0] = krb5pa->timestamp[0];
  salt->salt_buf[1] = krb5pa->timestamp[1];
  salt->salt_buf[2] = krb5pa->timestamp[2];
  salt->salt_buf[3] = krb5pa->timestamp[3];
  salt->salt_buf[4] = krb5pa->timestamp[4];
  salt->salt_buf[5] = krb5pa->timestamp[5];
  salt->salt_buf[6] = krb5pa->timestamp[6];
  salt->salt_buf[7] = krb5pa->timestamp[7];
  salt->salt_buf[8] = krb5pa->timestamp[8];

  salt->salt_len = 36;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = krb5pa->checksum[3];

  return (PARSER_OK);
}

int sapb_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_7700) || (input_len > DISPLAY_LEN_MAX_7700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *salt_pos = input_buf;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 1 - salt_len;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  /**
   * valid some data
   */

  u32 user_len = 0;

  for (u32 i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
   * copy data
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  if (is_valid_hex_string (hash_pos, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[8]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int sapg_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_7800) || (input_len > DISPLAY_LEN_MAX_7800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *salt_pos = input_buf;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len >= 40) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 1 - salt_len;

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  /**
   * valid some data
   */

  u32 user_len = 0;

  for (u32 i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  // this is kinda buggy. if the username is in utf the length can be up to length 12*3
  // so far nobody complained so we stay with this because it helps in optimization
  // final string can have a max size of 32 (password) + (10 * 5) = lengthMagicArray + 12 (max salt) + 1 (the 0x80)

  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  /**
   * copy data
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int drupal7_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_7900) || (input_len > DISPLAY_LEN_MAX_7900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DRUPAL7, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 3;

  u32 salt_iter = 1u << itoa64_to_int (iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy ((u8 *) salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  u8 *salt_pos = iter_pos + 1;

  u32 salt_len = 8;

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  u8 *hash_pos = salt_pos + salt_len;

  drupal7_decode ((u8 *) digest, (u8 *) hash_pos);

  // ugly hack start

  u8 *tmp = (u8 *) salt->salt_buf_pc;

  tmp[0] = hash_pos[42];

  // ugly hack end

  digest[ 0] = byte_swap_64 (digest[ 0]);
  digest[ 1] = byte_swap_64 (digest[ 1]);
  digest[ 2] = byte_swap_64 (digest[ 2]);
  digest[ 3] = byte_swap_64 (digest[ 3]);
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;

  return (PARSER_OK);
}

int sybasease_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8000) || (input_len > DISPLAY_LEN_MAX_8000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SYBASEASE, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 6;

  u32 salt_len = 16;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u8 *hash_pos = input_buf + 6 + 16;

  if (is_valid_hex_string (hash_pos, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int mysql323_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_200) || (input_len > DISPLAY_LEN_MAX_200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rakp_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_7300) || (input_len > DISPLAY_LEN_MAX_7300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rakp_t *rakp = (rakp_t *) hash_buf->esalt;

  u8 *saltbuf_pos = input_buf;

  u8 *hashbuf_pos = (u8 *) strchr ((const char *) saltbuf_pos, ':');

  if (hashbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltbuf_len = hashbuf_pos - saltbuf_pos;

  if (saltbuf_len <  64) return (PARSER_SALT_LENGTH);
  if (saltbuf_len > 512) return (PARSER_SALT_LENGTH);

  if (saltbuf_len & 1) return (PARSER_SALT_LENGTH); // muss gerade sein wegen hex

  hashbuf_pos++;

  u32 hashbuf_len = input_len - saltbuf_len - 1;

  if (hashbuf_len != 40) return (PARSER_HASH_LENGTH);

  u8 *salt_ptr = (u8 *) saltbuf_pos;
  u8 *rakp_ptr = (u8 *) rakp->salt_buf;

  if (is_valid_hex_string (salt_ptr, saltbuf_len) == false) return (PARSER_SALT_ENCODING);

  u32 i;
  u32 j;

  for (i = 0, j = 0; i < saltbuf_len; i += 2, j += 1)
  {
    rakp_ptr[j] = hex_to_u8 ((const u8 *) &salt_ptr[i]);
  }

  rakp_ptr[j] = 0x80;

  rakp->salt_len = j;

  for (i = 0; i < 64; i++)
  {
    rakp->salt_buf[i] = byte_swap_32 (rakp->salt_buf[i]);
  }

  salt->salt_buf[0] = rakp->salt_buf[0];
  salt->salt_buf[1] = rakp->salt_buf[1];
  salt->salt_buf[2] = rakp->salt_buf[2];
  salt->salt_buf[3] = rakp->salt_buf[3];
  salt->salt_buf[4] = rakp->salt_buf[4];
  salt->salt_buf[5] = rakp->salt_buf[5];
  salt->salt_buf[6] = rakp->salt_buf[6];
  salt->salt_buf[7] = rakp->salt_buf[7];

  salt->salt_len = 32; // muss min. 32 haben

  if (is_valid_hex_string (hashbuf_pos, 40) == false) return (PARSER_SALT_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hashbuf_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int netscaler_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8100) || (input_len > DISPLAY_LEN_MAX_8100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (memcmp (SIGNATURE_NETSCALER, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  u8 *salt_pos = input_buf + 1;

  memcpy (salt->salt_buf, salt_pos, 8);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_len = 8;

  u8 *hash_pos = salt_pos + 8;

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int chap_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_4800) || (input_len > DISPLAY_LEN_MAX_4800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u8 *salt_buf_ptr = input_buf + 32 + 1;

  u32 *salt_buf = salt->salt_buf;

  if (is_valid_hex_string (salt_buf_ptr, 32) == false) return (PARSER_SALT_ENCODING);

  salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf_ptr[ 0]);
  salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf_ptr[ 8]);
  salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf_ptr[16]);
  salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf_ptr[24]);

  salt->salt_len = 16 + 1;

  if (input_buf[65] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u8 *idbyte_buf_ptr = input_buf + 32 + 1 + 32 + 1;

  salt_buf[4] = hex_to_u8 ((const u8 *) &idbyte_buf_ptr[0]) & 0xff;

  return (PARSER_OK);
}

int cloudkey_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8200) || (input_len > DISPLAY_LEN_MAX_8200)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  cloudkey_t *cloudkey = (cloudkey_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *hashbuf_pos = input_buf;

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) hashbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 hashbuf_len = saltbuf_pos - hashbuf_pos;

  if (hashbuf_len != 64) return (PARSER_HASH_LENGTH);

  saltbuf_pos++;

  u8 *iteration_pos = (u8 *) strchr ((const char *) saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  u8 *databuf_pos = (u8 *) strchr ((const char *) iteration_pos, ':');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 iteration_len = databuf_pos - iteration_pos;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 8) return (PARSER_SALT_ITERATION);

  const u32 databuf_len = input_len - hashbuf_len - 1 - saltbuf_len - 1 - iteration_len - 1;

  if (databuf_len <    1) return (PARSER_SALT_LENGTH);
  if (databuf_len > 2048) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  // digest

  if (is_valid_hex_string (hashbuf_pos, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hashbuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hashbuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hashbuf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hashbuf_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hashbuf_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hashbuf_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hashbuf_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  // salt

  u8 *saltbuf_ptr = (u8 *) salt->salt_buf;

  for (u32 i = 0; i < saltbuf_len; i += 2)
  {
    const u8 p0 = saltbuf_pos[i + 0];
    const u8 p1 = saltbuf_pos[i + 1];

    *saltbuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  salt->salt_buf[4] = 0x01000000;
  salt->salt_buf[5] = 0x80;

  salt->salt_len = saltbuf_len / 2;

  // iteration

  salt->salt_iter = atoll ((const char *) iteration_pos) - 1;

  // data

  u8 *databuf_ptr = (u8 *) cloudkey->data_buf;

  for (u32 i = 0; i < databuf_len; i += 2)
  {
    const u8 p0 = databuf_pos[i + 0];
    const u8 p1 = databuf_pos[i + 1];

    *databuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  *databuf_ptr++ = 0x80;

  for (u32 i = 0; i < 512; i++)
  {
    cloudkey->data_buf[i] = byte_swap_32 (cloudkey->data_buf[i]);
  }

  cloudkey->data_len = databuf_len / 2;

  return (PARSER_OK);
}

int nsec3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8300) || (input_len > DISPLAY_LEN_MAX_8300)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *hashbuf_pos = input_buf;

  u8 *domainbuf_pos = (u8 *) strchr ((const char *) hashbuf_pos, ':');

  if (domainbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 hashbuf_len = domainbuf_pos - hashbuf_pos;

  if (hashbuf_len != 32) return (PARSER_HASH_LENGTH);

  domainbuf_pos++;

  if (domainbuf_pos[0] != '.') return (PARSER_SALT_VALUE);

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) domainbuf_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 domainbuf_len = saltbuf_pos - domainbuf_pos;

  if (domainbuf_len >= 32) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  u8 *iteration_pos = (u8 *) strchr ((const char *) saltbuf_pos, ':');

  if (iteration_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 saltbuf_len = iteration_pos - saltbuf_pos;

  if (saltbuf_len >= 28) return (PARSER_SALT_LENGTH); // 28 = 32 - 4; 4 = length

  if ((domainbuf_len + saltbuf_len) >= 48) return (PARSER_SALT_LENGTH);

  iteration_pos++;

  const u32 iteration_len = input_len - hashbuf_len - 1 - domainbuf_len - 1 - saltbuf_len - 1;

  if (iteration_len < 1) return (PARSER_SALT_ITERATION);
  if (iteration_len > 5) return (PARSER_SALT_ITERATION);

  // ok, the plan for this algorithm is the following:
  // we have 2 salts here, the domain-name and a random salt
  // while both are used in the initial transformation,
  // only the random salt is used in the following iterations
  // so we create two buffer, one that includes domain-name (stored into salt_buf_pc[])
  // and one that includes only the real salt (stored into salt_buf[]).
  // the domain-name length is put into array position 7 of salt_buf_pc[] since there is not salt_pc_len

  u8 tmp_buf[100] = { 0 };

  base32_decode (itoa32_to_int, (const u8 *) hashbuf_pos, 32, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // domain

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  memcpy (salt_buf_pc_ptr, domainbuf_pos, domainbuf_len);

  if (salt_buf_pc_ptr[0] != '.') return (PARSER_SALT_VALUE);

  u8 *len_ptr = salt_buf_pc_ptr;

  *len_ptr = 0;

  for (u32 i = 1; i < domainbuf_len; i++)
  {
    if (salt_buf_pc_ptr[i] == '.')
    {
      len_ptr = salt_buf_pc_ptr + i;

      *len_ptr = 0;
    }
    else
    {
      *len_ptr += 1;
    }
  }

  salt->salt_buf_pc[7] = domainbuf_len;

  // "real" salt

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  const u32 salt_len = parse_and_store_salt (salt_buf_ptr, saltbuf_pos, saltbuf_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  // iteration

  salt->salt_iter = atoll ((const char *) iteration_pos);

  return (PARSER_OK);
}

int wbb3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8400) || (input_len > DISPLAY_LEN_MAX_8400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int opencart_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13900) || (input_len > DISPLAY_LEN_MAX_13900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if ((salt_len != 9) || (salt_len == UINT_MAX)) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int racf_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  const u8 ascii_to_ebcdic[] =
  {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
    0x40, 0x4f, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0x4a, 0xe0, 0x5a, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x6a, 0xd0, 0xa1, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
    0x9f, 0xa0, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  };

  if ((input_len < DISPLAY_LEN_MIN_8500) || (input_len > DISPLAY_LEN_MAX_8500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RACF, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 6 + 1;

  u8 *digest_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = digest_pos - salt_pos;

  if (salt_len > 8) return (PARSER_SALT_LENGTH);

  u32 hash_len = input_len - 1 - salt_len - 1 - 6;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);

  digest_pos++;

  u8 *salt_buf_ptr    = (u8 *) salt->salt_buf;
  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  for (u32 i = 0; i < salt_len; i++)
  {
    salt_buf_pc_ptr[i] = ascii_to_ebcdic[(int) salt_buf_ptr[i]];
  }
  for (u32 i = salt_len; i < 8; i++)
  {
    salt_buf_pc_ptr[i] = 0x40;
  }

  u32 tt;

  IP (salt->salt_buf_pc[0], salt->salt_buf_pc[1], tt);

  salt->salt_buf_pc[0] = rotl32 (salt->salt_buf_pc[0], 3u);
  salt->salt_buf_pc[1] = rotl32 (salt->salt_buf_pc[1], 3u);

  if (is_valid_hex_string (digest_pos, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);

  IP (digest[0], digest[1], tt);

  digest[0] = rotr32 (digest[0], 29);
  digest[1] = rotr32 (digest[1], 29);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int des_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_14000) || (input_len > DISPLAY_LEN_MAX_14000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *digest_pos = input_buf;

  u8 *salt_pos = (u8 *) strchr ((const char *) digest_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  if (input_buf[16] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = salt_pos - digest_pos;

  u32 hash_len = input_len - 1 - salt_len;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);
  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  salt_pos++;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  u32 tt;

  salt->salt_buf_pc[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf_pc[1] = byte_swap_32 (salt->salt_buf[1]);

  IP (salt->salt_buf_pc[0], salt->salt_buf_pc[1], tt);

  if (is_valid_hex_string (digest_pos, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);

  IP (digest[0], digest[1], tt);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int lotus5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8600) || (input_len > DISPLAY_LEN_MAX_8600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  return (PARSER_OK);
}

int lotus6_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8700) || (input_len > DISPLAY_LEN_MAX_8700)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'G') || (input_buf[21] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, (const u8 *) input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  memcpy (salt->salt_buf, tmp_buf, 5);

  salt->salt_len = 5;

  memcpy (digest, tmp_buf + 5, 9);

  // yes, only 9 byte are needed to crack, but 10 to display

  salt->salt_buf_pc[7] = input_buf[20];

  return (PARSER_OK);
}

int lotus8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9100) || (input_len > DISPLAY_LEN_MAX_9100)) return (PARSER_GLOBAL_LENGTH);

  if ((input_buf[0] != '(') || (input_buf[1] != 'H') || (input_buf[DISPLAY_LEN_MAX_9100 - 1] != ')')) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, (const u8 *) input_buf + 2, input_len - 3, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  // salt

  memcpy (salt->salt_buf, tmp_buf, 16);

  salt->salt_len = 16; // Attention: in theory we have 2 salt_len, one for the -m 8700 part (len: 8), 2nd for the 9100 part (len: 16)

  // iteration

  char tmp_iter_buf[11] = { 0 };

  memcpy (tmp_iter_buf, tmp_buf + 16, 10);

  tmp_iter_buf[10] = 0;

  salt->salt_iter = atoll ((const char *) tmp_iter_buf);

  if (salt->salt_iter < 1) // well, the limit hopefully is much higher
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter--; // first round in init

  // 2 additional bytes for display only

  salt->salt_buf_pc[0] = tmp_buf[26];
  salt->salt_buf_pc[1] = tmp_buf[27];

  // digest

  memcpy (digest, tmp_buf + 28, 8);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int hmailserver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1421) || (input_len > DISPLAY_LEN_MAX_1421)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf_pos = input_buf;

  u8 *hash_buf_pos = salt_buf_pos + 6;

  if (is_valid_hex_string (hash_buf_pos, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_buf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_buf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_buf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_buf_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_buf_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_buf_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_buf_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_buf_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  const u32 salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf_pos, 6, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int phps_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_2612) || (input_len > DISPLAY_LEN_MAX_2612)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (memcmp (SIGNATURE_PHPS, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 6;

  u8 *digest_buf = (u8 *) strchr ((const char *) salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  if (is_valid_hex_string (digest_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int mediawiki_b_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_3711) || (input_len > DISPLAY_LEN_MAX_3711)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MEDIAWIKI_B, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_buf = input_buf + 3;

  u8 *digest_buf = (u8 *) strchr ((const char *) salt_buf, '$');

  if (digest_buf == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = digest_buf - salt_buf;

  digest_buf++; // skip the '$' symbol

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len] = 0x2d;

  salt->salt_len = salt_len + 1;

  if (is_valid_hex_string (digest_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  return (PARSER_OK);
}

int peoplesoft_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_133) || (input_len > DISPLAY_LEN_MAX_133)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) input_buf, input_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  salt->salt_buf[0] = 0x80;

  salt->salt_len = 0;

  return (PARSER_OK);
}

int skype_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_23) || (input_len > DISPLAY_LEN_MAX_23)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  if (input_buf[32] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  /*
   * add static "salt" part
   */

  memcpy (salt_buf_ptr + salt_len, "\nskyper\n", 8);

  salt_len += 8;

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int androidfde_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8800) || (input_len > DISPLAY_LEN_MAX_8800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ANDROIDFDE, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  androidfde_t *androidfde = (androidfde_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *saltlen_pos = input_buf + 1 + 3 + 1;

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) saltlen_pos, '$');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltlen_len = saltbuf_pos - saltlen_pos;

  if (saltlen_len != 2) return (PARSER_SALT_LENGTH);

  saltbuf_pos++;

  u8 *keylen_pos = (u8 *) strchr ((const char *) saltbuf_pos, '$');

  if (keylen_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltbuf_len = keylen_pos - saltbuf_pos;

  if (saltbuf_len != 32) return (PARSER_SALT_LENGTH);

  keylen_pos++;

  u8 *keybuf_pos = (u8 *) strchr ((const char *) keylen_pos, '$');

  if (keybuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keylen_len = keybuf_pos - keylen_pos;

  if (keylen_len != 2) return (PARSER_SALT_LENGTH);

  keybuf_pos++;

  u8 *databuf_pos = (u8 *) strchr ((const char *) keybuf_pos, '$');

  if (databuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keybuf_len = databuf_pos - keybuf_pos;

  if (keybuf_len != 32) return (PARSER_SALT_LENGTH);

  databuf_pos++;

  // u32 data_len = input_len - 1 - 3 - 1 - saltlen_len - 1 - saltbuf_len - 1 - keylen_len - 1 - keybuf_len - 1;
  //
  // the following check is not needed, since we already checked all the other lengths (sub strings)
  // if (data_len != 3072) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  if (is_valid_hex_string (keybuf_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &keybuf_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &keybuf_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &keybuf_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &keybuf_pos[24]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (is_valid_hex_string (saltbuf_pos, 32) == false) return (PARSER_HASH_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &saltbuf_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &saltbuf_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &saltbuf_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &saltbuf_pos[24]);

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_ANDROIDFDE - 1;

  if (is_valid_hex_string (databuf_pos, 3072) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; i < 3072; i += 8, j += 1)
  {
    androidfde->data[j] = hex_to_u32 ((const u8 *) &databuf_pos[i]);

    androidfde->data[j] = byte_swap_32 (androidfde->data[j]);
  }

  return (PARSER_OK);
}

int scrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_8900) || (input_len > DISPLAY_LEN_MAX_8900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SCRYPT, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  // first is the N salt parameter

  u8 *N_pos = input_buf + 6;

  if (N_pos[0] != ':') return (PARSER_SEPARATOR_UNMATCHED);

  N_pos++;

  salt->scrypt_N = atoll ((const char *) N_pos);

  // r

  u8 *r_pos = (u8 *) strchr ((const char *) N_pos, ':');

  if (r_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  r_pos++;

  salt->scrypt_r = atoll ((const char *) r_pos);

  // p

  u8 *p_pos = (u8 *) strchr ((const char *) r_pos, ':');

  if (p_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  p_pos++;

  salt->scrypt_p = atoll ((const char *) p_pos);

  // salt

  u8 *saltbuf_pos = (u8 *) strchr ((const char *) p_pos, ':');

  if (saltbuf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  saltbuf_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) saltbuf_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  // base64 decode

  int salt_len_base64 = hash_pos - saltbuf_pos;

  if (salt_len_base64 > 45) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[33] = { 0 };

  int tmp_len = base64_decode (base64_to_int, (const u8 *) saltbuf_pos, salt_len_base64, tmp_buf);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, tmp_buf, tmp_len);

  salt->salt_len  = tmp_len;
  salt->salt_iter = 1;

  // digest - base64 decode

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = input_len - (hash_pos - input_buf);

  if (tmp_len != 44) return (PARSER_GLOBAL_LENGTH);

  base64_decode (base64_to_int, (const u8 *) hash_pos, tmp_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  return (PARSER_OK);
}

int juniper_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_501) || (input_len > DISPLAY_LEN_MAX_501)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 decrypted[76] = { 0 }; // iv + hash

  juniper_decrypt_hash (input_buf, decrypted);

  u8 *md5crypt_hash = decrypted + 12;

  if (memcmp ((const char *) md5crypt_hash, "$1$danastre$", 12)) return (PARSER_SALT_VALUE);

  salt->salt_iter = ROUNDS_MD5CRYPT;

  u8 *salt_pos = md5crypt_hash + 3;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$'); // or simply salt_pos + 8

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt->salt_len = hash_pos - salt_pos;    // should be 8

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt->salt_len);

  hash_pos++;

  md5crypt_decode ((u8 *) digest, (u8 *) hash_pos);

  return (PARSER_OK);
}

int cisco8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9200) || (input_len > DISPLAY_LEN_MAX_9200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CISCO8, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // first is *raw* salt

  u8 *salt_pos = input_buf + 3;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, 14);

  salt_buf_ptr[17] = 0x01;
  salt_buf_ptr[18] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];

  salt->salt_len  = salt_len;
  salt->salt_iter = ROUNDS_CISCO8 - 1;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  u32 hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode (itoa64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int cisco9_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9300) || (input_len > DISPLAY_LEN_MAX_9300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CISCO9, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  // first is *raw* salt

  u8 *salt_pos = input_buf + 3;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len != 14) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;
  hash_pos++;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);
  salt_buf_ptr[salt_len] = 0;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  u32 hash_len = input_len - 3 - salt_len - 1;

  int tmp_len = base64_decode (itoa64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  // fixed:
  salt->scrypt_N  = 16384;
  salt->scrypt_r  = 1;
  salt->scrypt_p  = 1;
  salt->salt_iter = 1;

  return (PARSER_OK);
}

int office2007_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9400) || (input_len > DISPLAY_LEN_MAX_9400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2007, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2007_t *office2007 = (office2007_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 8 + 1;

  u8 *verifierHashSize_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (verifierHashSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = verifierHashSize_pos - version_pos;

  verifierHashSize_pos++;

  u8 *keySize_pos = (u8 *) strchr ((const char *) verifierHashSize_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 verifierHashSize_len = keySize_pos - verifierHashSize_pos;

  keySize_pos++;

  u8 *saltSize_pos = (u8 *) strchr ((const char *) keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  saltSize_pos++;

  u8 *osalt_pos = (u8 *) strchr ((const char *) saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - verifierHashSize_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  if (version_len           !=  4) return (PARSER_SALT_LENGTH);
  if (verifierHashSize_len  !=  2) return (PARSER_SALT_LENGTH);
  if (keySize_len           !=  3) return (PARSER_SALT_LENGTH);
  if (saltSize_len          !=  2) return (PARSER_SALT_LENGTH);
  if (osalt_len             != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  const u32 version           = atoll ((const char *) version_pos);
  const u32 verifierHashSize  = atoll ((const char *) verifierHashSize_pos);
  const u32 keySize           = atoll ((const char *) keySize_pos);
  const u32 saltSize          = atoll ((const char *) saltSize_pos);

  if (version           != 2007)            return (PARSER_SALT_VALUE);
  if (verifierHashSize  != 20)              return (PARSER_SALT_VALUE);
  if (saltSize          != 16)              return (PARSER_SALT_VALUE);
  if ((keySize != 128) && (keySize != 256)) return (PARSER_SALT_VALUE);

  office2007->keySize = keySize;

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_OFFICE2007;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  office2007->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2007->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2007->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2007->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2007->encryptedVerifier[0] = byte_swap_32 (office2007->encryptedVerifier[0]);
  office2007->encryptedVerifier[1] = byte_swap_32 (office2007->encryptedVerifier[1]);
  office2007->encryptedVerifier[2] = byte_swap_32 (office2007->encryptedVerifier[2]);
  office2007->encryptedVerifier[3] = byte_swap_32 (office2007->encryptedVerifier[3]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  office2007->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2007->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2007->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2007->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2007->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  office2007->encryptedVerifierHash[0] = byte_swap_32 (office2007->encryptedVerifierHash[0]);
  office2007->encryptedVerifierHash[1] = byte_swap_32 (office2007->encryptedVerifierHash[1]);
  office2007->encryptedVerifierHash[2] = byte_swap_32 (office2007->encryptedVerifierHash[2]);
  office2007->encryptedVerifierHash[3] = byte_swap_32 (office2007->encryptedVerifierHash[3]);
  office2007->encryptedVerifierHash[4] = byte_swap_32 (office2007->encryptedVerifierHash[4]);

  /**
   * digest
   */

  digest[0] = office2007->encryptedVerifierHash[0];
  digest[1] = office2007->encryptedVerifierHash[1];
  digest[2] = office2007->encryptedVerifierHash[2];
  digest[3] = office2007->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2010_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9500) || (input_len > DISPLAY_LEN_MAX_9500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2010, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2010_t *office2010 = (office2010_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 8 + 1;

  u8 *spinCount_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  spinCount_pos++;

  u8 *keySize_pos = (u8 *) strchr ((const char *) spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  keySize_pos++;

  u8 *saltSize_pos = (u8 *) strchr ((const char *) keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  saltSize_pos++;

  u8 *osalt_pos = (u8 *) strchr ((const char *) saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  if (version_len           !=  4) return (PARSER_SALT_LENGTH);
  if (spinCount_len         !=  6) return (PARSER_SALT_LENGTH);
  if (keySize_len           !=  3) return (PARSER_SALT_LENGTH);
  if (saltSize_len          !=  2) return (PARSER_SALT_LENGTH);
  if (osalt_len             != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  const u32 version   = atoll ((const char *) version_pos);
  const u32 spinCount = atoll ((const char *) spinCount_pos);
  const u32 keySize   = atoll ((const char *) keySize_pos);
  const u32 saltSize  = atoll ((const char *) saltSize_pos);

  if (version   != 2010)    return (PARSER_SALT_VALUE);
  if (spinCount != 100000)  return (PARSER_SALT_VALUE);
  if (keySize   != 128)     return (PARSER_SALT_VALUE);
  if (saltSize  != 16)      return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  office2010->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2010->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2010->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2010->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2010->encryptedVerifier[0] = byte_swap_32 (office2010->encryptedVerifier[0]);
  office2010->encryptedVerifier[1] = byte_swap_32 (office2010->encryptedVerifier[1]);
  office2010->encryptedVerifier[2] = byte_swap_32 (office2010->encryptedVerifier[2]);
  office2010->encryptedVerifier[3] = byte_swap_32 (office2010->encryptedVerifier[3]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 64) == false) return (PARSER_HASH_ENCODING);

  office2010->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2010->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2010->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2010->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2010->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);
  office2010->encryptedVerifierHash[5] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[40]);
  office2010->encryptedVerifierHash[6] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[48]);
  office2010->encryptedVerifierHash[7] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[56]);

  office2010->encryptedVerifierHash[0] = byte_swap_32 (office2010->encryptedVerifierHash[0]);
  office2010->encryptedVerifierHash[1] = byte_swap_32 (office2010->encryptedVerifierHash[1]);
  office2010->encryptedVerifierHash[2] = byte_swap_32 (office2010->encryptedVerifierHash[2]);
  office2010->encryptedVerifierHash[3] = byte_swap_32 (office2010->encryptedVerifierHash[3]);
  office2010->encryptedVerifierHash[4] = byte_swap_32 (office2010->encryptedVerifierHash[4]);
  office2010->encryptedVerifierHash[5] = byte_swap_32 (office2010->encryptedVerifierHash[5]);
  office2010->encryptedVerifierHash[6] = byte_swap_32 (office2010->encryptedVerifierHash[6]);
  office2010->encryptedVerifierHash[7] = byte_swap_32 (office2010->encryptedVerifierHash[7]);

  /**
   * digest
   */

  digest[0] = office2010->encryptedVerifierHash[0];
  digest[1] = office2010->encryptedVerifierHash[1];
  digest[2] = office2010->encryptedVerifierHash[2];
  digest[3] = office2010->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2013_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9600) || (input_len > DISPLAY_LEN_MAX_9600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OFFICE2013, input_buf, 8)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2013_t *office2013 = (office2013_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 8 + 1;

  u8 *spinCount_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (spinCount_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = spinCount_pos - version_pos;

  spinCount_pos++;

  u8 *keySize_pos = (u8 *) strchr ((const char *) spinCount_pos, '*');

  if (keySize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 spinCount_len = keySize_pos - spinCount_pos;

  keySize_pos++;

  u8 *saltSize_pos = (u8 *) strchr ((const char *) keySize_pos, '*');

  if (saltSize_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 keySize_len = saltSize_pos - keySize_pos;

  saltSize_pos++;

  u8 *osalt_pos = (u8 *) strchr ((const char *) saltSize_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 saltSize_len = osalt_pos - saltSize_pos;

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  encryptedVerifierHash_pos++;

  u32 encryptedVerifierHash_len = input_len - 8 - 1 - version_len - 1 - spinCount_len - 1 - keySize_len - 1 - saltSize_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;

  if (encryptedVerifierHash_len != 64) return (PARSER_SALT_LENGTH);

  if (version_len           !=  4) return (PARSER_SALT_LENGTH);
  if (spinCount_len         !=  6) return (PARSER_SALT_LENGTH);
  if (keySize_len           !=  3) return (PARSER_SALT_LENGTH);
  if (saltSize_len          !=  2) return (PARSER_SALT_LENGTH);
  if (osalt_len             != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  const u32 version   = atoll ((const char *) version_pos);
  const u32 spinCount = atoll ((const char *) spinCount_pos);
  const u32 keySize   = atoll ((const char *) keySize_pos);
  const u32 saltSize  = atoll ((const char *) saltSize_pos);

  if (version   != 2013)    return (PARSER_SALT_VALUE);
  if (spinCount != 100000)  return (PARSER_SALT_VALUE);
  if (keySize   != 256)     return (PARSER_SALT_VALUE);
  if (saltSize  != 16)      return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  office2013->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  office2013->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  office2013->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  office2013->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  office2013->encryptedVerifier[0] = byte_swap_32 (office2013->encryptedVerifier[0]);
  office2013->encryptedVerifier[1] = byte_swap_32 (office2013->encryptedVerifier[1]);
  office2013->encryptedVerifier[2] = byte_swap_32 (office2013->encryptedVerifier[2]);
  office2013->encryptedVerifier[3] = byte_swap_32 (office2013->encryptedVerifier[3]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 64) == false) return (PARSER_HASH_ENCODING);

  office2013->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  office2013->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  office2013->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  office2013->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  office2013->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);
  office2013->encryptedVerifierHash[5] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[40]);
  office2013->encryptedVerifierHash[6] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[48]);
  office2013->encryptedVerifierHash[7] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[56]);

  office2013->encryptedVerifierHash[0] = byte_swap_32 (office2013->encryptedVerifierHash[0]);
  office2013->encryptedVerifierHash[1] = byte_swap_32 (office2013->encryptedVerifierHash[1]);
  office2013->encryptedVerifierHash[2] = byte_swap_32 (office2013->encryptedVerifierHash[2]);
  office2013->encryptedVerifierHash[3] = byte_swap_32 (office2013->encryptedVerifierHash[3]);
  office2013->encryptedVerifierHash[4] = byte_swap_32 (office2013->encryptedVerifierHash[4]);
  office2013->encryptedVerifierHash[5] = byte_swap_32 (office2013->encryptedVerifierHash[5]);
  office2013->encryptedVerifierHash[6] = byte_swap_32 (office2013->encryptedVerifierHash[6]);
  office2013->encryptedVerifierHash[7] = byte_swap_32 (office2013->encryptedVerifierHash[7]);

  /**
   * digest
   */

  digest[0] = office2013->encryptedVerifierHash[0];
  digest[1] = office2013->encryptedVerifierHash[1];
  digest[2] = office2013->encryptedVerifierHash[2];
  digest[3] = office2013->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9700) || (input_len > DISPLAY_LEN_MAX_9700)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 11;

  u8 *osalt_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  // The following check is implied (and therefore not needed aka dead code):
  // u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;
  // if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  const u32 version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice01->version = version;

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice01->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);

  /**
   * salt
   */

  salt->salt_len = 16;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice01->encryptedVerifierHash[0];
  digest[1] = oldoffice01->encryptedVerifierHash[1];
  digest[2] = oldoffice01->encryptedVerifierHash[2];
  digest[3] = oldoffice01->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice01cm1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  return oldoffice01_parse_hash (input_buf, input_len, hash_buf, hashconfig);
}

int oldoffice01cm2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9720) || (input_len > DISPLAY_LEN_MAX_9720)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE0, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE1, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 11;

  u8 *osalt_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  encryptedVerifierHash_pos++;

  u8 *rc4key_pos = (u8 *) strchr ((const char *) encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  if (version_len               !=  1) return (PARSER_SALT_LENGTH);
  if (osalt_len                 != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifier_len     != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifierHash_len != 32) return (PARSER_SALT_LENGTH);

  const u32 version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice01->version = version;

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice01->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice01->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice01->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice01->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);

  oldoffice01->rc4key[1] = 0;
  oldoffice01->rc4key[0] = 0;

  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  oldoffice01->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  oldoffice01->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  oldoffice01->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  oldoffice01->rc4key[0] = byte_swap_32 (oldoffice01->rc4key[0]);
  oldoffice01->rc4key[1] = byte_swap_32 (oldoffice01->rc4key[1]);

  /**
   * salt
   */

  salt->salt_len = 16;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice01->rc4key[0];
  digest[1] = oldoffice01->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int oldoffice34_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9800) || (input_len > DISPLAY_LEN_MAX_9800)) return (PARSER_GLOBAL_LENGTH);

  if ((memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) && (memcmp (SIGNATURE_OLDOFFICE4, input_buf, 12))) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 11;

  u8 *osalt_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  if (version_len != 1) return (PARSER_SALT_LENGTH);

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  if (osalt_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  if (encryptedVerifier_len != 32) return (PARSER_SALT_LENGTH);

  encryptedVerifierHash_pos++;

  // The following check is implied (and therefore not needed aka dead code):
  // u32 encryptedVerifierHash_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1;
  // if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);

  const u32 version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice34->version = version;

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice34->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  /**
   * salt
   */

  salt->salt_len = 16;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice34->encryptedVerifierHash[0];
  digest[1] = oldoffice34->encryptedVerifierHash[1];
  digest[2] = oldoffice34->encryptedVerifierHash[2];
  digest[3] = oldoffice34->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int oldoffice34cm1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  return oldoffice34_parse_hash (input_buf, input_len, hash_buf, hashconfig);
}

int oldoffice34cm2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9820) || (input_len > DISPLAY_LEN_MAX_9820)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_OLDOFFICE3, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  oldoffice34_t *oldoffice34 = (oldoffice34_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *version_pos = input_buf + 11;

  u8 *osalt_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (osalt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = osalt_pos - version_pos;

  osalt_pos++;

  u8 *encryptedVerifier_pos = (u8 *) strchr ((const char *) osalt_pos, '*');

  if (encryptedVerifier_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 osalt_len = encryptedVerifier_pos - osalt_pos;

  encryptedVerifier_pos++;

  u8 *encryptedVerifierHash_pos = (u8 *) strchr ((const char *) encryptedVerifier_pos, '*');

  if (encryptedVerifierHash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifier_len = encryptedVerifierHash_pos - encryptedVerifier_pos;

  encryptedVerifierHash_pos++;

  u8 *rc4key_pos = (u8 *) strchr ((const char *) encryptedVerifierHash_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 encryptedVerifierHash_len = rc4key_pos - encryptedVerifierHash_pos;

  rc4key_pos++;

  u32 rc4key_len = input_len - 11 - version_len - 1 - osalt_len - 1 - encryptedVerifier_len - 1 - encryptedVerifierHash_len - 1;

  if (version_len               !=  1) return (PARSER_SALT_LENGTH);
  if (osalt_len                 != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifier_len     != 32) return (PARSER_SALT_LENGTH);
  if (encryptedVerifierHash_len != 40) return (PARSER_SALT_LENGTH);
  if (rc4key_len                != 10) return (PARSER_SALT_LENGTH);

  const u32 version = *version_pos - 0x30;

  if (version != 3 && version != 4) return (PARSER_SALT_VALUE);

  /**
   * esalt
   */

  oldoffice34->version = version;

  if (is_valid_hex_string (encryptedVerifier_pos, 32) == false) return (PARSER_HASH_ENCODING);

  oldoffice34->encryptedVerifier[0] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 0]);
  oldoffice34->encryptedVerifier[1] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[ 8]);
  oldoffice34->encryptedVerifier[2] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[16]);
  oldoffice34->encryptedVerifier[3] = hex_to_u32 ((const u8 *) &encryptedVerifier_pos[24]);

  if (is_valid_hex_string (encryptedVerifierHash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  oldoffice34->encryptedVerifierHash[0] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 0]);
  oldoffice34->encryptedVerifierHash[1] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[ 8]);
  oldoffice34->encryptedVerifierHash[2] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[16]);
  oldoffice34->encryptedVerifierHash[3] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[24]);
  oldoffice34->encryptedVerifierHash[4] = hex_to_u32 ((const u8 *) &encryptedVerifierHash_pos[32]);

  oldoffice34->rc4key[1] = 0;
  oldoffice34->rc4key[0] = 0;

  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  oldoffice34->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  oldoffice34->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  oldoffice34->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  oldoffice34->rc4key[0] = byte_swap_32 (oldoffice34->rc4key[0]);
  oldoffice34->rc4key[1] = byte_swap_32 (oldoffice34->rc4key[1]);

  /**
   * salt
   */

  salt->salt_len = 16;

  if (is_valid_hex_string (osalt_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &osalt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &osalt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &osalt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &osalt_pos[24]);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_len += 32;

  salt->salt_buf[ 4] = oldoffice34->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice34->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice34->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice34->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice34->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice34->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice34->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice34->encryptedVerifierHash[3];

  /**
   * digest
   */

  digest[0] = oldoffice34->rc4key[0];
  digest[1] = oldoffice34->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int radmin2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_9900) || (input_len > DISPLAY_LEN_MAX_9900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  return (PARSER_OK);
}

int djangosha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_124) || (input_len > DISPLAY_LEN_MAX_124)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DJANGOSHA1, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *signature_pos = input_buf;

  u8 *salt_pos = (u8 *) strchr ((const char *) signature_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 signature_len = salt_pos - signature_pos;

  if (signature_len != 4) return (PARSER_SIGNATURE_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - signature_len - 1 - salt_len - 1;

  if (hash_len != 40) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int djangopbkdf2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10000) || (input_len > DISPLAY_LEN_MAX_10000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_DJANGOPBKDF2, input_buf, 14)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *iter_pos = input_buf + 14;

  const int iter = atoi ((const char *) iter_pos);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const u32 salt_len = hash_pos - salt_pos;

  hash_pos++;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len  = salt_len;

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // base64 decode hash

  u8 tmp_buf[100] = { 0 };

  u32 hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 44) return (PARSER_HASH_LENGTH);

  base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int siphash_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10100) || (input_len > DISPLAY_LEN_MAX_10100)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 16) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  if (input_buf[16] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[18] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);
  if (input_buf[20] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  char iter_c = input_buf[17];
  char iter_d = input_buf[19];

  // atm only defaults, let's see if there's more request
  if (iter_c != '2') return (PARSER_SALT_ITERATION);
  if (iter_d != '4') return (PARSER_SALT_ITERATION);

  u8 *salt_buf = input_buf + 16 + 1 + 1 + 1 + 1 + 1;

  if (is_valid_hex_string (salt_buf, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int crammd5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10200) || (input_len > DISPLAY_LEN_MAX_10200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_CRAM_MD5, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  cram_md5_t *cram_md5 = (cram_md5_t *) hash_buf->esalt;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 10;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  hash_pos++;

  u32 hash_len = input_len - 10 - salt_len - 1;

  // base64 decode salt

  if (salt_len > 133) return (PARSER_SALT_LENGTH);

  u8 tmp_buf[100] = { 0 };

  salt_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, tmp_buf);

  if (salt_len > 55) return (PARSER_SALT_LENGTH);

  tmp_buf[salt_len] = 0x80;

  memcpy (&salt->salt_buf, tmp_buf, salt_len + 1);

  salt->salt_len = salt_len;

  // base64 decode hash

  if (hash_len > 133) return (PARSER_HASH_LENGTH);

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (hash_len < 32 + 1) return (PARSER_HASH_LENGTH);

  u32 user_len = hash_len - 32;

  const u8 *tmp_hash = tmp_buf + user_len;

  user_len--; // skip the trailing space

  if (is_valid_hex_string (tmp_hash, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 (&tmp_hash[ 0]);
  digest[1] = hex_to_u32 (&tmp_hash[ 8]);
  digest[2] = hex_to_u32 (&tmp_hash[16]);
  digest[3] = hex_to_u32 (&tmp_hash[24]);

  // store username for host only (output hash if cracked)

  memset (cram_md5->user, 0, sizeof (cram_md5->user));
  memcpy (cram_md5->user, tmp_buf, user_len);

  return (PARSER_OK);
}

int saph_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10300) || (input_len > DISPLAY_LEN_MAX_10300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SAPH_SHA1, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 10;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter < 1)
  {
    return (PARSER_SALT_ITERATION);
  }

  iter--; // first iteration is special

  salt->salt_iter = iter;

  u8 *base64_pos = (u8 *) strchr ((const char *) iter_pos, '}');

  if (base64_pos == NULL)
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }

  base64_pos++;

  // base64 decode salt

  const u32 base64_len = input_len - (base64_pos - input_buf);

  u8 tmp_buf[100] = { 0 };

  const u32 decoded_len = base64_decode (base64_to_int, (const u8 *) base64_pos, base64_len, tmp_buf);

  if (decoded_len < 24)
  {
    return (PARSER_SALT_LENGTH);
  }

  // copy the salt

  const u32 salt_len = decoded_len - 20;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy (&salt->salt_buf, tmp_buf + 20, salt_len);

  salt->salt_len = salt_len;

  // set digest

  u32 *digest_ptr = (u32*) tmp_buf;

  digest[0] = byte_swap_32 (digest_ptr[0]);
  digest[1] = byte_swap_32 (digest_ptr[1]);
  digest[2] = byte_swap_32 (digest_ptr[2]);
  digest[3] = byte_swap_32 (digest_ptr[3]);
  digest[4] = byte_swap_32 (digest_ptr[4]);

  return (PARSER_OK);
}

int redmine_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_4521) || (input_len > DISPLAY_LEN_MAX_4521)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int punbb_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_4522) || (input_len > DISPLAY_LEN_MAX_4522)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len != 12) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int pdf11_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10400) || (input_len > DISPLAY_LEN_MAX_10400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PDF, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *V_pos = input_buf + 5;

  u8 *R_pos = (u8 *) strchr ((const char *) V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  u8 *bits_pos = (u8 *) strchr ((const char *) R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  u8 *P_pos = (u8 *) strchr ((const char *) bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  u8 *enc_md_pos = (u8 *) strchr ((const char *) P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  u8 *id_len_pos = (u8 *) strchr ((const char *) enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  u8 *id_buf_pos = (u8 *) strchr ((const char *) id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  u8 *u_len_pos = (u8 *) strchr ((const char *) id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  u8 *u_buf_pos = (u8 *) strchr ((const char *) u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  u8 *o_len_pos = (u8 *) strchr ((const char *) u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  u8 *o_buf_pos = (u8 *) strchr ((const char *) o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi ((const char *) V_pos);
  const int R = atoi ((const char *) R_pos);
  const int P = atoi ((const char *) P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi ((const char *) enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi ((const char *) id_len_pos);
  const int u_len  = atoi ((const char *) u_len_pos);
  const int o_len  = atoi ((const char *) o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi ((const char *) bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  if (is_valid_hex_string (id_buf_pos, 32) == false) return (PARSER_SALT_ENCODING);

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);
  pdf->id_len    = id_len;

  if (is_valid_hex_string (u_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  if (is_valid_hex_string (o_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_len    = pdf->id_len;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];

  return (PARSER_OK);
}

int pdf11cm1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  return pdf11_parse_hash (input_buf, input_len, hash_buf, hashconfig);
}

int pdf11cm2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10420) || (input_len > DISPLAY_LEN_MAX_10420)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PDF, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *V_pos = input_buf + 5;

  u8 *R_pos = (u8 *) strchr ((const char *) V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  u8 *bits_pos = (u8 *) strchr ((const char *) R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  u8 *P_pos = (u8 *) strchr ((const char *) bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  u8 *enc_md_pos = (u8 *) strchr ((const char *) P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  u8 *id_len_pos = (u8 *) strchr ((const char *) enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  u8 *id_buf_pos = (u8 *) strchr ((const char *) id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  u8 *u_len_pos = (u8 *) strchr ((const char *) id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if (id_buf_len != 32) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  u8 *u_buf_pos = (u8 *) strchr ((const char *) u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  u8 *o_len_pos = (u8 *) strchr ((const char *) u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  u8 *o_buf_pos = (u8 *) strchr ((const char *) o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u8 *rc4key_pos = (u8 *) strchr ((const char *) o_buf_pos, ':');

  if (rc4key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_buf_len = rc4key_pos - o_buf_pos;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  rc4key_pos++;

  u32 rc4key_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1 - o_buf_len - 1;

  if (rc4key_len != 10) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi ((const char *) V_pos);
  const int R = atoi ((const char *) R_pos);
  const int P = atoi ((const char *) P_pos);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = atoi ((const char *) enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = atoi ((const char *) id_len_pos);
  const int u_len  = atoi ((const char *) u_len_pos);
  const int o_len  = atoi ((const char *) o_len_pos);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi ((const char *) bits_pos);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  if (is_valid_hex_string (id_buf_pos, 32) == false) return (PARSER_SALT_ENCODING);

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);
  pdf->id_len    = id_len;

  if (is_valid_hex_string (u_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  if (is_valid_hex_string (o_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  pdf->rc4key[1] = 0;
  pdf->rc4key[0] = 0;

  pdf->rc4key[0] |= hex_convert (rc4key_pos[0]) << 28;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[1]) << 24;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[2]) << 20;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[3]) << 16;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[4]) << 12;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[5]) <<  8;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[6]) <<  4;
  pdf->rc4key[0] |= hex_convert (rc4key_pos[7]) <<  0;
  pdf->rc4key[1] |= hex_convert (rc4key_pos[8]) << 28;
  pdf->rc4key[1] |= hex_convert (rc4key_pos[9]) << 24;

  pdf->rc4key[0] = byte_swap_32 (pdf->rc4key[0]);
  pdf->rc4key[1] = byte_swap_32 (pdf->rc4key[1]);

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len    = pdf->id_len + 16;

  digest[0] = pdf->rc4key[0];
  digest[1] = pdf->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf14_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10500) || (input_len > DISPLAY_LEN_MAX_10500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PDF, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *V_pos = input_buf + 5;

  u8 *R_pos = (u8 *) strchr ((const char *) V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  u8 *bits_pos = (u8 *) strchr ((const char *) R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  u8 *P_pos = (u8 *) strchr ((const char *) bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  u8 *enc_md_pos = (u8 *) strchr ((const char *) P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  u8 *id_len_pos = (u8 *) strchr ((const char *) enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  u8 *id_buf_pos = (u8 *) strchr ((const char *) id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  u8 *u_len_pos = (u8 *) strchr ((const char *) id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  if ((id_buf_len != 32) && (id_buf_len != 64)) return (PARSER_SALT_LENGTH);

  u_len_pos++;

  u8 *u_buf_pos = (u8 *) strchr ((const char *) u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  u8 *o_len_pos = (u8 *) strchr ((const char *) u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  if (u_buf_len != 64) return (PARSER_SALT_LENGTH);

  o_len_pos++;

  u8 *o_buf_pos = (u8 *) strchr ((const char *) o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u32 o_buf_len = input_len - 5 - V_len - 1 - R_len - 1 - bits_len - 1 - P_len - 1 - enc_md_len - 1 - id_len_len - 1 - id_buf_len - 1 - u_len_len - 1 - u_buf_len - 1 - o_len_len - 1;

  if (o_buf_len != 64) return (PARSER_SALT_LENGTH);

  // validate data

  const int V = atoi ((const char *) V_pos);
  const int R = atoi ((const char *) R_pos);
  const int P = atoi ((const char *) P_pos);

  int vr_ok = 0;

  if ((V == 2) && (R == 3)) vr_ok = 1;
  if ((V == 4) && (R == 4)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int id_len = atoi ((const char *) id_len_pos);
  const int u_len  = atoi ((const char *) u_len_pos);
  const int o_len  = atoi ((const char *) o_len_pos);

  if ((id_len != 16) && (id_len != 32)) return (PARSER_SALT_VALUE);

  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = atoi ((const char *) bits_pos);

  if (bits != 128) return (PARSER_SALT_VALUE);

  int enc_md = 1;

  if (R >= 4)
  {
    enc_md = atoi ((const char *) enc_md_pos);
  }

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  if (is_valid_hex_string (id_buf_pos, 32) == false) return (PARSER_SALT_ENCODING);

  pdf->id_buf[0] = hex_to_u32 ((const u8 *) &id_buf_pos[ 0]);
  pdf->id_buf[1] = hex_to_u32 ((const u8 *) &id_buf_pos[ 8]);
  pdf->id_buf[2] = hex_to_u32 ((const u8 *) &id_buf_pos[16]);
  pdf->id_buf[3] = hex_to_u32 ((const u8 *) &id_buf_pos[24]);

  if (id_len == 32)
  {
    if (is_valid_hex_string (id_buf_pos + 32, 32) == false) return (PARSER_SALT_ENCODING);

    pdf->id_buf[4] = hex_to_u32 ((const u8 *) &id_buf_pos[32]);
    pdf->id_buf[5] = hex_to_u32 ((const u8 *) &id_buf_pos[40]);
    pdf->id_buf[6] = hex_to_u32 ((const u8 *) &id_buf_pos[48]);
    pdf->id_buf[7] = hex_to_u32 ((const u8 *) &id_buf_pos[56]);
  }

  pdf->id_len = id_len;

  if (is_valid_hex_string (u_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->u_buf[0]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 0]);
  pdf->u_buf[1]  = hex_to_u32 ((const u8 *) &u_buf_pos[ 8]);
  pdf->u_buf[2]  = hex_to_u32 ((const u8 *) &u_buf_pos[16]);
  pdf->u_buf[3]  = hex_to_u32 ((const u8 *) &u_buf_pos[24]);
  pdf->u_buf[4]  = hex_to_u32 ((const u8 *) &u_buf_pos[32]);
  pdf->u_buf[5]  = hex_to_u32 ((const u8 *) &u_buf_pos[40]);
  pdf->u_buf[6]  = hex_to_u32 ((const u8 *) &u_buf_pos[48]);
  pdf->u_buf[7]  = hex_to_u32 ((const u8 *) &u_buf_pos[56]);
  pdf->u_len     = u_len;

  if (is_valid_hex_string (o_buf_pos, 64) == false) return (PARSER_SALT_ENCODING);

  pdf->o_buf[0]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 0]);
  pdf->o_buf[1]  = hex_to_u32 ((const u8 *) &o_buf_pos[ 8]);
  pdf->o_buf[2]  = hex_to_u32 ((const u8 *) &o_buf_pos[16]);
  pdf->o_buf[3]  = hex_to_u32 ((const u8 *) &o_buf_pos[24]);
  pdf->o_buf[4]  = hex_to_u32 ((const u8 *) &o_buf_pos[32]);
  pdf->o_buf[5]  = hex_to_u32 ((const u8 *) &o_buf_pos[40]);
  pdf->o_buf[6]  = hex_to_u32 ((const u8 *) &o_buf_pos[48]);
  pdf->o_buf[7]  = hex_to_u32 ((const u8 *) &o_buf_pos[56]);
  pdf->o_len     = o_len;

  // precompute rc4 data for later use

  u32 padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  // md5

  u32 salt_pc_block[32] = { 0 };

  u8 *salt_pc_ptr = (u8 *) salt_pc_block;

  memcpy (salt_pc_ptr, padding, 32);
  memcpy (salt_pc_ptr + 32, pdf->id_buf, pdf->id_len);

  u32 salt_pc_digest[4] = { 0 };

  md5_complete_no_limit (salt_pc_digest, salt_pc_block, 32 + pdf->id_len);

  pdf->rc4data[0] = salt_pc_digest[0];
  pdf->rc4data[1] = salt_pc_digest[1];

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_buf[4] = pdf->u_buf[0];
  salt->salt_buf[5] = pdf->u_buf[1];
  salt->salt_buf[6] = pdf->o_buf[0];
  salt->salt_buf[7] = pdf->o_buf[1];
  salt->salt_len    = pdf->id_len + 16;

  salt->salt_iter   = ROUNDS_PDF14;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int pdf17l3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  int ret = pdf17l8_parse_hash (input_buf, input_len, hash_buf, hashconfig);

  if (ret != PARSER_OK)
  {
    return ret;
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  salt->salt_buf[2] = 0x80;

  return (PARSER_OK);
}

int pdf17l8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10600) || (input_len > DISPLAY_LEN_MAX_10600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PDF, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *V_pos = input_buf + 5;

  u8 *R_pos = (u8 *) strchr ((const char *) V_pos, '*');

  if (R_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 V_len = R_pos - V_pos;

  R_pos++;

  u8 *bits_pos = (u8 *) strchr ((const char *) R_pos, '*');

  if (bits_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 R_len = bits_pos - R_pos;

  bits_pos++;

  u8 *P_pos = (u8 *) strchr ((const char *) bits_pos, '*');

  if (P_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 bits_len = P_pos - bits_pos;

  P_pos++;

  u8 *enc_md_pos = (u8 *) strchr ((const char *) P_pos, '*');

  if (enc_md_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 P_len = enc_md_pos - P_pos;

  enc_md_pos++;

  u8 *id_len_pos = (u8 *) strchr ((const char *) enc_md_pos, '*');

  if (id_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_md_len = id_len_pos - enc_md_pos;

  id_len_pos++;

  u8 *id_buf_pos = (u8 *) strchr ((const char *) id_len_pos, '*');

  if (id_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_len_len = id_buf_pos - id_len_pos;

  id_buf_pos++;

  u8 *u_len_pos = (u8 *) strchr ((const char *) id_buf_pos, '*');

  if (u_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 id_buf_len = u_len_pos - id_buf_pos;

  u_len_pos++;

  u8 *u_buf_pos = (u8 *) strchr ((const char *) u_len_pos, '*');

  if (u_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_len_len = u_buf_pos - u_len_pos;

  u_buf_pos++;

  u8 *o_len_pos = (u8 *) strchr ((const char *) u_buf_pos, '*');

  if (o_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 u_buf_len = o_len_pos - u_buf_pos;

  o_len_pos++;

  u8 *o_buf_pos = (u8 *) strchr ((const char *) o_len_pos, '*');

  if (o_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 o_len_len = o_buf_pos - o_len_pos;

  o_buf_pos++;

  u8 *last = (u8 *) strchr ((const char *) o_buf_pos, '*');

  if (last == NULL) last = input_buf + input_len;

  u32 o_buf_len = last - o_buf_pos;

  // validate data

  const int V = atoi ((const char *) V_pos);
  const int R = atoi ((const char *) R_pos);

  int vr_ok = 0;

  if ((V == 5) && (R == 5)) vr_ok = 1;
  if ((V == 5) && (R == 6)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int bits = atoi ((const char *) bits_pos);

  if (bits != 256) return (PARSER_SALT_VALUE);

  int enc_md = atoi ((const char *) enc_md_pos);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const u32 id_len = atoll ((const char *) id_len_pos);
  const u32 u_len  = atoll ((const char *) u_len_pos);
  const u32 o_len  = atoll ((const char *) o_len_pos);

  if (V_len      > 6) return (PARSER_SALT_LENGTH);
  if (R_len      > 6) return (PARSER_SALT_LENGTH);
  if (P_len      > 6) return (PARSER_SALT_LENGTH);
  if (id_len_len > 6) return (PARSER_SALT_LENGTH);
  if (u_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (o_len_len  > 6) return (PARSER_SALT_LENGTH);
  if (bits_len   > 6) return (PARSER_SALT_LENGTH);
  if (enc_md_len > 6) return (PARSER_SALT_LENGTH);

  if ((id_len * 2) != id_buf_len) return (PARSER_SALT_VALUE);
  if ((u_len  * 2) != u_buf_len)  return (PARSER_SALT_VALUE);
  if ((o_len  * 2) != o_buf_len)  return (PARSER_SALT_VALUE);

  // copy data to esalt

  if (u_len < 40) return (PARSER_SALT_VALUE);

  if (is_valid_hex_string (u_buf_pos, 80) == false) return (PARSER_SALT_ENCODING);

  for (int i = 0, j = 0; i < 8 + 2; i += 1, j += 8)
  {
    pdf->u_buf[i] = hex_to_u32 ((const u8 *) &u_buf_pos[j]);
  }

  salt->salt_buf[0] = pdf->u_buf[8];
  salt->salt_buf[1] = pdf->u_buf[9];

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_PDF17L8;

  digest[0] = byte_swap_32 (pdf->u_buf[0]);
  digest[1] = byte_swap_32 (pdf->u_buf[1]);
  digest[2] = byte_swap_32 (pdf->u_buf[2]);
  digest[3] = byte_swap_32 (pdf->u_buf[3]);
  digest[4] = byte_swap_32 (pdf->u_buf[4]);
  digest[5] = byte_swap_32 (pdf->u_buf[5]);
  digest[6] = byte_swap_32 (pdf->u_buf[6]);
  digest[7] = byte_swap_32 (pdf->u_buf[7]);

  return (PARSER_OK);
}

int pbkdf2_sha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_10900) || (input_len > DISPLAY_LEN_MAX_10900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA256, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  u8 *iter_pos = input_buf + 7;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len > (64 - 8)) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int prestashop_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11000) || (input_len > DISPLAY_LEN_MAX_11000)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);

  if (input_buf[32] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 32 - 1;

  u8 *salt_buf = input_buf + 32 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int postgresql_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11100) || (input_len > DISPLAY_LEN_MAX_11100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_POSTGRESQL_AUTH, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *user_pos = input_buf + 10;

  u8 *salt_pos = (u8 *) strchr ((const char *) user_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  u32 hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 32) return (PARSER_HASH_LENGTH);

  u32 user_len = salt_pos - user_pos - 1;

  u32 salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 8) return (PARSER_SALT_LENGTH);

  /*
   * store digest
   */

  if (is_valid_hex_string (hash_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  digest[0] -= MD5M_A;
  digest[1] -= MD5M_B;
  digest[2] -= MD5M_C;
  digest[3] -= MD5M_D;

  /*
   * store salt
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  // first 4 bytes are the "challenge"

  if (is_valid_hex_string (salt_pos, 8) == false) return (PARSER_SALT_ENCODING);

  salt_buf_ptr[0] = hex_to_u8 ((const u8 *) &salt_pos[0]);
  salt_buf_ptr[1] = hex_to_u8 ((const u8 *) &salt_pos[2]);
  salt_buf_ptr[2] = hex_to_u8 ((const u8 *) &salt_pos[4]);
  salt_buf_ptr[3] = hex_to_u8 ((const u8 *) &salt_pos[6]);

  // append the user name

  user_len = parse_and_store_salt (salt_buf_ptr + 4, user_pos, user_len, hashconfig);

  salt->salt_len = 4 + user_len;

  return (PARSER_OK);
}

int mysql_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11200) || (input_len > DISPLAY_LEN_MAX_11200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MYSQL_AUTH, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *salt_pos = input_buf + 9;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  hash_pos++;

  u32 hash_len = input_len - (hash_pos - input_buf);

  if (hash_len != 40) return (PARSER_HASH_LENGTH);

  u32 salt_len = hash_pos - salt_pos - 1;

  if (salt_len != 40) return (PARSER_SALT_LENGTH);

  /*
   * store digest
   */

  if (is_valid_hex_string (hash_pos, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  /*
   * store salt
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int bitcoin_wallet_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11300) || (input_len > DISPLAY_LEN_MAX_11300)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_BITCOIN_WALLET, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  bitcoin_wallet_t *bitcoin_wallet = (bitcoin_wallet_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *cry_master_len_pos = input_buf + 9;

  u8 *cry_master_buf_pos = (u8 *) strchr ((const char *) cry_master_len_pos, '$');

  if (cry_master_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_len_len = cry_master_buf_pos - cry_master_len_pos;

  cry_master_buf_pos++;

  u8 *cry_salt_len_pos = (u8 *) strchr ((const char *) cry_master_buf_pos, '$');

  if (cry_salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_master_buf_len = cry_salt_len_pos - cry_master_buf_pos;

  cry_salt_len_pos++;

  u8 *cry_salt_buf_pos = (u8 *) strchr ((const char *) cry_salt_len_pos, '$');

  if (cry_salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_len_len = cry_salt_buf_pos - cry_salt_len_pos;

  cry_salt_buf_pos++;

  u8 *cry_rounds_pos = (u8 *) strchr ((const char *) cry_salt_buf_pos, '$');

  if (cry_rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_salt_buf_len = cry_rounds_pos - cry_salt_buf_pos;

  cry_rounds_pos++;

  u8 *ckey_len_pos = (u8 *) strchr ((const char *) cry_rounds_pos, '$');

  if (ckey_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 cry_rounds_len = ckey_len_pos - cry_rounds_pos;

  ckey_len_pos++;

  u8 *ckey_buf_pos = (u8 *) strchr ((const char *) ckey_len_pos, '$');

  if (ckey_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_len_len = ckey_buf_pos - ckey_len_pos;

  ckey_buf_pos++;

  u8 *public_key_len_pos = (u8 *) strchr ((const char *) ckey_buf_pos, '$');

  if (public_key_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ckey_buf_len = public_key_len_pos - ckey_buf_pos;

  public_key_len_pos++;

  u8 *public_key_buf_pos = (u8 *) strchr ((const char *) public_key_len_pos, '$');

  if (public_key_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 public_key_len_len = public_key_buf_pos - public_key_len_pos;

  public_key_buf_pos++;

  u32 public_key_buf_len = input_len - 1 - 7 - 1 - cry_master_len_len - 1 - cry_master_buf_len - 1 - cry_salt_len_len - 1 - cry_salt_buf_len - 1 - cry_rounds_len - 1 - ckey_len_len - 1 - ckey_buf_len - 1 - public_key_len_len - 1;

  const u32 cry_master_len = atoll ((const char *) cry_master_len_pos);
  const u32 cry_salt_len   = atoll ((const char *) cry_salt_len_pos);
  const u32 ckey_len       = atoll ((const char *) ckey_len_pos);
  const u32 public_key_len = atoll ((const char *) public_key_len_pos);

  if (cry_master_buf_len != cry_master_len) return (PARSER_SALT_VALUE);
  if (cry_salt_buf_len   != cry_salt_len)   return (PARSER_SALT_VALUE);
  if (ckey_buf_len       != ckey_len)       return (PARSER_SALT_VALUE);
  if (public_key_buf_len != public_key_len) return (PARSER_SALT_VALUE);

  if (is_valid_hex_string (cry_master_buf_pos, cry_master_len) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; j < cry_master_len; i += 1, j += 8)
  {
    bitcoin_wallet->cry_master_buf[i] = hex_to_u32 ((const u8 *) &cry_master_buf_pos[j]);
  }

  if (is_valid_hex_string (ckey_buf_pos, ckey_len) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; j < ckey_len; i += 1, j += 8)
  {
    bitcoin_wallet->ckey_buf[i] = hex_to_u32 ((const u8 *) &ckey_buf_pos[j]);
  }

  if (is_valid_hex_string (public_key_buf_pos, public_key_len) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; j < public_key_len; i += 1, j += 8)
  {
    bitcoin_wallet->public_key_buf[i] = hex_to_u32 ((const u8 *) &public_key_buf_pos[j]);
  }

  bitcoin_wallet->cry_master_len = cry_master_len / 2;
  bitcoin_wallet->ckey_len       = ckey_len / 2;
  bitcoin_wallet->public_key_len = public_key_len / 2;

  /*
   * store digest (should be unique enought, hopefully)
   */

  digest[0] = bitcoin_wallet->cry_master_buf[0];
  digest[1] = bitcoin_wallet->cry_master_buf[1];
  digest[2] = bitcoin_wallet->cry_master_buf[2];
  digest[3] = bitcoin_wallet->cry_master_buf[3];

  /*
   * store salt
   */

  if (cry_rounds_len >= 7) return (PARSER_SALT_VALUE);

  const u32 cry_rounds = atoll ((const char *) cry_rounds_pos);

  salt->salt_iter = cry_rounds - 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  const u32 salt_len = parse_and_store_salt (salt_buf_ptr, cry_salt_buf_pos, cry_salt_buf_len, hashconfig);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int sip_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11400) || (input_len > DISPLAY_LEN_MAX_11400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SIP_AUTH, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  sip_t *sip = (sip_t *) hash_buf->esalt;

  // work with a temporary copy of input_buf (s.t. we can manipulate it directly)
  // why? should be fine to use original buffer
  //u8 *temp_input_buf = (u8 *) hcmalloc (input_len + 1);
  //memcpy (temp_input_buf, input_buf, input_len);

  // URI_server:

  u8 *URI_server_pos = input_buf + 6;

  u8 *URI_client_pos = (u8 *) strchr ((const char *) URI_server_pos, '*');

  if (URI_client_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  URI_client_pos[0] = 0;
  URI_client_pos++;

  u32 URI_server_len = strlen ((const char *) URI_server_pos);

  if (URI_server_len > 512) return (PARSER_SALT_LENGTH);

  // URI_client:

  u8 *user_pos = (u8 *) strchr ((const char *) URI_client_pos, '*');

  if (user_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  user_pos[0] = 0;
  user_pos++;

  u32 URI_client_len = strlen ((const char *) URI_client_pos);

  if (URI_client_len > 512) return (PARSER_SALT_LENGTH);

  // user:

  u8 *realm_pos = (u8 *) strchr ((const char *) user_pos, '*');

  if (realm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  realm_pos[0] = 0;
  realm_pos++;

  u32 user_len = strlen ((const char *) user_pos);

  if (user_len > 116) return (PARSER_SALT_LENGTH);

  // realm:

  u8 *method_pos = (u8 *) strchr ((const char *) realm_pos, '*');

  if (method_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  method_pos[0] = 0;
  method_pos++;

  u32 realm_len = strlen ((const char *) realm_pos);

  if (realm_len > 116) return (PARSER_SALT_LENGTH);

  // method:

  u8 *URI_prefix_pos = (u8 *) strchr ((const char *) method_pos, '*');

  if (URI_prefix_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  URI_prefix_pos[0] = 0;
  URI_prefix_pos++;

  u32 method_len = strlen ((const char *) method_pos);

  if (method_len > 246) return (PARSER_SALT_LENGTH);

  // URI_prefix:

  u8 *URI_resource_pos = (u8 *) strchr ((const char *) URI_prefix_pos, '*');

  if (URI_resource_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  URI_resource_pos[0] = 0;
  URI_resource_pos++;

  u32 URI_prefix_len = strlen ((const char *) URI_prefix_pos);

  if (URI_prefix_len > 245) return (PARSER_SALT_LENGTH);

  // URI_resource:

  u8 *URI_suffix_pos = (u8 *) strchr ((const char *) URI_resource_pos, '*');

  if (URI_suffix_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  URI_suffix_pos[0] = 0;
  URI_suffix_pos++;

  u32 URI_resource_len = strlen ((const char *) URI_resource_pos);

  if (URI_resource_len < 1 || URI_resource_len > 246) return (PARSER_SALT_LENGTH);

  // URI_suffix:

  u8 *nonce_pos = (u8 *) strchr ((const char *) URI_suffix_pos, '*');

  if (nonce_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  nonce_pos[0] = 0;
  nonce_pos++;

  u32 URI_suffix_len = strlen ((const char *) URI_suffix_pos);

  if (URI_suffix_len > 245) return (PARSER_SALT_LENGTH);

  // nonce:

  u8 *nonce_client_pos = (u8 *) strchr ((const char *) nonce_pos, '*');

  if (nonce_client_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  nonce_client_pos[0] = 0;
  nonce_client_pos++;

  u32 nonce_len = strlen ((const char *) nonce_pos);

  if (nonce_len < 1 || nonce_len > 50) return (PARSER_SALT_LENGTH);

  // nonce_client:

  u8 *nonce_count_pos = (u8 *) strchr ((const char *) nonce_client_pos, '*');

  if (nonce_count_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  nonce_count_pos[0] = 0;
  nonce_count_pos++;

  u32 nonce_client_len = strlen ((const char *) nonce_client_pos);

  if (nonce_client_len > 50) return (PARSER_SALT_LENGTH);

  // nonce_count:

  u8 *qop_pos = (u8 *) strchr ((const char *) nonce_count_pos, '*');

  if (qop_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  qop_pos[0] = 0;
  qop_pos++;

  u32 nonce_count_len = strlen ((const char *) nonce_count_pos);

  if (nonce_count_len > 50) return (PARSER_SALT_LENGTH);

  // qop:

  u8 *directive_pos = (u8 *) strchr ((const char *) qop_pos, '*');

  if (directive_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  directive_pos[0] = 0;
  directive_pos++;

  u32 qop_len = strlen ((const char *) qop_pos);

  if (qop_len > 50) return (PARSER_SALT_LENGTH);

  // directive

  u8 *digest_pos = (u8 *) strchr ((const char *) directive_pos, '*');

  if (digest_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  digest_pos[0] = 0;
  digest_pos++;

  u32 directive_len = strlen ((const char *) directive_pos);

  if (directive_len != 3) return (PARSER_SALT_LENGTH);

  if (memcmp (directive_pos, "MD5", 3)) return (PARSER_SIP_AUTH_DIRECTIVE);

  /*
   * first (pre-)compute: HA2 = md5 ($method . ":" . $uri)
   */

  u32 md5_len = 0;

  u32 md5_max_len = 4 * 64;

  u32 total_length = method_len + 1 + URI_prefix_len + URI_resource_len + URI_suffix_len;

  if (URI_prefix_len) total_length++;
  if (URI_suffix_len) total_length++;

  if (total_length >= md5_max_len) return (PARSER_SALT_LENGTH);

  u32 md5_remaining_len = md5_max_len;

  u32 tmp_md5_buf[64] = { 0 };

  u8 *tmp_md5_ptr = (u8 *) tmp_md5_buf;

  snprintf ((char *) tmp_md5_ptr, md5_remaining_len, "%s:", method_pos);

  md5_len     += method_len + 1;
  tmp_md5_ptr += method_len + 1;

  if (URI_prefix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf ((char *) tmp_md5_ptr, md5_remaining_len + 1, "%s:", URI_prefix_pos);

    md5_len     += URI_prefix_len + 1;
    tmp_md5_ptr += URI_prefix_len + 1;
  }

  md5_remaining_len = md5_max_len - md5_len;

  snprintf ((char *) tmp_md5_ptr, md5_remaining_len + 1, "%s", URI_resource_pos);

  md5_len     += URI_resource_len;
  tmp_md5_ptr += URI_resource_len;

  if (URI_suffix_len > 0)
  {
    md5_remaining_len = md5_max_len - md5_len;

    snprintf ((char *) tmp_md5_ptr, md5_remaining_len + 1, ":%s", URI_suffix_pos);

    md5_len += 1 + URI_suffix_len;
  }

  u32 tmp_digest[4] = { 0 };

  md5_complete_no_limit (tmp_digest, tmp_md5_buf, md5_len);

  tmp_digest[0] = byte_swap_32 (tmp_digest[0]);
  tmp_digest[1] = byte_swap_32 (tmp_digest[1]);
  tmp_digest[2] = byte_swap_32 (tmp_digest[2]);
  tmp_digest[3] = byte_swap_32 (tmp_digest[3]);

  /*
   * esalt
   */

  u8 *esalt_buf_ptr = (u8 *) sip->esalt_buf;

  u32 esalt_len = 0;

  u32 max_esalt_len = sizeof (sip->esalt_buf); // 151 = (64 + 64 + 55) - 32, where 32 is the hexadecimal MD5 HA1 hash

  // there are 2 possibilities for the esalt:

  bool with_auth = false;

  if (strlen ((const char *) qop_pos) == 4)
  {
    if (strncmp ((const char *) qop_pos, "auth", 4) == 0)
    {
      with_auth = true;
    }
  }

  if (strlen ((const char *) qop_pos) == 8)
  {
    if (strncmp ((const char *) qop_pos, "auth-int", 8) == 0)
    {
      with_auth = true;
    }
  }

  if (with_auth == true)
  {
    esalt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

    if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    snprintf ((char *) esalt_buf_ptr, max_esalt_len, ":%s:%s:%s:%s:%08x%08x%08x%08x",
      nonce_pos,
      nonce_count_pos,
      nonce_client_pos,
      qop_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }
  else
  {
    esalt_len = 1 + nonce_len + 1 + 32;

    //if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    snprintf ((char *) esalt_buf_ptr, max_esalt_len, ":%s:%08x%08x%08x%08x",
      nonce_pos,
      tmp_digest[0],
      tmp_digest[1],
      tmp_digest[2],
      tmp_digest[3]);
  }

  if (esalt_len >= 152) return (PARSER_SALT_LENGTH);

  // add 0x80 to esalt

  esalt_buf_ptr[esalt_len] = 0x80;

  sip->esalt_len = esalt_len;

  /*
   * actual salt
   */

  u8 *sip_salt_ptr = (u8 *) sip->salt_buf;

  u32 salt_len = user_len + 1 + realm_len + 1;

  u32 max_salt_len = 119;

  if (salt_len > max_salt_len) return (PARSER_SALT_LENGTH);

  snprintf ((char *) sip_salt_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  sip->salt_len = salt_len;

  /*
   * fake salt (for sorting)
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  max_salt_len = 55;

  u32 fake_salt_len = salt_len;

  if (fake_salt_len > max_salt_len)
  {
    fake_salt_len = max_salt_len;
  }

  snprintf ((char *) salt_buf_ptr, max_salt_len + 1, "%s:%s:", user_pos, realm_pos);

  salt->salt_len = fake_salt_len;

  /*
   * digest
   */

  if (is_valid_hex_string (digest_pos, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  return (PARSER_OK);
}

int crc32_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11500) || (input_len > DISPLAY_LEN_MAX_11500)) return (PARSER_GLOBAL_LENGTH);

  if (input_buf[8] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  // digest

  u8 *digest_pos = input_buf;

  if (is_valid_hex_string (digest_pos, 8) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  // salt

  u8 *salt_buf = input_buf + 8 + 1;

  u32 salt_len = 8;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int seven_zip_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11600) || (input_len > DISPLAY_LEN_MAX_11600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SEVEN_ZIP, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  seven_zip_hook_salt_t *seven_zip = (seven_zip_hook_salt_t *) hash_buf->hook_salt;

  /**
   * parse line
   */

  u8 *data_type_pos = input_buf + 4;

  u8 *NumCyclesPower_pos = (u8 *) strchr ((const char *) data_type_pos, '$');

  if (NumCyclesPower_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_type_len = NumCyclesPower_pos - data_type_pos;

  NumCyclesPower_pos++;

  u8 *salt_len_pos = (u8 *) strchr ((const char *) NumCyclesPower_pos, '$');

  if (salt_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 NumCyclesPower_len = salt_len_pos - NumCyclesPower_pos;

  salt_len_pos++;

  u8 *salt_buf_pos = (u8 *) strchr ((const char *) salt_len_pos, '$');

  if (salt_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len_len = salt_buf_pos - salt_len_pos;

  salt_buf_pos++;

  u8 *iv_len_pos = (u8 *) strchr ((const char *) salt_buf_pos, '$');

  if (iv_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_buf_len = iv_len_pos - salt_buf_pos;

  iv_len_pos++;

  u8 *iv_buf_pos = (u8 *) strchr ((const char *) iv_len_pos, '$');

  if (iv_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_len_len = iv_buf_pos - iv_len_pos;

  iv_buf_pos++;

  u8 *crc_buf_pos = (u8 *) strchr ((const char *) iv_buf_pos, '$');

  if (crc_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_buf_len = crc_buf_pos - iv_buf_pos;

  crc_buf_pos++;

  u8 *data_len_pos = (u8 *) strchr ((const char *) crc_buf_pos, '$');

  if (data_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 crc_buf_len = data_len_pos - crc_buf_pos;

  data_len_pos++;

  u8 *unpack_size_pos = (u8 *) strchr ((const char *) data_len_pos, '$');

  if (unpack_size_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = unpack_size_pos - data_len_pos;

  unpack_size_pos++;

  u8 *data_buf_pos = (u8 *) strchr ((const char *) unpack_size_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 unpack_size_len = data_buf_pos - unpack_size_pos;

  data_buf_pos++;

  // fields only used when data was compressed:

  u8 *crc_len_pos = (u8 *) strchr ((const char *) data_buf_pos, '$');

  u32 crc_len_len          = 0;
  u8 *coder_attributes_pos = 0;
  u32 coder_attributes_len = 0;

  u32 data_buf_len = 0;

  if (crc_len_pos != NULL)
  {
    data_buf_len = crc_len_pos - data_buf_pos;

    crc_len_pos++;

    coder_attributes_pos = (u8 *) strchr ((const char *) crc_len_pos, '$');

    if (coder_attributes_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    crc_len_len = coder_attributes_pos - crc_len_pos;

    coder_attributes_pos++;
  }
  else
  {
    data_buf_len = input_len - 1 - 2 - 1 - data_type_len - 1 - NumCyclesPower_len - 1 - salt_len_len - 1 - salt_buf_len - 1 - iv_len_len - 1 - iv_buf_len - 1 - crc_buf_len - 1 - data_len_len - 1 - unpack_size_len - 1;
  }

  const u32 iter         = atoll ((const char *) NumCyclesPower_pos);
  const u32 crc          = atoll ((const char *) crc_buf_pos);
  const u32 data_type    = atoll ((const char *) data_type_pos);
  const u32 salt_len     = atoll ((const char *) salt_len_pos);
  const u32 iv_len       = atoll ((const char *) iv_len_pos);
  const u32 unpack_size  = atoll ((const char *) unpack_size_pos);
  const u32 data_len     = atoll ((const char *) data_len_pos);

  // if neither uncompressed nor truncated, then we need the length for crc and coder attributes

  u32 crc_len = 0;

  bool is_compressed = ((data_type != 0) && (data_type != 0x80));

  if (is_compressed == true)
  {
    if (crc_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    coder_attributes_len = input_len - 1 - 2 - 1 - data_type_len - 1 - NumCyclesPower_len - 1 - salt_len_len - 1 - salt_buf_len - 1 - iv_len_len - 1 - iv_buf_len - 1 - crc_buf_len - 1 - data_len_len - 1 - unpack_size_len - 1 - data_buf_len - 1 - crc_len_len - 1;

    crc_len = atoll ((const char *) crc_len_pos);
  }

  /**
   * verify some data
   */

  if (data_type > 2) // this includes also 0x80 (special case that means "truncated")
  {
    return (PARSER_SALT_VALUE);
  }

  if (salt_len != 0) return (PARSER_SALT_VALUE);

  if ((data_len * 2) != data_buf_len) return (PARSER_SALT_VALUE);

  if (data_len > 327528) return (PARSER_SALT_VALUE);

  if (unpack_size > data_len) return (PARSER_SALT_VALUE);

  if (is_compressed == true)
  {
    if (crc_len_len > 5) return (PARSER_SALT_VALUE);

    if (coder_attributes_len > 10) return (PARSER_SALT_VALUE);

    if ((coder_attributes_len % 2) != 0) return (PARSER_SALT_VALUE);

    // we should be more strict about the needed attribute_len:

    if (data_type == 1) // LZMA1
    {
      if ((coder_attributes_len / 2) != 5) return (PARSER_SALT_VALUE);
    }
    else if (data_type == 2) // LZMA2
    {
      if ((coder_attributes_len / 2) != 1) return (PARSER_SALT_VALUE);
    }
  }

  /**
   * store data
   */

  seven_zip->data_type = data_type;

  if (is_valid_hex_string (iv_buf_pos, 32) == false) return (PARSER_SALT_ENCODING);

  seven_zip->iv_buf[0] = hex_to_u32 ((const u8 *) &iv_buf_pos[ 0]);
  seven_zip->iv_buf[1] = hex_to_u32 ((const u8 *) &iv_buf_pos[ 8]);
  seven_zip->iv_buf[2] = hex_to_u32 ((const u8 *) &iv_buf_pos[16]);
  seven_zip->iv_buf[3] = hex_to_u32 ((const u8 *) &iv_buf_pos[24]);

  seven_zip->iv_len = iv_len;

  memcpy (seven_zip->salt_buf, salt_buf_pos, salt_buf_len); // we just need that for later ascii_digest()

  seven_zip->salt_len = 0;

  seven_zip->crc = crc;

  if (is_valid_hex_string (data_buf_pos, data_buf_len) == false) return (PARSER_SALT_ENCODING);

  for (u32 i = 0, j = 0; j < data_buf_len; i += 1, j += 8)
  {
    seven_zip->data_buf[i] = hex_to_u32 ((const u8 *) &data_buf_pos[j]);
  }

  seven_zip->data_len = data_len;

  seven_zip->unpack_size = unpack_size;

  seven_zip->crc_len = crc_len;

  memset (seven_zip->coder_attributes, 0, sizeof (seven_zip->coder_attributes));

  seven_zip->coder_attributes_len = 0;

  if (is_compressed == 1)
  {
    if (is_valid_hex_string (coder_attributes_pos, coder_attributes_len) == false) return (PARSER_SALT_ENCODING);

    for (u32 i = 0, j = 0; j < coder_attributes_len; i += 1, j += 2)
    {
      seven_zip->coder_attributes[i] = hex_to_u8 ((const u8 *) &coder_attributes_pos[j]);

      seven_zip->coder_attributes_len++;
    }
  }

  // normally: crc_len <= unpacksize <= packsize (== data_len)

  u32 aes_len = data_len;

  if (crc_len != 0) // it is 0 only in case of uncompressed data or truncated data
  {
    // in theory we could just use crc_len, but sometimes (very rare) the compressed data
    // is larger than the original data! (because of some additional bytes from lzma/headers)
    // the +0.5 is used to round up (just to be sure we don't truncate)

    if (data_type == 1) // LZMA1 uses more bytes
    {
      aes_len = 32.5f + (float) crc_len * 1.05f; // +5% max (only for small random inputs)
    }
    else if (data_type == 2) // LZMA2 is more clever (e.g. uncompressed chunks)
    {
      aes_len =  4.5f + (float) crc_len * 1.01f; // +1% max (only for small random inputs)
    }

    // just make sure we never go beyond the data_len limit itself

    aes_len = MIN (aes_len, data_len);
  }

  seven_zip->aes_len = aes_len;

  // real salt

  salt->salt_buf[0] = seven_zip->data_buf[0];
  salt->salt_buf[1] = seven_zip->data_buf[1];
  salt->salt_buf[2] = seven_zip->data_buf[2];
  salt->salt_buf[3] = seven_zip->data_buf[3];

  salt->salt_len = 16;

  salt->salt_sign[0] = data_type;

  salt->salt_iter = 1u << iter;

  /**
   * digest
   */

  digest[0] = crc;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int gost2012sbog_256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11700) || (input_len > DISPLAY_LEN_MAX_11700)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  return (PARSER_OK);
}

int gost2012sbog_512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11800) || (input_len > DISPLAY_LEN_MAX_11800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[ 0] = hex_to_u32 ((const u8 *) &input_buf[  0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &input_buf[  8]);
  digest[ 2] = hex_to_u32 ((const u8 *) &input_buf[ 16]);
  digest[ 3] = hex_to_u32 ((const u8 *) &input_buf[ 24]);
  digest[ 4] = hex_to_u32 ((const u8 *) &input_buf[ 32]);
  digest[ 5] = hex_to_u32 ((const u8 *) &input_buf[ 40]);
  digest[ 6] = hex_to_u32 ((const u8 *) &input_buf[ 48]);
  digest[ 7] = hex_to_u32 ((const u8 *) &input_buf[ 56]);
  digest[ 8] = hex_to_u32 ((const u8 *) &input_buf[ 64]);
  digest[ 9] = hex_to_u32 ((const u8 *) &input_buf[ 72]);
  digest[10] = hex_to_u32 ((const u8 *) &input_buf[ 80]);
  digest[11] = hex_to_u32 ((const u8 *) &input_buf[ 88]);
  digest[12] = hex_to_u32 ((const u8 *) &input_buf[ 96]);
  digest[13] = hex_to_u32 ((const u8 *) &input_buf[104]);
  digest[14] = hex_to_u32 ((const u8 *) &input_buf[112]);
  digest[15] = hex_to_u32 ((const u8 *) &input_buf[120]);

  return (PARSER_OK);
}

int pbkdf2_md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_11900) || (input_len > DISPLAY_LEN_MAX_11900)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_MD5, input_buf, 4)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_md5_t *pbkdf2_md5 = (pbkdf2_md5_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  u8 *iter_pos = input_buf + 4;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  u8 *salt_buf_ptr = (u8 *) pbkdf2_md5->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len > (64 - 8)) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_md5->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_md5->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_md5->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_md5->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12000) || (input_len > DISPLAY_LEN_MAX_12000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA1, input_buf, 5)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha1_t *pbkdf2_sha1 = (pbkdf2_sha1_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  u8 *iter_pos = input_buf + 5;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha1->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len > (64 - 8)) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha1->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha1->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha1->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha1->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int pbkdf2_sha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12100) || (input_len > DISPLAY_LEN_MAX_12100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_PBKDF2_SHA512, input_buf, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iterations

  u8 *iter_pos = input_buf + 7;

  u32 iter = atoll ((const char *) iter_pos);

  if (iter <      1) return (PARSER_SALT_ITERATION);
  if (iter > 999999) return (PARSER_SALT_ITERATION);

  // first is *raw* salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, ':');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  if (salt_len > 64) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_b64_len = input_len - (hash_pos - input_buf);

  if (hash_b64_len > 88) return (PARSER_HASH_LENGTH);

  // decode salt

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha512->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  if (salt_len > (128 - 16)) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // decode hash

  u8 tmp_buf[100] = { 0 };

  int hash_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_b64_len, tmp_buf);

  if (hash_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int ecryptfs_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12200) || (input_len > DISPLAY_LEN_MAX_12200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ECRYPTFS, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *salt_pos = input_buf + 10 + 2 + 2; // skip over "0$" and "1$"

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  hash_pos++;

  u32 hash_len = input_len - 10 - 2 - 2 - salt_len - 1;

  if (hash_len != 16) return (PARSER_HASH_LENGTH);
  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  // decode hash

  if (is_valid_hex_string (hash_pos, 16) == false) return (PARSER_HASH_ENCODING);

  digest[ 0] = hex_to_u32 ((const u8 *) &hash_pos[0]);
  digest[ 1] = hex_to_u32 ((const u8 *) &hash_pos[8]);
  digest[ 2] = 0;
  digest[ 3] = 0;
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;
  digest[ 8] = 0;
  digest[ 9] = 0;
  digest[10] = 0;
  digest[11] = 0;
  digest[12] = 0;
  digest[13] = 0;
  digest[14] = 0;
  digest[15] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  // decode salt

  if (is_valid_hex_string (salt_pos, 16) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[8]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_iter = ROUNDS_ECRYPTFS;
  salt->salt_len  = 8;

  return (PARSER_OK);
}

int bsdicrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12400) || (input_len > DISPLAY_LEN_MAX_12400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_BSDICRYPT, input_buf, 1)) return (PARSER_SIGNATURE_UNMATCHED);

  unsigned char c19 = itoa64_to_int (input_buf[19]);

  if (c19 & 3) return (PARSER_HASH_VALUE);

  salt_t *salt = hash_buf->salt;

  u32 *digest = (u32 *) hash_buf->digest;

  // iteration count

  salt->salt_iter = itoa64_to_int (input_buf[1])
                  | itoa64_to_int (input_buf[2]) <<  6
                  | itoa64_to_int (input_buf[3]) << 12
                  | itoa64_to_int (input_buf[4]) << 18;

  // set salt

  salt->salt_buf[0] = itoa64_to_int (input_buf[5])
                    | itoa64_to_int (input_buf[6]) <<  6
                    | itoa64_to_int (input_buf[7]) << 12
                    | itoa64_to_int (input_buf[8]) << 18;

  salt->salt_len = 4;

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) input_buf + 9, 11, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  u32 tt;

  IP (digest[0], digest[1], tt);

  digest[0] = rotr32 (digest[0], 31);
  digest[1] = rotr32 (digest[1], 31);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar3hp_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12500) || (input_len > DISPLAY_LEN_MAX_12500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RAR3, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *type_pos = input_buf + 6 + 1;

  u8 *salt_pos = (u8 *) strchr ((const char *) type_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 type_len = salt_pos - type_pos;

  salt_pos++;

  u8 *crypted_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (crypted_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = crypted_pos - salt_pos;

  crypted_pos++;

  u32 crypted_len = input_len - 6 - 1 - type_len - 1 - salt_len - 1;

  if (crypted_len != 32) return (PARSER_SALT_LENGTH);
  if (type_len    !=  1) return (PARSER_SALT_LENGTH);
  if (salt_len    != 16) return (PARSER_SALT_LENGTH);

  /**
   * copy data
   */

  if (is_valid_hex_string (salt_pos, 16) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[8]);

  if (is_valid_hex_string (crypted_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &crypted_pos[ 0]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &crypted_pos[ 8]);
  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &crypted_pos[16]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &crypted_pos[24]);

  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);
  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);

  salt->salt_len  = 24;
  salt->salt_iter = ROUNDS_RAR3;

  // there's no hash for rar3. the data which is in crypted_pos is some encrypted data and
  // if it matches the value \xc4\x3d\x7b\x00\x40\x07\x00 after decrypt we know that we successfully cracked it.

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int rar5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13000) || (input_len > DISPLAY_LEN_MAX_13000)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_RAR5, input_buf, 1 + 4 + 1)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  rar5_t *rar5 = (rar5_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *param0_pos = input_buf + 1 + 4 + 1;

  u8 *param1_pos = (u8 *) strchr ((const char *) param0_pos, '$');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  u8 *param2_pos = (u8 *) strchr ((const char *) param1_pos, '$');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  u8 *param3_pos = (u8 *) strchr ((const char *) param2_pos, '$');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  u8 *param4_pos = (u8 *) strchr ((const char *) param3_pos, '$');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  u8 *param5_pos = (u8 *) strchr ((const char *) param4_pos, '$');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  u32 param5_len = input_len - 1 - 4 - 1 - param0_len - 1 - param1_len - 1 - param2_len - 1 - param3_len - 1 - param4_len - 1;

  u8 *salt_buf = param1_pos;
  u8 *iv       = param3_pos;
  u8 *pswcheck = param5_pos;

  const u32 salt_len     = atoll ((const char *) param0_pos);
  const u32 iterations   = atoll ((const char *) param2_pos);
  const u32 pswcheck_len = atoll ((const char *) param4_pos);

  /**
   * verify some data
   */

  if (param1_len   != 32) return (PARSER_SALT_VALUE);
  if (param3_len   != 32) return (PARSER_SALT_VALUE);
  if (param5_len   != 16) return (PARSER_SALT_VALUE);

  if (salt_len     != 16) return (PARSER_SALT_VALUE);
  if (iterations   ==  0) return (PARSER_SALT_VALUE);
  if (pswcheck_len !=  8) return (PARSER_SALT_VALUE);

  /**
   * store data
   */

  if (is_valid_hex_string (salt_buf, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  if (is_valid_hex_string (iv, 32) == false) return (PARSER_SALT_ENCODING);

  rar5->iv[0] = hex_to_u32 ((const u8 *) &iv[ 0]);
  rar5->iv[1] = hex_to_u32 ((const u8 *) &iv[ 8]);
  rar5->iv[2] = hex_to_u32 ((const u8 *) &iv[16]);
  rar5->iv[3] = hex_to_u32 ((const u8 *) &iv[24]);

  rar5->iv[0] = byte_swap_32 (rar5->iv[0]);
  rar5->iv[1] = byte_swap_32 (rar5->iv[1]);
  rar5->iv[2] = byte_swap_32 (rar5->iv[2]);
  rar5->iv[3] = byte_swap_32 (rar5->iv[3]);

  salt->salt_len = 16;

  salt->salt_sign[0] = iterations;

  salt->salt_iter = ((1u << iterations) + 32) - 1;

  /**
   * digest buf
   */

  if (is_valid_hex_string (pswcheck, 16) == false) return (PARSER_SALT_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &pswcheck[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &pswcheck[ 8]);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int krb5tgs_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13100) || (input_len > DISPLAY_LEN_MAX_13100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KRB5TGS, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  krb5tgs_t *krb5tgs = (krb5tgs_t *) hash_buf->esalt;

  /**
   * parse line
   */

  /* Skip '$' */
  u8 *account_pos = input_buf + 11 + 1;

  u8 *data_pos;

  u32 data_len;

  if (account_pos[0] == '*')
  {
    account_pos++;

    data_pos = (u8 *) strchr ((const char *) account_pos, '*');

    if (data_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    /* Skip '*' */
    data_pos++;

    u32 account_len = data_pos - account_pos + 1;

    if (account_len >= 512) return (PARSER_SALT_LENGTH);

    /* Skip '$' */
    data_pos++;

    data_len = input_len - 11 - 1 - account_len - 2;

    memcpy (krb5tgs->account_info, account_pos - 1, account_len);
  }
  else
  {
    /* assume $krb5tgs$23$checksum$edata2 */
    data_pos = account_pos;

    memcpy (krb5tgs->account_info, "**", 3);

    data_len = input_len - 11 - 1 - 1;
  }

  if (data_len < ((16 + 32) * 2)) return (PARSER_SALT_LENGTH);

  u8 *checksum_ptr = (u8 *) krb5tgs->checksum;

  for (u32 i = 0; i < 16 * 2; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  u8 *edata_ptr = (u8 *) krb5tgs->edata2;

  krb5tgs->edata2_len = (data_len - 32) / 2;

  /* skip '$' */
  for (u32 i = 16 * 2 + 1; i < (krb5tgs->edata2_len * 2) + (16 * 2 + 1); i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];
    *edata_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

 /* this is needed for hmac_md5 */
  *edata_ptr++ = 0x80;

  salt->salt_buf[0] = krb5tgs->checksum[0];
  salt->salt_buf[1] = krb5tgs->checksum[1];
  salt->salt_buf[2] = krb5tgs->checksum[2];
  salt->salt_buf[3] = krb5tgs->checksum[3];

  salt->salt_len = 32;

  digest[0] = krb5tgs->checksum[0];
  digest[1] = krb5tgs->checksum[1];
  digest[2] = krb5tgs->checksum[2];
  digest[3] = krb5tgs->checksum[3];

  return (PARSER_OK);
}

int axcrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13200) || (input_len > DISPLAY_LEN_MAX_13200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_AXCRYPT, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  /* Skip '*' */
  u8 *wrapping_rounds_pos = input_buf + 11 + 1;

  u8 *salt_pos;

  u8 *wrapped_key_pos;

  u8 *data_pos;

  salt->salt_iter = atoll ((const char *) wrapping_rounds_pos);

  salt_pos = (u8 *) strchr ((const char *) wrapping_rounds_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 wrapping_rounds_len = salt_pos - wrapping_rounds_pos;

  /* Skip '*' */
  salt_pos++;

  data_pos = salt_pos;

  wrapped_key_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (wrapped_key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = wrapped_key_pos - salt_pos;

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  u32 wrapped_key_len = input_len - 11 - 1 - wrapping_rounds_len - 1 - salt_len - 1;

  if (wrapped_key_len != 48) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (data_pos, 32) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &data_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &data_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &data_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &data_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  data_pos += 33;

  if (is_valid_hex_string (data_pos, 48) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &data_pos[ 0]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &data_pos[ 8]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &data_pos[16]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &data_pos[24]);
  salt->salt_buf[8] = hex_to_u32 ((const u8 *) &data_pos[32]);
  salt->salt_buf[9] = hex_to_u32 ((const u8 *) &data_pos[40]);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);
  salt->salt_buf[8] = byte_swap_32 (salt->salt_buf[8]);
  salt->salt_buf[9] = byte_swap_32 (salt->salt_buf[9]);

  salt->salt_len = 40;

  digest[0] = salt->salt_buf[0];
  digest[1] = salt->salt_buf[1];
  digest[2] = salt->salt_buf[2];
  digest[3] = salt->salt_buf[3];

  return (PARSER_OK);
}

int keepass_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13400) || (input_len > DISPLAY_LEN_MAX_13400)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_KEEPASS, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  keepass_t *keepass = (keepass_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8  *version_pos;
  u8  *rounds_pos;
  u8  *algorithm_pos;
  u8  *final_random_seed_pos;
  u32  final_random_seed_len;
  u8  *transf_random_seed_pos;
  u32  transf_random_seed_len;
  u8  *enc_iv_pos;
  u32  enc_iv_len;

  /* default is no keyfile provided */
  bool is_keyfile_present = false;
  u8  *keyfile_inline_pos;
  u8  *keyfile_pos;

  /* specific to version 1 */
  u8  *contents_pos;

  /* specific to version 2 */
  u8  *expected_bytes_pos;
  u32  expected_bytes_len;

  u8  *contents_hash_pos;
  u32  contents_hash_len;

  version_pos = input_buf + 8 + 1 + 1;

  keepass->version = atoll ((const char *) version_pos);

  rounds_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (rounds_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  rounds_pos++;

  salt->salt_iter = (atoll ((const char *) rounds_pos));

  algorithm_pos = (u8 *) strchr ((const char *) rounds_pos, '*');

  if (algorithm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  algorithm_pos++;

  keepass->algorithm = atoll ((const char *) algorithm_pos);

  final_random_seed_pos = (u8 *) strchr ((const char *) algorithm_pos, '*');

  if (final_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_pos++;

  if (is_valid_hex_string (final_random_seed_pos, 32) == false) return (PARSER_SALT_ENCODING);

  keepass->final_random_seed[0] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 0]);
  keepass->final_random_seed[1] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 8]);
  keepass->final_random_seed[2] = hex_to_u32 ((const u8 *) &final_random_seed_pos[16]);
  keepass->final_random_seed[3] = hex_to_u32 ((const u8 *) &final_random_seed_pos[24]);

  keepass->final_random_seed[0] = byte_swap_32 (keepass->final_random_seed[0]);
  keepass->final_random_seed[1] = byte_swap_32 (keepass->final_random_seed[1]);
  keepass->final_random_seed[2] = byte_swap_32 (keepass->final_random_seed[2]);
  keepass->final_random_seed[3] = byte_swap_32 (keepass->final_random_seed[3]);

  if (keepass->version == 2)
  {
    if (is_valid_hex_string (final_random_seed_pos + 32, 32) == false) return (PARSER_SALT_ENCODING);

    keepass->final_random_seed[4] = hex_to_u32 ((const u8 *) &final_random_seed_pos[32]);
    keepass->final_random_seed[5] = hex_to_u32 ((const u8 *) &final_random_seed_pos[40]);
    keepass->final_random_seed[6] = hex_to_u32 ((const u8 *) &final_random_seed_pos[48]);
    keepass->final_random_seed[7] = hex_to_u32 ((const u8 *) &final_random_seed_pos[56]);

    keepass->final_random_seed[4] = byte_swap_32 (keepass->final_random_seed[4]);
    keepass->final_random_seed[5] = byte_swap_32 (keepass->final_random_seed[5]);
    keepass->final_random_seed[6] = byte_swap_32 (keepass->final_random_seed[6]);
    keepass->final_random_seed[7] = byte_swap_32 (keepass->final_random_seed[7]);
  }

  transf_random_seed_pos = (u8 *) strchr ((const char *) final_random_seed_pos, '*');

  if (transf_random_seed_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  final_random_seed_len = transf_random_seed_pos - final_random_seed_pos;

  if (keepass->version == 1 && final_random_seed_len != 32) return (PARSER_SALT_LENGTH);
  if (keepass->version == 2 && final_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  transf_random_seed_pos++;

  if (is_valid_hex_string (transf_random_seed_pos, 64) == false) return (PARSER_SALT_ENCODING);

  keepass->transf_random_seed[0] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 0]);
  keepass->transf_random_seed[1] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 8]);
  keepass->transf_random_seed[2] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[16]);
  keepass->transf_random_seed[3] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[24]);
  keepass->transf_random_seed[4] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[32]);
  keepass->transf_random_seed[5] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[40]);
  keepass->transf_random_seed[6] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[48]);
  keepass->transf_random_seed[7] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[56]);

  keepass->transf_random_seed[0] = byte_swap_32 (keepass->transf_random_seed[0]);
  keepass->transf_random_seed[1] = byte_swap_32 (keepass->transf_random_seed[1]);
  keepass->transf_random_seed[2] = byte_swap_32 (keepass->transf_random_seed[2]);
  keepass->transf_random_seed[3] = byte_swap_32 (keepass->transf_random_seed[3]);
  keepass->transf_random_seed[4] = byte_swap_32 (keepass->transf_random_seed[4]);
  keepass->transf_random_seed[5] = byte_swap_32 (keepass->transf_random_seed[5]);
  keepass->transf_random_seed[6] = byte_swap_32 (keepass->transf_random_seed[6]);
  keepass->transf_random_seed[7] = byte_swap_32 (keepass->transf_random_seed[7]);

  enc_iv_pos = (u8 *) strchr ((const char *) transf_random_seed_pos, '*');

  if (enc_iv_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  transf_random_seed_len = enc_iv_pos - transf_random_seed_pos;

  if (transf_random_seed_len != 64) return (PARSER_SALT_LENGTH);

  enc_iv_pos++;

  if (is_valid_hex_string (enc_iv_pos, 32) == false) return (PARSER_SALT_ENCODING);

  keepass->enc_iv[0] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 0]);
  keepass->enc_iv[1] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 8]);
  keepass->enc_iv[2] = hex_to_u32 ((const u8 *) &enc_iv_pos[16]);
  keepass->enc_iv[3] = hex_to_u32 ((const u8 *) &enc_iv_pos[24]);

  keepass->enc_iv[0] = byte_swap_32 (keepass->enc_iv[0]);
  keepass->enc_iv[1] = byte_swap_32 (keepass->enc_iv[1]);
  keepass->enc_iv[2] = byte_swap_32 (keepass->enc_iv[2]);
  keepass->enc_iv[3] = byte_swap_32 (keepass->enc_iv[3]);

  if (keepass->version == 1)
  {
    contents_hash_pos = (u8 *) strchr ((const char *) enc_iv_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = contents_hash_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    if (is_valid_hex_string (contents_hash_pos, 64) == false) return (PARSER_SALT_ENCODING);

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    keepass->contents_hash[0] = byte_swap_32 (keepass->contents_hash[0]);
    keepass->contents_hash[1] = byte_swap_32 (keepass->contents_hash[1]);
    keepass->contents_hash[2] = byte_swap_32 (keepass->contents_hash[2]);
    keepass->contents_hash[3] = byte_swap_32 (keepass->contents_hash[3]);
    keepass->contents_hash[4] = byte_swap_32 (keepass->contents_hash[4]);
    keepass->contents_hash[5] = byte_swap_32 (keepass->contents_hash[5]);
    keepass->contents_hash[6] = byte_swap_32 (keepass->contents_hash[6]);
    keepass->contents_hash[7] = byte_swap_32 (keepass->contents_hash[7]);

    /* get length of contents following */
    u8 *inline_flag_pos = (u8 *) strchr ((const char *) contents_hash_pos, '*');

    if (inline_flag_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_hash_len = inline_flag_pos - contents_hash_pos;

    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);

    inline_flag_pos++;

    u32 inline_flag = atoll ((const char *) inline_flag_pos);

    if (inline_flag != 1) return (PARSER_SALT_LENGTH);

    u8 *contents_len_pos = (u8 *) strchr ((const char *) inline_flag_pos, '*');

    if (contents_len_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_len_pos++;

    int contents_len = atoi ((const char *) contents_len_pos);

    if (contents_len > 50000) return (PARSER_SALT_LENGTH);

    contents_pos = (u8 *) strchr ((const char *) contents_len_pos, '*');

    if (contents_pos == NULL) return (PARSER_SALT_LENGTH);

    contents_pos++;

    keepass->contents_len = contents_len;

    contents_len = contents_len / 4;

    keyfile_inline_pos = (u8 *) strchr ((const char *) contents_pos, '*');

    u32 real_contents_len;

    if (keyfile_inline_pos == NULL)
    {
      real_contents_len = input_len - (contents_pos - input_buf);
    }
    else
    {
      real_contents_len = keyfile_inline_pos - contents_pos;

      keyfile_inline_pos++;

      is_keyfile_present = true;
    }

    if (real_contents_len != keepass->contents_len * 2) return (PARSER_SALT_LENGTH);

    if (is_valid_hex_string (contents_pos, contents_len) == false) return (PARSER_SALT_ENCODING);

    for (int i = 0; i < contents_len; i++)
    {
      keepass->contents[i] = hex_to_u32 ((const u8 *) &contents_pos[i * 8]);

      keepass->contents[i] = byte_swap_32 (keepass->contents[i]);
    }
  }
  else if (keepass->version == 2)
  {
    expected_bytes_pos = (u8 *) strchr ((const char *) enc_iv_pos, '*');

    if (expected_bytes_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    enc_iv_len = expected_bytes_pos - enc_iv_pos;

    if (enc_iv_len != 32) return (PARSER_SALT_LENGTH);

    expected_bytes_pos++;

    if (is_valid_hex_string (expected_bytes_pos, 64) == false) return (PARSER_SALT_ENCODING);

    keepass->expected_bytes[0] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 0]);
    keepass->expected_bytes[1] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 8]);
    keepass->expected_bytes[2] = hex_to_u32 ((const u8 *) &expected_bytes_pos[16]);
    keepass->expected_bytes[3] = hex_to_u32 ((const u8 *) &expected_bytes_pos[24]);
    keepass->expected_bytes[4] = hex_to_u32 ((const u8 *) &expected_bytes_pos[32]);
    keepass->expected_bytes[5] = hex_to_u32 ((const u8 *) &expected_bytes_pos[40]);
    keepass->expected_bytes[6] = hex_to_u32 ((const u8 *) &expected_bytes_pos[48]);
    keepass->expected_bytes[7] = hex_to_u32 ((const u8 *) &expected_bytes_pos[56]);

    keepass->expected_bytes[0] = byte_swap_32 (keepass->expected_bytes[0]);
    keepass->expected_bytes[1] = byte_swap_32 (keepass->expected_bytes[1]);
    keepass->expected_bytes[2] = byte_swap_32 (keepass->expected_bytes[2]);
    keepass->expected_bytes[3] = byte_swap_32 (keepass->expected_bytes[3]);
    keepass->expected_bytes[4] = byte_swap_32 (keepass->expected_bytes[4]);
    keepass->expected_bytes[5] = byte_swap_32 (keepass->expected_bytes[5]);
    keepass->expected_bytes[6] = byte_swap_32 (keepass->expected_bytes[6]);
    keepass->expected_bytes[7] = byte_swap_32 (keepass->expected_bytes[7]);

    contents_hash_pos = (u8 *) strchr ((const char *) expected_bytes_pos, '*');

    if (contents_hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    expected_bytes_len = contents_hash_pos - expected_bytes_pos;

    if (expected_bytes_len != 64) return (PARSER_SALT_LENGTH);

    contents_hash_pos++;

    if (is_valid_hex_string (contents_hash_pos, 64) == false) return (PARSER_SALT_ENCODING);

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    keepass->contents_hash[0] = byte_swap_32 (keepass->contents_hash[0]);
    keepass->contents_hash[1] = byte_swap_32 (keepass->contents_hash[1]);
    keepass->contents_hash[2] = byte_swap_32 (keepass->contents_hash[2]);
    keepass->contents_hash[3] = byte_swap_32 (keepass->contents_hash[3]);
    keepass->contents_hash[4] = byte_swap_32 (keepass->contents_hash[4]);
    keepass->contents_hash[5] = byte_swap_32 (keepass->contents_hash[5]);
    keepass->contents_hash[6] = byte_swap_32 (keepass->contents_hash[6]);
    keepass->contents_hash[7] = byte_swap_32 (keepass->contents_hash[7]);

    keyfile_inline_pos = (u8 *) strchr ((const char *) contents_hash_pos, '*');

    if (keyfile_inline_pos == NULL)
    {
      contents_hash_len = input_len - (int) (contents_hash_pos - input_buf);
    }
    else
    {
      contents_hash_len = keyfile_inline_pos - contents_hash_pos;

      keyfile_inline_pos++;

      is_keyfile_present = true;
    }

    if (contents_hash_len != 64) return (PARSER_SALT_LENGTH);
  }

  if (is_keyfile_present == true)
  {
    u8 *keyfile_len_pos = (u8 *) strchr ((const char *) keyfile_inline_pos, '*');

    if (keyfile_len_pos == NULL) return (PARSER_SALT_LENGTH);

    keyfile_len_pos++;

    int keyfile_len = atoi ((const char *) keyfile_len_pos);

    keepass->keyfile_len = keyfile_len;

    if (keyfile_len != 64) return (PARSER_SALT_LENGTH);

    keyfile_pos = (u8 *) strchr ((const char *) keyfile_len_pos, '*');

    if (keyfile_pos == NULL) return (PARSER_SALT_LENGTH);

    keyfile_pos++;

    u32 real_keyfile_len = input_len - (keyfile_pos - input_buf);

    if (real_keyfile_len != 64) return (PARSER_SALT_LENGTH);

    if (is_valid_hex_string (keyfile_pos, 64) == false) return (PARSER_SALT_ENCODING);

    keepass->keyfile[0] = hex_to_u32 ((const u8 *) &keyfile_pos[ 0]);
    keepass->keyfile[1] = hex_to_u32 ((const u8 *) &keyfile_pos[ 8]);
    keepass->keyfile[2] = hex_to_u32 ((const u8 *) &keyfile_pos[16]);
    keepass->keyfile[3] = hex_to_u32 ((const u8 *) &keyfile_pos[24]);
    keepass->keyfile[4] = hex_to_u32 ((const u8 *) &keyfile_pos[32]);
    keepass->keyfile[5] = hex_to_u32 ((const u8 *) &keyfile_pos[40]);
    keepass->keyfile[6] = hex_to_u32 ((const u8 *) &keyfile_pos[48]);
    keepass->keyfile[7] = hex_to_u32 ((const u8 *) &keyfile_pos[56]);

    keepass->keyfile[0] = byte_swap_32 (keepass->keyfile[0]);
    keepass->keyfile[1] = byte_swap_32 (keepass->keyfile[1]);
    keepass->keyfile[2] = byte_swap_32 (keepass->keyfile[2]);
    keepass->keyfile[3] = byte_swap_32 (keepass->keyfile[3]);
    keepass->keyfile[4] = byte_swap_32 (keepass->keyfile[4]);
    keepass->keyfile[5] = byte_swap_32 (keepass->keyfile[5]);
    keepass->keyfile[6] = byte_swap_32 (keepass->keyfile[6]);
    keepass->keyfile[7] = byte_swap_32 (keepass->keyfile[7]);
  }

  digest[0] = keepass->enc_iv[0];
  digest[1] = keepass->enc_iv[1];
  digest[2] = keepass->enc_iv[2];
  digest[3] = keepass->enc_iv[3];

  salt->salt_buf[0] = keepass->transf_random_seed[0];
  salt->salt_buf[1] = keepass->transf_random_seed[1];
  salt->salt_buf[2] = keepass->transf_random_seed[2];
  salt->salt_buf[3] = keepass->transf_random_seed[3];
  salt->salt_buf[4] = keepass->transf_random_seed[4];
  salt->salt_buf[5] = keepass->transf_random_seed[5];
  salt->salt_buf[6] = keepass->transf_random_seed[6];
  salt->salt_buf[7] = keepass->transf_random_seed[7];

  return (PARSER_OK);
}

int cf10_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12600) || (input_len > DISPLAY_LEN_MAX_12600)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (input_buf[64] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 64 - 1;

  u8 *salt_buf = input_buf + 64 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  /**
   * we can precompute the first sha256 transform
   */

  u32 w[16] = { 0 };

  w[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  w[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  w[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  w[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  w[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  w[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  w[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  w[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  w[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  w[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  w[10] = byte_swap_32 (salt->salt_buf[10]);
  w[11] = byte_swap_32 (salt->salt_buf[11]);
  w[12] = byte_swap_32 (salt->salt_buf[12]);
  w[13] = byte_swap_32 (salt->salt_buf[13]);
  w[14] = byte_swap_32 (salt->salt_buf[14]);
  w[15] = byte_swap_32 (salt->salt_buf[15]);

  u32 pc256[8] = { SHA256M_A, SHA256M_B, SHA256M_C, SHA256M_D, SHA256M_E, SHA256M_F, SHA256M_G, SHA256M_H };

  sha256_64 (w, pc256);

  salt->salt_buf_pc[0] = pc256[0];
  salt->salt_buf_pc[1] = pc256[1];
  salt->salt_buf_pc[2] = pc256[2];
  salt->salt_buf_pc[3] = pc256[3];
  salt->salt_buf_pc[4] = pc256[4];
  salt->salt_buf_pc[5] = pc256[5];
  salt->salt_buf_pc[6] = pc256[6];
  salt->salt_buf_pc[7] = pc256[7];

  digest[0] -= pc256[0];
  digest[1] -= pc256[1];
  digest[2] -= pc256[2];
  digest[3] -= pc256[3];
  digest[4] -= pc256[4];
  digest[5] -= pc256[5];
  digest[6] -= pc256[6];
  digest[7] -= pc256[7];

  return (PARSER_OK);
}

int mywallet_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12700) || (input_len > DISPLAY_LEN_MAX_12700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MYWALLET, input_buf, 12)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *data_len_pos = input_buf + 1 + 10 + 1;

  u8 *data_buf_pos = (u8 *) strchr ((const char *) data_len_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = data_buf_pos - data_len_pos;

  if (data_len_len < 1) return (PARSER_SALT_LENGTH);
  if (data_len_len > 5) return (PARSER_SALT_LENGTH);

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 10 - 1 - data_len_len - 1;

  if (data_buf_len < 64) return (PARSER_HASH_LENGTH);

  if (data_buf_len % 16) return (PARSER_HASH_LENGTH);

  u32 data_len = atoll ((const char *) data_len_pos);

  if ((data_len * 2) != data_buf_len) return (PARSER_HASH_LENGTH);

  /**
   * salt
   */

  u8 *salt_pos = data_buf_pos;

  if (is_valid_hex_string (salt_pos, 64) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &salt_pos[32]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &salt_pos[40]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &salt_pos[48]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &salt_pos[56]);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  salt->salt_iter = ROUNDS_MYWALLET - 1;

  /**
   * digest buf
   */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int mywalletv2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15200) || (input_len > DISPLAY_LEN_MAX_15200)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MYWALLETV2, input_buf, 15)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *iter_pos = input_buf + 1 + 10 + 1 + 2 + 1;

  u8 *data_len_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (data_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_pos_len = data_len_pos - iter_pos;

  if (iter_pos_len < 1) return (PARSER_SALT_LENGTH);
  if (iter_pos_len > 8) return (PARSER_SALT_LENGTH);

  data_len_pos++;

  u8 *data_buf_pos = (u8 *) strchr ((const char *) data_len_pos, '$');

  if (data_buf_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 data_len_len = data_buf_pos - data_len_pos;

  if (data_len_len < 1) return (PARSER_SALT_LENGTH);
  if (data_len_len > 5) return (PARSER_SALT_LENGTH);

  data_buf_pos++;

  u32 data_buf_len = input_len - 1 - 10 - 1 - 2 - 1 - iter_pos_len - 1 - data_len_len - 1;

  if (data_buf_len < 64) return (PARSER_HASH_LENGTH);

  if (data_buf_len % 16) return (PARSER_HASH_LENGTH);

  u32 data_len = atoll ((const char *) data_len_pos);

  if ((data_len * 2) != data_buf_len) return (PARSER_HASH_LENGTH);

  u32 iter = atoll ((const char *) iter_pos);

  /**
   * salt
   */

  u8 *salt_pos = data_buf_pos;

  if (is_valid_hex_string (salt_pos, 64) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &salt_pos[32]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &salt_pos[40]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &salt_pos[48]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &salt_pos[56]);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  salt->salt_iter = iter - 1;

  /**
   * digest buf
   */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int ms_drsr_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12800) || (input_len > DISPLAY_LEN_MAX_12800)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_MS_DRSR, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *salt_pos = input_buf + 11 + 1;

  u8 *iter_pos = (u8 *) strchr ((const char *) salt_pos, ',');

  if (iter_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = iter_pos - salt_pos;

  if (salt_len != 20) return (PARSER_SALT_LENGTH);

  iter_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) iter_pos, ',');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_len = hash_pos - iter_pos;

  if (iter_len > 5) return (PARSER_SALT_LENGTH);

  hash_pos++;

  u32 hash_len = input_len - 11 - 1 - salt_len - 1 - iter_len - 1;

  if (hash_len != 64) return (PARSER_HASH_LENGTH);

  /**
   * salt
   */

  if (is_valid_hex_string (salt_pos, 20) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]) & 0x0000ffff;
  salt->salt_buf[3] = 0x00800100;

  salt->salt_len = salt_len / 2;

  salt->salt_iter = atoll ((const char *) iter_pos) - 1u;

  /**
   * digest buf
   */

  if (is_valid_hex_string (hash_pos, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int androidfde_samsung_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12900) || (input_len > DISPLAY_LEN_MAX_12900)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  /**
   * parse line
   */

  u8 *hash_pos  = input_buf + 64;
  u8 *salt1_pos = input_buf + 128;
  u8 *salt2_pos = input_buf;

  /**
   * salt
   */

  if (is_valid_hex_string (salt1_pos, 32) == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (salt2_pos, 64) == false) return (PARSER_SALT_ENCODING);

  salt->salt_buf[ 0] = hex_to_u32 ((const u8 *) &salt1_pos[ 0]);
  salt->salt_buf[ 1] = hex_to_u32 ((const u8 *) &salt1_pos[ 8]);
  salt->salt_buf[ 2] = hex_to_u32 ((const u8 *) &salt1_pos[16]);
  salt->salt_buf[ 3] = hex_to_u32 ((const u8 *) &salt1_pos[24]);
  salt->salt_buf[ 4] = hex_to_u32 ((const u8 *) &salt2_pos[ 0]);
  salt->salt_buf[ 5] = hex_to_u32 ((const u8 *) &salt2_pos[ 8]);
  salt->salt_buf[ 6] = hex_to_u32 ((const u8 *) &salt2_pos[16]);
  salt->salt_buf[ 7] = hex_to_u32 ((const u8 *) &salt2_pos[24]);
  salt->salt_buf[ 8] = hex_to_u32 ((const u8 *) &salt2_pos[32]);
  salt->salt_buf[ 9] = hex_to_u32 ((const u8 *) &salt2_pos[40]);
  salt->salt_buf[10] = hex_to_u32 ((const u8 *) &salt2_pos[48]);
  salt->salt_buf[11] = hex_to_u32 ((const u8 *) &salt2_pos[56]);

  salt->salt_buf[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  salt->salt_buf[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  salt->salt_buf[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  salt->salt_buf[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  salt->salt_buf[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  salt->salt_buf[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  salt->salt_buf[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  salt->salt_buf[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  salt->salt_buf[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  salt->salt_buf[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  salt->salt_buf[10] = byte_swap_32 (salt->salt_buf[10]);
  salt->salt_buf[11] = byte_swap_32 (salt->salt_buf[11]);

  salt->salt_len = 48;

  salt->salt_iter = ROUNDS_ANDROIDFDE_SAMSUNG - 1;

  /**
   * digest buf
   */

  if (is_valid_hex_string (hash_pos, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int zip2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13600) || (input_len > DISPLAY_LEN_MAX_13600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ZIP2_START, input_buf                , 6)) return (PARSER_SIGNATURE_UNMATCHED);
  if (memcmp (SIGNATURE_ZIP2_STOP , input_buf + input_len - 7, 7)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  zip2_t *zip2 = (zip2_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *param0_pos = input_buf + 6 + 1;

  u8 *param1_pos = (u8 *) strchr ((const char *) param0_pos, '*');

  if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param0_len = param1_pos - param0_pos;

  param1_pos++;

  u8 *param2_pos = (u8 *) strchr ((const char *) param1_pos, '*');

  if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param1_len = param2_pos - param1_pos;

  param2_pos++;

  u8 *param3_pos = (u8 *) strchr ((const char *) param2_pos, '*');

  if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param2_len = param3_pos - param2_pos;

  param3_pos++;

  u8 *param4_pos = (u8 *) strchr ((const char *) param3_pos, '*');

  if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param3_len = param4_pos - param3_pos;

  param4_pos++;

  u8 *param5_pos = (u8 *) strchr ((const char *) param4_pos, '*');

  if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param4_len = param5_pos - param4_pos;

  param5_pos++;

  u8 *param6_pos = (u8 *) strchr ((const char *) param5_pos, '*');

  if (param6_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param5_len = param6_pos - param5_pos;

  param6_pos++;

  u8 *param7_pos = (u8 *) strchr ((const char *) param6_pos, '*');

  if (param7_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param6_len = param7_pos - param6_pos;

  param7_pos++;

  u8 *param8_pos = (u8 *) strchr ((const char *) param7_pos, '*');

  if (param8_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 param7_len = param8_pos - param7_pos;

  const u32 type  = atoll ((const char *) param0_pos);
  const u32 mode  = atoll ((const char *) param1_pos);
  const u32 magic = atoll ((const char *) param2_pos);

  u8 *salt_buf = param3_pos;

  u32 verify_bytes;

  if (sscanf ((const char *) param4_pos, "%4x*", &verify_bytes) == EOF)
  {
    return (PARSER_SALT_VALUE);
  }

  const u32 compress_length = atoll ((const char *) param5_pos);

  u8 *data_buf = param6_pos;
  u8 *auth     = param7_pos;

  /**
   * verify some data
   */

  if (param0_len != 1) return (PARSER_SALT_VALUE);

  if (param1_len != 1) return (PARSER_SALT_VALUE);

  if (param2_len != 1) return (PARSER_SALT_VALUE);

  if ((param3_len != 16) && (param3_len != 24) && (param3_len != 32)) return (PARSER_SALT_VALUE);

  if (param4_len >= 5) return (PARSER_SALT_VALUE);

  if (param5_len >= 5) return (PARSER_SALT_VALUE);

  if (param6_len >= 8192) return (PARSER_SALT_VALUE);

  if (param6_len & 1) return (PARSER_SALT_VALUE);

  if (param7_len != 20) return (PARSER_SALT_VALUE);

  if (type != 0) return (PARSER_SALT_VALUE);

  if ((mode != 1) && (mode != 2) && (mode != 3)) return (PARSER_SALT_VALUE);

  if (magic != 0) return (PARSER_SALT_VALUE);

  if (verify_bytes >= 0x10000) return (PARSER_SALT_VALUE);

  /**
   * store data
   */

  zip2->type  = type;
  zip2->mode  = mode;
  zip2->magic = magic;

  if (mode == 1)
  {
    if (is_valid_hex_string (salt_buf, 16) == false) return (PARSER_SALT_ENCODING);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = 0;
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 8;
  }
  else if (mode == 2)
  {
    if (is_valid_hex_string (salt_buf, 24) == false) return (PARSER_SALT_ENCODING);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 12;
  }
  else if (mode == 3)
  {
    if (is_valid_hex_string (salt_buf, 32) == false) return (PARSER_SALT_ENCODING);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_buf[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_buf[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_buf[16]);
    zip2->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_buf[24]);

    zip2->salt_len = 16;
  }

  zip2->verify_bytes = verify_bytes;

  zip2->compress_length = compress_length;

  u8 *data_buf_ptr = (u8 *) zip2->data_buf;

  for (u32 i = 0; i < param6_len; i += 2)
  {
    const u8 p0 = data_buf[i + 0];
    const u8 p1 = data_buf[i + 1];

    *data_buf_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;

    zip2->data_len++;
  }

  *data_buf_ptr = 0x80;

  u8 *auth_ptr = (u8 *) zip2->auth_buf;

  for (u32 i = 0; i < param7_len; i += 2)
  {
    const u8 p0 = auth[i + 0];
    const u8 p1 = auth[i + 1];

    *auth_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;

    zip2->auth_len++;
  }

  /**
   * salt buf (fake)
   */

  salt->salt_buf[0] = zip2->salt_buf[0];
  salt->salt_buf[1] = zip2->salt_buf[1];
  salt->salt_buf[2] = zip2->salt_buf[2];
  salt->salt_buf[3] = zip2->salt_buf[3];
  salt->salt_buf[4] = zip2->data_buf[0];
  salt->salt_buf[5] = zip2->data_buf[1];
  salt->salt_buf[6] = zip2->data_buf[2];
  salt->salt_buf[7] = zip2->data_buf[3];

  salt->salt_len = 32;

  salt->salt_iter = ROUNDS_ZIP2 - 1;

  /**
   * digest buf (fake)
   */

  digest[0] = zip2->auth_buf[0];
  digest[1] = zip2->auth_buf[1];
  digest[2] = zip2->auth_buf[2];
  digest[3] = zip2->auth_buf[3];

  return (PARSER_OK);
}

int win8phone_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_13800) || (input_len > DISPLAY_LEN_MAX_13800)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  win8phone_t *esalt = (win8phone_t *) hash_buf->esalt;

  if (is_valid_hex_string (input_buf, 64) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);
  digest[5] = hex_to_u32 ((const u8 *) &input_buf[40]);
  digest[6] = hex_to_u32 ((const u8 *) &input_buf[48]);
  digest[7] = hex_to_u32 ((const u8 *) &input_buf[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (input_buf[64] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u8 *salt_buf_ptr = input_buf + 64 + 1;

  u32 *salt_buf = esalt->salt_buf;

  if (is_valid_hex_string (salt_buf_ptr, 256) == false) return (PARSER_SALT_ENCODING);

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    salt_buf[i] = hex_to_u32 ((const u8 *) &salt_buf_ptr[j]);

    salt_buf[i] = byte_swap_32 (salt_buf[i]);
  }

  salt->salt_buf[0] = salt_buf[0];
  salt->salt_buf[1] = salt_buf[1];
  salt->salt_buf[2] = salt_buf[2];
  salt->salt_buf[3] = salt_buf[3];
  salt->salt_buf[4] = salt_buf[4];
  salt->salt_buf[5] = salt_buf[5];
  salt->salt_buf[6] = salt_buf[6];
  salt->salt_buf[7] = salt_buf[7];

  salt->salt_len = 64;

  return (PARSER_OK);
}

int plaintext_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_99999) || (input_len > DISPLAY_LEN_MAX_99999)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  memset (digest, 0, hashconfig->dgst_size);

  memcpy ((char *) digest + 64, input_buf, input_len);

  //strncpy ((char *) digest + 64, (char *) input_buf, 64);

  u32 w[16] = { 0 };

  //strncpy ((char *) w, (char *) input_buf, 64);

  memcpy (w, input_buf, input_len);

  u8 *w_ptr = (u8 *) w;

  w_ptr[input_len] = 0x80;

  w[14] = input_len * 8;

  u32 dgst[4];

  dgst[0] = MD4M_A;
  dgst[1] = MD4M_B;
  dgst[2] = MD4M_C;
  dgst[3] = MD4M_D;

  md4_64 (w, dgst);

  dgst[0] -= MD4M_A;
  dgst[1] -= MD4M_B;
  dgst[2] -= MD4M_C;
  dgst[3] -= MD4M_D;

  digest[0] = dgst[0];
  digest[1] = dgst[1];
  digest[2] = dgst[2];
  digest[3] = dgst[3];

  return (PARSER_OK);
}

int sha1cx_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_14400) || (input_len > DISPLAY_LEN_MAX_14400)) return (PARSER_GLOBAL_LENGTH);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 40) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 ((const u8 *) &input_buf[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &input_buf[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &input_buf[16]);
  digest[3] = hex_to_u32 ((const u8 *) &input_buf[24]);
  digest[4] = hex_to_u32 ((const u8 *) &input_buf[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (input_buf[40] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 40 - 1;

  u8 *salt_buf = input_buf + 40 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int luks_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig, const int keyslot_idx)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  luks_t *luks = (luks_t *) hash_buf->esalt;

  if (input_len == 0) return (PARSER_HASH_LENGTH);

  FILE *fp = fopen ((const char *) input_buf, "rb");

  if (fp == NULL) return (PARSER_HASH_FILE);

  struct luks_phdr hdr;

  const size_t nread = fread (&hdr, sizeof (hdr), 1, fp);

  if (nread != 1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // copy digest which we're not using ;)

  u32 *mkDigest_ptr = (u32 *) hdr.mkDigest;

  digest[0] = mkDigest_ptr[0];
  digest[1] = mkDigest_ptr[1];
  digest[2] = mkDigest_ptr[2];
  digest[3] = mkDigest_ptr[3];
  digest[4] = mkDigest_ptr[4];
  digest[5] = 0;
  digest[6] = 0;
  digest[7] = 0;

  // verify the content

  char luks_magic[6] = LUKS_MAGIC;

  if (memcmp (hdr.magic, luks_magic, LUKS_MAGIC_L))
  {
    fclose (fp);

    return (PARSER_LUKS_MAGIC);
  }

  if (byte_swap_16 (hdr.version) != 1)
  {
    fclose (fp);

    return (PARSER_LUKS_VERSION);
  }

  if (strcmp (hdr.cipherName, "aes") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_AES;
  }
  else if (strcmp (hdr.cipherName, "serpent") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_SERPENT;
  }
  else if (strcmp (hdr.cipherName, "twofish") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_TWOFISH;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_CIPHER_TYPE);
  }

  if (strcmp (hdr.cipherMode, "cbc-essiv:sha256") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_ESSIV;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_CIPHER_MODE);
  }

  if (strcmp (hdr.hashSpec, "sha1") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA1;
  }
  else if (strcmp (hdr.hashSpec, "sha256") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA256;
  }
  else if (strcmp (hdr.hashSpec, "sha512") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA512;
  }
  else if (strcmp (hdr.hashSpec, "ripemd160") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_RIPEMD160;
  }
  else if (strcmp (hdr.hashSpec, "whirlpool") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_WHIRLPOOL;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_HASH_TYPE);
  }

  const u32 keyBytes = byte_swap_32 (hdr.keyBytes);

  if (keyBytes == 16)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_128;
  }
  else if (keyBytes == 32)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_256;
  }
  else if (keyBytes == 64)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_512;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_SIZE);
  }

  // find the correct kernel based on hash and cipher

  if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA1_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA256_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_SHA512_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_RIPEMD160_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    hashconfig->kern_type = KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH;
  }
  else
  {
    fclose (fp);

    return (PARSER_LUKS_HASH_CIPHER);
  }

  // verify the selected keyslot informations

  const u32 active  = byte_swap_32 (hdr.keyblock[keyslot_idx].active);
  const u32 stripes = byte_swap_32 (hdr.keyblock[keyslot_idx].stripes);

  if (active  != LUKS_KEY_ENABLED)
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_DISABLED);
  }

  if (stripes != LUKS_STRIPES)
  {
    fclose (fp);

    return (PARSER_LUKS_KEY_STRIPES);
  }

  // configure the salt (not esalt)

  u32 *passwordSalt_ptr = (u32 *) hdr.keyblock[keyslot_idx].passwordSalt;

  salt->salt_buf[0] = passwordSalt_ptr[0];
  salt->salt_buf[1] = passwordSalt_ptr[1];
  salt->salt_buf[2] = passwordSalt_ptr[2];
  salt->salt_buf[3] = passwordSalt_ptr[3];
  salt->salt_buf[4] = passwordSalt_ptr[4];
  salt->salt_buf[5] = passwordSalt_ptr[5];
  salt->salt_buf[6] = passwordSalt_ptr[6];
  salt->salt_buf[7] = passwordSalt_ptr[7];

  salt->salt_len = LUKS_SALTSIZE;

  const u32 passwordIterations = byte_swap_32 (hdr.keyblock[keyslot_idx].passwordIterations);

  salt->salt_iter = passwordIterations - 1;

  // Load AF data for this keyslot into esalt

  const u32 keyMaterialOffset = byte_swap_32 (hdr.keyblock[keyslot_idx].keyMaterialOffset);

  const int rc_seek1 = fseeko (fp, keyMaterialOffset * 512, SEEK_SET);

  if (rc_seek1 == -1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread2 = fread (luks->af_src_buf, keyBytes, stripes, fp);

  if (nread2 != stripes)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // finally, copy some encrypted payload data for entropy check

  const u32 payloadOffset = byte_swap_32 (hdr.payloadOffset);

  const int rc_seek2 = fseeko (fp, payloadOffset * 512, SEEK_SET);

  if (rc_seek2 == -1)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread3 = fread (luks->ct_buf, sizeof (u32), 128, fp);

  if (nread3 != 128)
  {
    fclose (fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // that should be it, close the fp

  fclose (fp);

  return (PARSER_OK);
}

int itunes_backup_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_14700) || (input_len > DISPLAY_LEN_MAX_14700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ITUNES_BACKUP, input_buf, 15)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 hash_mode = hashconfig->hash_mode;

  salt_t *salt = hash_buf->salt;

  itunes_backup_t *itunes_backup = (itunes_backup_t *) hash_buf->esalt;

  /**
   * parse line
   */

  if (input_buf[15] != '*') return (PARSER_SEPARATOR_UNMATCHED);

  // version (9 or 10)

  u8 *version_pos = input_buf + 15 + 1;

  // WPKY

  u8 *wpky_pos = (u8 *) strchr ((const char *) version_pos, '*');

  if (wpky_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version_len = wpky_pos - version_pos;

  wpky_pos++;

  // iterations

  u8 *iter_pos = (u8 *) strchr ((const char *) wpky_pos, '*');

  if (iter_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 wpky_len = iter_pos - wpky_pos;

  iter_pos++;

  // salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_len = salt_pos - iter_pos;

  salt_pos++;

  // DPIC

  u8 *dpic_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (dpic_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = dpic_pos - salt_pos;

  dpic_pos++;

  // DPSL

  u8 *dpsl_pos = (u8 *) strchr ((const char *) dpic_pos, '*');

  if (dpsl_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 dpic_len = dpsl_pos - dpic_pos;

  dpsl_pos++;

  u32 dpsl_len = input_len - 15 - 1 - version_len - 1 - wpky_len - 1 - iter_len - 1 - salt_len - 1 - dpic_len - 1;

  /**
   * verify some data
   */

  if ((version_len != 1) && (version_len != 2)) return (PARSER_SEPARATOR_UNMATCHED);

  u32 version = atoi ((const char *) version_pos);

  if (hash_mode == 14700)
  {
    if (version !=  9) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (version != 10) return (PARSER_SEPARATOR_UNMATCHED);
  }

  if (wpky_len != 80) return (PARSER_HASH_LENGTH);

  if (iter_len < 1) return (PARSER_SALT_ITERATION);
  if (iter_len > 6) return (PARSER_SALT_ITERATION);

  u32 iter = atoi ((const char *) iter_pos);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  if (salt_len != 40) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (salt_pos, 20) == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (wpky_pos, 40) == false) return (PARSER_HASH_ENCODING);

  u32 dpic = 0;

  if (hash_mode == 14700)
  {
    if (dpic_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
    if (dpsl_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (dpic_len < 1) return (PARSER_SALT_ITERATION);
    if (dpic_len > 9) return (PARSER_SALT_ITERATION);

    dpic = atoi ((const char *) dpic_pos);

    if (dpic < 1) return (PARSER_SALT_ITERATION);

    if (dpsl_len != 40) return (PARSER_SEPARATOR_UNMATCHED);

    if (is_valid_hex_string (dpsl_pos, 40) == false) return (PARSER_SALT_ENCODING);
  }

  /**
   * store data
   */

  // version

  salt->salt_sign[0] = (char) version;

  // wpky

  u32 *wpky_buf_ptr = (u32 *) itunes_backup->wpky;

  wpky_buf_ptr[0] = hex_to_u32 ((const u8 *) &wpky_pos[ 0]);
  wpky_buf_ptr[1] = hex_to_u32 ((const u8 *) &wpky_pos[ 8]);
  wpky_buf_ptr[2] = hex_to_u32 ((const u8 *) &wpky_pos[16]);
  wpky_buf_ptr[3] = hex_to_u32 ((const u8 *) &wpky_pos[24]);
  wpky_buf_ptr[4] = hex_to_u32 ((const u8 *) &wpky_pos[32]);
  wpky_buf_ptr[5] = hex_to_u32 ((const u8 *) &wpky_pos[40]);
  wpky_buf_ptr[6] = hex_to_u32 ((const u8 *) &wpky_pos[48]);
  wpky_buf_ptr[7] = hex_to_u32 ((const u8 *) &wpky_pos[56]);
  wpky_buf_ptr[8] = hex_to_u32 ((const u8 *) &wpky_pos[64]);
  wpky_buf_ptr[9] = hex_to_u32 ((const u8 *) &wpky_pos[72]);

  wpky_buf_ptr[0] = byte_swap_32 (wpky_buf_ptr[0]);
  wpky_buf_ptr[1] = byte_swap_32 (wpky_buf_ptr[1]);
  wpky_buf_ptr[2] = byte_swap_32 (wpky_buf_ptr[2]);
  wpky_buf_ptr[3] = byte_swap_32 (wpky_buf_ptr[3]);
  wpky_buf_ptr[4] = byte_swap_32 (wpky_buf_ptr[4]);
  wpky_buf_ptr[5] = byte_swap_32 (wpky_buf_ptr[5]);
  wpky_buf_ptr[6] = byte_swap_32 (wpky_buf_ptr[6]);
  wpky_buf_ptr[7] = byte_swap_32 (wpky_buf_ptr[7]);
  wpky_buf_ptr[8] = byte_swap_32 (wpky_buf_ptr[8]);
  wpky_buf_ptr[9] = byte_swap_32 (wpky_buf_ptr[9]);

  // iter

  if (hash_mode == 14700)
  {
    salt->salt_iter  = iter - 1;
  }
  else if (hash_mode == 14800)
  {
    salt->salt_iter  = dpic - 1;
    salt->salt_iter2 = iter - 1;
  }

  // salt

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  salt->salt_len = salt_len;

  // dpsl

  if (hash_mode == 14800)
  {
    u32 *dpsl_buf_ptr = (u32 *) itunes_backup->dpsl;

    dpsl_buf_ptr[0] = hex_to_u32 ((const u8 *) &dpsl_pos[ 0]);
    dpsl_buf_ptr[1] = hex_to_u32 ((const u8 *) &dpsl_pos[ 8]);
    dpsl_buf_ptr[2] = hex_to_u32 ((const u8 *) &dpsl_pos[16]);
    dpsl_buf_ptr[3] = hex_to_u32 ((const u8 *) &dpsl_pos[24]);
    dpsl_buf_ptr[4] = hex_to_u32 ((const u8 *) &dpsl_pos[32]);

    dpsl_buf_ptr[0] = byte_swap_32 (dpsl_buf_ptr[ 0]);
    dpsl_buf_ptr[1] = byte_swap_32 (dpsl_buf_ptr[ 1]);
    dpsl_buf_ptr[2] = byte_swap_32 (dpsl_buf_ptr[ 2]);
    dpsl_buf_ptr[3] = byte_swap_32 (dpsl_buf_ptr[ 3]);
    dpsl_buf_ptr[4] = byte_swap_32 (dpsl_buf_ptr[ 4]);
  }

  return (PARSER_OK);
}

int skip32_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (input_len != DISPLAY_LEN_MIN_14900) return (PARSER_GLOBAL_LENGTH);

  u32    *digest = (u32 *) hash_buf->digest;
  salt_t *salt   = hash_buf->salt;

  /**
   * parse line
   */

  u8 *hash_pos = input_buf;

  u8 *salt_pos = (u8 *) strchr ((const char *) hash_pos, ':');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = salt_pos - hash_pos;

  salt_pos++;

  /**
   * verify data
   */

  if (is_valid_hex_string (hash_pos, 8) == false) return (PARSER_HASH_ENCODING);

  if (is_valid_hex_string (salt_pos, 8) == false) return (PARSER_SALT_ENCODING);

  /**
   * store data
   */

  // digest

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  // salt

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[0]);

  salt->salt_len = salt_len / 2; // 4

  return (PARSER_OK);
}

int fortigate_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if (input_len != DISPLAY_LEN_MIN_7000) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_FORTIGATE, input_buf, 3)) return (PARSER_SIGNATURE_UNMATCHED);

  u32    *digest = (u32 *) hash_buf->digest;
  salt_t *salt   = hash_buf->salt;

  /**
   * parse line
   */

  u8 *hash_pos = input_buf + 3;

  /**
   * verify data
   */

  // decode salt + SHA1 hash (12 + 20 = 32)

  u8 tmp_buf[100] = { 0 };

  int decoded_len = base64_decode (base64_to_int, (const u8 *) hash_pos, DISPLAY_LEN_MAX_7000 - 3, tmp_buf);

  if (decoded_len != 32) return (PARSER_HASH_LENGTH);

  /**
   * store data
   */

  // salt

  u32 salt_len = 12;

  memcpy (salt->salt_buf, tmp_buf, salt_len);

  salt->salt_len = salt_len;

  // digest

  memcpy (digest, tmp_buf + salt_len, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  digest[0] -= SHA1M_A;
  digest[1] -= SHA1M_B;
  digest[2] -= SHA1M_C;
  digest[3] -= SHA1M_D;
  digest[4] -= SHA1M_E;

  return (PARSER_OK);
}

int sha256b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_1411) || (input_len > DISPLAY_LEN_MAX_1411)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_SHA256B64S, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 tmp_buf[120] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, (const u8 *) input_buf + 9, input_len - 9, tmp_buf);

  if (tmp_len < 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  digest[0] -= SHA256M_A;
  digest[1] -= SHA256M_B;
  digest[2] -= SHA256M_C;
  digest[3] -= SHA256M_D;
  digest[4] -= SHA256M_E;
  digest[5] -= SHA256M_F;
  digest[6] -= SHA256M_G;
  digest[7] -= SHA256M_H;

  const int salt_len = tmp_len - 32;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, tmp_buf + 32, salt->salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt->salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int filezilla_server_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15000) || (input_len > DISPLAY_LEN_MAX_15000)) return (PARSER_GLOBAL_LENGTH);

  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (is_valid_hex_string (input_buf, 128) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u64 ((const u8 *) &input_buf[  0]);
  digest[1] = hex_to_u64 ((const u8 *) &input_buf[ 16]);
  digest[2] = hex_to_u64 ((const u8 *) &input_buf[ 32]);
  digest[3] = hex_to_u64 ((const u8 *) &input_buf[ 48]);
  digest[4] = hex_to_u64 ((const u8 *) &input_buf[ 64]);
  digest[5] = hex_to_u64 ((const u8 *) &input_buf[ 80]);
  digest[6] = hex_to_u64 ((const u8 *) &input_buf[ 96]);
  digest[7] = hex_to_u64 ((const u8 *) &input_buf[112]);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  digest[0] -= SHA512M_A;
  digest[1] -= SHA512M_B;
  digest[2] -= SHA512M_C;
  digest[3] -= SHA512M_D;
  digest[4] -= SHA512M_E;
  digest[5] -= SHA512M_F;
  digest[6] -= SHA512M_G;
  digest[7] -= SHA512M_H;

  if (input_buf[128] != hashconfig->separator) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = input_len - 128 - 1;

  u8 *salt_buf = input_buf + 128 + 1;

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_buf, salt_len, hashconfig);

  if (salt_len == UINT_MAX) return (PARSER_SALT_LENGTH);

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int netbsd_sha1crypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15100) || (input_len > DISPLAY_LEN_MAX_15100)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_NETBSD_SHA1CRYPT, input_buf, 6)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  u8 *iter_pos = input_buf + 6;

  /**
   * parse line
   */

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '$');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  salt_pos++;

  u8 *hash_pos = (u8 *) strchr ((const char *) salt_pos, '$');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = hash_pos - salt_pos;

  hash_pos++;

  u32 hash_len = input_len - (hash_pos - input_buf);

  /**
   * verify data
   */

  u32 iter = atoi ((const char *) iter_pos);

  if (iter < 99) return (PARSER_SALT_ITERATION); // (actually: CRYPT_SHA1_ITERATIONS should be 24680 or more)

  if (salt_len != 8) return (PARSER_SALT_LENGTH);

  if (hash_len != 28) return (PARSER_HASH_LENGTH);

  /**
   * store data
   */

  // iterations:

  salt->salt_iter = iter - 1;

  // salt:

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  // salt length:

  salt->salt_len = salt_len;

  // digest:

  netbsd_sha1crypt_decode ((u8 *) digest, (u8 *) hash_pos, (u8 *) salt->salt_sign);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // precompute salt

  char *ptr = (char *) salt->salt_buf_pc;

  const int salt_len_pc = snprintf (ptr, 64, "%s$sha1$%u", (char *) salt->salt_buf, iter);

  ptr[salt_len_pc] = 0x80;

  salt->salt_len_pc = salt_len_pc;

  return (PARSER_OK);
}

int atlassian_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_12001) || (input_len > DISPLAY_LEN_MAX_12001)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ATLASSIAN, input_buf, 9)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha1_t *pbkdf2_sha1 = (pbkdf2_sha1_t *) hash_buf->esalt;

  /**
   * parse line
   */

  u8 *base64_pos = input_buf + 9;

  // base64 ($salt . $digest)

  u8 tmp_buf[100] = { 0 };

  int base64_decode_len = base64_decode (base64_to_int, (const u8 *) base64_pos, input_len - 9, tmp_buf);

  if (base64_decode_len != (16 + 32)) return (PARSER_HASH_LENGTH);

  /**
   * store data
   */

  // store salt

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha1->salt_buf;

  u32 salt_len = parse_and_store_salt (salt_buf_ptr, tmp_buf, 16, hashconfig);

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_len  = salt_len;
  salt->salt_iter = ROUNDS_ATLASSIAN - 1;

  // store hash

  memcpy (digest, tmp_buf + 16, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha1->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha1->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha1->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha1->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int jks_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15500) || (input_len > DISPLAY_LEN_MAX_15500)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_JKS_SHA1, input_buf, 10)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  jks_sha1_t *jks_sha1 = (jks_sha1_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // checksum

  u8 *checksum_pos = input_buf + 10 + 1;

  // iv

  u8 *iv_pos = (u8 *) strchr ((const char *) checksum_pos, '*');

  if (iv_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 checksum_len = iv_pos - checksum_pos;

  iv_pos++;

  // iterations

  u8 *enc_key_pos = (u8 *) strchr ((const char *) iv_pos, '*');

  if (enc_key_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iv_len = enc_key_pos - iv_pos;

  enc_key_pos++;

  // der1

  u8 *der1_pos = (u8 *) strchr ((const char *) enc_key_pos, '*');

  if (der1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 enc_key_len = der1_pos - enc_key_pos;

  der1_pos++;

  // der2

  u8 *der2_pos = (u8 *) strchr ((const char *) der1_pos, '*');

  if (der2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 der1_len = der2_pos - der1_pos;

  der2_pos++;

  // alias

  u8 *alias_pos = (u8 *) strchr ((const char *) der2_pos, '*');

  if (alias_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 der2_len = alias_pos - der2_pos;

  alias_pos++;

  u32 alias_len = input_len - 10 - 1 - checksum_len - 1 - iv_len - 1 - enc_key_len - 1 - der1_len - 1 - der2_len - 1;

  /**
   * verify data
   */

  if (checksum_len != 40)    return (PARSER_HASH_LENGTH);
  if (iv_len       != 40)    return (PARSER_SALT_LENGTH);
  if (enc_key_len  >= 16384) return (PARSER_SALT_LENGTH);
  if (der1_len     != 2)     return (PARSER_SALT_LENGTH);
  if (der2_len     != 28)    return (PARSER_SALT_LENGTH);
  if (alias_len    >= 64)    return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (checksum_pos, 40) == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (iv_pos,       40) == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (der1_pos,      2) == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (der2_pos,     28) == false) return (PARSER_SALT_ENCODING);

  /**
   * store data
   */

  // checksum

  jks_sha1->checksum[0] = hex_to_u32 ((const u8 *) &checksum_pos[ 0]);
  jks_sha1->checksum[1] = hex_to_u32 ((const u8 *) &checksum_pos[ 8]);
  jks_sha1->checksum[2] = hex_to_u32 ((const u8 *) &checksum_pos[16]);
  jks_sha1->checksum[3] = hex_to_u32 ((const u8 *) &checksum_pos[24]);
  jks_sha1->checksum[4] = hex_to_u32 ((const u8 *) &checksum_pos[32]);

  // iv

  jks_sha1->iv[0] = hex_to_u32 ((const u8 *) &iv_pos[ 0]);
  jks_sha1->iv[1] = hex_to_u32 ((const u8 *) &iv_pos[ 8]);
  jks_sha1->iv[2] = hex_to_u32 ((const u8 *) &iv_pos[16]);
  jks_sha1->iv[3] = hex_to_u32 ((const u8 *) &iv_pos[24]);
  jks_sha1->iv[4] = hex_to_u32 ((const u8 *) &iv_pos[32]);

  // enc_key

  u8 *enc_key_buf = (u8 *) jks_sha1->enc_key_buf;

  for (u32 i = 0, j = 0; j < enc_key_len; i += 1, j += 2)
  {
    enc_key_buf[i] = hex_to_u8 ((const u8 *) &enc_key_pos[j]);

    jks_sha1->enc_key_len++;
  }

  // der1

  u8 *der = (u8 *) jks_sha1->der;

  der[0] = hex_to_u8 ((const u8 *) &der1_pos[0]);

  // der2

  for (u32 i = 6, j = 0; j < 28; i += 1, j += 2)
  {
    der[i] = hex_to_u8 ((const u8 *) &der2_pos[j]);
  }

  der[1] = 0;
  der[2] = 0;
  der[3] = 0;
  der[4] = 0;
  der[5] = 0;

  // alias

  strncpy ((char *) jks_sha1->alias, (const char *) alias_pos, (size_t) 64);

  // fake salt

  salt->salt_buf[0] = jks_sha1->iv[0];
  salt->salt_buf[1] = jks_sha1->iv[1];
  salt->salt_buf[2] = jks_sha1->iv[2];
  salt->salt_buf[3] = jks_sha1->iv[3];
  salt->salt_buf[4] = jks_sha1->iv[4];

  salt->salt_len = 20;

  // fake digest

  digest[0] = byte_swap_32 (jks_sha1->der[0]);
  digest[1] = byte_swap_32 (jks_sha1->der[1]);
  digest[2] = byte_swap_32 (jks_sha1->der[2]);
  digest[3] = byte_swap_32 (jks_sha1->der[3]);
  digest[4] = byte_swap_32 (jks_sha1->der[4]);

  return (PARSER_OK);
}

int ethereum_pbkdf2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15600) || (input_len > DISPLAY_LEN_MAX_15600)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ETHEREUM_PBKDF2, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ethereum_pbkdf2_t *ethereum_pbkdf2 = (ethereum_pbkdf2_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // iter

  u8 *iter_pos = input_buf + 11 + 1;

  // salt

  u8 *salt_pos = (u8 *) strchr ((const char *) iter_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 iter_len = salt_pos - iter_pos;

  salt_pos++;

  // ciphertext

  u8 *ciphertext_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (ciphertext_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = ciphertext_pos - salt_pos;

  ciphertext_pos++;

  // hash

  u8 *hash_pos = (u8 *) strchr ((const char *) ciphertext_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ciphertext_len = hash_pos - ciphertext_pos;

  hash_pos++;

  u32 hash_len = input_len - 11 - 1 - iter_len - 1 - salt_len - 1 - ciphertext_len - 1;

  /**
   * verify some data
   */

  const u32 iter = atoi ((const char *) iter_pos);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  if ((salt_len != 32) && (salt_len != 64)) return (PARSER_SALT_LENGTH);
  if (ciphertext_len != 64)                 return (PARSER_SALT_LENGTH);
  if (hash_len       != 64)                 return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (salt_pos, salt_len)             == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (ciphertext_pos, ciphertext_len) == false) return (PARSER_HASH_ENCODING);
  if (is_valid_hex_string (hash_pos, hash_len)             == false) return (PARSER_HASH_ENCODING);

  /**
   * store data
   */

  u8 *salt_buf_ptr = (u8 *) ethereum_pbkdf2->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  // salt

  salt->salt_buf[0] = ethereum_pbkdf2->salt_buf[0];
  salt->salt_buf[1] = ethereum_pbkdf2->salt_buf[1];
  salt->salt_buf[2] = ethereum_pbkdf2->salt_buf[2];
  salt->salt_buf[3] = ethereum_pbkdf2->salt_buf[3];
  salt->salt_buf[4] = ethereum_pbkdf2->salt_buf[4];
  salt->salt_buf[5] = ethereum_pbkdf2->salt_buf[5];
  salt->salt_buf[6] = ethereum_pbkdf2->salt_buf[6];
  salt->salt_buf[7] = ethereum_pbkdf2->salt_buf[7];

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // ciphtertext

  ethereum_pbkdf2->ciphertext[0] = hex_to_u32 ((const u8 *) &ciphertext_pos[ 0]);
  ethereum_pbkdf2->ciphertext[1] = hex_to_u32 ((const u8 *) &ciphertext_pos[ 8]);
  ethereum_pbkdf2->ciphertext[2] = hex_to_u32 ((const u8 *) &ciphertext_pos[16]);
  ethereum_pbkdf2->ciphertext[3] = hex_to_u32 ((const u8 *) &ciphertext_pos[24]);
  ethereum_pbkdf2->ciphertext[4] = hex_to_u32 ((const u8 *) &ciphertext_pos[32]);
  ethereum_pbkdf2->ciphertext[5] = hex_to_u32 ((const u8 *) &ciphertext_pos[40]);
  ethereum_pbkdf2->ciphertext[6] = hex_to_u32 ((const u8 *) &ciphertext_pos[48]);
  ethereum_pbkdf2->ciphertext[7] = hex_to_u32 ((const u8 *) &ciphertext_pos[56]);

  // hash

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  return (PARSER_OK);
}

int ethereum_scrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig)
{
  if ((input_len < DISPLAY_LEN_MIN_15700) || (input_len > DISPLAY_LEN_MAX_15700)) return (PARSER_GLOBAL_LENGTH);

  if (memcmp (SIGNATURE_ETHEREUM_SCRYPT, input_buf, 11)) return (PARSER_SIGNATURE_UNMATCHED);

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ethereum_scrypt_t *ethereum_scrypt = (ethereum_scrypt_t *) hash_buf->esalt;

  /**
   * parse line
   */

  // scryptN

  u8 *scryptN_pos = input_buf + 11 + 1;

  // scryptr

  u8 *scryptr_pos = (u8 *) strchr ((const char *) scryptN_pos, '*');

  if (scryptr_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 scryptN_len = scryptr_pos - scryptN_pos;

  scryptr_pos++;

  // scryptp

  u8 *scryptp_pos = (u8 *) strchr ((const char *) scryptr_pos, '*');

  if (scryptp_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 scryptr_len = scryptp_pos - scryptr_pos;

  scryptp_pos++;

  // salt

  u8 *salt_pos = (u8 *) strchr ((const char *) scryptp_pos, '*');

  if (salt_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 scryptp_len = salt_pos - scryptp_pos;

  salt_pos++;

  // ciphertext

  u8 *ciphertext_pos = (u8 *) strchr ((const char *) salt_pos, '*');

  if (ciphertext_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 salt_len = ciphertext_pos - salt_pos;

  ciphertext_pos++;

  // hash

  u8 *hash_pos = (u8 *) strchr ((const char *) ciphertext_pos, '*');

  if (hash_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  u32 ciphertext_len = hash_pos - ciphertext_pos;

  hash_pos++;

  u32 hash_len = input_len - 11 - 1 - scryptN_len - 1 - scryptr_len - 1 - scryptp_len - 1 - salt_len - 1 - ciphertext_len - 1;

  /**
   * verify some data
   */

  const u32 scrypt_N = atoi ((const char *) scryptN_pos);
  const u32 scrypt_r = atoi ((const char *) scryptr_pos);
  const u32 scrypt_p = atoi ((const char *) scryptp_pos);

  if (salt_len       != 64) return (PARSER_SALT_LENGTH);
  if (ciphertext_len != 64) return (PARSER_SALT_LENGTH);
  if (hash_len       != 64) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (salt_pos, salt_len)             == false) return (PARSER_SALT_ENCODING);
  if (is_valid_hex_string (ciphertext_pos, ciphertext_len) == false) return (PARSER_HASH_ENCODING);
  if (is_valid_hex_string (hash_pos, hash_len)             == false) return (PARSER_HASH_ENCODING);

  /**
   * store data
   */

  u8 *salt_buf_ptr = (u8 *) ethereum_scrypt->salt_buf;

  salt_len = parse_and_store_salt (salt_buf_ptr, salt_pos, salt_len, hashconfig);

  // salt

  salt->salt_buf[0] = ethereum_scrypt->salt_buf[0];
  salt->salt_buf[1] = ethereum_scrypt->salt_buf[1];
  salt->salt_buf[2] = ethereum_scrypt->salt_buf[2];
  salt->salt_buf[3] = ethereum_scrypt->salt_buf[3];
  salt->salt_buf[4] = ethereum_scrypt->salt_buf[4];
  salt->salt_buf[5] = ethereum_scrypt->salt_buf[5];
  salt->salt_buf[6] = ethereum_scrypt->salt_buf[6];
  salt->salt_buf[7] = ethereum_scrypt->salt_buf[7];

  salt->salt_len  = salt_len;
  salt->salt_iter = 1;

  salt->scrypt_N = scrypt_N;
  salt->scrypt_r = scrypt_r;
  salt->scrypt_p = scrypt_p;

  // ciphtertext

  ethereum_scrypt->ciphertext[0] = hex_to_u32 ((const u8 *) &ciphertext_pos[ 0]);
  ethereum_scrypt->ciphertext[1] = hex_to_u32 ((const u8 *) &ciphertext_pos[ 8]);
  ethereum_scrypt->ciphertext[2] = hex_to_u32 ((const u8 *) &ciphertext_pos[16]);
  ethereum_scrypt->ciphertext[3] = hex_to_u32 ((const u8 *) &ciphertext_pos[24]);
  ethereum_scrypt->ciphertext[4] = hex_to_u32 ((const u8 *) &ciphertext_pos[32]);
  ethereum_scrypt->ciphertext[5] = hex_to_u32 ((const u8 *) &ciphertext_pos[40]);
  ethereum_scrypt->ciphertext[6] = hex_to_u32 ((const u8 *) &ciphertext_pos[48]);
  ethereum_scrypt->ciphertext[7] = hex_to_u32 ((const u8 *) &ciphertext_pos[56]);

  // hash

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  return (PARSER_OK);
}

/**
 * hook functions
 */

void seven_zip_hook_func (hc_device_param_t *device_param, hashes_t *hashes, const u32 salt_pos, const u32 pws_cnt)
{
  seven_zip_hook_t *hook_items = (seven_zip_hook_t *) device_param->hooks_buf;

  seven_zip_hook_salt_t *seven_zips = (seven_zip_hook_salt_t *) hashes->hook_salts_buf;
  seven_zip_hook_salt_t *seven_zip  = &seven_zips[salt_pos];

  u8   data_type   = seven_zip->data_type;
  u32 *data_buf    = seven_zip->data_buf;
  u32  unpack_size = seven_zip->unpack_size;

  for (u32 pw_pos = 0; pw_pos < pws_cnt; pw_pos++)
  {
    // this hook data needs to be updated (the "hook_success" variable):

    seven_zip_hook_t *hook_item = &hook_items[pw_pos];

    const u8 *ukey = (const u8 *) hook_item->ukey;

    // init AES

    AES_KEY aes_key;

    memset (&aes_key, 0, sizeof (aes_key));

    AES_set_decrypt_key (ukey, 256, &aes_key);

    int aes_len = seven_zip->aes_len;

    u32 data[4];
    u32 out [4];
    u32 iv  [4];

    iv[0] = seven_zip->iv_buf[0];
    iv[1] = seven_zip->iv_buf[1];
    iv[2] = seven_zip->iv_buf[2];
    iv[3] = seven_zip->iv_buf[3];

    u32 out_full[81882];

    // if aes_len > 16 we need to loop

    int i = 0;
    int j = 0;

    for (i = 0, j = 0; i < aes_len - 16; i += 16, j += 4)
    {
      data[0] = data_buf[j + 0];
      data[1] = data_buf[j + 1];
      data[2] = data_buf[j + 2];
      data[3] = data_buf[j + 3];

      AES_decrypt (&aes_key, (u8*) data, (u8*) out);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];

      out_full[j + 0] = out[0];
      out_full[j + 1] = out[1];
      out_full[j + 2] = out[2];
      out_full[j + 3] = out[3];
    }

    // we need to run it at least once:

    data[0] = data_buf[j + 0];
    data[1] = data_buf[j + 1];
    data[2] = data_buf[j + 2];
    data[3] = data_buf[j + 3];

    AES_decrypt (&aes_key, (u8*) data, (u8*) out);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    out_full[j + 0] = out[0];
    out_full[j + 1] = out[1];
    out_full[j + 2] = out[2];
    out_full[j + 3] = out[3];

    /*
     * check the CRC32 "hash"
     */

    u32 seven_zip_crc = seven_zip->crc;

    u32 crc;

    if (data_type == 0) // uncompressed
    {
      crc = cpu_crc32_buffer ((u8 *) out_full, unpack_size);
    }
    else
    {
      u32 crc_len = seven_zip->crc_len;

      char *coder_attributes = seven_zip->coder_attributes;

      // input buffers and length

      u8 *compressed_data = (u8 *) out_full;

      SizeT compressed_data_len = aes_len;

      // output buffers and length

      unsigned char *decompressed_data;

      decompressed_data = (unsigned char *) hcmalloc (crc_len);

      SizeT decompressed_data_len = crc_len;

      int ret;

      if (data_type == 1) // LZMA1
      {
        ret = hc_lzma1_decompress (compressed_data, &compressed_data_len, decompressed_data, &decompressed_data_len, coder_attributes);
      }
      else // we only support LZMA2 in addition to LZMA1
      {
        ret = hc_lzma2_decompress (compressed_data, &compressed_data_len, decompressed_data, &decompressed_data_len, coder_attributes);
      }

      if (ret != SZ_OK)
      {
        hook_item->hook_success = 0;

        hcfree (decompressed_data);

        continue;
      }

      crc = cpu_crc32_buffer (decompressed_data, crc_len);

      hcfree (decompressed_data);
    }

    if (crc == seven_zip_crc)
    {
      hook_item->hook_success = 1;
    }
    else
    {
      hook_item->hook_success = 0;
    }
  }
}

/**
 * output
 */

char *stroptitype (const u32 opti_type)
{
  switch (opti_type)
  {
    case OPTI_TYPE_ZERO_BYTE:         return ((char *) OPTI_STR_ZERO_BYTE);
    case OPTI_TYPE_PRECOMPUTE_INIT:   return ((char *) OPTI_STR_PRECOMPUTE_INIT);
    case OPTI_TYPE_PRECOMPUTE_MERKLE: return ((char *) OPTI_STR_PRECOMPUTE_MERKLE);
    case OPTI_TYPE_PRECOMPUTE_PERMUT: return ((char *) OPTI_STR_PRECOMPUTE_PERMUT);
    case OPTI_TYPE_MEET_IN_MIDDLE:    return ((char *) OPTI_STR_MEET_IN_MIDDLE);
    case OPTI_TYPE_EARLY_SKIP:        return ((char *) OPTI_STR_EARLY_SKIP);
    case OPTI_TYPE_NOT_SALTED:        return ((char *) OPTI_STR_NOT_SALTED);
    case OPTI_TYPE_NOT_ITERATED:      return ((char *) OPTI_STR_NOT_ITERATED);
    case OPTI_TYPE_PREPENDED_SALT:    return ((char *) OPTI_STR_PREPENDED_SALT);
    case OPTI_TYPE_APPENDED_SALT:     return ((char *) OPTI_STR_APPENDED_SALT);
    case OPTI_TYPE_SINGLE_HASH:       return ((char *) OPTI_STR_SINGLE_HASH);
    case OPTI_TYPE_SINGLE_SALT:       return ((char *) OPTI_STR_SINGLE_SALT);
    case OPTI_TYPE_BRUTE_FORCE:       return ((char *) OPTI_STR_BRUTE_FORCE);
    case OPTI_TYPE_RAW_HASH:          return ((char *) OPTI_STR_RAW_HASH);
    case OPTI_TYPE_SLOW_HASH_SIMD:    return ((char *) OPTI_STR_SLOW_HASH_SIMD);
    case OPTI_TYPE_USES_BITS_8:       return ((char *) OPTI_STR_USES_BITS_8);
    case OPTI_TYPE_USES_BITS_16:      return ((char *) OPTI_STR_USES_BITS_16);
    case OPTI_TYPE_USES_BITS_32:      return ((char *) OPTI_STR_USES_BITS_32);
    case OPTI_TYPE_USES_BITS_64:      return ((char *) OPTI_STR_USES_BITS_64);
  }

  return (NULL);
}

char *strhashtype (const u32 hash_mode)
{
  switch (hash_mode)
  {
    case     0: return ((char *) HT_00000);
    case    10: return ((char *) HT_00010);
    case    11: return ((char *) HT_00011);
    case    12: return ((char *) HT_00012);
    case    20: return ((char *) HT_00020);
    case    21: return ((char *) HT_00021);
    case    22: return ((char *) HT_00022);
    case    23: return ((char *) HT_00023);
    case    30: return ((char *) HT_00030);
    case    40: return ((char *) HT_00040);
    case    50: return ((char *) HT_00050);
    case    60: return ((char *) HT_00060);
    case   100: return ((char *) HT_00100);
    case   101: return ((char *) HT_00101);
    case   110: return ((char *) HT_00110);
    case   111: return ((char *) HT_00111);
    case   112: return ((char *) HT_00112);
    case   120: return ((char *) HT_00120);
    case   121: return ((char *) HT_00121);
    case   122: return ((char *) HT_00122);
    case   124: return ((char *) HT_00124);
    case   125: return ((char *) HT_00125);
    case   130: return ((char *) HT_00130);
    case   131: return ((char *) HT_00131);
    case   132: return ((char *) HT_00132);
    case   133: return ((char *) HT_00133);
    case   140: return ((char *) HT_00140);
    case   141: return ((char *) HT_00141);
    case   150: return ((char *) HT_00150);
    case   160: return ((char *) HT_00160);
    case   200: return ((char *) HT_00200);
    case   300: return ((char *) HT_00300);
    case   400: return ((char *) HT_00400);
    case   500: return ((char *) HT_00500);
    case   501: return ((char *) HT_00501);
    case   600: return ((char *) HT_00600);
    case   900: return ((char *) HT_00900);
    case  1000: return ((char *) HT_01000);
    case  1100: return ((char *) HT_01100);
    case  1300: return ((char *) HT_01300);
    case  1400: return ((char *) HT_01400);
    case  1410: return ((char *) HT_01410);
    case  1411: return ((char *) HT_01411);
    case  1420: return ((char *) HT_01420);
    case  1421: return ((char *) HT_01421);
    case  1430: return ((char *) HT_01430);
    case  1440: return ((char *) HT_01440);
    case  1441: return ((char *) HT_01441);
    case  1450: return ((char *) HT_01450);
    case  1460: return ((char *) HT_01460);
    case  1500: return ((char *) HT_01500);
    case  1600: return ((char *) HT_01600);
    case  1700: return ((char *) HT_01700);
    case  1710: return ((char *) HT_01710);
    case  1711: return ((char *) HT_01711);
    case  1720: return ((char *) HT_01720);
    case  1722: return ((char *) HT_01722);
    case  1730: return ((char *) HT_01730);
    case  1731: return ((char *) HT_01731);
    case  1740: return ((char *) HT_01740);
    case  1750: return ((char *) HT_01750);
    case  1760: return ((char *) HT_01760);
    case  1800: return ((char *) HT_01800);
    case  2100: return ((char *) HT_02100);
    case  2400: return ((char *) HT_02400);
    case  2410: return ((char *) HT_02410);
    case  2500: return ((char *) HT_02500);
    case  2600: return ((char *) HT_02600);
    case  2611: return ((char *) HT_02611);
    case  2612: return ((char *) HT_02612);
    case  2711: return ((char *) HT_02711);
    case  2811: return ((char *) HT_02811);
    case  3000: return ((char *) HT_03000);
    case  3100: return ((char *) HT_03100);
    case  3200: return ((char *) HT_03200);
    case  3710: return ((char *) HT_03710);
    case  3711: return ((char *) HT_03711);
    case  3800: return ((char *) HT_03800);
    case  3910: return ((char *) HT_03910);
    case  4010: return ((char *) HT_04010);
    case  4110: return ((char *) HT_04110);
    case  4300: return ((char *) HT_04300);
    case  4400: return ((char *) HT_04400);
    case  4500: return ((char *) HT_04500);
    case  4520: return ((char *) HT_04520);
    case  4521: return ((char *) HT_04521);
    case  4522: return ((char *) HT_04522);
    case  4700: return ((char *) HT_04700);
    case  4800: return ((char *) HT_04800);
    case  4900: return ((char *) HT_04900);
    case  5000: return ((char *) HT_05000);
    case  5100: return ((char *) HT_05100);
    case  5200: return ((char *) HT_05200);
    case  5300: return ((char *) HT_05300);
    case  5400: return ((char *) HT_05400);
    case  5500: return ((char *) HT_05500);
    case  5600: return ((char *) HT_05600);
    case  5700: return ((char *) HT_05700);
    case  5800: return ((char *) HT_05800);
    case  6000: return ((char *) HT_06000);
    case  6100: return ((char *) HT_06100);
    case  6211: return ((char *) HT_06211);
    case  6212: return ((char *) HT_06212);
    case  6213: return ((char *) HT_06213);
    case  6221: return ((char *) HT_06221);
    case  6222: return ((char *) HT_06222);
    case  6223: return ((char *) HT_06223);
    case  6231: return ((char *) HT_06231);
    case  6232: return ((char *) HT_06232);
    case  6233: return ((char *) HT_06233);
    case  6241: return ((char *) HT_06241);
    case  6242: return ((char *) HT_06242);
    case  6243: return ((char *) HT_06243);
    case  6300: return ((char *) HT_06300);
    case  6400: return ((char *) HT_06400);
    case  6500: return ((char *) HT_06500);
    case  6600: return ((char *) HT_06600);
    case  6700: return ((char *) HT_06700);
    case  6800: return ((char *) HT_06800);
    case  6900: return ((char *) HT_06900);
    case  7000: return ((char *) HT_07000);
    case  7100: return ((char *) HT_07100);
    case  7200: return ((char *) HT_07200);
    case  7300: return ((char *) HT_07300);
    case  7400: return ((char *) HT_07400);
    case  7500: return ((char *) HT_07500);
    case  7700: return ((char *) HT_07700);
    case  7800: return ((char *) HT_07800);
    case  7900: return ((char *) HT_07900);
    case  8000: return ((char *) HT_08000);
    case  8100: return ((char *) HT_08100);
    case  8200: return ((char *) HT_08200);
    case  8300: return ((char *) HT_08300);
    case  8400: return ((char *) HT_08400);
    case  8500: return ((char *) HT_08500);
    case  8600: return ((char *) HT_08600);
    case  8700: return ((char *) HT_08700);
    case  8800: return ((char *) HT_08800);
    case  8900: return ((char *) HT_08900);
    case  9000: return ((char *) HT_09000);
    case  9100: return ((char *) HT_09100);
    case  9200: return ((char *) HT_09200);
    case  9300: return ((char *) HT_09300);
    case  9400: return ((char *) HT_09400);
    case  9500: return ((char *) HT_09500);
    case  9600: return ((char *) HT_09600);
    case  9700: return ((char *) HT_09700);
    case  9710: return ((char *) HT_09710);
    case  9720: return ((char *) HT_09720);
    case  9800: return ((char *) HT_09800);
    case  9810: return ((char *) HT_09810);
    case  9820: return ((char *) HT_09820);
    case  9900: return ((char *) HT_09900);
    case 10000: return ((char *) HT_10000);
    case 10100: return ((char *) HT_10100);
    case 10200: return ((char *) HT_10200);
    case 10300: return ((char *) HT_10300);
    case 10400: return ((char *) HT_10400);
    case 10410: return ((char *) HT_10410);
    case 10420: return ((char *) HT_10420);
    case 10500: return ((char *) HT_10500);
    case 10600: return ((char *) HT_10600);
    case 10700: return ((char *) HT_10700);
    case 10800: return ((char *) HT_10800);
    case 10900: return ((char *) HT_10900);
    case 11000: return ((char *) HT_11000);
    case 11100: return ((char *) HT_11100);
    case 11200: return ((char *) HT_11200);
    case 11300: return ((char *) HT_11300);
    case 11400: return ((char *) HT_11400);
    case 11500: return ((char *) HT_11500);
    case 11600: return ((char *) HT_11600);
    case 11700: return ((char *) HT_11700);
    case 11800: return ((char *) HT_11800);
    case 11900: return ((char *) HT_11900);
    case 12000: return ((char *) HT_12000);
    case 12001: return ((char *) HT_12001);
    case 12100: return ((char *) HT_12100);
    case 12200: return ((char *) HT_12200);
    case 12300: return ((char *) HT_12300);
    case 12400: return ((char *) HT_12400);
    case 12500: return ((char *) HT_12500);
    case 12600: return ((char *) HT_12600);
    case 12700: return ((char *) HT_12700);
    case 12800: return ((char *) HT_12800);
    case 12900: return ((char *) HT_12900);
    case 13000: return ((char *) HT_13000);
    case 13100: return ((char *) HT_13100);
    case 13200: return ((char *) HT_13200);
    case 13300: return ((char *) HT_13300);
    case 13400: return ((char *) HT_13400);
    case 13500: return ((char *) HT_13500);
    case 13600: return ((char *) HT_13600);
    case 13711: return ((char *) HT_13711);
    case 13712: return ((char *) HT_13712);
    case 13713: return ((char *) HT_13713);
    case 13721: return ((char *) HT_13721);
    case 13722: return ((char *) HT_13722);
    case 13723: return ((char *) HT_13723);
    case 13731: return ((char *) HT_13731);
    case 13732: return ((char *) HT_13732);
    case 13733: return ((char *) HT_13733);
    case 13741: return ((char *) HT_13741);
    case 13742: return ((char *) HT_13742);
    case 13743: return ((char *) HT_13743);
    case 13751: return ((char *) HT_13751);
    case 13752: return ((char *) HT_13752);
    case 13753: return ((char *) HT_13753);
    case 13761: return ((char *) HT_13761);
    case 13762: return ((char *) HT_13762);
    case 13763: return ((char *) HT_13763);
    case 13800: return ((char *) HT_13800);
    case 13900: return ((char *) HT_13900);
    case 14000: return ((char *) HT_14000);
    case 14100: return ((char *) HT_14100);
    case 14400: return ((char *) HT_14400);
    case 14600: return ((char *) HT_14600);
    case 14700: return ((char *) HT_14700);
    case 14800: return ((char *) HT_14800);
    case 14900: return ((char *) HT_14900);
    case 15000: return ((char *) HT_15000);
    case 15100: return ((char *) HT_15100);
    case 15200: return ((char *) HT_15200);
    case 15300: return ((char *) HT_15300);
    case 15400: return ((char *) HT_15400);
    case 15500: return ((char *) HT_15500);
    case 15600: return ((char *) HT_15600);
    case 15700: return ((char *) HT_15700);
    case 99999: return ((char *) HT_99999);
  }

  return ((char *) "Unknown");
}

char *strparser (const u32 parser_status)
{
  switch (parser_status)
  {
    case PARSER_OK:                   return ((char *) PA_000);
    case PARSER_COMMENT:              return ((char *) PA_001);
    case PARSER_GLOBAL_ZERO:          return ((char *) PA_002);
    case PARSER_GLOBAL_LENGTH:        return ((char *) PA_003);
    case PARSER_HASH_LENGTH:          return ((char *) PA_004);
    case PARSER_HASH_VALUE:           return ((char *) PA_005);
    case PARSER_SALT_LENGTH:          return ((char *) PA_006);
    case PARSER_SALT_VALUE:           return ((char *) PA_007);
    case PARSER_SALT_ITERATION:       return ((char *) PA_008);
    case PARSER_SEPARATOR_UNMATCHED:  return ((char *) PA_009);
    case PARSER_SIGNATURE_UNMATCHED:  return ((char *) PA_010);
    case PARSER_HCCAPX_FILE_SIZE:     return ((char *) PA_011);
    case PARSER_HCCAPX_EAPOL_LEN:     return ((char *) PA_012);
    case PARSER_PSAFE2_FILE_SIZE:     return ((char *) PA_013);
    case PARSER_PSAFE3_FILE_SIZE:     return ((char *) PA_014);
    case PARSER_TC_FILE_SIZE:         return ((char *) PA_015);
    case PARSER_VC_FILE_SIZE:         return ((char *) PA_016);
    case PARSER_SIP_AUTH_DIRECTIVE:   return ((char *) PA_017);
    case PARSER_HASH_FILE:            return ((char *) PA_018);
    case PARSER_HASH_ENCODING:        return ((char *) PA_019);
    case PARSER_SALT_ENCODING:        return ((char *) PA_020);
    case PARSER_LUKS_FILE_SIZE:       return ((char *) PA_021);
    case PARSER_LUKS_MAGIC:           return ((char *) PA_022);
    case PARSER_LUKS_VERSION:         return ((char *) PA_023);
    case PARSER_LUKS_CIPHER_TYPE:     return ((char *) PA_024);
    case PARSER_LUKS_CIPHER_MODE:     return ((char *) PA_025);
    case PARSER_LUKS_HASH_TYPE:       return ((char *) PA_026);
    case PARSER_LUKS_KEY_SIZE:        return ((char *) PA_027);
    case PARSER_LUKS_KEY_DISABLED:    return ((char *) PA_028);
    case PARSER_LUKS_KEY_STRIPES:     return ((char *) PA_029);
    case PARSER_LUKS_HASH_CIPHER:     return ((char *) PA_030);
    case PARSER_HCCAPX_SIGNATURE:     return ((char *) PA_031);
    case PARSER_HCCAPX_VERSION:       return ((char *) PA_032);
    case PARSER_HCCAPX_MESSAGE_PAIR:  return ((char *) PA_033);
  }

  return ((char *) PA_255);
}

int check_old_hccap (const char *hashfile)
{
  FILE *fp = fopen (hashfile, "rb");

  if (fp == NULL) return -1;

  u32 signature;

  const size_t nread = fread (&signature, sizeof (u32), 1, fp);

  fclose (fp);

  if (nread != 1) return -1;

  if (signature == HCCAPX_SIGNATURE) return 0;

  return 1;
}

void to_hccapx_t (hashcat_ctx_t *hashcat_ctx, hccapx_t *hccapx, const u32 salt_pos, const u32 digest_pos)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  const salt_t *salts_buf   = hashes->salts_buf;
  const void   *esalts_buf  = hashes->esalts_buf;

  memset (hccapx, 0, sizeof (hccapx_t));

  hccapx->signature = HCCAPX_SIGNATURE;
  hccapx->version   = HCCAPX_VERSION;

  const salt_t *salt = &salts_buf[salt_pos];

  const u32 digest_cur = salt->digests_offset + digest_pos;

  hccapx->essid_len = salt->salt_len;

  memcpy (hccapx->essid, salt->salt_buf, hccapx->essid_len);

  wpa_t *wpas = (wpa_t *) esalts_buf;
  wpa_t *wpa  = &wpas[digest_cur];

  hccapx->message_pair = wpa->message_pair;
  hccapx->keyver = wpa->keyver;

  hccapx->eapol_len = wpa->eapol_len;

  if (wpa->keyver != 1)
  {
    u32 eapol_tmp[64] = { 0 };

    for (u32 i = 0; i < 64; i++)
    {
      eapol_tmp[i] = byte_swap_32 (wpa->eapol[i]);
    }

    memcpy (hccapx->eapol, eapol_tmp, wpa->eapol_len);
  }
  else
  {
    memcpy (hccapx->eapol, wpa->eapol, wpa->eapol_len);
  }

  memcpy (hccapx->mac_ap,    wpa->orig_mac_ap,    6);
  memcpy (hccapx->mac_sta,   wpa->orig_mac_sta,   6);
  memcpy (hccapx->nonce_ap,  wpa->orig_nonce_ap,  32);
  memcpy (hccapx->nonce_sta, wpa->orig_nonce_sta, 32);

  if (wpa->keyver != 1)
  {
    u32 digest_tmp[4];

    digest_tmp[0] = byte_swap_32 (wpa->keymic[0]);
    digest_tmp[1] = byte_swap_32 (wpa->keymic[1]);
    digest_tmp[2] = byte_swap_32 (wpa->keymic[2]);
    digest_tmp[3] = byte_swap_32 (wpa->keymic[3]);

    memcpy (hccapx->keymic, digest_tmp, 16);
  }
  else
  {
    memcpy (hccapx->keymic, wpa->keymic, 16);
  }
}

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const size_t out_len, const u32 salt_pos, const u32 digest_pos)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const hashes_t     *hashes     = hashcat_ctx->hashes;

  void        *digests_buf = hashes->digests_buf;
  salt_t      *salts_buf   = hashes->salts_buf;
  void        *esalts_buf  = hashes->esalts_buf;
  hashinfo_t **hash_info   = hashes->hash_info;
  const char  *hashfile    = hashes->hashfile;

  const u32 hash_type = hashconfig->hash_type;
  const u32 hash_mode = hashconfig->hash_mode;
  const u32 salt_type = hashconfig->salt_type;
  const u64 opts_type = hashconfig->opts_type;
  const u32 opti_type = hashconfig->opti_type;
  const u32 dgst_size = hashconfig->dgst_size;

  const u32 digest_cur = salts_buf[salt_pos].digests_offset + digest_pos;

  u8 datax[256] = { 0 };

  u64 *digest_buf64 = (u64 *) datax;
  u32 *digest_buf   = (u32 *) datax;

  char *digests_buf_ptr = (char *) digests_buf;

  memcpy (digest_buf, digests_buf_ptr + (salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

  if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
  {
    u32 tt;

    switch (hash_type)
    {
      case HASH_TYPE_DES:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_DESCRYPT:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_DESRACF:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_LM:
        FP (digest_buf[1], digest_buf[0], tt);
        break;

      case HASH_TYPE_NETNTLM:
        digest_buf[0] = rotl32 (digest_buf[0], 29);
        digest_buf[1] = rotl32 (digest_buf[1], 29);
        digest_buf[2] = rotl32 (digest_buf[2], 29);
        digest_buf[3] = rotl32 (digest_buf[3], 29);

        FP (digest_buf[1], digest_buf[0], tt);
        FP (digest_buf[3], digest_buf[2], tt);
        break;

      case HASH_TYPE_BSDICRYPT:
        digest_buf[0] = rotl32 (digest_buf[0], 31);
        digest_buf[1] = rotl32 (digest_buf[1], 31);

        FP (digest_buf[1], digest_buf[0], tt);
        break;
    }
  }

  if (opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    switch (hash_type)
    {
      case HASH_TYPE_MD4:
        digest_buf[0] += MD4M_A;
        digest_buf[1] += MD4M_B;
        digest_buf[2] += MD4M_C;
        digest_buf[3] += MD4M_D;
        break;

      case HASH_TYPE_MD5:
        digest_buf[0] += MD5M_A;
        digest_buf[1] += MD5M_B;
        digest_buf[2] += MD5M_C;
        digest_buf[3] += MD5M_D;
        break;

      case HASH_TYPE_SHA1:
        digest_buf[0] += SHA1M_A;
        digest_buf[1] += SHA1M_B;
        digest_buf[2] += SHA1M_C;
        digest_buf[3] += SHA1M_D;
        digest_buf[4] += SHA1M_E;
        break;

      case HASH_TYPE_SHA224:
        digest_buf[0] += SHA224M_A;
        digest_buf[1] += SHA224M_B;
        digest_buf[2] += SHA224M_C;
        digest_buf[3] += SHA224M_D;
        digest_buf[4] += SHA224M_E;
        digest_buf[5] += SHA224M_F;
        digest_buf[6] += SHA224M_G;
        break;

      case HASH_TYPE_SHA256:
        digest_buf[0] += SHA256M_A;
        digest_buf[1] += SHA256M_B;
        digest_buf[2] += SHA256M_C;
        digest_buf[3] += SHA256M_D;
        digest_buf[4] += SHA256M_E;
        digest_buf[5] += SHA256M_F;
        digest_buf[6] += SHA256M_G;
        digest_buf[7] += SHA256M_H;
        break;

      case HASH_TYPE_SHA384:
        digest_buf64[0] += SHA384M_A;
        digest_buf64[1] += SHA384M_B;
        digest_buf64[2] += SHA384M_C;
        digest_buf64[3] += SHA384M_D;
        digest_buf64[4] += SHA384M_E;
        digest_buf64[5] += SHA384M_F;
        digest_buf64[6] += 0;
        digest_buf64[7] += 0;
        break;

      case HASH_TYPE_SHA512:
        digest_buf64[0] += SHA512M_A;
        digest_buf64[1] += SHA512M_B;
        digest_buf64[2] += SHA512M_C;
        digest_buf64[3] += SHA512M_D;
        digest_buf64[4] += SHA512M_E;
        digest_buf64[5] += SHA512M_F;
        digest_buf64[6] += SHA512M_G;
        digest_buf64[7] += SHA512M_H;
        break;
    }
  }

  if (opts_type & OPTS_TYPE_PT_GENERATE_LE)
  {
    if (dgst_size == DGST_SIZE_4_2)
    {
      for (int i = 0; i < 2; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_4)
    {
      for (int i = 0; i < 4; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_5)
    {
      for (int i = 0; i < 5; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_6)
    {
      for (int i = 0; i < 6; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_7)
    {
      for (int i = 0; i < 7; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_4_8)
    {
      for (int i = 0; i < 8; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if ((dgst_size == DGST_SIZE_4_16) || (dgst_size == DGST_SIZE_8_8)) // same size, same result :)
    {
      if (hash_type == HASH_TYPE_WHIRLPOOL)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
      else if (hash_type == HASH_TYPE_SHA384)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_SHA512)
      {
        for (int i = 0; i < 8; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
      }
      else if (hash_type == HASH_TYPE_GOST)
      {
        for (int i = 0; i < 16; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
      }
    }
    else if (dgst_size == DGST_SIZE_4_64)
    {
      for (int i = 0; i < 64; i++) digest_buf[i] = byte_swap_32 (digest_buf[i]);
    }
    else if (dgst_size == DGST_SIZE_8_25)
    {
      for (int i = 0; i < 25; i++) digest_buf64[i] = byte_swap_64 (digest_buf64[i]);
    }
  }

  salt_t salt;

  const bool isSalted = ((hashconfig->salt_type == SALT_TYPE_INTERN)
                      |  (hashconfig->salt_type == SALT_TYPE_EXTERN)
                      |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED));

  if (isSalted == true)
  {
    memcpy (&salt, &salts_buf[salt_pos], sizeof (salt_t));

    char *ptr = (char *) salt.salt_buf;

    if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
    {
      switch (hash_type)
      {
        case HASH_TYPE_NETNTLM:

          salt.salt_buf[0] = rotr32 (salt.salt_buf[0], 3);
          salt.salt_buf[1] = rotr32 (salt.salt_buf[1], 3);

          u32 tt;

          FP (salt.salt_buf[1], salt.salt_buf[0], tt);

          break;
      }
    }

    u32 salt_len = salt.salt_len;

    if (opts_type & OPTS_TYPE_ST_UTF16LE)
    {
      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        ptr[i] = ptr[j];
      }

      salt_len = salt_len / 2;
    }

    if (opts_type & OPTS_TYPE_ST_GENERATE_LE)
    {
      u32 max = salt.salt_len / 4;

      if (salt_len % 4) max++;

      for (u32 i = 0; i < max; i++)
      {
        salt.salt_buf[i] = byte_swap_32 (salt.salt_buf[i]);
      }
    }

    if (opts_type & OPTS_TYPE_ST_HEX)
    {
      char tmp[64] = { 0 };

      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        sprintf (tmp + j, "%02x", (unsigned char) ptr[i]);
      }

      salt_len = salt_len * 2;

      memcpy (ptr, tmp, salt_len);
    }

    u32 memset_size = ((48 - (int) salt_len) > 0) ? (48 - salt_len) : 0;

    memset (ptr + salt_len, 0, memset_size);

    salt.salt_len = salt_len;
  }
  else
  {
    memset (&salt, 0, sizeof (salt_t));
  }

  //
  // some modes require special encoding
  //

  u32 out_buf_plain[256] = { 0 };
  u32 out_buf_salt[256]  = { 0 };

  char tmp_buf[1024] = { 0 };

  char *ptr_plain = (char *) out_buf_plain;
  u8 *ptr_salt  = (u8 *) out_buf_salt;

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

    snprintf (out_buf, out_len - 1, "%s:%s",
      tmp_buf,
      username);
  }
  else if (hash_mode == 23)
  {
    // do not show the skyper part in output

    char *salt_buf_ptr = (char *) salt.salt_buf;

    salt_buf_ptr[salt.salt_len - 8] = 0;

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      salt_buf_ptr);
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

    snprintf (out_buf, out_len - 1, "{SHA}%s", ptr_plain);
  }
  else if (hash_mode == 111)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_len - 1, "{SSHA}%s", ptr_plain);
  }
  else if ((hash_mode == 122) || (hash_mode == 125))
  {
    snprintf (out_buf, out_len - 1, "%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 124)
  {
    snprintf (out_buf, out_len - 1, "sha1$%s$%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 131)
  {
    snprintf (out_buf, out_len - 1, "0x0100%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      0u, 0u, 0u, 0u, 0u,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 132)
  {
    snprintf (out_buf, out_len - 1, "0x0100%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 133)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, out_len - 1, "%s", ptr_plain);
  }
  else if (hash_mode == 141)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, (u8 *) ptr_salt);

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

    snprintf (out_buf, out_len - 1, "%s%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 400)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    phpass_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, out_len - 1, "%s%s%s", (char *) salt.salt_sign, (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 500)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf (out_buf, out_len - 1, "$1$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, out_len - 1, "$1$rounds=%u$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 501)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
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

    snprintf (out_buf, out_len - 1, "%s%s", SIGNATURE_SHA256B64S, ptr_plain);
  }
  else if (hash_mode == 1421)
  {
    u8 *salt_ptr = (u8 *) salt.salt_buf;

    snprintf (out_buf, out_len - 1, "%c%c%c%c%c%c%08x%08x%08x%08x%08x%08x%08x%08x",
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

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, (u8 *) ptr_salt);

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

    snprintf (out_buf, out_len - 1, "%s%s*%s", SIGNATURE_EPISERVER4, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1500)
  {
    out_buf[0] = salt.salt_sign[0] & 0xff;
    out_buf[1] = salt.salt_sign[1] & 0xff;
    //original method, but changed because of this ticket: https://hashcat.net/trac/ticket/269
    //out_buf[0] = int_to_itoa64 ((salt.salt_buf[0] >> 0) & 0x3f);
    //out_buf[1] = int_to_itoa64 ((salt.salt_buf[0] >> 6) & 0x3f);

    memset (tmp_buf, 0, sizeof (tmp_buf));

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);

    memcpy (tmp_buf, digest_buf, 8);

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 8, (u8 *) ptr_plain);

    snprintf (out_buf + 2, out_len - 1 - 2, "%s", ptr_plain);

    out_buf[13] = 0;
  }
  else if (hash_mode == 1600)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_MD5CRYPT)
    {
      snprintf (out_buf, out_len - 1, "$apr1$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, out_len - 1, "$apr1$rounds=%u$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
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

    snprintf (out_buf, out_len - 1, "%s%s", SIGNATURE_SHA512B64S, ptr_plain);
  }
  else if (hash_mode == 1722)
  {
    u32 *ptr = digest_buf;

    snprintf (out_buf, out_len - 1, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
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
  else if (hash_mode == 1731)
  {
    u32 *ptr = digest_buf;

    snprintf (out_buf, out_len - 1, "0x0200%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
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
  else if (hash_mode == 1800)
  {
    // temp workaround

    digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
    digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
    digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
    digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
    digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
    digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
    digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
    digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

    sha512crypt_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA512CRYPT)
    {
      snprintf (out_buf, out_len - 1, "$6$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, out_len - 1, "$6$rounds=%u$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 2100)
  {
    u32 pos = 0;

    snprintf (out_buf + pos, out_len - 1 - pos, "%s%u#",
      SIGNATURE_DCC2,
      salt.salt_iter + 1);

    u32 signature_len = strlen (out_buf);

    pos += signature_len;

    char *salt_ptr = (char *) salt.salt_buf;

    for (u32 i = 0; i < salt.salt_len; i++, pos++) snprintf (out_buf + pos, out_len - 1 - pos, "%c", salt_ptr[i]);

    snprintf (out_buf + pos, out_len - 1 - pos, "#%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if ((hash_mode == 2400) || (hash_mode == 2410))
  {
    memcpy (tmp_buf, digest_buf, 16);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    out_buf[ 0] = int_to_itoa64 ((digest_buf[0] >>  0) & 0x3f);
    out_buf[ 1] = int_to_itoa64 ((digest_buf[0] >>  6) & 0x3f);
    out_buf[ 2] = int_to_itoa64 ((digest_buf[0] >> 12) & 0x3f);
    out_buf[ 3] = int_to_itoa64 ((digest_buf[0] >> 18) & 0x3f);

    out_buf[ 4] = int_to_itoa64 ((digest_buf[1] >>  0) & 0x3f);
    out_buf[ 5] = int_to_itoa64 ((digest_buf[1] >>  6) & 0x3f);
    out_buf[ 6] = int_to_itoa64 ((digest_buf[1] >> 12) & 0x3f);
    out_buf[ 7] = int_to_itoa64 ((digest_buf[1] >> 18) & 0x3f);

    out_buf[ 8] = int_to_itoa64 ((digest_buf[2] >>  0) & 0x3f);
    out_buf[ 9] = int_to_itoa64 ((digest_buf[2] >>  6) & 0x3f);
    out_buf[10] = int_to_itoa64 ((digest_buf[2] >> 12) & 0x3f);
    out_buf[11] = int_to_itoa64 ((digest_buf[2] >> 18) & 0x3f);

    out_buf[12] = int_to_itoa64 ((digest_buf[3] >>  0) & 0x3f);
    out_buf[13] = int_to_itoa64 ((digest_buf[3] >>  6) & 0x3f);
    out_buf[14] = int_to_itoa64 ((digest_buf[3] >> 12) & 0x3f);
    out_buf[15] = int_to_itoa64 ((digest_buf[3] >> 18) & 0x3f);

    out_buf[16] = 0;
  }
  else if (hash_mode == 2500)
  {
    wpa_t *wpas = (wpa_t *) esalts_buf;

    wpa_t *wpa = &wpas[digest_cur];

    char *essid = (char *) wpa->essid;

    int tmp_len = 0;

    if (need_hexify (wpa->essid, wpa->essid_len, hashconfig->separator, 0) == true)
    {
      tmp_buf[tmp_len++] = '$';
      tmp_buf[tmp_len++] = 'H';
      tmp_buf[tmp_len++] = 'E';
      tmp_buf[tmp_len++] = 'X';
      tmp_buf[tmp_len++] = '[';

      exec_hexify (wpa->essid, wpa->essid_len, (u8 *) tmp_buf + tmp_len);

      tmp_len += wpa->essid_len * 2;

      tmp_buf[tmp_len++] = ']';

      essid = tmp_buf;
    }

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s",
      wpa->hash[0],
      wpa->hash[1],
      wpa->hash[2],
      wpa->hash[3],
      wpa->orig_mac_ap[0],
      wpa->orig_mac_ap[1],
      wpa->orig_mac_ap[2],
      wpa->orig_mac_ap[3],
      wpa->orig_mac_ap[4],
      wpa->orig_mac_ap[5],
      wpa->orig_mac_sta[0],
      wpa->orig_mac_sta[1],
      wpa->orig_mac_sta[2],
      wpa->orig_mac_sta[3],
      wpa->orig_mac_sta[4],
      wpa->orig_mac_sta[5],
      essid);
  }
  else if (hash_mode == 4400)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if (hash_mode == 4700)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 4800)
  {
    u8 chap_id_byte = (u8) salt.salt_buf[4];

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x:%08x%08x%08x%08x:%02x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      chap_id_byte);
  }
  else if (hash_mode == 4900)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 5100)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x",
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 5200)
  {
    snprintf (out_buf, out_len - 1, "%s", hashfile);
  }
  else if (hash_mode == 5300)
  {
    ikepsk_t *ikepsks = (ikepsk_t *) esalts_buf;

    ikepsk_t *ikepsk  = &ikepsks[digest_cur];

    size_t buf_len = out_len - 1;

    // msg_buf

    u32 ikepsk_msg_len = ikepsk->msg_len / 4;

    for (u32 i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    u32 ikepsk_nr_len = ikepsk->nr_len / 4;

    for (u32 i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (u32 i = 0; i < 4; i++)
    {
      if (i == 0)
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5400)
  {
    ikepsk_t *ikepsks = (ikepsk_t *) esalts_buf;

    ikepsk_t *ikepsk  = &ikepsks[digest_cur];

    size_t buf_len = out_len - 1;

    // msg_buf

    u32 ikepsk_msg_len = ikepsk->msg_len / 4;

    for (u32 i = 0; i < ikepsk_msg_len; i++)
    {
      if ((i == 32) || (i == 64) || (i == 66) || (i == 68) || (i == 108))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->msg_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // nr_buf

    u32 ikepsk_nr_len = ikepsk->nr_len / 4;

    for (u32 i = 0; i < ikepsk_nr_len; i++)
    {
      if ((i == 0) || (i == 5))
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", byte_swap_32 (ikepsk->nr_buf[i]));

      buf_len -= 8;
      out_buf += 8;
    }

    // digest_buf

    for (u32 i = 0; i < 5; i++)
    {
      if (i == 0)
      {
        snprintf (out_buf, buf_len, ":");

        buf_len--;
        out_buf++;
      }

      snprintf (out_buf, buf_len, "%08x", digest_buf[i]);

      buf_len -= 8;
      out_buf += 8;
    }
  }
  else if (hash_mode == 5500)
  {
    netntlm_t *netntlms = (netntlm_t *) esalts_buf;

    netntlm_t *netntlm = &netntlms[digest_cur];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (u32 i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (u32 i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (u32 i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (srvchall_buf + j, "%02x", ptr[i]);
    }

    for (u32 i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf (out_buf, out_len - 1, "%s::%s:%s:%08x%08x%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      byte_swap_32 (salt.salt_buf_pc[0]),
      byte_swap_32 (salt.salt_buf_pc[1]),
      clichall_buf);
  }
  else if (hash_mode == 5600)
  {
    netntlm_t *netntlms = (netntlm_t *) esalts_buf;

    netntlm_t *netntlm = &netntlms[digest_cur];

    char user_buf[64] = { 0 };
    char domain_buf[64] = { 0 };
    char srvchall_buf[1024] = { 0 };
    char clichall_buf[1024] = { 0 };

    for (u32 i = 0, j = 0; j < netntlm->user_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      user_buf[i] = ptr[j];
    }

    for (u32 i = 0, j = 0; j < netntlm->domain_len; i += 1, j += 2)
    {
      char *ptr = (char *) netntlm->userdomain_buf;

      domain_buf[i] = ptr[netntlm->user_len + j];
    }

    for (u32 i = 0, j = 0; i < netntlm->srvchall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (srvchall_buf + j, "%02x", ptr[i]);
    }

    for (u32 i = 0, j = 0; i < netntlm->clichall_len; i += 1, j += 2)
    {
      u8 *ptr = (u8 *) netntlm->chall_buf;

      sprintf (clichall_buf + j, "%02x", ptr[netntlm->srvchall_len + i]);
    }

    snprintf (out_buf, out_len - 1, "%s::%s:%s:%08x%08x%08x%08x:%s",
      user_buf,
      domain_buf,
      srvchall_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      clichall_buf);
  }
  else if (hash_mode == 5700)
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

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

    ptr_plain[43] = 0;

    snprintf (out_buf, out_len - 1, "%s", ptr_plain);
  }
  else if (hash_mode == 5800)
  {
    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if ((hash_mode >= 6200) && (hash_mode <= 6299))
  {
    snprintf (out_buf, out_len - 1, "%s", hashfile);
  }
  else if (hash_mode == 6300)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);

    md5crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, out_len - 1, "{smd5}%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6400)
  {
    sha256aix_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, out_len - 1, "{ssha256}%02u$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6500)
  {
    sha512aix_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    snprintf (out_buf, out_len - 1, "{ssha512}%02u$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6600)
  {
    agilekey_t *agilekeys = (agilekey_t *) esalts_buf;

    agilekey_t *agilekey = &agilekeys[digest_cur];

    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);

    u32 off = snprintf (out_buf, out_len - 1, "%u:%08x%08x:", salt.salt_iter + 1, salt.salt_buf[0], salt.salt_buf[1]);

    for (u32 i = 0, j = off; i < 1040; i++, j += 2)
    {
      snprintf (out_buf + j, out_len - 1 - j, "%02x", agilekey->cipher[i]);
    }
  }
  else if (hash_mode == 6700)
  {
    sha1aix_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    snprintf (out_buf, out_len - 1, "{ssha1}%02u$%s$%s", salt.salt_sign[0], (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 6800)
  {
    snprintf (out_buf, out_len - 1, "%s", (char *) salt.salt_buf);
  }
  else if (hash_mode == 7000)
  {
    // salt

    memcpy (tmp_buf, salt.salt_buf, 12);

    // digest

    memcpy (tmp_buf + 12, digest_buf, 20);

    // base64 encode (salt + SHA1)

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 12 + 20, (u8 *) ptr_plain);

    ptr_plain[44] = 0;

    snprintf (out_buf, out_len - 1, "%s%s",
      SIGNATURE_FORTIGATE,
      ptr_plain);
  }
  else if (hash_mode == 7100)
  {
    u32 *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *) esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512  = &pbkdf2_sha512s[digest_cur];

    u32 esalt[8] = { 0 };

    esalt[0] = byte_swap_32 (pbkdf2_sha512->salt_buf[0]);
    esalt[1] = byte_swap_32 (pbkdf2_sha512->salt_buf[1]);
    esalt[2] = byte_swap_32 (pbkdf2_sha512->salt_buf[2]);
    esalt[3] = byte_swap_32 (pbkdf2_sha512->salt_buf[3]);
    esalt[4] = byte_swap_32 (pbkdf2_sha512->salt_buf[4]);
    esalt[5] = byte_swap_32 (pbkdf2_sha512->salt_buf[5]);
    esalt[6] = byte_swap_32 (pbkdf2_sha512->salt_buf[6]);
    esalt[7] = byte_swap_32 (pbkdf2_sha512->salt_buf[7]);

    snprintf (out_buf, out_len - 1, "%s%u$%08x%08x%08x%08x%08x%08x%08x%08x$%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_SHA512OSX,
      salt.salt_iter + 1,
      esalt[ 0], esalt[ 1],
      esalt[ 2], esalt[ 3],
      esalt[ 4], esalt[ 5],
      esalt[ 6], esalt[ 7],
      ptr  [ 1], ptr  [ 0],
      ptr  [ 3], ptr  [ 2],
      ptr  [ 5], ptr  [ 4],
      ptr  [ 7], ptr  [ 6],
      ptr  [ 9], ptr  [ 8],
      ptr  [11], ptr  [10],
      ptr  [13], ptr  [12],
      ptr  [15], ptr  [14]);
  }
  else if (hash_mode == 7200)
  {
    u32 *ptr = digest_buf;

    pbkdf2_sha512_t *pbkdf2_sha512s = (pbkdf2_sha512_t *) esalts_buf;

    pbkdf2_sha512_t *pbkdf2_sha512  = &pbkdf2_sha512s[digest_cur];

    u32 len_used = 0;

    snprintf (out_buf + len_used, out_len - 1 - len_used, "%s%u.", SIGNATURE_SHA512GRUB, salt.salt_iter + 1);

    len_used = strlen (out_buf);

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha512->salt_buf;

    for (u32 i = 0; i < salt.salt_len; i++, len_used += 2)
    {
      snprintf (out_buf + len_used, out_len - 1 - len_used, "%02x", salt_buf_ptr[i]);
    }

    snprintf (out_buf + len_used, out_len - 1 - len_used, ".%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      ptr[ 1], ptr[ 0],
      ptr[ 3], ptr[ 2],
      ptr[ 5], ptr[ 4],
      ptr[ 7], ptr[ 6],
      ptr[ 9], ptr[ 8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 7300)
  {
    rakp_t *rakps = (rakp_t *) esalts_buf;

    rakp_t *rakp = &rakps[digest_cur];

    u32 i;
    u32 j;

    u8 *ptr = (u8 *) rakp->salt_buf;

    for (i = 0, j = 0; i < rakp->salt_len; i += 1, j += 2)
    {
      snprintf (out_buf + j, out_len - 1 - j, "%02x", ptr[i ^ 3]); // the ^ 3 index converts LE -> BE
    }

    snprintf (out_buf + j, out_len - 1 - j, ":%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7400)
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

    sha256crypt_encode ((unsigned char *) digest_buf, (unsigned char *) ptr_plain);

    if (salt.salt_iter == ROUNDS_SHA256CRYPT)
    {
      snprintf (out_buf, out_len - 1, "$5$%s$%s", (char *) salt.salt_buf, (char *) ptr_plain);
    }
    else
    {
      snprintf (out_buf, out_len - 1, "$5$rounds=%u$%s$%s", salt.salt_iter, (char *) salt.salt_buf, (char *) ptr_plain);
    }
  }
  else if (hash_mode == 7500)
  {
    krb5pa_t *krb5pas = (krb5pa_t *) esalts_buf;

    krb5pa_t *krb5pa = &krb5pas[digest_cur];

    u8 *ptr_timestamp = (u8 *) krb5pa->timestamp;
    u8 *ptr_checksum  = (u8 *) krb5pa->checksum;

    char data[128] = { 0 };

    char *ptr_data = data;

    for (u32 i = 0; i < 36; i++, ptr_data += 2)
    {
      sprintf (ptr_data, "%02x", ptr_timestamp[i]);
    }

    for (u32 i = 0; i < 16; i++, ptr_data += 2)
    {
      sprintf (ptr_data, "%02x", ptr_checksum[i]);
    }

    *ptr_data = 0;

    snprintf (out_buf, out_len - 1, "%s$%s$%s$%s$%s",
      SIGNATURE_KRB5PA,
      (char *) krb5pa->user,
      (char *) krb5pa->realm,
      (char *) krb5pa->salt,
      data);
  }
  else if (hash_mode == 7700)
  {
    snprintf (out_buf, out_len - 1, "%s$%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1]);
  }
  else if (hash_mode == 7800)
  {
    snprintf (out_buf, out_len - 1, "%s$%08X%08X%08X%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7900)
  {
    drupal7_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    // ugly hack start

    char *tmp = (char *) salt.salt_buf_pc;

    ptr_plain[42] = tmp[0];

    // ugly hack end

    ptr_plain[43] = 0;

    snprintf (out_buf, out_len - 1, "%s%s%s", (char *) salt.salt_sign, (char *) salt.salt_buf, (char *) ptr_plain);
  }
  else if (hash_mode == 8000)
  {
    snprintf (out_buf, out_len - 1, "0xc007%s%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 8100)
  {
    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);

    snprintf (out_buf, out_len - 1, "1%s%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 8200)
  {
    cloudkey_t *cloudkeys = (cloudkey_t *) esalts_buf;

    cloudkey_t *cloudkey = &cloudkeys[digest_cur];

    char data_buf[4096] = { 0 };

    for (int i = 0, j = 0; i < 512; i += 1, j += 8)
    {
      sprintf (data_buf + j, "%08x", cloudkey->data_buf[i]);
    }

    data_buf[cloudkey->data_len * 2] = 0;

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);
    salt.salt_buf[2] = byte_swap_32 (salt.salt_buf[2]);
    salt.salt_buf[3] = byte_swap_32 (salt.salt_buf[3]);

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x:%08x%08x%08x%08x:%u:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_iter + 1,
      data_buf);
  }
  else if (hash_mode == 8300)
  {
    char digest_buf_c[34] = { 0 };

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    base32_encode (int_to_itoa32, (const u8 *) digest_buf, 20, (u8 *) digest_buf_c);

    digest_buf_c[32] = 0;

    // domain

    const u32 salt_pc_len = salt.salt_buf_pc[7]; // what a hack

    char domain_buf_c[33] = { 0 };

    memcpy (domain_buf_c, (char *) salt.salt_buf_pc, salt_pc_len);

    for (u32 i = 0; i < salt_pc_len; i++)
    {
      const char next = domain_buf_c[i];

      domain_buf_c[i] = '.';

      i += next;
    }

    domain_buf_c[salt_pc_len] = 0;

    // final

    snprintf (out_buf, out_len - 1, "%s:%s:%s:%u", digest_buf_c, domain_buf_c, (char *) salt.salt_buf, salt.salt_iter);
  }
  else if (hash_mode == 8500)
  {
    snprintf (out_buf, out_len - 1, "%s*%s*%08X%08X", SIGNATURE_RACF, (char *) salt.salt_buf, digest_buf[0], digest_buf[1]);
  }
  else if (hash_mode == 2612)
  {
    snprintf (out_buf, out_len - 1, "%s%s$%08x%08x%08x%08x",
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

    snprintf (out_buf, out_len - 1, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_MEDIAWIKI_B,
      salt_ptr,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 8800)
  {
    androidfde_t *androidfdes = (androidfde_t *) esalts_buf;

    androidfde_t *androidfde = &androidfdes[digest_cur];

    char tmp[3073] = { 0 };

    for (u32 i = 0, j = 0; i < 384; i += 1, j += 8)
    {
      sprintf (tmp + j, "%08x", androidfde->data[i]);
    }

    tmp[3072] = 0;

    snprintf (out_buf, out_len - 1, "%s16$%08x%08x%08x%08x$16$%08x%08x%08x%08x$%s",
      SIGNATURE_ANDROIDFDE,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      tmp);
  }
  else if (hash_mode == 8900)
  {
    u32 N = salt.scrypt_N;
    u32 r = salt.scrypt_r;
    u32 p = salt.scrypt_p;

    char base64_salt[32] = { 0 };

    base64_encode (int_to_base64, (const u8 *) salt.salt_buf, salt.salt_len, (u8 *) base64_salt);

    memset (tmp_buf, 0, 46);

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_base64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    snprintf (out_buf, out_len - 1, "%s:%u:%u:%u:%s:%s",
      SIGNATURE_SCRYPT,
      N,
      r,
      p,
      base64_salt,
      tmp_buf);
  }
  else if (hash_mode == 9000)
  {
    snprintf (out_buf, out_len - 1, "%s", hashfile);
  }
  else if (hash_mode == 9200)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[digest_cur];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    tmp_buf[43] = 0; // cut it here

    // output

    snprintf (out_buf, out_len - 1, "%s%s$%s", SIGNATURE_CISCO8, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9300)
  {
    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    tmp_buf[43] = 0; // cut it here

    unsigned char *salt_buf_ptr = (unsigned char *) salt.salt_buf;

    snprintf (out_buf, out_len - 1, "%s%s$%s", SIGNATURE_CISCO9, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9400)
  {
    office2007_t *office2007s = (office2007_t *) esalts_buf;

    office2007_t *office2007 = &office2007s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%d*%d*%u*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2007,
      2007,
      20,
      office2007->keySize,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2007->encryptedVerifier[0],
      office2007->encryptedVerifier[1],
      office2007->encryptedVerifier[2],
      office2007->encryptedVerifier[3],
      office2007->encryptedVerifierHash[0],
      office2007->encryptedVerifierHash[1],
      office2007->encryptedVerifierHash[2],
      office2007->encryptedVerifierHash[3],
      office2007->encryptedVerifierHash[4]);
  }
  else if (hash_mode == 9500)
  {
    office2010_t *office2010s = (office2010_t *) esalts_buf;

    office2010_t *office2010 = &office2010s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%d*%d*%d*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2010,
      2010,
      100000,
      128,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2010->encryptedVerifier[0],
      office2010->encryptedVerifier[1],
      office2010->encryptedVerifier[2],
      office2010->encryptedVerifier[3],
      office2010->encryptedVerifierHash[0],
      office2010->encryptedVerifierHash[1],
      office2010->encryptedVerifierHash[2],
      office2010->encryptedVerifierHash[3],
      office2010->encryptedVerifierHash[4],
      office2010->encryptedVerifierHash[5],
      office2010->encryptedVerifierHash[6],
      office2010->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9600)
  {
    office2013_t *office2013s = (office2013_t *) esalts_buf;

    office2013_t *office2013 = &office2013s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%d*%d*%d*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2013,
      2013,
      100000,
      256,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2013->encryptedVerifier[0],
      office2013->encryptedVerifier[1],
      office2013->encryptedVerifier[2],
      office2013->encryptedVerifier[3],
      office2013->encryptedVerifierHash[0],
      office2013->encryptedVerifierHash[1],
      office2013->encryptedVerifierHash[2],
      office2013->encryptedVerifierHash[3],
      office2013->encryptedVerifierHash[4],
      office2013->encryptedVerifierHash[5],
      office2013->encryptedVerifierHash[6],
      office2013->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 9700)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9710)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]));
  }
  else if (hash_mode == 9720)
  {
    oldoffice01_t *oldoffice01s = (oldoffice01_t *) esalts_buf;

    oldoffice01_t *oldoffice01 = &oldoffice01s[digest_cur];

    u8 *rc4key = (u8 *) oldoffice01->rc4key;

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice01->version == 0) ? SIGNATURE_OLDOFFICE0 : SIGNATURE_OLDOFFICE1,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (oldoffice01->encryptedVerifier[0]),
      byte_swap_32 (oldoffice01->encryptedVerifier[1]),
      byte_swap_32 (oldoffice01->encryptedVerifier[2]),
      byte_swap_32 (oldoffice01->encryptedVerifier[3]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice01->encryptedVerifierHash[3]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 9800)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9810)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]));
  }
  else if (hash_mode == 9820)
  {
    oldoffice34_t *oldoffice34s = (oldoffice34_t *) esalts_buf;

    oldoffice34_t *oldoffice34 = &oldoffice34s[digest_cur];

    u8 *rc4key = (u8 *) oldoffice34->rc4key;

    snprintf (out_buf, out_len - 1, "%s*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
      (oldoffice34->version == 3) ? SIGNATURE_OLDOFFICE3 : SIGNATURE_OLDOFFICE4,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      byte_swap_32 (oldoffice34->encryptedVerifier[0]),
      byte_swap_32 (oldoffice34->encryptedVerifier[1]),
      byte_swap_32 (oldoffice34->encryptedVerifier[2]),
      byte_swap_32 (oldoffice34->encryptedVerifier[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[0]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[1]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[2]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[3]),
      byte_swap_32 (oldoffice34->encryptedVerifierHash[4]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]);
  }
  else if (hash_mode == 10000)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[digest_cur];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_base64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    // output

    snprintf (out_buf, out_len - 1, "%s%u$%s$%s", SIGNATURE_DJANGOPBKDF2, salt.salt_iter + 1, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 10100)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x:%d:%d:%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      2,
      4,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]));
  }
  else if (hash_mode == 10200)
  {
    cram_md5_t *cram_md5s = (cram_md5_t *) esalts_buf;

    cram_md5_t *cram_md5 = &cram_md5s[digest_cur];

    // challenge

    char challenge[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) salt.salt_buf, salt.salt_len, (u8 *) challenge);

    // response

    int tmp_len = snprintf (tmp_buf, sizeof (tmp_buf) - 1, "%s %08x%08x%08x%08x",
      (char *) cram_md5->user,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);

    char response[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) response);

    snprintf (out_buf, out_len - 1, "%s%s$%s", SIGNATURE_CRAM_MD5, challenge, response);
  }
  else if (hash_mode == 10300)
  {
    memcpy (tmp_buf +  0, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    u32 tmp_len = 20 + salt.salt_len;

    // base64 encode it

    char base64_encoded[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) base64_encoded);

    snprintf (out_buf, out_len - 1, "%s%u}%s", SIGNATURE_SAPH_SHA1, salt.salt_iter + 1, base64_encoded);
  }
  else if (hash_mode == 10400)
  {
    pdf_t *pdfs = (pdf_t *) esalts_buf;

    pdf_t *pdf = &pdfs[digest_cur];

    snprintf (out_buf, out_len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7])
    );
  }
  else if (hash_mode == 10410)
  {
    pdf_t *pdfs = (pdf_t *) esalts_buf;

    pdf_t *pdf = &pdfs[digest_cur];

    snprintf (out_buf, out_len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7])
    );
  }
  else if (hash_mode == 10420)
  {
    pdf_t *pdfs = (pdf_t *) esalts_buf;

    pdf_t *pdf = &pdfs[digest_cur];

    u8 *rc4key = (u8 *) pdf->rc4key;

    snprintf (out_buf, out_len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x",

      pdf->V,
      pdf->R,
      40,
      pdf->P,
      pdf->enc_md,
      pdf->id_len,
      byte_swap_32 (pdf->id_buf[0]),
      byte_swap_32 (pdf->id_buf[1]),
      byte_swap_32 (pdf->id_buf[2]),
      byte_swap_32 (pdf->id_buf[3]),
      pdf->u_len,
      byte_swap_32 (pdf->u_buf[0]),
      byte_swap_32 (pdf->u_buf[1]),
      byte_swap_32 (pdf->u_buf[2]),
      byte_swap_32 (pdf->u_buf[3]),
      byte_swap_32 (pdf->u_buf[4]),
      byte_swap_32 (pdf->u_buf[5]),
      byte_swap_32 (pdf->u_buf[6]),
      byte_swap_32 (pdf->u_buf[7]),
      pdf->o_len,
      byte_swap_32 (pdf->o_buf[0]),
      byte_swap_32 (pdf->o_buf[1]),
      byte_swap_32 (pdf->o_buf[2]),
      byte_swap_32 (pdf->o_buf[3]),
      byte_swap_32 (pdf->o_buf[4]),
      byte_swap_32 (pdf->o_buf[5]),
      byte_swap_32 (pdf->o_buf[6]),
      byte_swap_32 (pdf->o_buf[7]),
      rc4key[0],
      rc4key[1],
      rc4key[2],
      rc4key[3],
      rc4key[4]
    );
  }
  else if (hash_mode == 10500)
  {
    pdf_t *pdfs = (pdf_t *) esalts_buf;

    pdf_t *pdf = &pdfs[digest_cur];

    if (pdf->id_len == 32)
    {
      snprintf (out_buf, out_len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32 (pdf->id_buf[0]),
        byte_swap_32 (pdf->id_buf[1]),
        byte_swap_32 (pdf->id_buf[2]),
        byte_swap_32 (pdf->id_buf[3]),
        byte_swap_32 (pdf->id_buf[4]),
        byte_swap_32 (pdf->id_buf[5]),
        byte_swap_32 (pdf->id_buf[6]),
        byte_swap_32 (pdf->id_buf[7]),
        pdf->u_len,
        byte_swap_32 (pdf->u_buf[0]),
        byte_swap_32 (pdf->u_buf[1]),
        byte_swap_32 (pdf->u_buf[2]),
        byte_swap_32 (pdf->u_buf[3]),
        byte_swap_32 (pdf->u_buf[4]),
        byte_swap_32 (pdf->u_buf[5]),
        byte_swap_32 (pdf->u_buf[6]),
        byte_swap_32 (pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32 (pdf->o_buf[0]),
        byte_swap_32 (pdf->o_buf[1]),
        byte_swap_32 (pdf->o_buf[2]),
        byte_swap_32 (pdf->o_buf[3]),
        byte_swap_32 (pdf->o_buf[4]),
        byte_swap_32 (pdf->o_buf[5]),
        byte_swap_32 (pdf->o_buf[6]),
        byte_swap_32 (pdf->o_buf[7])
      );
    }
    else
    {
      snprintf (out_buf, out_len - 1, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",

        pdf->V,
        pdf->R,
        128,
        pdf->P,
        pdf->enc_md,
        pdf->id_len,
        byte_swap_32 (pdf->id_buf[0]),
        byte_swap_32 (pdf->id_buf[1]),
        byte_swap_32 (pdf->id_buf[2]),
        byte_swap_32 (pdf->id_buf[3]),
        pdf->u_len,
        byte_swap_32 (pdf->u_buf[0]),
        byte_swap_32 (pdf->u_buf[1]),
        byte_swap_32 (pdf->u_buf[2]),
        byte_swap_32 (pdf->u_buf[3]),
        byte_swap_32 (pdf->u_buf[4]),
        byte_swap_32 (pdf->u_buf[5]),
        byte_swap_32 (pdf->u_buf[6]),
        byte_swap_32 (pdf->u_buf[7]),
        pdf->o_len,
        byte_swap_32 (pdf->o_buf[0]),
        byte_swap_32 (pdf->o_buf[1]),
        byte_swap_32 (pdf->o_buf[2]),
        byte_swap_32 (pdf->o_buf[3]),
        byte_swap_32 (pdf->o_buf[4]),
        byte_swap_32 (pdf->o_buf[5]),
        byte_swap_32 (pdf->o_buf[6]),
        byte_swap_32 (pdf->o_buf[7])
      );
    }
  }
  else if (hash_mode == 10600)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 10700)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 10900)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 11100)
  {
    u32 salt_challenge = salt.salt_buf[0];

    salt_challenge = byte_swap_32 (salt_challenge);

    unsigned char *user_name = (unsigned char *) (salt.salt_buf + 1);

    snprintf (out_buf, out_len - 1, "%s%s*%08x*%08x%08x%08x%08x",
        SIGNATURE_POSTGRESQL_AUTH,
        user_name,
        salt_challenge,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
  }
  else if (hash_mode == 11200)
  {
    snprintf (out_buf, out_len - 1, "%s%s*%08x%08x%08x%08x%08x",
        SIGNATURE_MYSQL_AUTH,
        (unsigned char *) salt.salt_buf,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
  }
  else if (hash_mode == 11300)
  {
    bitcoin_wallet_t *bitcoin_wallets = (bitcoin_wallet_t *) esalts_buf;

    bitcoin_wallet_t *bitcoin_wallet = &bitcoin_wallets[digest_cur];

    const u32 cry_master_len = bitcoin_wallet->cry_master_len;
    const u32 ckey_len       = bitcoin_wallet->ckey_len;
    const u32 public_key_len = bitcoin_wallet->public_key_len;

    char *cry_master_buf = (char *) hcmalloc ((cry_master_len * 2) + 1);
    char *ckey_buf       = (char *) hcmalloc ((ckey_len * 2)       + 1);
    char *public_key_buf = (char *) hcmalloc ((public_key_len * 2) + 1);

    for (u32 i = 0, j = 0; i < cry_master_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->cry_master_buf;

      sprintf (cry_master_buf + j, "%02x", ptr[i]);
    }

    for (u32 i = 0, j = 0; i < ckey_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->ckey_buf;

      sprintf (ckey_buf + j, "%02x", ptr[i]);
    }

    for (u32 i = 0, j = 0; i < public_key_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) bitcoin_wallet->public_key_buf;

      sprintf (public_key_buf + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, out_len - 1, "%s%u$%s$%u$%s$%u$%u$%s$%u$%s",
      SIGNATURE_BITCOIN_WALLET,
      cry_master_len * 2,
      cry_master_buf,
      salt.salt_len,
      (unsigned char *) salt.salt_buf,
      salt.salt_iter + 1,
      ckey_len * 2,
      ckey_buf,
      public_key_len * 2,
      public_key_buf
    );

    hcfree (cry_master_buf);
    hcfree (ckey_buf);
    hcfree (public_key_buf);
  }
  else if (hash_mode == 11400)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 11600)
  {
    seven_zip_hook_salt_t *seven_zips = (seven_zip_hook_salt_t *) hashes->hook_salts_buf;

    seven_zip_hook_salt_t *seven_zip  = &seven_zips[digest_cur];

    const u32 data_len = seven_zip->data_len;

    char *data_buf = (char *) hcmalloc ((data_len * 2) + 1);

    for (u32 i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) seven_zip->data_buf;

      snprintf (data_buf + j, (data_len * 2) + 1 - j, "%02x", ptr[i]);
    }

    u32 salt_iter = salt.salt_iter;

    u32 iv[4];

    iv[0] = byte_swap_32 (seven_zip->iv_buf[0]);
    iv[1] = byte_swap_32 (seven_zip->iv_buf[1]);
    iv[2] = byte_swap_32 (seven_zip->iv_buf[2]);
    iv[3] = byte_swap_32 (seven_zip->iv_buf[3]);

    u32 iv_len = seven_zip->iv_len;

    u32 cost = 0; // the log2 () of salt_iter

    while (salt_iter >>= 1)
    {
      cost++;
    }

    snprintf (out_buf, out_len - 1, "%s%d$%u$%d$%s$%u$%08x%08x%08x%08x$%u$%u$%u$%s",
      SIGNATURE_SEVEN_ZIP,
      salt.salt_sign[0],
      cost,
      seven_zip->salt_len,
      (char *) seven_zip->salt_buf,
      iv_len,
      iv[0],
      iv[1],
      iv[2],
      iv[3],
      seven_zip->crc,
      seven_zip->data_len,
      seven_zip->unpack_size,
      data_buf);

    if (seven_zip->data_type > 0)
    {
      u32 bytes_written = strlen (out_buf);

      snprintf (out_buf + bytes_written, out_len - bytes_written - 1, "$%i$", seven_zip->crc_len);

      bytes_written = strlen (out_buf);

      const u8 *ptr = (const u8 *) seven_zip->coder_attributes;

      for (u32 i = 0, j = 0; i < seven_zip->coder_attributes_len; i += 1, j += 2)
      {
        snprintf (out_buf + bytes_written, out_len - bytes_written - 1, "%02x", ptr[i]);

        bytes_written += 2;
      }
    }

    hcfree (data_buf);
  }
  else if (hash_mode == 11700)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 11800)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
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
  else if (hash_mode == 11900)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12000)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12001)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12100)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12200)
  {
    u32 *ptr_digest = digest_buf;

    snprintf (out_buf, out_len - 1, "%s0$1$%08x%08x$%08x%08x",
      SIGNATURE_ECRYPTFS,
      salt.salt_buf[0],
      salt.salt_buf[1],
      ptr_digest[0],
      ptr_digest[1]);
  }
  else if (hash_mode == 12300)
  {
    u32 *ptr_digest = digest_buf;

    snprintf (out_buf, out_len - 1, "%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
      ptr_digest[ 0], ptr_digest[ 1],
      ptr_digest[ 2], ptr_digest[ 3],
      ptr_digest[ 4], ptr_digest[ 5],
      ptr_digest[ 6], ptr_digest[ 7],
      ptr_digest[ 8], ptr_digest[ 9],
      ptr_digest[10], ptr_digest[11],
      ptr_digest[12], ptr_digest[13],
      ptr_digest[14], ptr_digest[15],
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3]);
  }
  else if (hash_mode == 12400)
  {
    // encode iteration count

    u8 salt_iter[5] = { 0 };

    salt_iter[0] = int_to_itoa64 ((salt.salt_iter      ) & 0x3f);
    salt_iter[1] = int_to_itoa64 ((salt.salt_iter >>  6) & 0x3f);
    salt_iter[2] = int_to_itoa64 ((salt.salt_iter >> 12) & 0x3f);
    salt_iter[3] = int_to_itoa64 ((salt.salt_iter >> 18) & 0x3f);
    salt_iter[4] = 0;

    // encode salt

    ptr_salt[0] = int_to_itoa64 ((salt.salt_buf[0]      ) & 0x3f);
    ptr_salt[1] = int_to_itoa64 ((salt.salt_buf[0] >>  6) & 0x3f);
    ptr_salt[2] = int_to_itoa64 ((salt.salt_buf[0] >> 12) & 0x3f);
    ptr_salt[3] = int_to_itoa64 ((salt.salt_buf[0] >> 18) & 0x3f);
    ptr_salt[4] = 0;

    // encode digest

    memset (tmp_buf, 0, sizeof (tmp_buf));

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);

    memcpy (tmp_buf, digest_buf, 8);

    base64_encode (int_to_itoa64, (const u8 *) tmp_buf, 8, (u8 *) ptr_plain);

    ptr_plain[11] = 0;

    // fill the resulting buffer

    snprintf (out_buf, out_len - 1, "_%s%s%s", salt_iter, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 12500)
  {
    snprintf (out_buf, out_len - 1, "%s*0*%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_RAR3,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5]);
  }
  else if (hash_mode == 12600)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0] + salt.salt_buf_pc[0],
      digest_buf[1] + salt.salt_buf_pc[1],
      digest_buf[2] + salt.salt_buf_pc[2],
      digest_buf[3] + salt.salt_buf_pc[3],
      digest_buf[4] + salt.salt_buf_pc[4],
      digest_buf[5] + salt.salt_buf_pc[5],
      digest_buf[6] + salt.salt_buf_pc[6],
      digest_buf[7] + salt.salt_buf_pc[7]);
  }
  else if (hash_mode == 12700)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 12800)
  {
    const u8 *ptr = (const u8 *) salt.salt_buf;

    snprintf (out_buf, out_len - 1, "%s,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%u,%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_MS_DRSR,
      ptr[0],
      ptr[1],
      ptr[2],
      ptr[3],
      ptr[4],
      ptr[5],
      ptr[6],
      ptr[7],
      ptr[8],
      ptr[9],
      salt.salt_iter + 1,
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7])
    );
  }
  else if (hash_mode == 12900)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      salt.salt_buf[ 4],
      salt.salt_buf[ 5],
      salt.salt_buf[ 6],
      salt.salt_buf[ 7],
      salt.salt_buf[ 8],
      salt.salt_buf[ 9],
      salt.salt_buf[10],
      salt.salt_buf[11],
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7]),
      salt.salt_buf[ 0],
      salt.salt_buf[ 1],
      salt.salt_buf[ 2],
      salt.salt_buf[ 3]
    );
  }
  else if (hash_mode == 13000)
  {
    rar5_t *rar5s = (rar5_t *) esalts_buf;

    rar5_t *rar5 = &rar5s[digest_cur];

    snprintf (out_buf, out_len - 1, "$rar5$16$%08x%08x%08x%08x$%u$%08x%08x%08x%08x$8$%08x%08x",
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_sign[0],
      rar5->iv[0],
      rar5->iv[1],
      rar5->iv[2],
      rar5->iv[3],
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1])
    );
  }
  else if (hash_mode == 13100)
  {
    krb5tgs_t *krb5tgss = (krb5tgs_t *) esalts_buf;

    krb5tgs_t *krb5tgs = &krb5tgss[digest_cur];

    u8 *ptr_checksum  = (u8 *) krb5tgs->checksum;
    u8 *ptr_edata2 = (u8 *) krb5tgs->edata2;

    char data[2560 * 4 * 2] = { 0 };

    char *ptr_data = data;

    for (u32 i = 0; i < 16; i++, ptr_data += 2)
      sprintf (ptr_data, "%02x", ptr_checksum[i]);

    /* skip '$' */
    ptr_data++;

    for (u32 i = 0; i < krb5tgs->edata2_len; i++, ptr_data += 2)
      sprintf (ptr_data, "%02x", ptr_edata2[i]);

    snprintf (out_buf, out_len - 1, "%s$%s$%s$%s",
      SIGNATURE_KRB5TGS,
      (char *) krb5tgs->account_info,
      data,
      data + 33);
  }
  else if (hash_mode == 13200)
  {
    snprintf (out_buf, out_len - 1, "%s*%u*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT,
      salt.salt_iter,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5],
      salt.salt_buf[6],
      salt.salt_buf[7],
      salt.salt_buf[8],
      salt.salt_buf[9]);
  }
  else if (hash_mode == 13300)
  {
    snprintf (out_buf, out_len - 1, "%s$%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT_SHA1,
              digest_buf[0],
              digest_buf[1],
              digest_buf[2],
              digest_buf[3]);
  }
  else if (hash_mode == 13400)
  {
    keepass_t *keepasss = (keepass_t *) esalts_buf;

    keepass_t *keepass = &keepasss[digest_cur];

    u32 version     = (u32) keepass->version;
    u32 rounds      = salt.salt_iter;
    u32 algorithm   = (u32) keepass->algorithm;
    u32 keyfile_len = (u32) keepass->keyfile_len;

    u32 *ptr_final_random_seed  = (u32 *) keepass->final_random_seed;
    u32 *ptr_transf_random_seed = (u32 *) keepass->transf_random_seed;
    u32 *ptr_enc_iv             = (u32 *) keepass->enc_iv;
    u32 *ptr_contents_hash      = (u32 *) keepass->contents_hash;
    u32 *ptr_keyfile            = (u32 *) keepass->keyfile;

    /* specific to version 2 */
    u32 expected_bytes_len;
    u32 *ptr_expected_bytes;

    u32 final_random_seed_len;
    u32 transf_random_seed_len;
    u32 enc_iv_len;
    u32 contents_hash_len;

    transf_random_seed_len = 8;
    enc_iv_len             = 4;
    contents_hash_len      = 8;
    final_random_seed_len  = 8;

    if (version == 1)
      final_random_seed_len = 4;

    snprintf (out_buf, out_len - 1, "%s*%u*%u*%u",
      SIGNATURE_KEEPASS,
      version,
      rounds,
      algorithm);

    char *ptr_data = out_buf;

    ptr_data += strlen(out_buf);

    *ptr_data = '*';
    ptr_data++;

    for (u32 i = 0; i < final_random_seed_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_final_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (u32 i = 0; i < transf_random_seed_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_transf_random_seed[i]);

    *ptr_data = '*';
    ptr_data++;

    for (u32 i = 0; i < enc_iv_len; i++, ptr_data += 8)
      sprintf (ptr_data, "%08x", ptr_enc_iv[i]);

    *ptr_data = '*';
    ptr_data++;

    if (version == 1)
    {
      u32  contents_len = (u32)   keepass->contents_len;
      u32 *ptr_contents = (u32 *) keepass->contents;

      for (u32 i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents_hash[i]);

      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      char ptr_contents_len[10] = { 0 };

      sprintf ((char*) ptr_contents_len, "%u", contents_len);

      sprintf (ptr_data, "%u", contents_len);

      ptr_data += strlen(ptr_contents_len);

      *ptr_data = '*';
      ptr_data++;

      for (u32 i = 0; i < contents_len / 4; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents[i]);
    }
    else if (version == 2)
    {
      expected_bytes_len = 8;
      ptr_expected_bytes = (u32 *) keepass->expected_bytes;

      for (u32 i = 0; i < expected_bytes_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_expected_bytes[i]);

      *ptr_data = '*';
      ptr_data++;

      for (u32 i = 0; i < contents_hash_len; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_contents_hash[i]);
    }
    if (keyfile_len)
    {
      *ptr_data = '*';
      ptr_data++;

      /* inline flag */
      *ptr_data = '1';
      ptr_data++;

      *ptr_data = '*';
      ptr_data++;

      sprintf (ptr_data, "%u", keyfile_len);

      ptr_data += 2;

      *ptr_data = '*';
      ptr_data++;

      for (u32 i = 0; i < 8; i++, ptr_data += 8)
        sprintf (ptr_data, "%08x", ptr_keyfile[i]);
    }
  }
  else if (hash_mode == 13500)
  {
    pstoken_t *pstokens = (pstoken_t *) esalts_buf;

    pstoken_t *pstoken = &pstokens[digest_cur];

    const u32 salt_len = (pstoken->salt_len > 512) ? 512 : pstoken->salt_len;

    char pstoken_tmp[1024 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) pstoken->salt_buf;

      sprintf (pstoken_tmp + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      pstoken_tmp);
  }
  else if (hash_mode == 13600)
  {
    zip2_t *zip2s = (zip2_t *) esalts_buf;

    zip2_t *zip2 = &zip2s[digest_cur];

    const u32 salt_len = zip2->salt_len;

    char salt_tmp[32 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->salt_buf;

      sprintf (salt_tmp + j, "%02x", ptr[i]);
    }

    const u32 data_len = zip2->data_len;

    char data_tmp[8192 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->data_buf;

      sprintf (data_tmp + j, "%02x", ptr[i]);
    }

    const u32 auth_len = zip2->auth_len;

    char auth_tmp[20 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < auth_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->auth_buf;

      sprintf (auth_tmp + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, out_len - 1, "%s*%u*%u*%u*%s*%x*%u*%s*%s*%s",
      SIGNATURE_ZIP2_START,
      zip2->type,
      zip2->mode,
      zip2->magic,
      salt_tmp,
      zip2->verify_bytes,
      zip2->compress_length,
      data_tmp,
      auth_tmp,
      SIGNATURE_ZIP2_STOP);
  }
  else if ((hash_mode >= 13700) && (hash_mode <= 13799))
  {
    snprintf (out_buf, out_len - 1, "%s", hashfile);
  }
  else if (hash_mode == 13800)
  {
    win8phone_t *esalts = (win8phone_t *) esalts_buf;

    win8phone_t *esalt = &esalts[digest_cur];

    char buf[256 + 1] = { 0 };

    for (int i = 0, j = 0; i < 32; i += 1, j += 8)
    {
      sprintf (buf + j, "%08x", esalt->salt_buf[i]);
    }

    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      buf);
  }
  else if (hash_mode == 14000)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x:%s", digest_buf[0], digest_buf[1], (char *) salt.salt_buf);
  }
  else if (hash_mode == 14100)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x:%s", digest_buf[0], digest_buf[1], (char *) salt.salt_buf);
  }
  else if (hash_mode == 14400)
  {
    snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 14600)
  {
    snprintf (out_buf, out_len - 1, "%s", hashfile);
  }
  else if (hash_mode == 14700)
  {
    // WPKY

    itunes_backup_t *itunes_backups = (itunes_backup_t *) esalts_buf;
    itunes_backup_t *itunes_backup  = &itunes_backups[digest_cur];

    u32 wkpy_u32[10];

    wkpy_u32[0] = byte_swap_32 (itunes_backup->wpky[0]);
    wkpy_u32[1] = byte_swap_32 (itunes_backup->wpky[1]);
    wkpy_u32[2] = byte_swap_32 (itunes_backup->wpky[2]);
    wkpy_u32[3] = byte_swap_32 (itunes_backup->wpky[3]);
    wkpy_u32[4] = byte_swap_32 (itunes_backup->wpky[4]);
    wkpy_u32[5] = byte_swap_32 (itunes_backup->wpky[5]);
    wkpy_u32[6] = byte_swap_32 (itunes_backup->wpky[6]);
    wkpy_u32[7] = byte_swap_32 (itunes_backup->wpky[7]);
    wkpy_u32[8] = byte_swap_32 (itunes_backup->wpky[8]);
    wkpy_u32[9] = byte_swap_32 (itunes_backup->wpky[9]);

    u8 wpky[80 + 1];

    u32_to_hex_lower (wkpy_u32[0], wpky +  0);
    u32_to_hex_lower (wkpy_u32[1], wpky +  8);
    u32_to_hex_lower (wkpy_u32[2], wpky + 16);
    u32_to_hex_lower (wkpy_u32[3], wpky + 24);
    u32_to_hex_lower (wkpy_u32[4], wpky + 32);
    u32_to_hex_lower (wkpy_u32[5], wpky + 40);
    u32_to_hex_lower (wkpy_u32[6], wpky + 48);
    u32_to_hex_lower (wkpy_u32[7], wpky + 56);
    u32_to_hex_lower (wkpy_u32[8], wpky + 64);
    u32_to_hex_lower (wkpy_u32[9], wpky + 72);

    wpky[80] = 0;

    snprintf (out_buf, out_len - 1, "%s*%i*%s*%i*%s**",
      SIGNATURE_ITUNES_BACKUP,
      salt.salt_sign[0],
      wpky,
      salt.salt_iter + 1,
      (char *) salt.salt_buf);
  }
  else if (hash_mode == 14800)
  {
    // WPKY

    itunes_backup_t *itunes_backups = (itunes_backup_t *) esalts_buf;
    itunes_backup_t *itunes_backup  = &itunes_backups[digest_cur];

    u32 wkpy_u32[10];

    wkpy_u32[0] = byte_swap_32 (itunes_backup->wpky[0]);
    wkpy_u32[1] = byte_swap_32 (itunes_backup->wpky[1]);
    wkpy_u32[2] = byte_swap_32 (itunes_backup->wpky[2]);
    wkpy_u32[3] = byte_swap_32 (itunes_backup->wpky[3]);
    wkpy_u32[4] = byte_swap_32 (itunes_backup->wpky[4]);
    wkpy_u32[5] = byte_swap_32 (itunes_backup->wpky[5]);
    wkpy_u32[6] = byte_swap_32 (itunes_backup->wpky[6]);
    wkpy_u32[7] = byte_swap_32 (itunes_backup->wpky[7]);
    wkpy_u32[8] = byte_swap_32 (itunes_backup->wpky[8]);
    wkpy_u32[9] = byte_swap_32 (itunes_backup->wpky[9]);

    u8 wpky[80 + 1];

    u32_to_hex_lower (wkpy_u32[0], wpky +  0);
    u32_to_hex_lower (wkpy_u32[1], wpky +  8);
    u32_to_hex_lower (wkpy_u32[2], wpky + 16);
    u32_to_hex_lower (wkpy_u32[3], wpky + 24);
    u32_to_hex_lower (wkpy_u32[4], wpky + 32);
    u32_to_hex_lower (wkpy_u32[5], wpky + 40);
    u32_to_hex_lower (wkpy_u32[6], wpky + 48);
    u32_to_hex_lower (wkpy_u32[7], wpky + 56);
    u32_to_hex_lower (wkpy_u32[8], wpky + 64);
    u32_to_hex_lower (wkpy_u32[9], wpky + 72);

    wpky[80] = 0;

    // DPSL

    u32 dpsl_u32[5];

    dpsl_u32[0] = byte_swap_32 (itunes_backup->dpsl[0]);
    dpsl_u32[1] = byte_swap_32 (itunes_backup->dpsl[1]);
    dpsl_u32[2] = byte_swap_32 (itunes_backup->dpsl[2]);
    dpsl_u32[3] = byte_swap_32 (itunes_backup->dpsl[3]);
    dpsl_u32[4] = byte_swap_32 (itunes_backup->dpsl[4]);

    u8 dpsl[80 + 1];

    u32_to_hex_lower (dpsl_u32[0], dpsl +  0);
    u32_to_hex_lower (dpsl_u32[1], dpsl +  8);
    u32_to_hex_lower (dpsl_u32[2], dpsl + 16);
    u32_to_hex_lower (dpsl_u32[3], dpsl + 24);
    u32_to_hex_lower (dpsl_u32[4], dpsl + 32);

    dpsl[40] = 0;

    snprintf (out_buf, out_len - 1, "%s*%i*%s*%i*%s*%i*%s",
      SIGNATURE_ITUNES_BACKUP,
      salt.salt_sign[0],
      wpky,
      salt.salt_iter2 + 1,
      (char *) salt.salt_buf,
      salt.salt_iter + 1,
      dpsl);
  }
  else if (hash_mode == 14900)
  {
    snprintf (out_buf, out_len - 1, "%08x:%08x", digest_buf[0], salt.salt_buf[0]);
  }
  else if (hash_mode == 15100)
  {
    // encode the digest:

    netbsd_sha1crypt_encode ((unsigned char *) digest_buf, salt.salt_sign[0], (unsigned char *) ptr_plain);

    // output:

    snprintf (out_buf, out_len - 1, "$sha1$%i$%s$%s",
      salt.salt_iter + 1,
      (char *) salt.salt_buf,
      ptr_plain);
  }
  else if (hash_mode == 15200)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_len - 1, "%s", hash_buf);
  }
  else if (hash_mode == 15300)
  {
    dpapimk_t *dpapimks = (dpapimk_t *) esalts_buf;

    dpapimk_t *dpapimk  = &dpapimks[digest_cur];

    u32 version      = (u32) dpapimk->version;
    u32 context      = (u32) dpapimk->context;
    u32 rounds       = salt.salt_iter + 1;
    u32 contents_len = (u32) dpapimk->contents_len;
    u32 SID_len      = (u32) dpapimk->SID_len;
    u32 iv_len       = 32;

    u8 cipher_algorithm[8] = { 0 };
    u8 hash_algorithm[8]   = { 0 };
    u8 SID[512]            = { 0 };
    u8* SID_tmp;

    u32  *ptr_SID          = (u32 *)  dpapimk->SID;
    u32  *ptr_iv           = (u32 *)  dpapimk->iv;
    u32  *ptr_contents     = (u32 *)  dpapimk->contents;

    u32 u32_iv[4];
    u8 iv[32 + 1];

    /* convert back SID */

    SID_tmp = (u8 *) hcmalloc ((SID_len + 1) * sizeof(u8));

    for (u32 i = 0; i < (SID_len / 4) + 1; i++)
    {
      u8 hex[8] = { 0 };
      u32_to_hex_lower (byte_swap_32 (ptr_SID[i]), hex);

      for (u32 j = 0, k = 0; j < 8; j += 2, k++)
      {
        SID_tmp[i * 4 + k] = hex_to_u8 (&hex[j]);
      }
    }
    /* overwrite trailing 0x80 */
    SID_tmp[SID_len] = 0;

    for (u32 i = 0, j = 0 ; j < SID_len ; i++, j += 2)
    {
      SID[i] = SID_tmp[j];
    }

    hcfree(SID_tmp);

    for (u32 i = 0; i < iv_len / 8; i++)
    {
      u32_iv[i] = byte_swap_32 (ptr_iv[i]);
      u32_to_hex_lower (u32_iv[i], iv +  i * 8);
    }
    iv[32] = 0;

    u32 u32_contents[36];
    u8  contents[288 + 1];

    for (u32 i = 0; i < contents_len / 8; i++)
    {
      u32_contents[i] = byte_swap_32 (ptr_contents[i]);
      u32_to_hex_lower (u32_contents[i], contents +  i * 8);
    }

    if (version == 1)
    {
      contents[208] = 0;
    }
    else
    {
      contents[288] = 0;
    }

    if (contents_len == 288 && version == 2)
    {
      memcpy(cipher_algorithm, "aes256", strlen("aes256"));
      memcpy(hash_algorithm,   "sha512", strlen("sha512"));
    }
    else if (contents_len == 208 && version == 1)
    {
      memcpy(cipher_algorithm, "des3", strlen("des3"));
      memcpy(hash_algorithm,   "sha1", strlen("sha1"));
    }

    snprintf (out_buf, out_len - 1, "%s%d*%d*%s*%s*%s*%d*%s*%d*%s",
      SIGNATURE_DPAPIMK,
      version,
      context,
      SID,
      cipher_algorithm,
      hash_algorithm,
      rounds,
      iv,
      contents_len,
      contents);
  }
  else if (hash_mode == 15500)
  {
    jks_sha1_t *jks_sha1s = (jks_sha1_t *) esalts_buf;

    jks_sha1_t *jks_sha1 = &jks_sha1s[digest_cur];

    char enc_key[16384 + 1] = { 0 };

    u8 *ptr = (u8 *) jks_sha1->enc_key_buf;

    for (u32 i = 0, j = 0; i < jks_sha1->enc_key_len; i += 1, j += 2)
    {
      sprintf (enc_key + j, "%02X", ptr[i]);
    }

    u8 *der = (u8 *) jks_sha1->der;

    snprintf (out_buf, out_len - 1, "%s*%08X%08X%08X%08X%08X*%08X%08X%08X%08X%08X*%s*%02X*%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X*%s",
      SIGNATURE_JKS_SHA1,
      byte_swap_32 (jks_sha1->checksum[0]),
      byte_swap_32 (jks_sha1->checksum[1]),
      byte_swap_32 (jks_sha1->checksum[2]),
      byte_swap_32 (jks_sha1->checksum[3]),
      byte_swap_32 (jks_sha1->checksum[4]),
      byte_swap_32 (jks_sha1->iv[0]),
      byte_swap_32 (jks_sha1->iv[1]),
      byte_swap_32 (jks_sha1->iv[2]),
      byte_swap_32 (jks_sha1->iv[3]),
      byte_swap_32 (jks_sha1->iv[4]),
      enc_key,
      der[ 0],
      der[ 6],
      der[ 7],
      der[ 8],
      der[ 9],
      der[10],
      der[11],
      der[12],
      der[13],
      der[14],
      der[15],
      der[16],
      der[17],
      der[18],
      der[19],
      (char *) jks_sha1->alias
    );
  }
  else if (hash_mode == 15600)
  {
    ethereum_pbkdf2_t *ethereum_pbkdf2s = (ethereum_pbkdf2_t *) esalts_buf;
    ethereum_pbkdf2_t *ethereum_pbkdf2  = &ethereum_pbkdf2s[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%d*%s*%08x%08x%08x%08x%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_ETHEREUM_PBKDF2,
      salt.salt_iter + 1,
      (char *) salt.salt_buf,
      byte_swap_32 (ethereum_pbkdf2->ciphertext[0]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[1]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[2]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[3]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[4]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[5]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[6]),
      byte_swap_32 (ethereum_pbkdf2->ciphertext[7]),
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]
    );
  }
  else if (hash_mode == 15700)
  {
    ethereum_scrypt_t *ethereum_scrypts = (ethereum_scrypt_t *) esalts_buf;
    ethereum_scrypt_t *ethereum_scrypt  = &ethereum_scrypts[digest_cur];

    snprintf (out_buf, out_len - 1, "%s*%d*%d*%d*%s*%08x%08x%08x%08x%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_ETHEREUM_SCRYPT,
      salt.scrypt_N,
      salt.scrypt_r,
      salt.scrypt_p,
      (char *) salt.salt_buf,
      byte_swap_32 (ethereum_scrypt->ciphertext[0]),
      byte_swap_32 (ethereum_scrypt->ciphertext[1]),
      byte_swap_32 (ethereum_scrypt->ciphertext[2]),
      byte_swap_32 (ethereum_scrypt->ciphertext[3]),
      byte_swap_32 (ethereum_scrypt->ciphertext[4]),
      byte_swap_32 (ethereum_scrypt->ciphertext[5]),
      byte_swap_32 (ethereum_scrypt->ciphertext[6]),
      byte_swap_32 (ethereum_scrypt->ciphertext[7]),
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]
    );
  }
  else if (hash_mode == 99999)
  {
    char *ptr = (char *) digest_buf;

    snprintf (out_buf, out_len - 1, "%s", ptr + 64);
  }
  else
  {
    if (hash_type == HASH_TYPE_MD4)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_MD5)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_SHA1)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_SHA224)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x",
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
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
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

      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
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

      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
    }
    else if (hash_type == HASH_TYPE_LM)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_ORACLEH)
    {
      snprintf (out_buf, out_len - 1, "%08X%08X",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_BCRYPT)
    {
      base64_encode (int_to_bf64, (const u8 *) salt.salt_buf, 16, (u8 *) tmp_buf + 0);
      base64_encode (int_to_bf64, (const u8 *) digest_buf,    23, (u8 *) tmp_buf + 22);

      tmp_buf[22 + 31] = 0; // base64_encode wants to pad

      snprintf (out_buf, out_len - 1, "%s$%s", (char *) salt.salt_sign, tmp_buf);
    }
    else if (hash_type == HASH_TYPE_KECCAK)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14],
        ptr[17], ptr[16],
        ptr[19], ptr[18],
        ptr[21], ptr[20],
        ptr[23], ptr[22],
        ptr[25], ptr[24],
        ptr[27], ptr[26],
        ptr[29], ptr[28],
        ptr[31], ptr[30],
        ptr[33], ptr[32],
        ptr[35], ptr[34],
        ptr[37], ptr[36],
        ptr[39], ptr[38],
        ptr[41], ptr[30],
        ptr[43], ptr[42],
        ptr[45], ptr[44],
        ptr[47], ptr[46],
        ptr[49], ptr[48]
      );

      out_buf[salt.keccak_mdlen * 2] = 0;
    }
    else if (hash_type == HASH_TYPE_BLAKE2B)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_len - 1, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        SIGNATURE_BLAKE2B,
        byte_swap_32(ptr[ 0]),
        byte_swap_32(ptr[ 1]),
        byte_swap_32(ptr[ 2]),
        byte_swap_32(ptr[ 3]),
        byte_swap_32(ptr[ 4]),
        byte_swap_32(ptr[ 5]),
        byte_swap_32(ptr[ 6]),
        byte_swap_32(ptr[ 7]),
        byte_swap_32(ptr[ 8]),
        byte_swap_32(ptr[ 9]),
        byte_swap_32(ptr[10]),
        byte_swap_32(ptr[11]),
        byte_swap_32(ptr[12]),
        byte_swap_32(ptr[13]),
        byte_swap_32(ptr[14]),
        byte_swap_32(ptr[15]));
    }
    else if (hash_type == HASH_TYPE_CHACHA20)
    {
      u32 *ptr = digest_buf;

      const chacha20_t *chacha20_tmp = (const chacha20_t *) esalts_buf;
      const chacha20_t *chacha20     = &chacha20_tmp[digest_cur];

      snprintf (out_buf, out_len - 1, "%s*%08x%08x*%d*%08x%08x*%08x%08x*%08x%08x",
        SIGNATURE_CHACHA20,
        byte_swap_32(chacha20->position[0]),
        byte_swap_32(chacha20->position[1]),
        chacha20->offset,
        byte_swap_32(chacha20->iv[1]),
        byte_swap_32(chacha20->iv[0]),
        byte_swap_32(chacha20->plain[0]),
        byte_swap_32(chacha20->plain[1]),
        ptr[1],
        ptr[0]);
    }
    else if (hash_type == HASH_TYPE_RIPEMD160)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_WHIRLPOOL)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
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
    else if (hash_type == HASH_TYPE_GOST)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_MYSQL)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_LOTUS5)
    {
      snprintf (out_buf, out_len - 1, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_LOTUS6)
    {
      digest_buf[ 0] = byte_swap_32 (digest_buf[ 0]);
      digest_buf[ 1] = byte_swap_32 (digest_buf[ 1]);
      digest_buf[ 2] = byte_swap_32 (digest_buf[ 2]);
      digest_buf[ 3] = byte_swap_32 (digest_buf[ 3]);

      char buf[16] = { 0 };

      memcpy (buf + 0, salt.salt_buf, 5);
      memcpy (buf + 5, digest_buf, 9);

      buf[3] -= -4;

      base64_encode (int_to_lotus64, (const u8 *) buf, 14, (u8 *) tmp_buf);

      tmp_buf[18] = salt.salt_buf_pc[7];
      tmp_buf[19] = 0;

      snprintf (out_buf, out_len - 1, "(G%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_LOTUS8)
    {
      char buf[52] = { 0 };

      // salt

      memcpy (buf + 0, salt.salt_buf, 16);

      buf[3] -= -4;

      // iteration

      snprintf (buf + 16, 11, "%010u", salt.salt_iter + 1);

      // chars

      buf[26] = salt.salt_buf_pc[0];
      buf[27] = salt.salt_buf_pc[1];

      // digest

      memcpy (buf + 28, digest_buf, 8);

      base64_encode (int_to_lotus64, (const u8 *) buf, 36, (u8 *) tmp_buf);

      tmp_buf[49] = 0;

      snprintf (out_buf, out_len - 1, "(H%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_CRC32)
    {
      snprintf (out_buf, out_len - 1, "%08x", byte_swap_32 (digest_buf[0]));
    }
  }

  if (salt_type == SALT_TYPE_INTERN)
  {
    size_t pos = strlen (out_buf);

    out_buf[pos] = hashconfig->separator;

    char *ptr = (char *) salt.salt_buf;

    memcpy (out_buf + pos + 1, ptr, salt.salt_len);

    out_buf[pos + 1 + salt.salt_len] = 0;
  }

  return 0;
}

int hashconfig_init (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  hashconfig->hash_mode       = user_options->hash_mode;
  hashconfig->hash_type       = 0;
  hashconfig->salt_type       = 0;
  hashconfig->attack_exec     = 0;
  hashconfig->opts_type       = 0;
  hashconfig->kern_type       = 0;
  hashconfig->dgst_size       = 0;
  hashconfig->esalt_size      = 0;
  hashconfig->hook_salt_size  = 0;
  hashconfig->tmp_size        = 0;
  hashconfig->hook_size       = 0;
  hashconfig->opti_type       = 0;
  hashconfig->is_salted       = 0;
  hashconfig->dgst_pos0       = 0;
  hashconfig->dgst_pos1       = 0;
  hashconfig->dgst_pos2       = 0;
  hashconfig->dgst_pos3       = 0;
  hashconfig->parse_func      = NULL;
  hashconfig->separator       = user_options->separator;

  switch (hashconfig->hash_mode)
  {
    case     0:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case    10:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_PWSLT;
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
                 break;

    case    11:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = joomla_parse_hash;
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
                 break;

    case    12:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = postgresql_parse_hash;
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
                 break;

    case    20:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
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
                 break;

    case    21:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = osc_parse_hash;
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
                 break;

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
                 break;

    case    23:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = skype_parse_hash;
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
                 break;

    case    30:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case    40:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
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
                 break;

    case    50:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = hmacmd5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case    60:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = hmacmd5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case   100:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1;
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
                 break;

    case   101:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1b64_parse_hash;
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
                 break;

    case   110:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWSLT;
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
                 break;

    case   111:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1b64s_parse_hash;
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
                 break;

    case   112:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = oracles_parse_hash;
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
                 break;

    case   120:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case   121:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_LOWER;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = smf_parse_hash;
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
                 break;

    case   122:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = osx1_parse_hash;
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
                 break;

    case   125:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = arubaos_parse_hash;
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
                 break;

    case   130:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case   131:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mssql2000_parse_hash;
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
                 break;

    case   132:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mssql2005_parse_hash;
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
                 break;

    case   133:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = peoplesoft_parse_hash;
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
                 break;

    case   140:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case   150:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = hmacsha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case   160:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = hmacsha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case   200:  hashconfig->hash_type      = HASH_TYPE_MYSQL;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = 0;
                 hashconfig->kern_type      = KERN_TYPE_MYSQL;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = mysql323_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case   300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_MYSQL41;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case   400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PHPASS;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = phpass_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case   500:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5crypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case   501:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_MD5CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = juniper_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case   600:  hashconfig->hash_type      = HASH_TYPE_BLAKE2B;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_BLAKE2B;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = blake2b_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 1;
                 hashconfig->dgst_pos1      = 0;
                 hashconfig->dgst_pos2      = 3;
                 hashconfig->dgst_pos3      = 2;
                 break;

    case   900:  hashconfig->hash_type      = HASH_TYPE_MD4;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD4;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md4_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  1000:  hashconfig->hash_type      = HASH_TYPE_MD4;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_MD4_PWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md4_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  1100:  hashconfig->hash_type      = HASH_TYPE_MD4;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_UTF16LE
                                            | OPTS_TYPE_ST_LOWER;
                 hashconfig->kern_type      = KERN_TYPE_MD44_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = dcc_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  1300:  hashconfig->hash_type      = HASH_TYPE_SHA224;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA224;
                 hashconfig->dgst_size      = DGST_SIZE_4_7;
                 hashconfig->parse_func     = sha224_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 5;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  1400:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  1410:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1420:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1430:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1440:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1450:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = hmacsha256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  1460:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = hmacsha256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  1500:  hashconfig->hash_type      = HASH_TYPE_DESCRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_BITSLICE;
                 hashconfig->kern_type      = KERN_TYPE_DESCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = descrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  1600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_APR1CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5apr1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  1700:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 break;

    case  1710:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1720:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 hashconfig->parse_func     = osx512_parse_hash;
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
                 break;

    case  1730:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1731:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLTU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = mssql2012_parse_hash;
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
                 break;

    case  1740:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  1750:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_PW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = hmacsha512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 break;

    case  1760:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = hmacsha512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 break;

    case  1800:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA512CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512crypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  2000:  hashconfig->hash_type      = HASH_TYPE_STDOUT;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_STDOUT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = NULL;
                 hashconfig->opti_type      = 0;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 0;
                 hashconfig->dgst_pos2      = 0;
                 hashconfig->dgst_pos3      = 0;
                 break;

    case  2100:  hashconfig->hash_type      = HASH_TYPE_DCC2;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_LOWER
                                            | OPTS_TYPE_ST_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_DCC2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = dcc2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  2400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5PIX;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5pix_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  2410:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5ASA;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5asa_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  2500:  hashconfig->hash_type      = HASH_TYPE_WPA;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_WPA;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = wpa_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
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
                 break;

    case  2611:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = vb3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
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
                 break;

    case  2711:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  2811:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_HASH_MD5
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD55_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = ipb2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  3000:  hashconfig->hash_type      = HASH_TYPE_LM;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_PT_BITSLICE
                                            | OPTS_TYPE_PT_ALWAYS_ASCII
                                            | OPTS_TYPE_HASH_SPLIT;
                 hashconfig->kern_type      = KERN_TYPE_LM;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = lm_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  3100:  hashconfig->hash_type      = HASH_TYPE_ORACLEH;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_ORACLEH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = oracleh_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  3200:  hashconfig->hash_type      = HASH_TYPE_BCRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_BCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_6;
                 hashconfig->parse_func     = bcrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  3710:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  3800:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  3910:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_HASH_MD5
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  4010:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  4110:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  4520:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  4521:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  4522:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  4800:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_CHAP;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = chap_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  4900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case  5000:  hashconfig->hash_type      = HASH_TYPE_KECCAK;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_KECCAK;
                 hashconfig->dgst_size      = DGST_SIZE_8_25;
                 hashconfig->parse_func     = keccak_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 2;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 4;
                 hashconfig->dgst_pos3      = 5;
                 break;

    case  5100:  hashconfig->hash_type      = HASH_TYPE_MD5H;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5H;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = md5half_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  5200:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_PSAFE3;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = psafe3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  5300:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_IKEPSK_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = ikepsk_md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  5400:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_IKEPSK_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = ikepsk_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  5500:  hashconfig->hash_type      = HASH_TYPE_NETNTLM;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_NETNTLMv1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = netntlmv1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  5600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_NETNTLMv2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = netntlmv2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  5700:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = cisco4_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  5800:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_ANDROIDPIN;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = androidpin_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
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
                 break;

    case  6211:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_2k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6212:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_2k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6213:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_2k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6221:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6222:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6223:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6231:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6232:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6233:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6241:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6242:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6243:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = truecrypt_parse_hash_1k;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6300:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5AIX;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5aix_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6400:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA256AIX;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256aix_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6500:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA512AIX;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512aix_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6600:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_AGILEKEY;
                 hashconfig->dgst_size      = DGST_SIZE_4_5; // because kernel uses _SHA1_
                 hashconfig->parse_func     = agilekey_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6700:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1AIX;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1aix_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6800:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LASTPASS;
                 hashconfig->dgst_size      = DGST_SIZE_4_8; // because kernel uses _SHA256_
                 hashconfig->parse_func     = lastpass_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  6900:  hashconfig->hash_type      = HASH_TYPE_GOST;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_GOST;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = gost_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7000:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_FORTIGATE;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = fortigate_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  7100:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA512;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = sha512osx_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7200:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA512;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = sha512grub_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_RAKP;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = rakp_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  7400:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA256CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256crypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7500:  hashconfig->hash_type      = HASH_TYPE_KRB5PA;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_KRB5PA;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = krb5pa_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7700:  hashconfig->hash_type      = HASH_TYPE_SAPB;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPB;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = sapb_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  7800:  hashconfig->hash_type      = HASH_TYPE_SAPG;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPG;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sapg_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  7900:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_DRUPAL7;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = drupal7_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8000:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SYBASEASE;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sybasease_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case  8100:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE;
                 hashconfig->kern_type      = KERN_TYPE_NETSCALER;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = netscaler_parse_hash;
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
                 break;

    case  8200:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_CLOUDKEY;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = cloudkey_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_HEX
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_NSEC3;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = nsec3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  8400:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_WBB3;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = wbb3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case  8500:  hashconfig->hash_type      = HASH_TYPE_DESRACF;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_RACF;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = racf_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8600:  hashconfig->hash_type      = HASH_TYPE_LOTUS5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS5;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = lotus5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8700:  hashconfig->hash_type      = HASH_TYPE_LOTUS6;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS6;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = lotus6_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8800:  hashconfig->hash_type      = HASH_TYPE_ANDROIDFDE;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ANDROIDFDE;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = androidfde_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  8900:  hashconfig->hash_type      = HASH_TYPE_SCRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = scrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9000:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_PSAFE2;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = psafe2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9100:  hashconfig->hash_type      = HASH_TYPE_LOTUS8;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS8;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = lotus8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9200:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = cisco8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9300:  hashconfig->hash_type      = HASH_TYPE_SCRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = cisco9_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9400:  hashconfig->hash_type      = HASH_TYPE_OFFICE2007;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OFFICE2007;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = office2007_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9500:  hashconfig->hash_type      = HASH_TYPE_OFFICE2010;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OFFICE2010;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = office2010_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9600:  hashconfig->hash_type      = HASH_TYPE_OFFICE2013;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OFFICE2013;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = office2013_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9700:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE01;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE01;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice01_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9710:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE01;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE01CM1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice01cm1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9720:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE01;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_PT_NEVERCRACK;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE01CM2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice01cm2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9800:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE34;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE34;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice34_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9810:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE34;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE34CM1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice34cm1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9820:  hashconfig->hash_type      = HASH_TYPE_OLDOFFICE34;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_PT_NEVERCRACK;
                 hashconfig->kern_type      = KERN_TYPE_OLDOFFICE34CM2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = oldoffice34cm2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case  9900:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_RADMIN2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = radmin2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 10000:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = djangopbkdf2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
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
                 break;

    case 10200:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = crammd5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 10300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SAPH_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = saph_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10400:  hashconfig->hash_type      = HASH_TYPE_PDFU16;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PDF11;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = pdf11_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10410:  hashconfig->hash_type      = HASH_TYPE_PDFU16;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PDF11CM1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = pdf11cm1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10420:  hashconfig->hash_type      = HASH_TYPE_PDFU16;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PDF11CM2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = pdf11cm2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10500:  hashconfig->hash_type      = HASH_TYPE_PDFU16;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PDF14;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = pdf14_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10600:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = pdf17l3_parse_hash;
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
                 break;

    case 10700:  hashconfig->hash_type      = HASH_TYPE_PDFU32;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PDF17L8;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = pdf17l8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 10800:  hashconfig->hash_type      = HASH_TYPE_SHA384;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA384;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha384_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 6;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 4;
                 hashconfig->dgst_pos3      = 5;
                 break;

    case 10900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = pbkdf2_sha256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11000:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_PRESTASHOP;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = prestashop_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 11100:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_POSTGRESQL_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = postgresql_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 11200:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_MYSQL_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mysql_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 11300:  hashconfig->hash_type      = HASH_TYPE_BITCOIN_WALLET;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_BITCOIN_WALLET;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = bitcoin_wallet_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_SIP_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = sip_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 11500:  hashconfig->hash_type      = HASH_TYPE_CRC32;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_CRC32;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = crc32_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11600:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HOOK23;
                 hashconfig->kern_type      = KERN_TYPE_SEVEN_ZIP;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = seven_zip_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11700:  hashconfig->hash_type      = HASH_TYPE_GOST_2012SBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_GOST_2012SBOG_256;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = gost2012sbog_256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11800:  hashconfig->hash_type      = HASH_TYPE_GOST_2012SBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_GOST_2012SBOG_512;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = gost2012sbog_512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 11900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = pbkdf2_md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12000:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = pbkdf2_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12001:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = atlassian_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12100:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA512;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = pbkdf2_sha512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12200:  hashconfig->hash_type      = HASH_TYPE_ECRYPTFS;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ECRYPTFS;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = ecryptfs_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12300:  hashconfig->hash_type      = HASH_TYPE_ORACLET;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ORACLET;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = oraclet_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12400:  hashconfig->hash_type      = HASH_TYPE_BSDICRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_BSDICRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = bsdicrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12500:  hashconfig->hash_type      = HASH_TYPE_RAR3HP;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_RAR3;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = rar3hp_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12600:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_CF10;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = cf10_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case 12700:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_MYWALLET;
                 hashconfig->dgst_size      = DGST_SIZE_4_5; // because kernel uses _SHA1_
                 hashconfig->parse_func     = mywallet_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12800:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MS_DRSR;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = ms_drsr_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 12900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ANDROIDFDE_SAMSUNG;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = androidfde_samsung_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13000:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_RAR5;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = rar5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13100:  hashconfig->hash_type      = HASH_TYPE_KRB5TGS;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_KRB5TGS;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = krb5tgs_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13200:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_AXCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = axcrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_AXCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1axcrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 3;
                 hashconfig->dgst_pos3      = 2;
                 break;

    case 13400:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_KEEPASS;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = keepass_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13500:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_PSTOKEN;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = pstoken_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 13600:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ZIP2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = zip2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13711:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_655331;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13712:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_655331;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13713:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_655331;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13721:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13722:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13723:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCSHA512_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13731:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13732:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13733:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCWHIRLPOOL_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13741:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_327661;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13742:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_327661;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13743:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_TCRIPEMD160_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = veracrypt_parse_hash_327661;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13751:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13752:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13753:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_500000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13761:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS512;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_200000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13762:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS1024;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_200000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13763:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_VCSHA256_XTS1536;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = veracrypt_parse_hash_200000;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 13800:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_WIN8PHONE;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = win8phone_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 break;

    case 13900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
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
                 break;

    case 14000:  hashconfig->hash_type      = HASH_TYPE_DES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_BITSLICE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_DES;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = des_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 14100:  hashconfig->hash_type      = HASH_TYPE_DES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_3DES;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = des_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_PERMUT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 14400:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1CX;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1cx_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 14600:  hashconfig->hash_type      = HASH_TYPE_LUKS;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_BINARY_HASHFILE;
                 hashconfig->kern_type      = KERN_TYPE_LUKS_SHA1_AES; // this gets overwritten from within parser
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = NULL; // luks_parse_hash is kind of unconvetional
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 14700:  hashconfig->hash_type      = HASH_TYPE_ITUNES_BACKUP_9;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_ITUNES_BACKUP_9;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // we actually do not have a digest
                 hashconfig->parse_func     = itunes_backup_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 14800:  hashconfig->hash_type      = HASH_TYPE_ITUNES_BACKUP_10;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX
                                            | OPTS_TYPE_INIT2
                                            | OPTS_TYPE_LOOP2;
                 hashconfig->kern_type      = KERN_TYPE_ITUNES_BACKUP_10;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // we actually do not have a digest
                 hashconfig->parse_func     = itunes_backup_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 14900:  hashconfig->hash_type      = HASH_TYPE_SKIP32;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_PT_NEVERCRACK;
                 hashconfig->kern_type      = KERN_TYPE_SKIP32;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = skip32_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15000:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_INTERN;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE; // OPTS_TYPE_ST_ADD80 added within kernel
                 hashconfig->kern_type      = KERN_TYPE_FILEZILLA_SERVER;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = filezilla_server_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 break;

    case 15100:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_NETBSD_SHA1CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = netbsd_sha1crypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15200:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_MYWALLET;
                 hashconfig->dgst_size      = DGST_SIZE_4_5; // because kernel uses _SHA1_
                 hashconfig->parse_func     = mywalletv2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15300:  hashconfig->hash_type      = HASH_TYPE_DPAPIMK;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_DPAPIMK;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = dpapimk_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15400:  hashconfig->hash_type      = HASH_TYPE_CHACHA20;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_CHACHA20;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = chacha20_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_32
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15500:  hashconfig->hash_type      = HASH_TYPE_JKS_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_JKS_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = jks_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    case 15600:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_ETHEREUM_PBKDF2;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = ethereum_pbkdf2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 15700:  hashconfig->hash_type      = HASH_TYPE_SCRYPT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_ETHEREUM_SCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = ethereum_scrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 break;

    case 99999:  hashconfig->hash_type      = HASH_TYPE_PLAINTEXT;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD4;
                 hashconfig->dgst_size      = DGST_SIZE_4_32; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = plaintext_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 break;

    default:     event_log_error (hashcat_ctx, "Unknown hash-type '%u' selected.", hashconfig->hash_mode);
                 return -1;
  }

  if (user_options->hex_salt)
  {
    if (hashconfig->salt_type == SALT_TYPE_INTERN)
    {
      hashconfig->opts_type |= OPTS_TYPE_ST_HEX;
    }
    else
    {
      event_log_error (hashcat_ctx, "Parameter hex-salt not valid for hash-type %u", hashconfig->hash_mode);

      return -1;
    }
  }

  if (user_options->keep_guessing)
  {
    hashconfig->opts_type |= OPTS_TYPE_PT_NEVERCRACK;
  }

  const u32 is_salted = ((hashconfig->salt_type == SALT_TYPE_INTERN)
                      |  (hashconfig->salt_type == SALT_TYPE_EXTERN)
                      |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED)
                      |  (hashconfig->salt_type == SALT_TYPE_VIRTUAL));

  hashconfig->is_salted = is_salted;

  // esalt_size

  hashconfig->esalt_size = 0;

  switch (hashconfig->hash_mode)
  {
    case   600: hashconfig->esalt_size = sizeof (blake2_t);          break;
    case  2500: hashconfig->esalt_size = sizeof (wpa_t);             break;
    case  5300: hashconfig->esalt_size = sizeof (ikepsk_t);          break;
    case  5400: hashconfig->esalt_size = sizeof (ikepsk_t);          break;
    case  5500: hashconfig->esalt_size = sizeof (netntlm_t);         break;
    case  5600: hashconfig->esalt_size = sizeof (netntlm_t);         break;
    case  6211: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6212: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6213: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6221: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6222: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6223: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6231: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6232: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6233: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6241: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6242: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6243: hashconfig->esalt_size = sizeof (tc_t);              break;
    case  6600: hashconfig->esalt_size = sizeof (agilekey_t);        break;
    case  7100: hashconfig->esalt_size = sizeof (pbkdf2_sha512_t);   break;
    case  7200: hashconfig->esalt_size = sizeof (pbkdf2_sha512_t);   break;
    case  7300: hashconfig->esalt_size = sizeof (rakp_t);            break;
    case  7500: hashconfig->esalt_size = sizeof (krb5pa_t);          break;
    case  8200: hashconfig->esalt_size = sizeof (cloudkey_t);        break;
    case  8800: hashconfig->esalt_size = sizeof (androidfde_t);      break;
    case  9200: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);   break;
    case  9400: hashconfig->esalt_size = sizeof (office2007_t);      break;
    case  9500: hashconfig->esalt_size = sizeof (office2010_t);      break;
    case  9600: hashconfig->esalt_size = sizeof (office2013_t);      break;
    case  9700: hashconfig->esalt_size = sizeof (oldoffice01_t);     break;
    case  9710: hashconfig->esalt_size = sizeof (oldoffice01_t);     break;
    case  9720: hashconfig->esalt_size = sizeof (oldoffice01_t);     break;
    case  9800: hashconfig->esalt_size = sizeof (oldoffice34_t);     break;
    case  9810: hashconfig->esalt_size = sizeof (oldoffice34_t);     break;
    case  9820: hashconfig->esalt_size = sizeof (oldoffice34_t);     break;
    case 10000: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);   break;
    case 10200: hashconfig->esalt_size = sizeof (cram_md5_t);        break;
    case 10400: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10410: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10420: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10500: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10600: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10700: hashconfig->esalt_size = sizeof (pdf_t);             break;
    case 10900: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);   break;
    case 11300: hashconfig->esalt_size = sizeof (bitcoin_wallet_t);  break;
    case 11400: hashconfig->esalt_size = sizeof (sip_t);             break;
    case 11900: hashconfig->esalt_size = sizeof (pbkdf2_md5_t);      break;
    case 12000: hashconfig->esalt_size = sizeof (pbkdf2_sha1_t);     break;
    case 12001: hashconfig->esalt_size = sizeof (pbkdf2_sha1_t);     break;
    case 12100: hashconfig->esalt_size = sizeof (pbkdf2_sha512_t);   break;
    case 13000: hashconfig->esalt_size = sizeof (rar5_t);            break;
    case 13100: hashconfig->esalt_size = sizeof (krb5tgs_t);         break;
    case 13400: hashconfig->esalt_size = sizeof (keepass_t);         break;
    case 13500: hashconfig->esalt_size = sizeof (pstoken_t);         break;
    case 13600: hashconfig->esalt_size = sizeof (zip2_t);            break;
    case 13711: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13712: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13713: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13721: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13722: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13723: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13731: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13732: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13733: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13741: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13742: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13743: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13751: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13752: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13753: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13761: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13762: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13763: hashconfig->esalt_size = sizeof (tc_t);              break;
    case 13800: hashconfig->esalt_size = sizeof (win8phone_t);       break;
    case 14600: hashconfig->esalt_size = sizeof (luks_t);            break;
    case 14700: hashconfig->esalt_size = sizeof (itunes_backup_t);   break;
    case 14800: hashconfig->esalt_size = sizeof (itunes_backup_t);   break;
    case 15300: hashconfig->esalt_size = sizeof (dpapimk_t);         break;
    case 15400: hashconfig->esalt_size = sizeof (chacha20_t);        break;
    case 15500: hashconfig->esalt_size = sizeof (jks_sha1_t);        break;
    case 15600: hashconfig->esalt_size = sizeof (ethereum_pbkdf2_t); break;
    case 15700: hashconfig->esalt_size = sizeof (ethereum_scrypt_t); break;
  }

  // hook_salt_size

  hashconfig->hook_salt_size = 0;

  switch (hashconfig->hash_mode)
  {
    case 11600: hashconfig->hook_salt_size = sizeof (seven_zip_hook_salt_t); break;
  }

  // tmp_size

  hashconfig->tmp_size = 4;

  switch (hashconfig->hash_mode)
  {
    case   400: hashconfig->tmp_size = sizeof (phpass_tmp_t);          break;
    case   500: hashconfig->tmp_size = sizeof (md5crypt_tmp_t);        break;
    case   501: hashconfig->tmp_size = sizeof (md5crypt_tmp_t);        break;
    case  1600: hashconfig->tmp_size = sizeof (md5crypt_tmp_t);        break;
    case  1800: hashconfig->tmp_size = sizeof (sha512crypt_tmp_t);     break;
    case  2100: hashconfig->tmp_size = sizeof (dcc2_tmp_t);            break;
    case  2500: hashconfig->tmp_size = sizeof (wpa_tmp_t);             break;
    case  3200: hashconfig->tmp_size = sizeof (bcrypt_tmp_t);          break;
    case  5200: hashconfig->tmp_size = sizeof (pwsafe3_tmp_t);         break;
    case  5800: hashconfig->tmp_size = sizeof (androidpin_tmp_t);      break;
    case  6211: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6212: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6213: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6221: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case  6222: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case  6223: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case  6231: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6232: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6233: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6241: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6242: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6243: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case  6300: hashconfig->tmp_size = sizeof (md5crypt_tmp_t);        break;
    case  6400: hashconfig->tmp_size = sizeof (sha256aix_tmp_t);       break;
    case  6500: hashconfig->tmp_size = sizeof (sha512aix_tmp_t);       break;
    case  6600: hashconfig->tmp_size = sizeof (agilekey_tmp_t);        break;
    case  6700: hashconfig->tmp_size = sizeof (sha1aix_tmp_t);         break;
    case  6800: hashconfig->tmp_size = sizeof (lastpass_tmp_t);        break;
    case  7100: hashconfig->tmp_size = sizeof (pbkdf2_sha512_tmp_t);   break;
    case  7200: hashconfig->tmp_size = sizeof (pbkdf2_sha512_tmp_t);   break;
    case  7400: hashconfig->tmp_size = sizeof (sha256crypt_tmp_t);     break;
    case  7900: hashconfig->tmp_size = sizeof (drupal7_tmp_t);         break;
    case  8200: hashconfig->tmp_size = sizeof (pbkdf2_sha512_tmp_t);   break;
    case  8800: hashconfig->tmp_size = sizeof (androidfde_tmp_t);      break;
    case  9000: hashconfig->tmp_size = sizeof (pwsafe2_tmp_t);         break;
    case  9100: hashconfig->tmp_size = sizeof (lotus8_tmp_t);          break;
    case  9200: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case  9400: hashconfig->tmp_size = sizeof (office2007_tmp_t);      break;
    case  9500: hashconfig->tmp_size = sizeof (office2010_tmp_t);      break;
    case  9600: hashconfig->tmp_size = sizeof (office2013_tmp_t);      break;
    case 10000: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 10200: hashconfig->tmp_size = sizeof (cram_md5_t);            break;
    case 10300: hashconfig->tmp_size = sizeof (saph_sha1_tmp_t);       break;
    case 10500: hashconfig->tmp_size = sizeof (pdf14_tmp_t);           break;
    case 10700: hashconfig->tmp_size = sizeof (pdf17l8_tmp_t);         break;
    case 10900: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 11300: hashconfig->tmp_size = sizeof (bitcoin_wallet_tmp_t);  break;
    case 11600: hashconfig->tmp_size = sizeof (seven_zip_tmp_t);       break;
    case 11900: hashconfig->tmp_size = sizeof (pbkdf2_md5_tmp_t);      break;
    case 12000: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);     break;
    case 12001: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);     break;
    case 12100: hashconfig->tmp_size = sizeof (pbkdf2_sha512_tmp_t);   break;
    case 12200: hashconfig->tmp_size = sizeof (ecryptfs_tmp_t);        break;
    case 12300: hashconfig->tmp_size = sizeof (oraclet_tmp_t);         break;
    case 12400: hashconfig->tmp_size = sizeof (bsdicrypt_tmp_t);       break;
    case 12500: hashconfig->tmp_size = sizeof (rar3_tmp_t);            break;
    case 12700: hashconfig->tmp_size = sizeof (mywallet_tmp_t);        break;
    case 12800: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 12900: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 13000: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 13200: hashconfig->tmp_size = sizeof (axcrypt_tmp_t);         break;
    case 13400: hashconfig->tmp_size = sizeof (keepass_tmp_t);         break;
    case 13600: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);     break;
    case 13711: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13712: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13713: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13721: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case 13722: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case 13723: hashconfig->tmp_size = sizeof (tc64_tmp_t);            break;
    case 13731: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13732: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13733: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13741: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13742: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13743: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13751: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13752: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13753: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13761: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13762: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 13763: hashconfig->tmp_size = sizeof (tc_tmp_t);              break;
    case 14600: hashconfig->tmp_size = sizeof (luks_tmp_t);            break;
    case 14700: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);     break;
    case 14800: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
    case 15100: hashconfig->tmp_size = sizeof (pbkdf1_sha1_tmp_t);     break;
    case 15200: hashconfig->tmp_size = sizeof (mywallet_tmp_t);        break;
    case 15300: hashconfig->tmp_size = sizeof (dpapimk_tmp_t);         break;
    case 15600: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);   break;
  };

  // hook_size

  hashconfig->hook_size = 4;

  switch (hashconfig->hash_mode)
  {
    case 11600: hashconfig->hook_size = sizeof (seven_zip_hook_t);     break;
  };

  // pw_min

  hashconfig->pw_min = PW_MIN;

  switch (hashconfig->hash_mode)
  {
    case  2500: hashconfig->pw_min = 8;
                break;
    case  9710: hashconfig->pw_min = 5;
                break;
    case  9810: hashconfig->pw_min = 5;
                break;
    case 10410: hashconfig->pw_min = 5;
                break;
    case 14000: hashconfig->pw_min = 8;
                break;
    case 14100: hashconfig->pw_min = 24;
                break;
    case 14900: hashconfig->pw_min = 10;
                break;
  }

  // pw_max

  hashconfig->pw_max = PW_MAX;

  if ((hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE))
  {
    hashconfig->pw_max = PW_MAX / 2;
  }

  switch (hashconfig->hash_mode)
  {
    case   125: hashconfig->pw_max = 32;
                break;
    case   400: hashconfig->pw_max = 40;
                break;
    case   500: hashconfig->pw_max = 16;
                break;
    case  1500: hashconfig->pw_max = 8;
                break;
    case  1600: hashconfig->pw_max = 16;
                break;
    case  1800: hashconfig->pw_max = 16;
                break;
    case  2100: hashconfig->pw_max = 16;
                break;
    case  3000: hashconfig->pw_max = 7;
                break;
    case  5200: hashconfig->pw_max = 24;
                break;
    case  5800: hashconfig->pw_max = 16;
                break;
    case  6300: hashconfig->pw_max = 16;
                break;
    case  7000: hashconfig->pw_max = 19;
                break;
    case  7400: hashconfig->pw_max = 16;
                break;
    case  7700: hashconfig->pw_max = 8;
                break;
    case  7900: hashconfig->pw_max = 48;
                break;
    case  8500: hashconfig->pw_max = 8;
                break;
    case  8600: hashconfig->pw_max = 16;
                break;
    case  9710: hashconfig->pw_max = 5;
                break;
    case  9810: hashconfig->pw_max = 5;
                break;
    case 10410: hashconfig->pw_max = 5;
                break;
    case 10300: hashconfig->pw_max = 40;
                break;
    case 10500: hashconfig->pw_max = 40;
                break;
    case 10700: hashconfig->pw_max = 16;
                break;
    case 11300: hashconfig->pw_max = 40;
                break;
    case 11600: hashconfig->pw_max = 32;
                break;
    case 12500: hashconfig->pw_max = 20;
                break;
    case 12800: hashconfig->pw_max = 24;
                break;
    case 14000: hashconfig->pw_max = 8;
                break;
    case 14100: hashconfig->pw_max = 24;
                break;
    case 14400: hashconfig->pw_max = 24;
                break;
    case 14900: hashconfig->pw_max = 10;
                break;
    case 15400: hashconfig->pw_max = 32;
                break;
    case 15500: hashconfig->pw_max = 16;
                break;
  }

  return 0;
}

void hashconfig_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  memset (hashconfig, 0, sizeof (hashconfig_t));
}

u32 hashconfig_get_kernel_threads (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  u32 kernel_threads = MIN (KERNEL_THREADS_MAX, device_param->device_maxworkgroup_size);

  if ((hashconfig->hash_mode == 8900) || (hashconfig->hash_mode == 9300) || (hashconfig->hash_mode == 15700))
  {
    const hashes_t *hashes = hashcat_ctx->hashes;

    const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
    const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;
    const u32 scrypt_l = scrypt_r * scrypt_p;

    if (scrypt_l)
    {
      kernel_threads = 256 / scrypt_l;
    }
    else
    {
      kernel_threads = 256;
    }
  }

  if (device_param->device_type & CL_DEVICE_TYPE_CPU)
  {
    kernel_threads = KERNEL_THREADS_MAX_CPU;
  }

  if (hashconfig->hash_mode ==  1500) kernel_threads = 64; // DES
  if (hashconfig->hash_mode ==  3000) kernel_threads = 64; // DES
  if (hashconfig->hash_mode ==  3100) kernel_threads = 64; // DES
  if (hashconfig->hash_mode ==  3200) kernel_threads = 8;  // Blowfish
  if (hashconfig->hash_mode ==  7500) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode ==  8500) kernel_threads = 64; // DES
  if (hashconfig->hash_mode ==  9000) kernel_threads = 8;  // Blowfish
  if (hashconfig->hash_mode ==  9700) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode ==  9710) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode ==  9800) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode ==  9810) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode == 10400) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode == 10410) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode == 10500) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode == 13100) kernel_threads = 64; // RC4
  if (hashconfig->hash_mode == 14000) kernel_threads = 64; // DES
  if (hashconfig->hash_mode == 14100) kernel_threads = 64; // DES

  return kernel_threads;
}

u32 hashconfig_get_kernel_loops (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  u32 kernel_loops_fixed = 0;

  if (hashconfig->hash_mode == 1500 && user_options->attack_mode == ATTACK_MODE_BF)
  {
    kernel_loops_fixed = 1024;
  }

  if (hashconfig->hash_mode == 3000 && user_options->attack_mode == ATTACK_MODE_BF)
  {
    kernel_loops_fixed = 1024;
  }

  if (hashconfig->hash_mode == 8900)
  {
    kernel_loops_fixed = 1;
  }

  if (hashconfig->hash_mode == 9300)
  {
    kernel_loops_fixed = 1;
  }

  if (hashconfig->hash_mode == 12500)
  {
    kernel_loops_fixed = ROUNDS_RAR3 / 16;
  }

  if (hashconfig->hash_mode == 14000 && user_options->attack_mode == ATTACK_MODE_BF)
  {
    kernel_loops_fixed = 1024;
  }

  if (hashconfig->hash_mode == 14100 && user_options->attack_mode == ATTACK_MODE_BF)
  {
    kernel_loops_fixed = 1024;
  }

  if (hashconfig->hash_mode == 15700)
  {
    kernel_loops_fixed = 1;
  }

  return kernel_loops_fixed;
}

int hashconfig_general_defaults (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  char *optional_param1 = NULL;

  if (user_options->truecrypt_keyfiles) optional_param1 = user_options->truecrypt_keyfiles;
  if (user_options->veracrypt_keyfiles) optional_param1 = user_options->veracrypt_keyfiles;

  if (optional_param1)
  {
    const hashes_t *hashes = hashcat_ctx->hashes;

    void *esalts_buf = hashes->esalts_buf;

    char *tcvc_keyfiles = (char *) optional_param1;

    u32 *keyfile_buf = ((tc_t *) esalts_buf)->keyfile_buf;

    char *keyfiles = hcstrdup (tcvc_keyfiles);

    if (keyfiles == NULL) return -1;

    char *saveptr;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    if (keyfile == NULL)
    {
      free (keyfiles);

      return -1;
    }

    do
    {
      const int rc_crc32 = cpu_crc32 (hashcat_ctx, keyfile, (u8 *) keyfile_buf);

      if (rc_crc32 == -1)
      {
        free (keyfiles);

        return -1;
      }

    } while ((keyfile = strtok_r (NULL, ",", &saveptr)) != NULL);

    free (keyfiles);
  }

  return 0;
}

void hashconfig_benchmark_defaults (hashcat_ctx_t *hashcat_ctx, salt_t *salt, void *esalt, void *hook_salt)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig->is_salted)
  {
    salt->salt_len = 8;

    // special salt handling

    switch (hashconfig->hash_mode)
    {
      case    22: salt->salt_len    = 30;
                  break;
      case  1500: salt->salt_len    = 2;
                  salt->salt_buf[0] = 388; // pure magic
                  break;
      case  1731: salt->salt_len = 4;
                  break;
      case  2410: salt->salt_len = 4;
                  break;
      case  2500: memcpy (salt->salt_buf, "hashcat.net", 11);
                  break;
      case  3100: salt->salt_len = 1;
                  break;
      case  5000: salt->keccak_mdlen = 32;
                  break;
      case  5800: salt->salt_len = 16;
                  break;
      case  6800: salt->salt_len = 32;
                  break;
      case  8400: salt->salt_len = 40;
                  break;
      case  8800: salt->salt_len = 16;
                  break;
      case  8900: salt->salt_len = 16;
                  salt->scrypt_N = 1024;
                  salt->scrypt_r = 1;
                  salt->scrypt_p = 1;
                  break;
      case  9100: salt->salt_len = 16;
                  break;
      case  9300: salt->salt_len = 14;
                  salt->scrypt_N = 16384;
                  salt->scrypt_r = 1;
                  salt->scrypt_p = 1;
                  break;
      case  9400: salt->salt_len = 16;
                  break;
      case  9500: salt->salt_len = 16;
                  break;
      case  9600: salt->salt_len = 16;
                  break;
      case  9700: salt->salt_len = 16;
                  break;
      case  9710: salt->salt_len = 16;
                  break;
      case  9720: salt->salt_len = 16;
                  break;
      case  9800: salt->salt_len = 16;
                  break;
      case  9810: salt->salt_len = 16;
                  break;
      case  9820: salt->salt_len = 16;
                  break;
      case 10300: salt->salt_len = 12;
                  break;
      case 11500: salt->salt_len = 4;
                  break;
      case 11600: salt->salt_len = 4;
                  break;
      case 12400: salt->salt_len = 4;
                  break;
      case 12500: salt->salt_len = 8;
                  break;
      case 12600: salt->salt_len = 64;
                  break;
      case 14000: salt->salt_len = 8;
                  break;
      case 14100: salt->salt_len = 8;
                  break;
      case 14600: salt->salt_len = LUKS_SALTSIZE;
                  break;
      case 14700: salt->salt_len = 20;
                  break;
      case 14800: salt->salt_len = 20;
                  break;
      case 14900: salt->salt_len = 4;
                  break;
      case 15100: salt->salt_len = 8;
                  break;
      case 15600: salt->salt_len = 32;
                  break;
      case 15700: salt->salt_len = 32;
                  salt->scrypt_N = 262144;
                  salt->scrypt_r = 1;
                  salt->scrypt_p = 8;
                  break;
    }

    // special esalt handling

    switch (hashconfig->hash_mode)
    {
      case  2500: ((wpa_t *)           esalt)->eapol_len    = 128;
                  break;
      case  5300: ((ikepsk_t *)        esalt)->nr_len        = 1;
                  ((ikepsk_t *)        esalt)->msg_len       = 1;
                  break;
      case  5400: ((ikepsk_t *)        esalt)->nr_len        = 1;
                  ((ikepsk_t *)        esalt)->msg_len       = 1;
                  break;
      case  5500: ((netntlm_t *)       esalt)->user_len      = 1;
                  ((netntlm_t *)       esalt)->domain_len    = 1;
                  ((netntlm_t *)       esalt)->srvchall_len  = 1;
                  ((netntlm_t *)       esalt)->clichall_len  = 1;
                  break;
      case  5600: ((netntlm_t *)       esalt)->user_len      = 1;
                  ((netntlm_t *)       esalt)->domain_len    = 1;
                  ((netntlm_t *)       esalt)->srvchall_len  = 1;
                  ((netntlm_t *)       esalt)->clichall_len  = 1;
                  break;
      case  7300: ((rakp_t *)          esalt)->salt_len      = 32;
                  break;
      case 10400: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 32;
                  ((pdf_t *)           esalt)->u_len         = 32;
                  break;
      case 10410: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 32;
                  ((pdf_t *)           esalt)->u_len         = 32;
                  break;
      case 10420: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 32;
                  ((pdf_t *)           esalt)->u_len         = 32;
                  break;
      case 10500: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 32;
                  ((pdf_t *)           esalt)->u_len         = 32;
                  break;
      case 10600: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 127;
                  ((pdf_t *)           esalt)->u_len         = 127;
                  break;
      case 10700: ((pdf_t *)           esalt)->id_len        = 16;
                  ((pdf_t *)           esalt)->o_len         = 127;
                  ((pdf_t *)           esalt)->u_len         = 127;
                  break;
      case 13400: ((keepass_t *)       esalt)->version       = 2;
                  break;
      case 13500: ((pstoken_t *)       esalt)->salt_len      = 113;
                  break;
      case 13600: ((zip2_t *)          esalt)->salt_len      = 16;
                  ((zip2_t *)          esalt)->data_len      = 32;
                  ((zip2_t *)          esalt)->mode          = 3;
                  break;
      case 14600: ((luks_t *)          esalt)->key_size      = HC_LUKS_KEY_SIZE_256;
                  ((luks_t *)          esalt)->cipher_type   = HC_LUKS_CIPHER_TYPE_AES;
                  ((luks_t *)          esalt)->cipher_mode   = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
                  break;
      case 15300: ((dpapimk_t *)       esalt)->version       = 1;
                  break;
    }

    // special hook salt handling

    switch (hashconfig->hash_mode)
    {
      case 11600: ((seven_zip_hook_salt_t *) hook_salt)->iv_len      = 16;
                  ((seven_zip_hook_salt_t *) hook_salt)->data_len    = 112;
                  ((seven_zip_hook_salt_t *) hook_salt)->unpack_size = 112;
                  break;
    }
  }

  // set default iterations

  switch (hashconfig->hash_mode)
  {
    case   400:  salt->salt_iter  = ROUNDS_PHPASS;
                 break;
    case   500:  salt->salt_iter  = ROUNDS_MD5CRYPT;
                 break;
    case   501:  salt->salt_iter  = ROUNDS_MD5CRYPT;
                 break;
    case  1600:  salt->salt_iter  = ROUNDS_MD5CRYPT;
                 break;
    case  1800:  salt->salt_iter  = ROUNDS_SHA512CRYPT;
                 break;
    case  2100:  salt->salt_iter  = ROUNDS_DCC2;
                 break;
    case  2500:  salt->salt_iter  = ROUNDS_WPA2;
                 break;
    case  3200:  salt->salt_iter  = ROUNDS_BCRYPT;
                 break;
    case  5200:  salt->salt_iter  = ROUNDS_PSAFE3;
                 break;
    case  5800:  salt->salt_iter  = ROUNDS_ANDROIDPIN - 1;
                 break;
    case  6211:  salt->salt_iter  = ROUNDS_TRUECRYPT_2K;
                 break;
    case  6212:  salt->salt_iter  = ROUNDS_TRUECRYPT_2K;
                 break;
    case  6213:  salt->salt_iter  = ROUNDS_TRUECRYPT_2K;
                 break;
    case  6221:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6222:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6223:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6231:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6232:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6233:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6241:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6242:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6243:  salt->salt_iter  = ROUNDS_TRUECRYPT_1K;
                 break;
    case  6300:  salt->salt_iter  = ROUNDS_MD5CRYPT;
                 break;
    case  6400:  salt->salt_iter  = ROUNDS_SHA256AIX;
                 break;
    case  6500:  salt->salt_iter  = ROUNDS_SHA512AIX;
                 break;
    case  6700:  salt->salt_iter  = ROUNDS_SHA1AIX;
                 break;
    case  6600:  salt->salt_iter  = ROUNDS_AGILEKEY;
                 break;
    case  6800:  salt->salt_iter  = ROUNDS_LASTPASS;
                 break;
    case  7100:  salt->salt_iter  = ROUNDS_SHA512OSX;
                 break;
    case  7200:  salt->salt_iter  = ROUNDS_GRUB;
                 break;
    case  7400:  salt->salt_iter  = ROUNDS_SHA256CRYPT;
                 break;
    case  7900:  salt->salt_iter  = ROUNDS_DRUPAL7;
                 break;
    case  8200:  salt->salt_iter  = ROUNDS_CLOUDKEY;
                 break;
    case  8300:  salt->salt_iter  = ROUNDS_NSEC3;
                 break;
    case  8800:  salt->salt_iter  = ROUNDS_ANDROIDFDE;
                 break;
    case  8900:  salt->salt_iter  = 1;
                 break;
    case  9000:  salt->salt_iter  = ROUNDS_PSAFE2;
                 break;
    case  9100:  salt->salt_iter  = ROUNDS_LOTUS8;
                 break;
    case  9200:  salt->salt_iter  = ROUNDS_CISCO8;
                 break;
    case  9300:  salt->salt_iter  = 1;
                 break;
    case  9400:  salt->salt_iter  = ROUNDS_OFFICE2007;
                 break;
    case  9500:  salt->salt_iter  = ROUNDS_OFFICE2010;
                 break;
    case  9600:  salt->salt_iter  = ROUNDS_OFFICE2013;
                 break;
    case 10000:  salt->salt_iter  = ROUNDS_DJANGOPBKDF2;
                 break;
    case 10300:  salt->salt_iter  = ROUNDS_SAPH_SHA1 - 1;
                 break;
    case 10500:  salt->salt_iter  = ROUNDS_PDF14;
                 break;
    case 10700:  salt->salt_iter  = ROUNDS_PDF17L8;
                 break;
    case 10900:  salt->salt_iter  = ROUNDS_PBKDF2_SHA256 - 1;
                 break;
    case 11300:  salt->salt_iter  = ROUNDS_BITCOIN_WALLET - 1;
                 break;
    case 11600:  salt->salt_iter  = ROUNDS_SEVEN_ZIP;
                 break;
    case 11900:  salt->salt_iter  = ROUNDS_PBKDF2_MD5 - 1;
                 break;
    case 12000:  salt->salt_iter  = ROUNDS_PBKDF2_SHA1 - 1;
                 break;
    case 12001:  salt->salt_iter  = ROUNDS_ATLASSIAN - 1;
                 break;
    case 12100:  salt->salt_iter  = ROUNDS_PBKDF2_SHA512 - 1;
                 break;
    case 12200:  salt->salt_iter  = ROUNDS_ECRYPTFS - 1;
                 break;
    case 12300:  salt->salt_iter  = ROUNDS_ORACLET - 1;
                 break;
    case 12400:  salt->salt_iter  = ROUNDS_BSDICRYPT - 1;
                 break;
    case 12500:  salt->salt_iter  = ROUNDS_RAR3;
                 break;
    case 12700:  salt->salt_iter  = ROUNDS_MYWALLET;
                 break;
    case 12800:  salt->salt_iter  = ROUNDS_MS_DRSR - 1;
                 break;
    case 12900:  salt->salt_iter  = ROUNDS_ANDROIDFDE_SAMSUNG - 1;
                 break;
    case 13000:  salt->salt_iter  = ROUNDS_RAR5 - 1;
                 break;
    case 13200:  salt->salt_iter  = ROUNDS_AXCRYPT;
                 break;
    case 13400:  salt->salt_iter  = ROUNDS_KEEPASS;
                 break;
    case 13600:  salt->salt_iter  = ROUNDS_ZIP2;
                 break;
    case 13711:  salt->salt_iter  = ROUNDS_VERACRYPT_655331;
                 break;
    case 13712:  salt->salt_iter  = ROUNDS_VERACRYPT_655331;
                 break;
    case 13713:  salt->salt_iter  = ROUNDS_VERACRYPT_655331;
                 break;
    case 13721:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13722:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13723:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13731:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13732:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13733:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13741:  salt->salt_iter  = ROUNDS_VERACRYPT_327661;
                 break;
    case 13742:  salt->salt_iter  = ROUNDS_VERACRYPT_327661;
                 break;
    case 13743:  salt->salt_iter  = ROUNDS_VERACRYPT_327661;
                 break;
    case 13751:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13752:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13753:  salt->salt_iter  = ROUNDS_VERACRYPT_500000;
                 break;
    case 13761:  salt->salt_iter  = ROUNDS_VERACRYPT_200000;
                 break;
    case 13762:  salt->salt_iter  = ROUNDS_VERACRYPT_200000;
                 break;
    case 13763:  salt->salt_iter  = ROUNDS_VERACRYPT_200000;
                 break;
    case 14600:  salt->salt_iter  = ROUNDS_LUKS;
                 break;
    case 14700:  salt->salt_iter  = ROUNDS_ITUNES9_BACKUP - 1;
                 break;
    case 14800:  salt->salt_iter  = ROUNDS_ITUNES101_BACKUP - 1;
                 salt->salt_iter2 = ROUNDS_ITUNES102_BACKUP - 1;
                 break;
    case 15100:  salt->salt_iter  = ROUNDS_NETBSD_SHA1CRYPT - 1;
                 break;
    case 15200:  salt->salt_iter  = ROUNDS_MYWALLETV2;
                 break;
    case 15300:  salt->salt_iter  = ROUNDS_DPAPIMK;
                 break;
    case 15600:  salt->salt_iter  = ROUNDS_ETHEREUM_PBKDF2;
                 break;
    case 15700:  salt->salt_iter  = 1;
                 break;
  }
}

const char *hashconfig_benchmark_mask (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *mask = NULL;

  switch (hashconfig->hash_mode)
  {
    case  2500: mask = "?a?a?a?a?a?a?a?a";
                break;
    case  9710: mask = "?b?b?b?b?b";
                break;
    case  9810: mask = "?b?b?b?b?b";
                break;
    case 10410: mask = "?b?b?b?b?b";
                break;
    case 12500: mask = "?b?b?b?b?b";
                break;
    case 14000: mask = "?b?b?b?b?b?b?bx";
                break;
    case 14100: mask = "?b?b?b?b?b?b?bxxxxxxxxxxxxxxxxx";
                break;
    case 14900: mask = "?b?b?b?b?bxxxxx";
                break;
    default:    mask = "?b?b?b?b?b?b?b";
                break;
  }

  return mask;
}
