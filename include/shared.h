/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef SHARED_H
#define SHARED_H

#include "common.h"
#include "inc_hash_constants.h"

/**
 * thread management
 */

#ifdef _WIN
#define hc_timer_get(a,r)           { hc_timer_t hr_freq; QueryPerformanceFrequency (&hr_freq); hc_timer_t hr_tmp; hc_timer_set (&hr_tmp); (r) = (double) ((double) (hr_tmp.QuadPart - (a).QuadPart) / (double) (hr_freq.QuadPart / 1000)); }
#define hc_timer_set(a)             { QueryPerformanceCounter ((a)); }
#elif _POSIX
#define hc_timer_get(a,r)           { hc_timer_t hr_tmp; hc_timer_set (&hr_tmp); (r) = (double) (((hr_tmp.tv_sec - (a).tv_sec) * 1000) + ((double) (hr_tmp.tv_usec - (a).tv_usec) / 1000)); }
#define hc_timer_set(a)             { gettimeofday ((a), NULL); }
#endif

#ifdef _WIN
#define hc_thread_create(t,f,a)     t = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) &f, a, 0, NULL)
#define hc_thread_wait(n,a)         for (uint i = 0; i < n; i++) WaitForSingleObject ((a)[i], INFINITE)
#define hc_thread_exit(t)           ExitThread (t)

#define hc_thread_mutex_lock(m)     EnterCriticalSection      (&m)
#define hc_thread_mutex_unlock(m)   LeaveCriticalSection      (&m)
#define hc_thread_mutex_init(m)     InitializeCriticalSection (&m)
#define hc_thread_mutex_delete(m)   DeleteCriticalSection     (&m)

#elif _POSIX

#define hc_thread_create(t,f,a)     pthread_create (&t, NULL, f, a)
#define hc_thread_wait(n,a)         for (uint i = 0; i < n; i++) pthread_join ((a)[i], NULL)
#define hc_thread_exit(t)           pthread_exit (&t)

#define hc_thread_mutex_lock(m)     pthread_mutex_lock     (&m)
#define hc_thread_mutex_unlock(m)   pthread_mutex_unlock   (&m)
#define hc_thread_mutex_init(m)     pthread_mutex_init     (&m, NULL)
#define hc_thread_mutex_delete(m)   pthread_mutex_destroy  (&m)
#endif

#ifdef __APPLE__
typedef struct cpu_set
{
  uint32_t count;

} cpu_set_t;

static inline void CPU_ZERO  (cpu_set_t *cs)          { cs->count = 0; }
static inline void CPU_SET   (int num, cpu_set_t *cs) { cs->count |= (1 << num); }
static inline int  CPU_ISSET (int num, cpu_set_t *cs) { return (cs->count & (1 << num)); }
#endif

/**
 * libraries stuff
 */

#ifdef _WIN
#define hc_dlopen LoadLibrary
#define hc_dlclose FreeLibrary
#define hc_dlsym GetProcAddress
#else
#define hc_dlopen dlopen
#define hc_dlclose dlclose
#define hc_dlsym dlsym
#endif

#define HC_LOAD_FUNC2(ptr,name,type,var,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->var, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        log_error ("ERROR: %s is missing from %s shared library.", #name, #libname); \
        exit (-1); \
      } else { \
        log_info ("WARNING: %s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } \
    } \
  }

#define HC_LOAD_FUNC(ptr,name,type,libname,noerr) \
  ptr->name = (type) hc_dlsym (ptr->lib, #name); \
  if (noerr != -1) { \
    if (!ptr->name) { \
      if (noerr == 1) { \
        log_error ("ERROR: %s is missing from %s shared library.", #name, #libname); \
        exit (-1); \
      } else { \
        log_info ("WARNING: %s is missing from %s shared library.", #name, #libname); \
        return -1; \
      } \
    } \
  }

#define HC_LOAD_ADDR(ptr,name,type,func,addr,libname,noerr) \
  ptr->name = (type) (*ptr->func) (addr); \
  if (!ptr->name) { \
    if (noerr == 1) { \
      log_error ("ERROR: %s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      exit (-1); \
    } else { \
      log_error ("WARNING: %s at address %08x is missing from %s shared library.", #name, addr, #libname); \
      return -1; \
    } \
  }

/**
 * system stuff
 */

#ifdef _WIN
#define hc_sleep(x) Sleep ((x) * 1000);
#elif _POSIX
#define hc_sleep(x) sleep ((x));
#endif

#include "ext_OpenCL.h"

/**
 * temperature management
 */

#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"

/**
 * shared stuff
 */

#define ETC_MAX                 (60 * 60 * 24 * 365 * 10)

#define DEVICES_MAX             128

#define CL_PLATFORMS_MAX        16

static const char CL_VENDOR_AMD[]           = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[]         = "Apple";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[]     = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]          = "Mesa";
static const char CL_VENDOR_NV[]            = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]          = "The pocl project";

typedef enum vendor_id
{
  VENDOR_ID_AMD           = (1 << 0),
  VENDOR_ID_APPLE         = (1 << 1),
  VENDOR_ID_INTEL_BEIGNET = (1 << 2),
  VENDOR_ID_INTEL_SDK     = (1 << 3),
  VENDOR_ID_MESA          = (1 << 4),
  VENDOR_ID_NV            = (1 << 5),
  VENDOR_ID_POCL          = (1 << 6),
  VENDOR_ID_AMD_USE_INTEL = (1 << 7),
  VENDOR_ID_GENERIC       = (1 << 31)

} vendor_id_t;

#define BLOCK_SIZE              64

#define CHARSIZ                 0x100
#define INFOSZ                  CHARSIZ

#define SP_HCSTAT               "hashcat.hcstat"
#define SP_PW_MIN               2
#define SP_PW_MAX               64
#define SP_ROOT_CNT             (SP_PW_MAX * CHARSIZ)
#define SP_MARKOV_CNT           (SP_PW_MAX * CHARSIZ * CHARSIZ)

#define TUNING_DB_FILE          "hashcat.hctune"

#define INDUCT_DIR              "induct"
#define OUTFILES_DIR            "outfiles"

#define LOOPBACK_FILE           "hashcat.loopback"

#define DICTSTAT_FILENAME       "hashcat.dictstat"
#define POTFILE_FILENAME        "hashcat.pot"

/**
 * types
 */

#ifdef _WIN
typedef LARGE_INTEGER     hc_timer_t;
typedef HANDLE            hc_thread_t;
typedef CRITICAL_SECTION  hc_thread_mutex_t;
#elif _POSIX
typedef struct timeval    hc_timer_t;
typedef pthread_t         hc_thread_t;
typedef pthread_mutex_t   hc_thread_mutex_t;
#endif

#include "types.h"
#include "rp_cpu.h"
#include "inc_rp.h"

/**
 * valid project specific global stuff
 */

extern const uint  VERSION_BIN;
extern const uint  RESTORE_MIN;

extern const char *USAGE_MINI[];
extern const char *USAGE_BIG[];

extern const char *PROMPT;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_display;

/**
 * Strings
 */

static const char HT_00000[] = "MD5";
static const char HT_00010[] = "md5($pass.$salt)";
static const char HT_00020[] = "md5($salt.$pass)";
static const char HT_00030[] = "md5(unicode($pass).$salt)";
static const char HT_00040[] = "md5($salt.unicode($pass))";
static const char HT_00050[] = "HMAC-MD5 (key = $pass)";
static const char HT_00060[] = "HMAC-MD5 (key = $salt)";
static const char HT_00100[] = "SHA1";
static const char HT_00110[] = "sha1($pass.$salt)";
static const char HT_00120[] = "sha1($salt.$pass)";
static const char HT_00130[] = "sha1(unicode($pass).$salt)";
static const char HT_00140[] = "sha1($salt.unicode($pass))";
static const char HT_00150[] = "HMAC-SHA1 (key = $pass)";
static const char HT_00160[] = "HMAC-SHA1 (key = $salt)";
static const char HT_00200[] = "MySQL323";
static const char HT_00300[] = "MySQL4.1/MySQL5";
static const char HT_00400[] = "phpass, MD5(Wordpress), MD5(phpBB3), MD5(Joomla)";
static const char HT_00500[] = "md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5";
static const char HT_00501[] = "Juniper IVE";
static const char HT_00900[] = "MD4";
static const char HT_00910[] = "md4($pass.$salt)";
static const char HT_01000[] = "NTLM";
static const char HT_01100[] = "Domain Cached Credentials (DCC), MS Cache";
static const char HT_01400[] = "SHA256";
static const char HT_01410[] = "sha256($pass.$salt)";
static const char HT_01420[] = "sha256($salt.$pass)";
static const char HT_01430[] = "sha256(unicode($pass).$salt)";
static const char HT_01440[] = "sha256($salt.$pass)";
static const char HT_01450[] = "HMAC-SHA256 (key = $pass)";
static const char HT_01460[] = "HMAC-SHA256 (key = $salt)";
static const char HT_01500[] = "descrypt, DES(Unix), Traditional DES";
static const char HT_01600[] = "md5apr1, MD5(APR), Apache MD5";
static const char HT_01700[] = "SHA512";
static const char HT_01710[] = "sha512($pass.$salt)";
static const char HT_01720[] = "sha512($salt.$pass)";
static const char HT_01730[] = "sha512(unicode($pass).$salt)";
static const char HT_01740[] = "sha512($salt.unicode($pass))";
static const char HT_01750[] = "HMAC-SHA512 (key = $pass)";
static const char HT_01760[] = "HMAC-SHA512 (key = $salt)";
static const char HT_01800[] = "sha512crypt, SHA512(Unix)";
static const char HT_02100[] = "Domain Cached Credentials 2 (DCC2), MS Cache 2";
static const char HT_02400[] = "Cisco-PIX MD5";
static const char HT_02410[] = "Cisco-ASA MD5";
static const char HT_02500[] = "WPA/WPA2";
static const char HT_02600[] = "Double MD5";
static const char HT_03000[] = "LM";
static const char HT_03100[] = "Oracle H: Type (Oracle 7+)";
static const char HT_03200[] = "bcrypt, Blowfish(OpenBSD)";
static const char HT_03710[] = "md5($salt.md5($pass))";
static const char HT_03711[] = "Mediawiki B type";
static const char HT_03800[] = "md5($salt.$pass.$salt)";
static const char HT_04300[] = "md5(strtoupper(md5($pass)))";
static const char HT_04400[] = "md5(sha1($pass))";
static const char HT_04500[] = "Double SHA1";
static const char HT_04700[] = "sha1(md5($pass))";
static const char HT_04800[] = "MD5(Chap), iSCSI CHAP authentication";
static const char HT_04900[] = "sha1($salt.$pass.$salt)";
static const char HT_05000[] = "SHA-3(Keccak)";
static const char HT_05100[] = "Half MD5";
static const char HT_05200[] = "Password Safe v3";
static const char HT_05300[] = "IKE-PSK MD5";
static const char HT_05400[] = "IKE-PSK SHA1";
static const char HT_05500[] = "NetNTLMv1-VANILLA / NetNTLMv1+ESS";
static const char HT_05600[] = "NetNTLMv2";
static const char HT_05700[] = "Cisco-IOS SHA256";
static const char HT_05800[] = "Android PIN";
static const char HT_06000[] = "RipeMD160";
static const char HT_06100[] = "Whirlpool";
static const char HT_06300[] = "AIX {smd5}";
static const char HT_06400[] = "AIX {ssha256}";
static const char HT_06500[] = "AIX {ssha512}";
static const char HT_06600[] = "1Password, agilekeychain";
static const char HT_06700[] = "AIX {ssha1}";
static const char HT_06800[] = "Lastpass";
static const char HT_06900[] = "GOST R 34.11-94";
static const char HT_07100[] = "OSX v10.8+";
static const char HT_07200[] = "GRUB 2";
static const char HT_07300[] = "IPMI2 RAKP HMAC-SHA1";
static const char HT_07400[] = "sha256crypt, SHA256(Unix)";
static const char HT_07500[] = "Kerberos 5 AS-REQ Pre-Auth etype 23";
static const char HT_07600[] = "Redmine Project Management Web App";
static const char HT_07700[] = "SAP CODVN B (BCODE)";
static const char HT_07800[] = "SAP CODVN F/G (PASSCODE)";
static const char HT_07900[] = "Drupal7";
static const char HT_08000[] = "Sybase ASE";
static const char HT_08100[] = "Citrix NetScaler";
static const char HT_08200[] = "1Password, cloudkeychain";
static const char HT_08300[] = "DNSSEC (NSEC3)";
static const char HT_08400[] = "WBB3, Woltlab Burning Board 3";
static const char HT_08500[] = "RACF";
static const char HT_08600[] = "Lotus Notes/Domino 5";
static const char HT_08700[] = "Lotus Notes/Domino 6";
static const char HT_08800[] = "Android FDE <= 4.3";
static const char HT_08900[] = "scrypt";
static const char HT_09000[] = "Password Safe v2";
static const char HT_09100[] = "Lotus Notes/Domino 8";
static const char HT_09200[] = "Cisco $8$";
static const char HT_09300[] = "Cisco $9$";
static const char HT_09400[] = "Office 2007";
static const char HT_09500[] = "Office 2010";
static const char HT_09600[] = "Office 2013";
static const char HT_09700[] = "MS Office <= 2003 MD5 + RC4, oldoffice$0, oldoffice$1";
static const char HT_09710[] = "MS Office <= 2003 MD5 + RC4, collision-mode #1";
static const char HT_09720[] = "MS Office <= 2003 MD5 + RC4, collision-mode #2";
static const char HT_09800[] = "MS Office <= 2003 SHA1 + RC4, oldoffice$3, oldoffice$4";
static const char HT_09810[] = "MS Office <= 2003 SHA1 + RC4, collision-mode #1";
static const char HT_09820[] = "MS Office <= 2003 SHA1 + RC4, collision-mode #2";
static const char HT_09900[] = "Radmin2";
static const char HT_10000[] = "Django (PBKDF2-SHA256)";
static const char HT_10100[] = "SipHash";
static const char HT_10200[] = "Cram MD5";
static const char HT_10300[] = "SAP CODVN H (PWDSALTEDHASH) iSSHA-1";
static const char HT_10400[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4)";
static const char HT_10410[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #1";
static const char HT_10420[] = "PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #2";
static const char HT_10500[] = "PDF 1.4 - 1.6 (Acrobat 5 - 8)";
static const char HT_10600[] = "PDF 1.7 Level 3 (Acrobat 9)";
static const char HT_10700[] = "PDF 1.7 Level 8 (Acrobat 10 - 11)";
static const char HT_10800[] = "SHA384";
static const char HT_10900[] = "PBKDF2-HMAC-SHA256";
static const char HT_11000[] = "PrestaShop";
static const char HT_11100[] = "PostgreSQL Challenge-Response Authentication (MD5)";
static const char HT_11200[] = "MySQL Challenge-Response Authentication (SHA1)";
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
static const char HT_12400[] = "BSDiCrypt, Extended DES";
static const char HT_12500[] = "RAR3-hp";
static const char HT_12600[] = "ColdFusion 10+";
static const char HT_12700[] = "Blockchain, My Wallet";
static const char HT_12800[] = "MS-AzureSync PBKDF2-HMAC-SHA256";
static const char HT_12900[] = "Android FDE (Samsung DEK)";
static const char HT_13000[] = "RAR5";
static const char HT_13100[] = "Kerberos 5 TGS-REP etype 23";
static const char HT_13200[] = "AxCrypt";
static const char HT_13300[] = "AxCrypt in memory SHA1";
static const char HT_13400[] = "Keepass 1 (AES/Twofish) and Keepass 2 (AES)";
static const char HT_13500[] = "PeopleSoft PS_TOKEN";
static const char HT_13600[] = "WinZip";
static const char HT_13800[] = "Windows 8+ phone PIN/Password";
static const char HT_13900[] = "OpenCart";
static const char HT_14000[] = "DES (PT = $salt, key = $pass)";
static const char HT_14100[] = "3DES (PT = $salt, key = $pass)";

static const char HT_00011[] = "Joomla < 2.5.18";
static const char HT_00012[] = "PostgreSQL";
static const char HT_00021[] = "osCommerce, xt:Commerce";
static const char HT_00022[] = "Juniper Netscreen/SSG (ScreenOS)";
static const char HT_00023[] = "Skype";
static const char HT_00101[] = "SHA-1(Base64), nsldap, Netscape LDAP SHA";
static const char HT_00111[] = "SSHA-1(Base64), nsldaps, Netscape LDAP SSHA";
static const char HT_00112[] = "Oracle S: Type (Oracle 11+)";
static const char HT_00121[] = "SMF > v1.1";
static const char HT_00122[] = "OSX v10.4, v10.5, v10.6";
static const char HT_00124[] = "Django (SHA-1)";
static const char HT_00125[] = "ArubaOS";
static const char HT_00131[] = "MSSQL(2000)";
static const char HT_00132[] = "MSSQL(2005)";
static const char HT_00133[] = "PeopleSoft";
static const char HT_00141[] = "EPiServer 6.x < v4";
static const char HT_01421[] = "hMailServer";
static const char HT_01441[] = "EPiServer 6.x > v4";
static const char HT_01711[] = "SSHA-512(Base64), LDAP {SSHA512}";
static const char HT_01722[] = "OSX v10.7";
static const char HT_01731[] = "MSSQL(2012)";
static const char HT_02611[] = "vBulletin < v3.8.5";
static const char HT_02612[] = "PHPS";
static const char HT_02711[] = "vBulletin > v3.8.5";
static const char HT_02811[] = "IPB2+, MyBB1.2+";
static const char HT_06211[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 512 bit";
static const char HT_06212[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 1024 bit";
static const char HT_06213[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 1536 bit";
static const char HT_06221[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit";
static const char HT_06222[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 1024 bit";
static const char HT_06223[] = "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 1536 bit";
static const char HT_06231[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit";
static const char HT_06232[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 1024 bit";
static const char HT_06233[] = "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 1536 bit";
static const char HT_06241[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 512 bit + boot-mode";
static const char HT_06242[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 1024 bit + boot-mode";
static const char HT_06243[] = "TrueCrypt PBKDF2-HMAC-RipeMD160 + XTS 1536 bit + boot-mode";
static const char HT_13711[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 512 bit";
static const char HT_13712[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 1024 bit";
static const char HT_13713[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 1536 bit";
static const char HT_13721[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit";
static const char HT_13722[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 1024 bit";
static const char HT_13723[] = "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 1536 bit";
static const char HT_13731[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit";
static const char HT_13732[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 1024 bit";
static const char HT_13733[] = "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 1536 bit";
static const char HT_13741[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 512 bit + boot-mode";
static const char HT_13742[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 1024 bit + boot-mode";
static const char HT_13743[] = "VeraCrypt PBKDF2-HMAC-RipeMD160 + XTS 1536 bit + boot-mode";
static const char HT_13751[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit";
static const char HT_13752[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1024 bit";
static const char HT_13753[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1536 bit";
static const char HT_13761[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 512 bit + boot-mode";
static const char HT_13762[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1024 bit + boot-mode";
static const char HT_13763[] = "VeraCrypt PBKDF2-HMAC-SHA256 + XTS 1536 bit + boot-mode";

/**
 * Outfile formats
 */

typedef enum outfile_fmt
{
  OUTFILE_FMT_HASH      = (1 << 0),
  OUTFILE_FMT_PLAIN     = (1 << 1),
  OUTFILE_FMT_HEXPLAIN  = (1 << 2),
  OUTFILE_FMT_CRACKPOS  = (1 << 3)

} outfile_fmt_t;

/**
 * algo specific
 */

typedef enum display_len
{
  DISPLAY_LEN_MIN_0     = 32,
  DISPLAY_LEN_MAX_0     = 32,
  DISPLAY_LEN_MIN_10    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_10    = 32 + 1 + 51,
  DISPLAY_LEN_MIN_10H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_10H   = 32 + 1 + 102,
  DISPLAY_LEN_MIN_20    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_20    = 32 + 1 + 31,
  DISPLAY_LEN_MIN_20H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_20H   = 32 + 1 + 62,
  DISPLAY_LEN_MIN_50    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_50    = 32 + 1 + 51,
  DISPLAY_LEN_MIN_50H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_50H   = 32 + 1 + 102,
  DISPLAY_LEN_MIN_100   = 40,
  DISPLAY_LEN_MAX_100   = 40,
  DISPLAY_LEN_MIN_110   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_110   = 40 + 1 + 51,
  DISPLAY_LEN_MIN_110H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_110H  = 40 + 1 + 102,
  DISPLAY_LEN_MIN_120   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_120   = 40 + 1 + 31,
  DISPLAY_LEN_MIN_120H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_120H  = 40 + 1 + 62,
  DISPLAY_LEN_MIN_150   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_150   = 40 + 1 + 51,
  DISPLAY_LEN_MIN_150H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_150H  = 40 + 1 + 102,
  DISPLAY_LEN_MIN_200   = 16,
  DISPLAY_LEN_MAX_200   = 16,
  DISPLAY_LEN_MIN_300   = 40,
  DISPLAY_LEN_MAX_300   = 40,
  DISPLAY_LEN_MIN_400   = 34,
  DISPLAY_LEN_MAX_400   = 34,
  DISPLAY_LEN_MIN_500   = 3 + 1 + 0 + 22,
  DISPLAY_LEN_MIN_501   = 104,
  DISPLAY_LEN_MAX_500   = 3 + 1 + 8 + 22,
  DISPLAY_LEN_MAX_501   = 104,
  DISPLAY_LEN_MIN_900   = 32,
  DISPLAY_LEN_MAX_900   = 32,
  DISPLAY_LEN_MIN_910   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_910   = 32 + 1 + 51,
  DISPLAY_LEN_MIN_910H  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_910H  = 32 + 1 + 102,
  DISPLAY_LEN_MIN_1000  = 32,
  DISPLAY_LEN_MAX_1000  = 32,
  DISPLAY_LEN_MIN_1100  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_1100  = 32 + 1 + 19,
  DISPLAY_LEN_MIN_1100H = 32 + 1 + 0,
  DISPLAY_LEN_MAX_1100H = 32 + 1 + 38,
  DISPLAY_LEN_MIN_1400  = 64,
  DISPLAY_LEN_MAX_1400  = 64,
  DISPLAY_LEN_MIN_1410  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1410  = 64 + 1 + 51,
  DISPLAY_LEN_MIN_1410H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1410H = 64 + 1 + 102,
  DISPLAY_LEN_MIN_1420  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1420  = 64 + 1 + 16,
  DISPLAY_LEN_MIN_1420H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1420H = 64 + 1 + 32,
  DISPLAY_LEN_MIN_1421  = 70,
  DISPLAY_LEN_MAX_1421  = 70,
  DISPLAY_LEN_MIN_1450  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1450  = 64 + 1 + 51,
  DISPLAY_LEN_MIN_1450H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1450H = 64 + 1 + 102,
  DISPLAY_LEN_MIN_1500  = 13,
  DISPLAY_LEN_MAX_1500  = 13,
  DISPLAY_LEN_MIN_1600  = 29 + 0,
  DISPLAY_LEN_MAX_1600  = 29 + 8,
  DISPLAY_LEN_MIN_1700  = 128,
  DISPLAY_LEN_MAX_1700  = 128,
  DISPLAY_LEN_MIN_1710  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1710  = 128 + 1 + 51,
  DISPLAY_LEN_MIN_1710H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1710H = 128 + 1 + 102,
  DISPLAY_LEN_MIN_1720  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1720  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1720H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1720H = 128 + 1 + 32,
  DISPLAY_LEN_MIN_1730  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1730  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1731  = 128 + 6 + 0,
  DISPLAY_LEN_MAX_1731  = 128 + 6 + 16,
  DISPLAY_LEN_MIN_1740  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1740  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1750  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1750  = 128 + 1 + 51,
  DISPLAY_LEN_MIN_1750H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1750H = 128 + 1 + 102,
  DISPLAY_LEN_MIN_1800  = 90 + 0,
  DISPLAY_LEN_MAX_1800  = 90 + 16,
  DISPLAY_LEN_MIN_2100  = 6 + 1 + 1 + 32 + 1 + 0,
  DISPLAY_LEN_MAX_2100  = 6 + 5 + 1 + 32 + 1 + 19,
  DISPLAY_LEN_MIN_2100H = 6 + 1 + 1 + 32 + 1 + 0,
  DISPLAY_LEN_MAX_2100H = 6 + 5 + 1 + 32 + 1 + 38,
  DISPLAY_LEN_MIN_2400  = 16,
  DISPLAY_LEN_MAX_2400  = 16,
  DISPLAY_LEN_MIN_2410  = 16 + 1 + 0,
  DISPLAY_LEN_MAX_2410  = 16 + 1 + 16,
  DISPLAY_LEN_MIN_2410H = 16 + 1 + 0,
  DISPLAY_LEN_MAX_2410H = 16 + 1 + 32,
  DISPLAY_LEN_MIN_2500  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_2500  = 64 + 1 + 15,
  DISPLAY_LEN_MIN_2600  = 32,
  DISPLAY_LEN_MAX_2600  = 32,
  DISPLAY_LEN_MIN_3000  = 16,
  DISPLAY_LEN_MAX_3000  = 16,
  DISPLAY_LEN_MIN_3100  = 16 + 1 + 0,
  DISPLAY_LEN_MAX_3100  = 16 + 1 + 30,
  DISPLAY_LEN_MIN_3100H = 16 + 1 + 0,
  DISPLAY_LEN_MAX_3100H = 16 + 1 + 60,
  DISPLAY_LEN_MIN_3200  = 60,
  DISPLAY_LEN_MAX_3200  = 60,
  DISPLAY_LEN_MIN_3711  = 3 +  0 + 1 + 32,
  DISPLAY_LEN_MAX_3711  = 3 + 31 + 1 + 32,
  DISPLAY_LEN_MIN_4300  = 32,
  DISPLAY_LEN_MAX_4300  = 32,
  DISPLAY_LEN_MIN_4800  = 32 + 1 + 32 + 1 + 2,
  DISPLAY_LEN_MAX_4800  = 32 + 1 + 32 + 1 + 2,
  DISPLAY_LEN_MIN_5000  = 16,
  DISPLAY_LEN_MAX_5000  = 400,
  DISPLAY_LEN_MIN_5100  = 16,
  DISPLAY_LEN_MAX_5100  = 16,
  DISPLAY_LEN_MIN_5300  = 48,
  DISPLAY_LEN_MAX_5300  = 1024,
  DISPLAY_LEN_MIN_5400  = 56,
  DISPLAY_LEN_MAX_5400  = 1024,
  DISPLAY_LEN_MIN_5500  =  1 + 1 + 0 +  1 +  1 +  1 +  0 +  1 + 48 + 1 + 16,
  DISPLAY_LEN_MAX_5500  = 60 + 1 + 0 +  1 + 45 +  1 + 48 +  1 + 48 + 1 + 16,
  DISPLAY_LEN_MIN_5600  =  1 + 1 + 0 +  1 +  1 +  1 + 16 +  1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_5600  = 60 + 1 + 0 +  1 + 45 +  1 + 16 +  1 + 32 + 1 + 1024,
  DISPLAY_LEN_MIN_5700  = 43,
  DISPLAY_LEN_MAX_5700  = 43,
  DISPLAY_LEN_MIN_5800  = 40 + 1 + 1,
  DISPLAY_LEN_MAX_5800  = 40 + 1 + 16,
  DISPLAY_LEN_MIN_6000  = 40,
  DISPLAY_LEN_MAX_6000  = 40,
  DISPLAY_LEN_MIN_6100  = 128,
  DISPLAY_LEN_MAX_6100  = 128,
  DISPLAY_LEN_MIN_6300  =  6 + 1 + 8 + 22,
  DISPLAY_LEN_MAX_6300  =  6 + 1 + 48 + 22,
  DISPLAY_LEN_MIN_6400  =  9 + 2 + 1 + 16 + 1 + 43,
  DISPLAY_LEN_MAX_6400  =  9 + 2 + 1 + 48 + 1 + 43,
  DISPLAY_LEN_MIN_6500  =  9 + 2 + 1 + 16 + 1 + 86,
  DISPLAY_LEN_MAX_6500  =  9 + 2 + 1 + 48 + 1 + 86,
  DISPLAY_LEN_MIN_6600  =  1 + 1 + 16 + 1 + 2080,
  DISPLAY_LEN_MAX_6600  =  6 + 1 + 16 + 1 + 2080,
  DISPLAY_LEN_MIN_6700  =  7 + 2 + 1 + 16 + 1 + 27,
  DISPLAY_LEN_MAX_6700  =  7 + 2 + 1 + 48 + 1 + 27,
  DISPLAY_LEN_MIN_6800  = 32 + 1 + 1 + 1 + 0,
  DISPLAY_LEN_MAX_6800  = 32 + 1 + 5 + 1 + 32,
  DISPLAY_LEN_MIN_6900  = 64,
  DISPLAY_LEN_MAX_6900  = 64,
  DISPLAY_LEN_MIN_7100  =  4 + 2 + 1 + 64 + 1 + 128,
  DISPLAY_LEN_MAX_7100  =  4 + 5 + 1 + 64 + 1 + 128,
  DISPLAY_LEN_MIN_7200  = 19 + 1 + 1 +   1 + 128,
  DISPLAY_LEN_MAX_7200  = 19 + 5 + 1 + 224 + 128,
  DISPLAY_LEN_MIN_7300  =  64 + 1 + 40,
  DISPLAY_LEN_MAX_7300  = 512 + 1 + 40,
  DISPLAY_LEN_MIN_7400  = 47 + 0,
  DISPLAY_LEN_MAX_7400  = 47 + 16,
  DISPLAY_LEN_MIN_7500  =  1 + 6 + 1 + 2 + 1 +  0 + 1 +  0 + 1 +   0 + 1 + 72 + 32,
  DISPLAY_LEN_MAX_7500  =  1 + 6 + 1 + 2 + 1 + 64 + 1 + 64 + 1 + 128 + 1 + 72 + 32,
  DISPLAY_LEN_MIN_7700  =  1 + 1 + 16,
  DISPLAY_LEN_MAX_7700  = 40 + 1 + 16,
  DISPLAY_LEN_MIN_7800  =  1 + 1 + 40,
  DISPLAY_LEN_MAX_7800  = 40 + 1 + 40,
  DISPLAY_LEN_MIN_7900  =  3 + 1 + 8 + 43,
  DISPLAY_LEN_MAX_7900  =  3 + 1 + 8 + 43,
  DISPLAY_LEN_MIN_8000  =  2 + 4 + 16 + 64,
  DISPLAY_LEN_MAX_8000  =  2 + 4 + 16 + 64,
  DISPLAY_LEN_MIN_8100  =  1 + 8 + 40,
  DISPLAY_LEN_MAX_8100  =  1 + 8 + 40,
  DISPLAY_LEN_MIN_8200  = 64 + 1 + 32 + 1 + 1 + 1 +    1,
  DISPLAY_LEN_MAX_8200  = 64 + 1 + 32 + 1 + 8 + 1 + 2048,
  DISPLAY_LEN_MIN_8300  = 32 + 1 +  1 + 1 +  1 + 1 + 1,
  DISPLAY_LEN_MAX_8300  = 32 + 1 + 32 + 1 + 32 + 1 + 5,
  DISPLAY_LEN_MIN_8400  = 40 + 1 + 40,
  DISPLAY_LEN_MAX_8400  = 40 + 1 + 40,
  DISPLAY_LEN_MIN_8500  =  6 + 1 + 1 + 1 +  1,
  DISPLAY_LEN_MAX_8500  =  6 + 1 + 8 + 1 + 16,
  DISPLAY_LEN_MIN_8600  = 32,
  DISPLAY_LEN_MAX_8600  = 32,
  DISPLAY_LEN_MIN_8700  = 22,
  DISPLAY_LEN_MAX_8700  = 22,
  DISPLAY_LEN_MIN_8800  = 1 + 3 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 3072,
  DISPLAY_LEN_MAX_8800  = 1 + 3 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 3072,
  DISPLAY_LEN_MIN_8900  = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 +  0 + 1 + 44,
  DISPLAY_LEN_MAX_8900  = 6 + 1 + 6 + 1 + 2 + 1 + 2 + 1 + 45 + 1 + 44,
  DISPLAY_LEN_MIN_9100  = 51,
  DISPLAY_LEN_MAX_9100  = 51,
  DISPLAY_LEN_MIN_9200  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MAX_9200  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MIN_9300  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MAX_9300  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MIN_9400  = 8 + 1 + 4 + 1 + 2 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MAX_9400  = 8 + 1 + 4 + 1 + 2 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_9500  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_9500  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MIN_9600  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_9600  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MIN_9700  = 12 + 1 + 32 + 1 + 32 + 1 + 32,
  DISPLAY_LEN_MAX_9700  = 12 + 1 + 32 + 1 + 32 + 1 + 32,
  DISPLAY_LEN_MIN_9720  = 12 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + 10,
  DISPLAY_LEN_MAX_9720  = 12 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + 10,
  DISPLAY_LEN_MIN_9800  = 12 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MAX_9800  = 12 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_9820  = 12 + 1 + 32 + 1 + 32 + 1 + 40 + 1 + 10,
  DISPLAY_LEN_MAX_9820  = 12 + 1 + 32 + 1 + 32 + 1 + 40 + 1 + 10,
  DISPLAY_LEN_MIN_9900  = 32,
  DISPLAY_LEN_MAX_9900  = 32,
  DISPLAY_LEN_MIN_10000 = 13 + 1 + 1 + 1 +  0 + 44,
  DISPLAY_LEN_MAX_10000 = 13 + 1 + 6 + 1 + 15 + 44,
  DISPLAY_LEN_MIN_10100 = 16 + 1 + 1 + 1 + 1 + 1 + 32,
  DISPLAY_LEN_MAX_10100 = 16 + 1 + 1 + 1 + 1 + 1 + 32,
  DISPLAY_LEN_MIN_10200 = 10 + 12 + 1 + 44,
  DISPLAY_LEN_MAX_10200 = 10 + 76 + 1 + 132,
  DISPLAY_LEN_MIN_10300 = 10 + 1 + 1 + 33,
  DISPLAY_LEN_MAX_10300 = 10 + 5 + 1 + 49,
  DISPLAY_LEN_MIN_10400 = 5 + 1 + 1 + 1 + 1 + 2 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10400 = 5 + 1 + 1 + 1 + 1 + 2 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10410 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10410 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10420 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64 + 1 + 10,
  DISPLAY_LEN_MAX_10420 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64 + 1 + 10,
  DISPLAY_LEN_MIN_10500 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10500 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 64 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10600 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_10600 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1000,
  DISPLAY_LEN_MIN_10700 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_10700 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1000,
  DISPLAY_LEN_MIN_10800 = 96,
  DISPLAY_LEN_MAX_10800 = 96,
  DISPLAY_LEN_MIN_10900 = 7 + 1 + 1 +  0 + 1 + 24,
  DISPLAY_LEN_MAX_10900 = 7 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_11000 = 32 + 1 + 56,
  DISPLAY_LEN_MAX_11000 = 32 + 1 + 56,
  DISPLAY_LEN_MIN_11100 = 10 +  0 + 1 + 8 + 1 + 32,
  DISPLAY_LEN_MAX_11100 = 10 + 32 + 1 + 8 + 1 + 32,
  DISPLAY_LEN_MIN_11200 = 9 + 40 + 1 + 40,
  DISPLAY_LEN_MAX_11200 = 9 + 40 + 1 + 40,
  DISPLAY_LEN_MIN_11300 = 1 + 7 + 1 + 2 + 1 + 96 + 1 + 2 + 1 + 16 + 1 + 1 + 1 + 2 + 1 + 96 + 1 + 1 + 1 + 2,
  DISPLAY_LEN_MAX_11300 = 1 + 7 + 1 + 2 + 1 + 96 + 1 + 2 + 1 + 16 + 1 + 6 + 1 + 2 + 1 + 96 + 1 + 3 + 1 + 512,
  DISPLAY_LEN_MIN_11400 = 6 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   1 + 1 +   0 + 1 +  1 + 1 +  0 + 1 +  0 + 1 +  0 + 1 + 3 + 1 + 32,
  DISPLAY_LEN_MAX_11400 = 6 + 512 + 1 + 512 + 1 + 116 + 1 + 116 + 1 + 246 + 1 + 245 + 1 + 246 + 1 + 245 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 3 + 1 + 32,
  DISPLAY_LEN_MIN_11500 = 8 + 1 + 8,
  DISPLAY_LEN_MAX_11500 = 8 + 1 + 8,
  DISPLAY_LEN_MIN_11600 = 1 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 1 +  0 + 1 + 1 + 1 + 32 + 1 +  1 + 1 + 1 + 1 + 1 + 1 +   2,
  DISPLAY_LEN_MAX_11600 = 1 + 2 + 1 + 1 + 1 + 2 + 1 + 1 + 1 + 64 + 1 + 1 + 1 + 32 + 1 + 10 + 1 + 3 + 1 + 3 + 1 + 768,
  DISPLAY_LEN_MIN_11700 = 64,
  DISPLAY_LEN_MAX_11700 = 64,
  DISPLAY_LEN_MIN_11800 = 128,
  DISPLAY_LEN_MAX_11800 = 128,
  DISPLAY_LEN_MIN_11900 = 3 + 1 + 1 +  0 + 1 + 12,
  DISPLAY_LEN_MAX_11900 = 3 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12000 = 4 + 1 + 1 +  0 + 1 + 16,
  DISPLAY_LEN_MAX_12000 = 4 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12100 = 6 + 1 + 1 +  0 + 1 + 16,
  DISPLAY_LEN_MAX_12100 = 6 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12200 = 1 + 8 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 16,
  DISPLAY_LEN_MAX_12200 = 1 + 8 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 16,
  DISPLAY_LEN_MIN_12300 = 160,
  DISPLAY_LEN_MAX_12300 = 160,
  DISPLAY_LEN_MIN_12400 = 1 + 4 + 4 + 11,
  DISPLAY_LEN_MAX_12400 = 1 + 4 + 4 + 11,
  DISPLAY_LEN_MIN_12500 = 6 + 1 + 1 + 1 + 16 + 1 + 32,
  DISPLAY_LEN_MAX_12500 = 6 + 1 + 1 + 1 + 16 + 1 + 32,
  DISPLAY_LEN_MIN_12600 = 64 + 1 + 64,
  DISPLAY_LEN_MAX_12600 = 64 + 1 + 64,
  DISPLAY_LEN_MIN_12700 =  1 + 10 + 1 + 1 + 1 + 64,
  DISPLAY_LEN_MAX_12700 =  1 + 10 + 1 + 5 + 1 + 20000,
  DISPLAY_LEN_MIN_12800 = 11 + 1 + 20 + 1 + 1 + 1 + 64,
  DISPLAY_LEN_MAX_12800 = 11 + 1 + 20 + 1 + 5 + 1 + 64,
  DISPLAY_LEN_MIN_12900 = 64 + 64 + 32,
  DISPLAY_LEN_MAX_12900 = 64 + 64 + 32,
  DISPLAY_LEN_MIN_13000 = 1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16,
  DISPLAY_LEN_MAX_13000 = 1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16,
  DISPLAY_LEN_MIN_13100 =  1 + 7 + 1 + 2 + 1 + 0 + 0 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_13100 =  1 + 7 + 1 + 2 + 1 + 2 + 512 + 1 + 32 + 1 + 20480,
  DISPLAY_LEN_MIN_13200 =  1 + 7 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 48,
  DISPLAY_LEN_MAX_13200 =  1 + 7 + 1 + 1 + 1 + 1 + 50 + 1 + 32 + 1 + 48 + 1 + 20480,
  DISPLAY_LEN_MIN_13300 =  1 + 12 + 1 + 32,
  DISPLAY_LEN_MAX_13300 =  1 + 12 + 1 + 40,
  DISPLAY_LEN_MIN_13400 =  1 + 7 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 64 + 1 + 32 + 1 + 64 + 1 + 1 + 1 + 1,
  DISPLAY_LEN_MAX_13400 =  1 + 7 + 1 + 1 + 10 + 1 + 3 + 1 + 64 + 1 + 64 + 1 + 32 + 1 + 64 + 1 + 4 + 1 + 600000 + 1 + 2 + 1 + 64,
  DISPLAY_LEN_MIN_13500 = 40 + 1 + 32,
  DISPLAY_LEN_MAX_13500 = 40 + 1 + 1024,
  DISPLAY_LEN_MIN_13600 = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 1 + 1 + 1 + 1 +    0 + 1 + 20 + 1 + 7,
  DISPLAY_LEN_MAX_13600 = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 4 + 1 + 4 + 1 + 8192 + 1 + 20 + 1 + 7,
  DISPLAY_LEN_MIN_13800 =  64 + 1 + 256,
  DISPLAY_LEN_MAX_13800 =  64 + 1 + 256,
  DISPLAY_LEN_MIN_13900 = 40 + 1 + 9,
  DISPLAY_LEN_MAX_13900 = 40 + 1 + 9,
  DISPLAY_LEN_MIN_14000 = 16 + 1 + 16,
  DISPLAY_LEN_MAX_14000 = 16 + 1 + 16,
  DISPLAY_LEN_MIN_14100 = 16 + 1 + 16,
  DISPLAY_LEN_MAX_14100 = 16 + 1 + 16,

  DISPLAY_LEN_MIN_11    = 32 + 1 + 16,
  DISPLAY_LEN_MAX_11    = 32 + 1 + 32,
  DISPLAY_LEN_MIN_11H   = 32 + 1 + 32,
  DISPLAY_LEN_MAX_11H   = 32 + 1 + 64,
  DISPLAY_LEN_MIN_12    = 32 + 1 + 1,
  DISPLAY_LEN_MAX_12    = 32 + 1 + 32,
  DISPLAY_LEN_MIN_12H   = 32 + 1 + 2,
  DISPLAY_LEN_MAX_12H   = 32 + 1 + 64,
  DISPLAY_LEN_MIN_21    = 32 + 1 + 1,
  DISPLAY_LEN_MAX_21    = 32 + 1 + 15,
  DISPLAY_LEN_MIN_21H   = 32 + 1 + 2,
  DISPLAY_LEN_MAX_21H   = 32 + 1 + 30,
  DISPLAY_LEN_MIN_22    = 30 + 1 + 1,
  DISPLAY_LEN_MAX_22    = 30 + 1 + 28,
  DISPLAY_LEN_MIN_22H   = 30 + 1 + 2,
  DISPLAY_LEN_MAX_22H   = 30 + 1 + 56,
  DISPLAY_LEN_MIN_23    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_23    = 32 + 1 + 23,
  DISPLAY_LEN_MIN_101   =  5 + 28,
  DISPLAY_LEN_MAX_101   =  5 + 28,
  DISPLAY_LEN_MIN_111   =  6 + 28 + 0,
  DISPLAY_LEN_MAX_111   =  6 + 28 + 40,
  DISPLAY_LEN_MIN_112   = 40 + 1 + 20,
  DISPLAY_LEN_MAX_112   = 40 + 1 + 20,
  DISPLAY_LEN_MIN_121   = 40 + 1 + 1,
  DISPLAY_LEN_MAX_121   = 40 + 1 + 32,
  DISPLAY_LEN_MIN_121H  = 40 + 1 + 2,
  DISPLAY_LEN_MAX_121H  = 40 + 1 + 64,
  DISPLAY_LEN_MIN_122   =  8 + 40,
  DISPLAY_LEN_MAX_122   =  8 + 40,
  DISPLAY_LEN_MIN_124   = 4 + 1 +  0 + 1 + 40,
  DISPLAY_LEN_MAX_124   = 4 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_125   = 10 + 40,
  DISPLAY_LEN_MAX_125   = 10 + 40,
  DISPLAY_LEN_MIN_131   =  6 +  8 + 80,
  DISPLAY_LEN_MAX_131   =  6 +  8 + 80,
  DISPLAY_LEN_MIN_132   =  6 +  8 + 40,
  DISPLAY_LEN_MAX_132   =  6 +  8 + 40,
  DISPLAY_LEN_MIN_133   = 28,
  DISPLAY_LEN_MAX_133   = 28,
  DISPLAY_LEN_MIN_141   = 14 +  0 +  1 + 28,
  DISPLAY_LEN_MAX_141   = 14 + 44 +  1 + 28,
  DISPLAY_LEN_MIN_1441  = 14 +  0 +  1 + 43,
  DISPLAY_LEN_MAX_1441  = 14 + 24 +  1 + 43,
  DISPLAY_LEN_MIN_1711  =  9 + 86 +  0,
  DISPLAY_LEN_MAX_1711  =  9 + 86 + 68,
  DISPLAY_LEN_MIN_1722  =  8 + 128,
  DISPLAY_LEN_MAX_1722  =  8 + 128,
  DISPLAY_LEN_MIN_2611  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2611  = 32 + 1 + 23,
  DISPLAY_LEN_MIN_2611H = 32 + 1 + 0,
  DISPLAY_LEN_MIN_2612  = 6 +  0 + 1 + 32,
  DISPLAY_LEN_MAX_2611H = 32 + 1 + 46,
  DISPLAY_LEN_MAX_2612  = 6 + 46 + 1 + 32,
  DISPLAY_LEN_MIN_2711  = 32 + 1 + 23,
  DISPLAY_LEN_MAX_2711  = 32 + 1 + 31,
  DISPLAY_LEN_MIN_2711H = 32 + 1 + 46,
  DISPLAY_LEN_MAX_2711H = 32 + 1 + 62,
  DISPLAY_LEN_MIN_2811  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2811  = 32 + 1 + 31,
  DISPLAY_LEN_MIN_2811H = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2811H = 32 + 1 + 62,
  DISPLAY_LEN_MIN_7600  = 40 + 1 + 32,
  DISPLAY_LEN_MAX_7600  = 40 + 1 + 32,

} display_len_t;

typedef enum hash_type
{
  HASH_TYPE_MD4                 = 1,
  HASH_TYPE_MD5                 = 2,
  HASH_TYPE_MD5H                = 3,
  HASH_TYPE_SHA1                = 4,
  HASH_TYPE_SHA256              = 5,
  HASH_TYPE_SHA384              = 6,
  HASH_TYPE_SHA512              = 7,
  HASH_TYPE_DCC2                = 8,
  HASH_TYPE_WPA                 = 9,
  HASH_TYPE_LM                  = 10,
  HASH_TYPE_DESCRYPT            = 11,
  HASH_TYPE_ORACLEH             = 12,
  HASH_TYPE_DESRACF             = 13,
  HASH_TYPE_BCRYPT              = 14,
  HASH_TYPE_KECCAK              = 15,
  HASH_TYPE_NETNTLM             = 16,
  HASH_TYPE_RIPEMD160           = 17,
  HASH_TYPE_WHIRLPOOL           = 18,
  HASH_TYPE_AES                 = 19,
  HASH_TYPE_GOST                = 20,
  HASH_TYPE_KRB5PA              = 21,
  HASH_TYPE_SAPB                = 22,
  HASH_TYPE_SAPG                = 23,
  HASH_TYPE_MYSQL               = 24,
  HASH_TYPE_LOTUS5              = 25,
  HASH_TYPE_LOTUS6              = 26,
  HASH_TYPE_ANDROIDFDE          = 27,
  HASH_TYPE_SCRYPT              = 28,
  HASH_TYPE_LOTUS8              = 29,
  HASH_TYPE_OFFICE2007          = 30,
  HASH_TYPE_OFFICE2010          = 31,
  HASH_TYPE_OFFICE2013          = 32,
  HASH_TYPE_OLDOFFICE01         = 33,
  HASH_TYPE_OLDOFFICE34         = 34,
  HASH_TYPE_SIPHASH             = 35,
  HASH_TYPE_PDFU16              = 36,
  HASH_TYPE_PDFU32              = 37,
  HASH_TYPE_PBKDF2_SHA256       = 38,
  HASH_TYPE_BITCOIN_WALLET      = 39,
  HASH_TYPE_CRC32               = 40,
  HASH_TYPE_GOST_2012SBOG_256   = 41,
  HASH_TYPE_GOST_2012SBOG_512   = 42,
  HASH_TYPE_PBKDF2_MD5          = 43,
  HASH_TYPE_PBKDF2_SHA1         = 44,
  HASH_TYPE_PBKDF2_SHA512       = 45,
  HASH_TYPE_ECRYPTFS            = 46,
  HASH_TYPE_ORACLET             = 47,
  HASH_TYPE_BSDICRYPT           = 48,
  HASH_TYPE_RAR3HP              = 49,
  HASH_TYPE_KRB5TGS             = 50,
  HASH_TYPE_STDOUT              = 51,
  HASH_TYPE_DES                 = 52

} hash_type_t;

typedef enum kern_type
{
  KERN_TYPE_MD5                 = 0,
  KERN_TYPE_MD5_PWSLT           = 10,
  KERN_TYPE_MD5_SLTPW           = 20,
  KERN_TYPE_MD5_PWUSLT          = 30,
  KERN_TYPE_MD5_SLTPWU          = 40,
  KERN_TYPE_HMACMD5_PW          = 50,
  KERN_TYPE_HMACMD5_SLT         = 60,
  KERN_TYPE_SHA1                = 100,
  KERN_TYPE_SHA1_PWSLT          = 110,
  KERN_TYPE_SHA1_SLTPW          = 120,
  KERN_TYPE_SHA1_PWUSLT         = 130,
  KERN_TYPE_SHA1_SLTPWU         = 140,
  KERN_TYPE_HMACSHA1_PW         = 150,
  KERN_TYPE_HMACSHA1_SLT        = 160,
  KERN_TYPE_MYSQL               = 200,
  KERN_TYPE_MYSQL41             = 300,
  KERN_TYPE_PHPASS              = 400,
  KERN_TYPE_MD5CRYPT            = 500,
  KERN_TYPE_MD4                 = 900,
  KERN_TYPE_MD4_PWU             = 1000,
  KERN_TYPE_MD44_PWUSLT         = 1100,
  KERN_TYPE_SHA256              = 1400,
  KERN_TYPE_SHA256_PWSLT        = 1410,
  KERN_TYPE_SHA256_SLTPW        = 1420,
  KERN_TYPE_SHA256_PWUSLT       = 1430,
  KERN_TYPE_SHA256_SLTPWU       = 1440,
  KERN_TYPE_HMACSHA256_PW       = 1450,
  KERN_TYPE_HMACSHA256_SLT      = 1460,
  KERN_TYPE_DESCRYPT            = 1500,
  KERN_TYPE_APR1CRYPT           = 1600,
  KERN_TYPE_SHA512              = 1700,
  KERN_TYPE_SHA512_PWSLT        = 1710,
  KERN_TYPE_SHA512_SLTPW        = 1720,
  KERN_TYPE_SHA512_PWSLTU       = 1730,
  KERN_TYPE_SHA512_SLTPWU       = 1740,
  KERN_TYPE_HMACSHA512_PW       = 1750,
  KERN_TYPE_HMACSHA512_SLT      = 1760,
  KERN_TYPE_SHA512CRYPT         = 1800,
  KERN_TYPE_STDOUT              = 2000,
  KERN_TYPE_DCC2                = 2100,
  KERN_TYPE_MD5PIX              = 2400,
  KERN_TYPE_MD5ASA              = 2410,
  KERN_TYPE_WPA                 = 2500,
  KERN_TYPE_MD55                = 2600,
  KERN_TYPE_MD55_PWSLT1         = 2610,
  KERN_TYPE_MD55_PWSLT2         = 2710,
  KERN_TYPE_MD55_SLTPW          = 2810,
  KERN_TYPE_LM                  = 3000,
  KERN_TYPE_ORACLEH             = 3100,
  KERN_TYPE_BCRYPT              = 3200,
  KERN_TYPE_MD5_SLT_MD5_PW      = 3710,
  KERN_TYPE_MD5_SLT_PW_SLT      = 3800,
  KERN_TYPE_MD5U5               = 4300,
  KERN_TYPE_MD5U5_PWSLT1        = 4310,
  KERN_TYPE_MD5_SHA1            = 4400,
  KERN_TYPE_SHA11               = 4500,
  KERN_TYPE_SHA1_MD5            = 4700,
  KERN_TYPE_MD5_CHAP            = 4800,
  KERN_TYPE_SHA1_SLT_PW_SLT     = 4900,
  KERN_TYPE_KECCAK              = 5000,
  KERN_TYPE_MD5H                = 5100,
  KERN_TYPE_PSAFE3              = 5200,
  KERN_TYPE_IKEPSK_MD5          = 5300,
  KERN_TYPE_IKEPSK_SHA1         = 5400,
  KERN_TYPE_NETNTLMv1           = 5500,
  KERN_TYPE_NETNTLMv2           = 5600,
  KERN_TYPE_ANDROIDPIN          = 5800,
  KERN_TYPE_RIPEMD160           = 6000,
  KERN_TYPE_WHIRLPOOL           = 6100,
  KERN_TYPE_TCRIPEMD160_XTS512  = 6211,
  KERN_TYPE_TCRIPEMD160_XTS1024 = 6212,
  KERN_TYPE_TCRIPEMD160_XTS1536 = 6213,
  KERN_TYPE_TCSHA512_XTS512     = 6221,
  KERN_TYPE_TCSHA512_XTS1024    = 6222,
  KERN_TYPE_TCSHA512_XTS1536    = 6223,
  KERN_TYPE_TCWHIRLPOOL_XTS512  = 6231,
  KERN_TYPE_TCWHIRLPOOL_XTS1024 = 6232,
  KERN_TYPE_TCWHIRLPOOL_XTS1536 = 6233,
  KERN_TYPE_VCSHA256_XTS512     = 13751,
  KERN_TYPE_VCSHA256_XTS1024    = 13752,
  KERN_TYPE_VCSHA256_XTS1536    = 13753,
  KERN_TYPE_MD5AIX              = 6300,
  KERN_TYPE_SHA256AIX           = 6400,
  KERN_TYPE_SHA512AIX           = 6500,
  KERN_TYPE_AGILEKEY            = 6600,
  KERN_TYPE_SHA1AIX             = 6700,
  KERN_TYPE_LASTPASS            = 6800,
  KERN_TYPE_GOST                = 6900,
  KERN_TYPE_PBKDF2_SHA512       = 7100,
  KERN_TYPE_RAKP                = 7300,
  KERN_TYPE_SHA256CRYPT         = 7400,
  KERN_TYPE_KRB5PA              = 7500,
  KERN_TYPE_SHA1_SLT_SHA1_PW    = 7600,
  KERN_TYPE_SAPB                = 7700,
  KERN_TYPE_SAPG                = 7800,
  KERN_TYPE_DRUPAL7             = 7900,
  KERN_TYPE_SYBASEASE           = 8000,
  KERN_TYPE_NETSCALER           = 8100,
  KERN_TYPE_CLOUDKEY            = 8200,
  KERN_TYPE_NSEC3               = 8300,
  KERN_TYPE_WBB3                = 8400,
  KERN_TYPE_RACF                = 8500,
  KERN_TYPE_LOTUS5              = 8600,
  KERN_TYPE_LOTUS6              = 8700,
  KERN_TYPE_ANDROIDFDE          = 8800,
  KERN_TYPE_SCRYPT              = 8900,
  KERN_TYPE_PSAFE2              = 9000,
  KERN_TYPE_LOTUS8              = 9100,
  KERN_TYPE_OFFICE2007          = 9400,
  KERN_TYPE_OFFICE2010          = 9500,
  KERN_TYPE_OFFICE2013          = 9600,
  KERN_TYPE_OLDOFFICE01         = 9700,
  KERN_TYPE_OLDOFFICE01CM1      = 9710,
  KERN_TYPE_OLDOFFICE01CM2      = 9720,
  KERN_TYPE_OLDOFFICE34         = 9800,
  KERN_TYPE_OLDOFFICE34CM1      = 9810,
  KERN_TYPE_OLDOFFICE34CM2      = 9820,
  KERN_TYPE_RADMIN2             = 9900,
  KERN_TYPE_SIPHASH             = 10100,
  KERN_TYPE_SAPH_SHA1           = 10300,
  KERN_TYPE_PDF11               = 10400,
  KERN_TYPE_PDF11CM1            = 10410,
  KERN_TYPE_PDF11CM2            = 10420,
  KERN_TYPE_PDF14               = 10500,
  KERN_TYPE_PDF17L8             = 10700,
  KERN_TYPE_SHA384              = 10800,
  KERN_TYPE_PBKDF2_SHA256       = 10900,
  KERN_TYPE_PRESTASHOP          = 11000,
  KERN_TYPE_POSTGRESQL_AUTH     = 11100,
  KERN_TYPE_MYSQL_AUTH          = 11200,
  KERN_TYPE_BITCOIN_WALLET      = 11300,
  KERN_TYPE_SIP_AUTH            = 11400,
  KERN_TYPE_CRC32               = 11500,
  KERN_TYPE_SEVEN_ZIP           = 11600,
  KERN_TYPE_GOST_2012SBOG_256   = 11700,
  KERN_TYPE_GOST_2012SBOG_512   = 11800,
  KERN_TYPE_PBKDF2_MD5          = 11900,
  KERN_TYPE_PBKDF2_SHA1         = 12000,
  KERN_TYPE_ECRYPTFS            = 12200,
  KERN_TYPE_ORACLET             = 12300,
  KERN_TYPE_BSDICRYPT           = 12400,
  KERN_TYPE_RAR3                = 12500,
  KERN_TYPE_CF10                = 12600,
  KERN_TYPE_MYWALLET            = 12700,
  KERN_TYPE_MS_DRSR             = 12800,
  KERN_TYPE_ANDROIDFDE_SAMSUNG  = 12900,
  KERN_TYPE_RAR5                = 13000,
  KERN_TYPE_KRB5TGS             = 13100,
  KERN_TYPE_AXCRYPT             = 13200,
  KERN_TYPE_SHA1_AXCRYPT        = 13300,
  KERN_TYPE_KEEPASS             = 13400,
  KERN_TYPE_PSTOKEN             = 13500,
  KERN_TYPE_ZIP2                = 13600,
  KERN_TYPE_WIN8PHONE           = 13800,
  KERN_TYPE_OPENCART            = 13900,
  KERN_TYPE_DES                 = 14000,
  KERN_TYPE_3DES                = 14100

} kern_type_t;

/**
 * signatures
 */

static const char SIGNATURE_ANDROIDFDE[]      = "$fde$";
static const char SIGNATURE_AXCRYPT[]         = "$axcrypt$*1";
static const char SIGNATURE_AXCRYPT_SHA1[]    = "$axcrypt_sha1";
static const char SIGNATURE_BCRYPT1[]         = "$2a$";
static const char SIGNATURE_BCRYPT2[]         = "$2b$";
static const char SIGNATURE_BCRYPT3[]         = "$2x$";
static const char SIGNATURE_BCRYPT4[]         = "$2y$";
static const char SIGNATURE_BITCOIN_WALLET[]  = "$bitcoin$";
static const char SIGNATURE_BSDICRYPT[]       = "_";
static const char SIGNATURE_CISCO8[]          = "$8$";
static const char SIGNATURE_CISCO9[]          = "$9$";
static const char SIGNATURE_CRAM_MD5[]        = "$cram_md5$";
static const char SIGNATURE_DCC2[]            = "$DCC2$";
static const char SIGNATURE_DJANGOPBKDF2[]    = "pbkdf2_sha256$";
static const char SIGNATURE_DJANGOSHA1[]      = "sha1$";
static const char SIGNATURE_DRUPAL7[]         = "$S$";
static const char SIGNATURE_ECRYPTFS[]        = "$ecryptfs$";
static const char SIGNATURE_EPISERVER4[]      = "$episerver$*1*";
static const char SIGNATURE_EPISERVER[]       = "$episerver$*0*";
static const char SIGNATURE_KEEPASS[]         = "$keepass$";
static const char SIGNATURE_KRB5PA[]          = "$krb5pa$23";
static const char SIGNATURE_KRB5TGS[]         = "$krb5tgs$23";
static const char SIGNATURE_MD5AIX[]          = "{smd5}";
static const char SIGNATURE_MD5APR1[]         = "$apr1$";
static const char SIGNATURE_MD5CRYPT[]        = "$1$";
static const char SIGNATURE_MEDIAWIKI_B[]     = "$B$";
static const char SIGNATURE_MS_DRSR[]         = "v1;PPH1_MD4";
static const char SIGNATURE_MSSQL[]           = "0x0100";
static const char SIGNATURE_MSSQL2012[]       = "0x0200";
static const char SIGNATURE_MYSQL_AUTH[]      = "$mysqlna$";
static const char SIGNATURE_MYWALLET[]        = "$blockchain$";
static const char SIGNATURE_NETSCALER[]       = "1";
static const char SIGNATURE_OFFICE2007[]      = "$office$";
static const char SIGNATURE_OFFICE2010[]      = "$office$";
static const char SIGNATURE_OFFICE2013[]      = "$office$";
static const char SIGNATURE_OLDOFFICE0[]      = "$oldoffice$0";
static const char SIGNATURE_OLDOFFICE1[]      = "$oldoffice$1";
static const char SIGNATURE_OLDOFFICE3[]      = "$oldoffice$3";
static const char SIGNATURE_OLDOFFICE4[]      = "$oldoffice$4";
static const char SIGNATURE_PBKDF2_MD5[]      = "md5:";
static const char SIGNATURE_PBKDF2_SHA1[]     = "sha1:";
static const char SIGNATURE_PBKDF2_SHA256[]   = "sha256:";
static const char SIGNATURE_PBKDF2_SHA512[]   = "sha512:";
static const char SIGNATURE_PDF[]             = "$pdf$";
static const char SIGNATURE_PHPASS1[]         = "$P$";
static const char SIGNATURE_PHPASS2[]         = "$H$";
static const char SIGNATURE_PHPS[]            = "$PHPS$";
static const char SIGNATURE_POSTGRESQL_AUTH[] = "$postgres$";
static const char SIGNATURE_PSAFE3[]          = "PWS3";
static const char SIGNATURE_RACF[]            = "$racf$";
static const char SIGNATURE_RAR3[]            = "$RAR3$";
static const char SIGNATURE_RAR5[]            = "$rar5$";
static const char SIGNATURE_SAPH_SHA1[]       = "{x-issha, ";
static const char SIGNATURE_SCRYPT[]          = "SCRYPT";
static const char SIGNATURE_SEVEN_ZIP[]       = "$7z$";
static const char SIGNATURE_SHA1AIX[]         = "{ssha1}";
static const char SIGNATURE_SHA1B64[]         = "{SHA}";
static const char SIGNATURE_SHA256AIX[]       = "{ssha256}";
static const char SIGNATURE_SHA256CRYPT[]     = "$5$";
static const char SIGNATURE_SHA512AIX[]       = "{ssha512}";
static const char SIGNATURE_SHA512B64S[]      = "{SSHA512}";
static const char SIGNATURE_SHA512CRYPT[]     = "$6$";
static const char SIGNATURE_SHA512GRUB[]      = "grub.pbkdf2.sha512.";
static const char SIGNATURE_SHA512OSX[]       = "$ml$";
static const char SIGNATURE_SIP_AUTH[]        = "$sip$*";
static const char SIGNATURE_SSHA1B64_lower[]  = "{ssha}";
static const char SIGNATURE_SSHA1B64_upper[]  = "{SSHA}";
static const char SIGNATURE_SYBASEASE[]       = "0xc007";
static const char SIGNATURE_TRUECRYPT[]       = "TRUE";
static const char SIGNATURE_ZIP2_START[]      = "$zip2$";
static const char SIGNATURE_ZIP2_STOP[]       = "$/zip2$";

/**
 * Default iteration numbers
 */

typedef enum rounds_count
{
   ROUNDS_PHPASS             = (1 << 11), // $P$B
   ROUNDS_DCC2               = 10240,
   ROUNDS_WPA2               = 4096,
   ROUNDS_BCRYPT             = (1 << 5),
   ROUNDS_PSAFE3             = 2048,
   ROUNDS_ANDROIDPIN         = 1024,
   ROUNDS_TRUECRYPT_1K       = 1000,
   ROUNDS_TRUECRYPT_2K       = 2000,
   ROUNDS_VERACRYPT_200000   = 200000,
   ROUNDS_VERACRYPT_500000   = 500000,
   ROUNDS_VERACRYPT_327661   = 327661,
   ROUNDS_VERACRYPT_655331   = 655331,
   ROUNDS_SHA1AIX            = (1 << 6),
   ROUNDS_SHA256AIX          = (1 << 6),
   ROUNDS_SHA512AIX          = (1 << 6),
   ROUNDS_MD5CRYPT           = 1000,
   ROUNDS_SHA256CRYPT        = 5000,
   ROUNDS_SHA512CRYPT        = 5000,
   ROUNDS_GRUB               = 10000,
   ROUNDS_SHA512OSX          = 35000,
   ROUNDS_AGILEKEY           = 1000,
   ROUNDS_LASTPASS           = 500,
   ROUNDS_DRUPAL7            = (1 << 14), // $S$C
   ROUNDS_CLOUDKEY           = 40000,
   ROUNDS_NSEC3              = 1,
   ROUNDS_ANDROIDFDE         = 2000,
   ROUNDS_PSAFE2             = 1000,
   ROUNDS_LOTUS8             = 5000,
   ROUNDS_CISCO8             = 20000,
   ROUNDS_OFFICE2007         = 50000,
   ROUNDS_OFFICE2010         = 100000,
   ROUNDS_OFFICE2013         = 100000,
   ROUNDS_DJANGOPBKDF2       = 20000,
   ROUNDS_SAPH_SHA1          = 1024,
   ROUNDS_PDF14              = (50 + 20),
   ROUNDS_PDF17L8            = 64,
   ROUNDS_PBKDF2_SHA256      = 1000,
   ROUNDS_BITCOIN_WALLET     = 200000,
   ROUNDS_SEVEN_ZIP          = (1 << 19),
   ROUNDS_PBKDF2_MD5         = 1000,
   ROUNDS_PBKDF2_SHA1        = 1000,
   ROUNDS_PBKDF2_SHA512      = 1000,
   ROUNDS_ECRYPTFS           = 65536,
   ROUNDS_ORACLET            = 4096,
   ROUNDS_BSDICRYPT          = 2900,
   ROUNDS_RAR3               = 262144,
   ROUNDS_MYWALLET           = 10,
   ROUNDS_MS_DRSR            = 100,
   ROUNDS_ANDROIDFDE_SAMSUNG = 4096,
   ROUNDS_RAR5               = (1 << 15),
   ROUNDS_AXCRYPT            = 10000,
   ROUNDS_KEEPASS            = 6000,
   ROUNDS_ZIP2               = 1000,
   ROUNDS_STDOUT             = 0

} rounds_count_t;

/**
 * salt types
 */

typedef enum salt_type
{
  SALT_TYPE_NONE     = 1,
  SALT_TYPE_EMBEDDED = 2,
  SALT_TYPE_INTERN   = 3,
  SALT_TYPE_EXTERN   = 4,
  SALT_TYPE_VIRTUAL  = 5

} salt_type_t;

/**
 * optimizer options
 */

typedef enum opti_type
{
  OPTI_TYPE_ZERO_BYTE         = (1 <<  1),
  OPTI_TYPE_PRECOMPUTE_INIT   = (1 <<  2),
  OPTI_TYPE_PRECOMPUTE_MERKLE = (1 <<  3),
  OPTI_TYPE_PRECOMPUTE_PERMUT = (1 <<  4),
  OPTI_TYPE_MEET_IN_MIDDLE    = (1 <<  5),
  OPTI_TYPE_EARLY_SKIP        = (1 <<  6),
  OPTI_TYPE_NOT_SALTED        = (1 <<  7),
  OPTI_TYPE_NOT_ITERATED      = (1 <<  8),
  OPTI_TYPE_PREPENDED_SALT    = (1 <<  9),
  OPTI_TYPE_APPENDED_SALT     = (1 << 10),
  OPTI_TYPE_SINGLE_HASH       = (1 << 11),
  OPTI_TYPE_SINGLE_SALT       = (1 << 12),
  OPTI_TYPE_BRUTE_FORCE       = (1 << 13),
  OPTI_TYPE_RAW_HASH          = (1 << 14),
  OPTI_TYPE_SLOW_HASH_SIMD    = (1 << 15),
  OPTI_TYPE_USES_BITS_8       = (1 << 16),
  OPTI_TYPE_USES_BITS_16      = (1 << 17),
  OPTI_TYPE_USES_BITS_32      = (1 << 18),
  OPTI_TYPE_USES_BITS_64      = (1 << 19)

} opti_type_t;

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

/**
 * hash options
 */

typedef enum opts_type
{
  OPTS_TYPE_PT_UNICODE        = (1 <<  0),
  OPTS_TYPE_PT_UPPER          = (1 <<  1),
  OPTS_TYPE_PT_LOWER          = (1 <<  2),
  OPTS_TYPE_PT_ADD01          = (1 <<  3),
  OPTS_TYPE_PT_ADD02          = (1 <<  4),
  OPTS_TYPE_PT_ADD80          = (1 <<  5),
  OPTS_TYPE_PT_ADDBITS14      = (1 <<  6),
  OPTS_TYPE_PT_ADDBITS15      = (1 <<  7),
  OPTS_TYPE_PT_GENERATE_LE    = (1 <<  8),
  OPTS_TYPE_PT_GENERATE_BE    = (1 <<  9),
  OPTS_TYPE_PT_NEVERCRACK     = (1 << 10), // if we want all possible results
  OPTS_TYPE_PT_BITSLICE       = (1 << 11),
  OPTS_TYPE_ST_UNICODE        = (1 << 12),
  OPTS_TYPE_ST_UPPER          = (1 << 13),
  OPTS_TYPE_ST_LOWER          = (1 << 14),
  OPTS_TYPE_ST_ADD01          = (1 << 15),
  OPTS_TYPE_ST_ADD02          = (1 << 16),
  OPTS_TYPE_ST_ADD80          = (1 << 17),
  OPTS_TYPE_ST_ADDBITS14      = (1 << 18),
  OPTS_TYPE_ST_ADDBITS15      = (1 << 19),
  OPTS_TYPE_ST_GENERATE_LE    = (1 << 20),
  OPTS_TYPE_ST_GENERATE_BE    = (1 << 21),
  OPTS_TYPE_ST_HEX            = (1 << 22),
  OPTS_TYPE_ST_BASE64         = (1 << 23),
  OPTS_TYPE_HASH_COPY         = (1 << 24),
  OPTS_TYPE_HOOK12            = (1 << 25),
  OPTS_TYPE_HOOK23            = (1 << 26)

} opts_type_t;

/**
 * digests
 */

typedef enum dgst_size
{
  DGST_SIZE_4_2  = (2  * sizeof (uint)),   // 8
  DGST_SIZE_4_4  = (4  * sizeof (uint)),   // 16
  DGST_SIZE_4_5  = (5  * sizeof (uint)),   // 20
  DGST_SIZE_4_6  = (6  * sizeof (uint)),   // 24
  DGST_SIZE_4_8  = (8  * sizeof (uint)),   // 32
  DGST_SIZE_4_16 = (16 * sizeof (uint)),   // 64 !!!
  DGST_SIZE_4_32 = (32 * sizeof (uint)),   // 128 !!!
  DGST_SIZE_4_64 = (64 * sizeof (uint)),   // 256
  DGST_SIZE_8_8  = (8  * sizeof (u64)),    // 64 !!!
  DGST_SIZE_8_16 = (16 * sizeof (u64)),    // 128 !!!
  DGST_SIZE_8_25 = (25 * sizeof (u64))     // 200

} dgst_size_t;

/**
 * parser
 */

typedef enum parser_rc
{
  PARSER_OK                  = 0,
  PARSER_COMMENT             = -1,
  PARSER_GLOBAL_ZERO         = -2,
  PARSER_GLOBAL_LENGTH       = -3,
  PARSER_HASH_LENGTH         = -4,
  PARSER_HASH_VALUE          = -5,
  PARSER_SALT_LENGTH         = -6,
  PARSER_SALT_VALUE          = -7,
  PARSER_SALT_ITERATION      = -8,
  PARSER_SEPARATOR_UNMATCHED = -9,
  PARSER_SIGNATURE_UNMATCHED = -10,
  PARSER_HCCAP_FILE_SIZE     = -11,
  PARSER_HCCAP_EAPOL_SIZE    = -12,
  PARSER_PSAFE2_FILE_SIZE    = -13,
  PARSER_PSAFE3_FILE_SIZE    = -14,
  PARSER_TC_FILE_SIZE        = -15,
  PARSER_VC_FILE_SIZE        = -16,
  PARSER_SIP_AUTH_DIRECTIVE  = -17,
  PARSER_UNKNOWN_ERROR       = -255

} parser_rc_t;

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
static const char PA_011[] = "Invalid hccap filesize";
static const char PA_012[] = "Invalid eapol size";
static const char PA_013[] = "Invalid psafe2 filesize";
static const char PA_014[] = "Invalid psafe3 filesize";
static const char PA_015[] = "Invalid truecrypt filesize";
static const char PA_016[] = "Invalid veracrypt filesize";
static const char PA_017[] = "Invalid SIP directive, only MD5 is supported";
static const char PA_255[] = "Unknown error";

/**
 * status
 */

typedef enum status_rc
{
   STATUS_STARTING           = 0,
   STATUS_INIT               = 1,
   STATUS_RUNNING            = 2,
   STATUS_PAUSED             = 3,
   STATUS_EXHAUSTED          = 4,
   STATUS_CRACKED            = 5,
   STATUS_ABORTED            = 6,
   STATUS_QUIT               = 7,
   STATUS_BYPASS             = 8,
   STATUS_STOP_AT_CHECKPOINT = 9,
   STATUS_AUTOTUNE           = 10

} status_rc_t;

static const char ST_0000[] = "Initializing";
static const char ST_0001[] = "Starting";
static const char ST_0002[] = "Running";
static const char ST_0003[] = "Paused";
static const char ST_0004[] = "Exhausted";
static const char ST_0005[] = "Cracked";
static const char ST_0006[] = "Aborted";
static const char ST_0007[] = "Quit";
static const char ST_0008[] = "Bypass";
static const char ST_0009[] = "Running (stop at checkpoint)";
static const char ST_0010[] = "Autotuning";

/**
 * kernel types
 */

typedef enum kern_run
{
  KERN_RUN_1    = 1000,
  KERN_RUN_12   = 1500,
  KERN_RUN_2    = 2000,
  KERN_RUN_23   = 2500,
  KERN_RUN_3    = 3000

} kern_run_t;

typedef enum kern_run_mp
{
  KERN_RUN_MP   = 101,
  KERN_RUN_MP_L = 102,
  KERN_RUN_MP_R = 103

} kern_run_mp_t;

/*
 * functions
 */

u8  hex_convert (const u8 c);
u8  hex_to_u8   (const u8 hex[2]);
u32 hex_to_u32  (const u8 hex[8]);
u64 hex_to_u64  (const u8 hex[16]);

void dump_hex (const u8 *s, const int sz);

void truecrypt_crc32 (const char *filename, u8 keytab[64]);

char *get_exec_path   (void);
char *get_install_dir (const char *progname);
char *get_profile_dir (const char *homedir);
char *get_session_dir (const char *profile_dir);
uint count_lines (FILE *fd);

void *rulefind (const void *key, void *base, int nmemb, size_t size, int (*compar) (const void *, const void *));

int sort_by_u32          (const void *p1, const void *p2);
int sort_by_mtime        (const void *p1, const void *p2);
int sort_by_cpu_rule     (const void *p1, const void *p2);
int sort_by_kernel_rule  (const void *p1, const void *p2);
int sort_by_stringptr    (const void *p1, const void *p2);
int sort_by_dictstat     (const void *s1, const void *s2);
int sort_by_bitmap       (const void *s1, const void *s2);

int sort_by_pot          (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2);
int sort_by_hash_no_salt (const void *v1, const void *v2);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_salt_buf     (const void *v1, const void *v2);
int sort_by_hash_t_salt  (const void *v1, const void *v2);
int sort_by_digest_4_2   (const void *v1, const void *v2);
int sort_by_digest_4_4   (const void *v1, const void *v2);
int sort_by_digest_4_5   (const void *v1, const void *v2);
int sort_by_digest_4_6   (const void *v1, const void *v2);
int sort_by_digest_4_8   (const void *v1, const void *v2);
int sort_by_digest_4_16  (const void *v1, const void *v2);
int sort_by_digest_4_32  (const void *v1, const void *v2);
int sort_by_digest_4_64  (const void *v1, const void *v2);
int sort_by_digest_8_8   (const void *v1, const void *v2);
int sort_by_digest_8_16  (const void *v1, const void *v2);
int sort_by_digest_8_25  (const void *v1, const void *v2);
int sort_by_digest_p0p1  (const void *v1, const void *v2);

// special version for hccap (last 2 uints should be skipped where the digest is located)
int sort_by_hash_t_salt_hccap (const void *v1, const void *v2);

void format_debug (char * debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len);
void format_plain (FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex);
void format_output (FILE *out_fp, char *out_buf, unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, unsigned char *username, const uint user_len);
void handle_show_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_show_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);
void handle_left_request_lm (pot_t *pot, uint pot_cnt, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *), FILE *out_fp);

u32            setup_opencl_platforms_filter (char *opencl_platforms);
u32            setup_devices_filter          (char *opencl_devices);
cl_device_type setup_device_types_filter     (char *opencl_device_types);

u32 get_random_num (const u32 min, const u32 max);

u32 mydivc32 (const u32 dividend, const u32 divisor);
u64 mydivc64 (const u64 dividend, const u64 divisor);

void ascii_digest (char *out_buf, uint salt_pos, uint digest_pos);
void to_hccap_t (hccap_t *hccap, uint salt_pos, uint digest_pos);

void format_speed_display (double val, char *buf, size_t len);
void format_timer_display (struct tm *tm, char *buf, size_t len);
void lowercase (u8 *buf, int len);
void uppercase (u8 *buf, int len);
int fgetl (FILE *fp, char *line_buf);
int in_superchop (char *buf);
char **scan_directory (const char *path);
int count_dictionaries (char **dictionary_files);
char *strparser (const uint parser_status);
char *stroptitype (const uint opti_type);
char *strhashtype (const uint hash_mode);
char *strstatus (const uint threads_status);
void status ();

void *mycalloc (size_t nmemb, size_t size);
void myfree (void *ptr);
void *mymalloc (size_t size);
void *myrealloc (void *ptr, size_t oldsz, size_t add);
char *mystrdup (const char *s);

char *logfile_generate_topid (void);
char *logfile_generate_subid (void);
void logfile_append (const char *fmt, ...);

#ifdef F_SETLKW
void lock_file (FILE *fp);
void unlock_file (FILE *fp);
#else
#define lock_file(dummy) {}
#define unlock_file(dummy) {}
#endif

#ifdef _WIN
void fsync (int fd);
#endif

#ifdef HAVE_HWMON

int get_adapters_num_adl (void *adl, int *iNumberAdapters);

int hm_get_adapter_index_adl (hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);

int hm_get_adapter_index_nvapi (HM_ADAPTER_NVAPI nvapiGPUHandle[DEVICES_MAX]);

int hm_get_adapter_index_nvml (HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX]);

LPAdapterInfo hm_get_adapter_info_adl (void *adl, int iNumberAdapters);

u32 *hm_get_list_valid_adl_adapters (int iNumberAdapters, int *num_adl_adapters, LPAdapterInfo lpAdapterInfo);

int hm_get_overdrive_version  (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);
int hm_check_fanspeed_control (void *adl, hm_attrs_t *hm_device, u32 *valid_adl_device_list, int num_adl_adapters, LPAdapterInfo lpAdapterInfo);

// int hm_get_device_num (void *adl, HM_ADAPTER_ADL hm_adapter_index, int *hm_device_num);
// void hm_get_opencl_busid_devid (hm_attrs_t *hm_device, uint opencl_num_devices, cl_device_id *devices);

int hm_get_threshold_slowdown_with_device_id (const uint device_id);
int hm_get_threshold_shutdown_with_device_id (const uint device_id);
int hm_get_temperature_with_device_id        (const uint device_id);
int hm_get_fanspeed_with_device_id           (const uint device_id);
int hm_get_fanpolicy_with_device_id          (const uint device_id);
int hm_get_buslanes_with_device_id           (const uint device_id);
int hm_get_utilization_with_device_id        (const uint device_id);
int hm_get_memoryspeed_with_device_id        (const uint device_id);
int hm_get_corespeed_with_device_id          (const uint device_id);
int hm_get_throttle_with_device_id           (const uint device_id);
int hm_set_fanspeed_with_device_id_adl       (const uint device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_nvapi     (const uint device_id, const int fanspeed, const int fanpolicy);
int hm_set_fanspeed_with_device_id_xnvctrl   (const uint device_id, const int fanspeed);

void hm_device_val_to_str (char *target_buf, int max_buf_size, char *suffix, int value);
#endif // HAVE_HWMON

void myabort (void);
void myquit  (void);

void set_cpu_affinity (char *cpu_affinity);

void usage_mini_print (const char *progname);
void usage_big_print  (const char *progname);

void mp_css_to_uniq_tbl (uint css_cnt, cs_t *css, uint uniq_tbls[SP_PW_MAX][CHARSIZ]);
void mp_cut_at (char *mask, uint max);
void mp_exec (u64 val, char *buf, cs_t *css, int css_cnt);
cs_t *mp_gen_css (char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint *css_cnt);
u64 mp_get_sum (uint css_cnt, cs_t *css);
void mp_setup_sys (cs_t *mp_sys);
void mp_setup_usr (cs_t *mp_sys, cs_t *mp_usr, char *buf, uint index);
void mp_reset_usr (cs_t *mp_usr, uint index);
char *mp_get_truncated_mask (char *mask_buf, size_t mask_len, uint len);

u64 sp_get_sum (uint start, uint stop, cs_t *root_css_buf);
void sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint start, uint stop);
int sp_comp_val (const void *p1, const void *p2);
void sp_setup_tbl (const char *install_dir, char *hcstat, uint disable, uint classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf);
void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint threshold, uint uniq_tbls[SP_PW_MAX][CHARSIZ]);
void sp_stretch_markov (hcstat_table_t *in, hcstat_table_t *out);
void sp_stretch_root (hcstat_table_t *in, hcstat_table_t *out);

void tuning_db_destroy (tuning_db_t *tuning_db);
tuning_db_t *tuning_db_alloc (FILE *fp);
tuning_db_t *tuning_db_init (const char *tuning_db_file);
tuning_db_entry_t *tuning_db_search (tuning_db_t *tuning_db, hc_device_param_t *device_param, int attack_mode, int hash_type);

int bcrypt_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int cisco4_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int dcc_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int dcc2_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int descrypt_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int des_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int episerver_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int ipb2_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int joomla_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int postgresql_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int netscreen_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int keccak_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int lm_parse_hash                 (char *input_buf, uint input_len, hash_t *hash_buf);
int md4_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int md4s_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int md5_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int md5s_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int md5half_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int md5md5_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int md5pix_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int md5asa_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int md5apr1_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int md5crypt_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int mssql2000_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int mssql2005_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int netntlmv1_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int netntlmv2_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int oracleh_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int oracles_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int oraclet_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int osc_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int arubaos_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int osx1_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int osx512_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int phpass_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1b64_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1b64s_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1s_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int sha256_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int sha256s_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sha384_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512s_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512crypt_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int smf_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int vb3_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int vb30_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int wpa_parse_hash                (char *input_buf, uint input_len, hash_t *hash_buf);
int psafe2_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int psafe3_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int ikepsk_md5_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int ikepsk_sha1_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int androidpin_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int ripemd160_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int whirlpool_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int truecrypt_parse_hash_1k       (char *input_buf, uint input_len, hash_t *hash_buf);
int truecrypt_parse_hash_2k       (char *input_buf, uint input_len, hash_t *hash_buf);
int md5aix_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int sha256aix_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512aix_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int agilekey_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1aix_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int lastpass_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int gost_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int sha256crypt_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int mssql2012_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512osx_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int episerver4_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512grub_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int sha512b64s_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int hmacsha1_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int hmacsha256_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int hmacsha512_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int hmacmd5_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int krb5pa_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int krb5tgs_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sapb_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int sapg_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int drupal7_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sybasease_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int mysql323_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int rakp_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int netscaler_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int chap_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int cloudkey_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int nsec3_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int wbb3_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int racf_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int lotus5_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int lotus6_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int lotus8_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int hmailserver_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int phps_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int mediawiki_b_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int peoplesoft_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int skype_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int androidfde_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int scrypt_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int juniper_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int cisco8_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int cisco9_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int office2007_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int office2010_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int office2013_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice01_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice01cm1_parse_hash     (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice01cm2_parse_hash     (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice34_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice34cm1_parse_hash     (char *input_buf, uint input_len, hash_t *hash_buf);
int oldoffice34cm2_parse_hash     (char *input_buf, uint input_len, hash_t *hash_buf);
int radmin2_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int djangosha1_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int djangopbkdf2_parse_hash       (char *input_buf, uint input_len, hash_t *hash_buf);
int siphash_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int crammd5_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int saph_sha1_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int redmine_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf11_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf11cm1_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf11cm2_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf14_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf17l3_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int pdf17l8_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int pbkdf2_sha256_parse_hash      (char *input_buf, uint input_len, hash_t *hash_buf);
int prestashop_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int postgresql_auth_parse_hash    (char *input_buf, uint input_len, hash_t *hash_buf);
int mysql_auth_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int bitcoin_wallet_parse_hash     (char *input_buf, uint input_len, hash_t *hash_buf);
int sip_auth_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int crc32_parse_hash              (char *input_buf, uint input_len, hash_t *hash_buf);
int seven_zip_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int gost2012sbog_256_parse_hash   (char *input_buf, uint input_len, hash_t *hash_buf);
int gost2012sbog_512_parse_hash   (char *input_buf, uint input_len, hash_t *hash_buf);
int pbkdf2_md5_parse_hash         (char *input_buf, uint input_len, hash_t *hash_buf);
int pbkdf2_sha1_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int pbkdf2_sha512_parse_hash      (char *input_buf, uint input_len, hash_t *hash_buf);
int ecryptfs_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int bsdicrypt_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int rar3hp_parse_hash             (char *input_buf, uint input_len, hash_t *hash_buf);
int rar5_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int cf10_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int mywallet_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);
int ms_drsr_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int androidfde_samsung_parse_hash (char *input_buf, uint input_len, hash_t *hash_buf);
int axcrypt_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int sha1axcrypt_parse_hash        (char *input_buf, uint input_len, hash_t *hash_buf);
int keepass_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int pstoken_parse_hash            (char *input_buf, uint input_len, hash_t *hash_buf);
int zip2_parse_hash               (char *input_buf, uint input_len, hash_t *hash_buf);
int veracrypt_parse_hash_200000   (char *input_buf, uint input_len, hash_t *hash_buf);
int veracrypt_parse_hash_500000   (char *input_buf, uint input_len, hash_t *hash_buf);
int veracrypt_parse_hash_327661   (char *input_buf, uint input_len, hash_t *hash_buf);
int veracrypt_parse_hash_655331   (char *input_buf, uint input_len, hash_t *hash_buf);
int win8phone_parse_hash          (char *input_buf, uint input_len, hash_t *hash_buf);
int opencart_parse_hash           (char *input_buf, uint input_len, hash_t *hash_buf);

void naive_replace (char *s, const u8 key_char, const u8 replace_char);
void naive_escape (char *s, size_t s_max, const u8 key_char, const u8 escape_char);
void load_kernel (const char *kernel_file, int num_devices, size_t *kernel_lengths, const u8 **kernel_sources);
void writeProgramBin (char *dst, u8 *binary, size_t binary_size);

u64 get_lowest_words_done (void);

restore_data_t *init_restore  (int argc, char **argv);
void            read_restore  (const char *eff_restore_file, restore_data_t *rd);
void            write_restore (const char *new_restore_file, restore_data_t *rd);
void            cycle_restore (void);
void            check_checkpoint (void);

#ifdef WIN

BOOL WINAPI sigHandler_default   (DWORD sig);
BOOL WINAPI sigHandler_benchmark (DWORD sig);
void hc_signal (BOOL WINAPI (callback) (DWORD sig));

#else

void sigHandler_default   (int sig);
void sigHandler_benchmark (int sig);
void hc_signal (void c (int));

#endif

bool class_num   (u8 c);
bool class_lower (u8 c);
bool class_upper (u8 c);
bool class_alpha (u8 c);

int mangle_lrest              (char arr[BLOCK_SIZE], int arr_len);
int mangle_urest              (char arr[BLOCK_SIZE], int arr_len);
int mangle_trest              (char arr[BLOCK_SIZE], int arr_len);
int mangle_reverse            (char arr[BLOCK_SIZE], int arr_len);
int mangle_double             (char arr[BLOCK_SIZE], int arr_len);
int mangle_double_times       (char arr[BLOCK_SIZE], int arr_len, int times);
int mangle_reflect            (char arr[BLOCK_SIZE], int arr_len);
int mangle_rotate_left        (char arr[BLOCK_SIZE], int arr_len);
int mangle_rotate_right       (char arr[BLOCK_SIZE], int arr_len);
int mangle_append             (char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_prepend            (char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_delete_at          (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_extract            (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_omit               (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_insert             (char arr[BLOCK_SIZE], int arr_len, int upos, char c);
int mangle_overstrike         (char arr[BLOCK_SIZE], int arr_len, int upos, char c);
int mangle_truncate_at        (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_replace            (char arr[BLOCK_SIZE], int arr_len, char oldc, char newc);
int mangle_purgechar          (char arr[BLOCK_SIZE], int arr_len, char c);
int mangle_dupeblock_prepend  (char arr[BLOCK_SIZE], int arr_len, int ulen);
int mangle_dupeblock_append   (char arr[BLOCK_SIZE], int arr_len, int ulen);
int mangle_dupechar_at        (char arr[BLOCK_SIZE], int arr_len, int upos, int ulen);
int mangle_dupechar           (char arr[BLOCK_SIZE], int arr_len);
int mangle_switch_at_check    (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2);
int mangle_switch_at          (char arr[BLOCK_SIZE], int arr_len, int upos, int upos2);
int mangle_chr_shiftl         (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_shiftr         (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_incr           (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_chr_decr           (char arr[BLOCK_SIZE], int arr_len, int upos);
int mangle_title              (char arr[BLOCK_SIZE], int arr_len);

int generate_random_rule (char rule_buf[RP_RULE_BUFSIZ], u32 rp_gen_func_min, u32 rp_gen_func_max);
int _old_apply_rule (char *rule, int rule_len, char in[BLOCK_SIZE], int in_len, char out[BLOCK_SIZE]);

int cpu_rule_to_kernel_rule (char *rule_buf, uint rule_len, kernel_rule_t *rule);
int kernel_rule_to_cpu_rule (char *rule_buf, kernel_rule_t *rule);

void *thread_device_watch (void *p);
void *thread_keypress     (void *p);
void *thread_runtime      (void *p);

void status_display (void);
void status_display_machine_readable (void);

/**
 * checksum for use on cpu
 */

#include "cpu-crc32.h"
#include "cpu-md5.h"
#include "cpu-sha1.h"
#include "cpu-sha256.h"

/**
 * ciphers for use on cpu
 */

#include "cpu-aes.h"
#include "cpu-des.h"

#endif // SHARED_H
