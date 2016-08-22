#pragma once
static const char PROGNAME[] = "hashcat";
static const char VERSION_TAG[] = "HEAD -> master, v3.10";
static const unsigned int VERSION_BIN = 310u;

#ifdef __cplusplus
static const auto
#else
static const unsigned int
#endif
COMPTIME = 1471824637u;

#define HAVE_HWMON

enum HASHCAT_CONFIG_ {
  ETC_MAX = 60 * 60 * 24 * 365 * 10,
  DEVICES_MAX = 128,
  CL_PLATFORMS_MAX = 16,
  BLOCK_SIZE = 64,
  CHARSIZ = 0x100,

  EXEC_CACHE = 128,
  SPEED_CACHE = 128,

  SPEED_MAXAGE = 4096,

  HCBUFSIZ = 0x50000,
  EXPECTED_ITERATIONS = 0x50000,
  CPT_BUF = 0x20000,
  MAX_CUT_TRIES = 4,
  MAX_DICTSTAT = 10000,
  VERIFIER_CNT = 1,
  STEPS_CNT = 10,
  RULES_MAX = 256,
  PW_MIN = 0,
  PW_MAX = 54,
  PW_DICTMAX = 31,
  PARAMCNT = 64,

  INFOSZ = CHARSIZ,
  SP_PW_MIN = 2,
  SP_PW_MAX = 64,

  PW_MAX1 = (PW_MAX + 1),
  PW_DICTMAX1 = (PW_DICTMAX + 1),
  SP_ROOT_CNT = (SP_PW_MAX * CHARSIZ),
  SP_MARKOV_CNT = (SP_PW_MAX * CHARSIZ * CHARSIZ),
};

static const char LOOPBACK_FILE[] = "hashcat.loopback";
static const char DICTSTAT_FILENAME[] = "hashcat.dictstat";
static const char POTFILE_FILENAME[] = "hashcat.pot";
static const char SP_HCSTAT[] = "hashcat.hcstat";
static const char TUNING_DB_FILE[] = "hashcat.hctune";

static const char INDUCT_DIR[] = "induct";
static const char OUTFILES_DIR[] = "outfiles";
static const char SESSIONS_FOLDER[] = "sessions";
static const char DOT_HASHCAT[] = ".hashcat";


#ifdef __linux__
static const char INSTALL_FOLDER[] = "/usr/local/bin";
static const char SHARED_FOLDER[] = "/usr/local/share/doc/hashcat";
static const char DOCUMENT_FOLDER[] = "/usr/local/share/hashcat";
#endif
