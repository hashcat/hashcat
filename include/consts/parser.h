#pragma once
/**
* parser
*/
typedef enum PARSER_ {
  PARSER_OK = 0,
  PARSER_COMMENT = -1,
  PARSER_GLOBAL_ZERO = -2,
  PARSER_GLOBAL_LENGTH = -3,
  PARSER_HASH_LENGTH = -4,
  PARSER_HASH_VALUE = -5,
  PARSER_SALT_LENGTH = -6,
  PARSER_SALT_VALUE = -7,
  PARSER_SALT_ITERATION = -8,
  PARSER_SEPARATOR_UNMATCHED = -9,
  PARSER_SIGNATURE_UNMATCHED = -10,
  PARSER_HCCAP_FILE_SIZE = -11,
  PARSER_HCCAP_EAPOL_SIZE = -12,
  PARSER_PSAFE2_FILE_SIZE = -13,
  PARSER_PSAFE3_FILE_SIZE = -14,
  PARSER_TC_FILE_SIZE = -15,
  PARSER_VC_FILE_SIZE = -16,
  PARSER_SIP_AUTH_DIRECTIVE = -17,
  PARSER_UNKNOWN_ERROR = -255
} PARSER;

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
