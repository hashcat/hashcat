#pragma once
/**
* Outfile formats
*/
typedef enum OUTFILE_FMT_ {
  OUTFILE_FMT_HASH = (1 << 0),
  OUTFILE_FMT_PLAIN = (1 << 1),
  OUTFILE_FMT_HEXPLAIN = (1 << 2),
  OUTFILE_FMT_CRACKPOS = (1 << 3),
} OUTFILE_FMT;
