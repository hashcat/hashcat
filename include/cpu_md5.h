/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_MD5_H
#define _CPU_MD5_H

#include <string.h>

void md5_64 (uint block[16], uint digest[4]);
void md5_complete_no_limit (uint digest[4], uint *plain, uint plain_len);

#endif // _CPU_MD5_H
