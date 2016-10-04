/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_MD5_H
#define _CPU_MD5_H

#include <string.h>

void md5_64 (u32 block[16], u32 digest[4]);
void md5_complete_no_limit (u32 digest[4], u32 *plain, u32 plain_len);

#endif // _CPU_MD5_H
