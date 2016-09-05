/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

void md5_64 (uint block[16], uint digest[4]);
void md5_complete_no_limit (uint digest[4], uint *plain, uint plain_len);
