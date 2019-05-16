/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         Serpent by Ross Anderson, Eli Biham and Lars Knudsen         */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */
/*                                                                      */
/* -------------------------------------------------------------------- */
/*                                                                      */
/* Cleaned and optimized for GPU use with hashcat by Jens Steube        */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_serpent.h"

/* 15 terms */

#define sb0(a,b,c,d,e,f,g,h)    \
    t1 = a ^ d;     \
    t2 = a & d;     \
    t3 = c ^ t1;    \
    t6 = b & t1;    \
    t4 = b ^ t3;    \
    t10 = ~t3;      \
    h = t2 ^ t4;    \
    t7 = a ^ t6;    \
    t14 = ~t7;      \
    t8 = c | t7;    \
    t11 = t3 ^ t7;  \
    g = t4 ^ t8;    \
    t12 = h & t11;  \
    f = t10 ^ t12;  \
    e = t12 ^ t14

/* 15 terms */

#define ib0(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = a ^ b;     \
    t3 = t1 | t2;   \
    t4 = d ^ t3;    \
    t7 = d & t2;    \
    t5 = c ^ t4;    \
    t8 = t1 ^ t7;   \
    g = t2 ^ t5;    \
    t11 = a & t4;   \
    t9 = g & t8;    \
    t14 = t5 ^ t8;  \
    f = t4 ^ t9;    \
    t12 = t5 | f;   \
    h = t11 ^ t12;  \
    e = h ^ t14

/* 14 terms!  */

#define sb1(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = b ^ t1;    \
    t3 = a | t2;    \
    t4 = d | t2;    \
    t5 = c ^ t3;    \
    g = d ^ t5;     \
    t7 = b ^ t4;    \
    t8 = t2 ^ g;    \
    t9 = t5 & t7;   \
    h = t8 ^ t9;    \
    t11 = t5 ^ t7;  \
    f = h ^ t11;    \
    t13 = t8 & t11; \
    e = t5 ^ t13

/* 17 terms */

#define ib1(a,b,c,d,e,f,g,h)    \
    t1 = a ^ d;     \
    t2 = a & b;     \
    t3 = b ^ c;     \
    t4 = a ^ t3;    \
    t5 = b | d;     \
    t7 = c | t1;    \
    h = t4 ^ t5;    \
    t8 = b ^ t7;    \
    t11 = ~t2;      \
    t9 = t4 & t8;   \
    f = t1 ^ t9;    \
    t13 = t9 ^ t11; \
    t12 = h & f;    \
    g = t12 ^ t13;  \
    t15 = a & d;    \
    t16 = c ^ t13;  \
    e = t15 ^ t16

/* 16 terms */

#define sb2(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = b ^ d;     \
    t3 = c & t1;    \
    t13 = d | t1;   \
    e = t2 ^ t3;    \
    t5 = c ^ t1;    \
    t6 = c ^ e;     \
    t7 = b & t6;    \
    t10 = e | t5;   \
    h = t5 ^ t7;    \
    t9 = d | t7;    \
    t11 = t9 & t10; \
    t14 = t2 ^ h;   \
    g = a ^ t11;    \
    t15 = g ^ t13;  \
    f = t14 ^ t15

/* 16 terms */

#define ib2(a,b,c,d,e,f,g,h)    \
    t1 = b ^ d;     \
    t2 = ~t1;       \
    t3 = a ^ c;     \
    t4 = c ^ t1;    \
    t7 = a | t2;    \
    t5 = b & t4;    \
    t8 = d ^ t7;    \
    t11 = ~t4;      \
    e = t3 ^ t5;    \
    t9 = t3 | t8;   \
    t14 = d & t11;  \
    h = t1 ^ t9;    \
    t12 = e | h;    \
    f = t11 ^ t12;  \
    t15 = t3 ^ t12; \
    g = t14 ^ t15

/* 17 terms */

#define sb3(a,b,c,d,e,f,g,h)    \
    t1 = a ^ c;     \
    t2 = d ^ t1;    \
    t3 = a & t2;    \
    t4 = d ^ t3;    \
    t5 = b & t4;    \
    g = t2 ^ t5;    \
    t7 = a | g;     \
    t8 = b | d;     \
    t11 = a | d;    \
    t9 = t4 & t7;   \
    f = t8 ^ t9;    \
    t12 = b ^ t11;  \
    t13 = g ^ t9;   \
    t15 = t3 ^ t8;  \
    h = t12 ^ t13;  \
    t16 = c & t15;  \
    e = t12 ^ t16

/* 16 term solution that performs less well than 17 term one
   in my environment (PPro/PII)

#define sb3(a,b,c,d,e,f,g,h)    \
    t1 = a ^ b;     \
    t2 = a & c;     \
    t3 = a | d;     \
    t4 = c ^ d;     \
    t5 = t1 & t3;   \
    t6 = t2 | t5;   \
    g = t4 ^ t6;    \
    t8 = b ^ t3;    \
    t9 = t6 ^ t8;   \
    t10 = t4 & t9;  \
    e = t1 ^ t10;   \
    t12 = g & e;    \
    f = t9 ^ t12;   \
    t14 = b | d;    \
    t15 = t4 ^ t12; \
    h = t14 ^ t15
*/

/* 17 terms */

#define ib3(a,b,c,d,e,f,g,h)    \
    t1 = b ^ c;     \
    t2 = b | c;     \
    t3 = a ^ c;     \
    t7 = a ^ d;     \
    t4 = t2 ^ t3;   \
    t5 = d | t4;    \
    t9 = t2 ^ t7;   \
    e = t1 ^ t5;    \
    t8 = t1 | t5;   \
    t11 = a & t4;   \
    g = t8 ^ t9;    \
    t12 = e | t9;   \
    f = t11 ^ t12;  \
    t14 = a & g;    \
    t15 = t2 ^ t14; \
    t16 = e & t15;  \
    h = t4 ^ t16

/* 15 terms */

#define sb4(a,b,c,d,e,f,g,h)    \
    t1 = a ^ d;     \
    t2 = d & t1;    \
    t3 = c ^ t2;    \
    t4 = b | t3;    \
    h = t1 ^ t4;    \
    t6 = ~b;        \
    t7 = t1 | t6;   \
    e = t3 ^ t7;    \
    t9 = a & e;     \
    t10 = t1 ^ t6;  \
    t11 = t4 & t10; \
    g = t9 ^ t11;   \
    t13 = a ^ t3;   \
    t14 = t10 & g;  \
    f = t13 ^ t14

/* 17 terms */

#define ib4(a,b,c,d,e,f,g,h)    \
    t1 = c ^ d;     \
    t2 = c | d;     \
    t3 = b ^ t2;    \
    t4 = a & t3;    \
    f = t1 ^ t4;    \
    t6 = a ^ d;     \
    t7 = b | d;     \
    t8 = t6 & t7;   \
    h = t3 ^ t8;    \
    t10 = ~a;       \
    t11 = c ^ h;    \
    t12 = t10 | t11;\
    e = t3 ^ t12;   \
    t14 = c | t4;   \
    t15 = t7 ^ t14; \
    t16 = h | t10;  \
    g = t15 ^ t16

/* 16 terms */

#define sb5(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = a ^ b;     \
    t3 = a ^ d;     \
    t4 = c ^ t1;    \
    t5 = t2 | t3;   \
    e = t4 ^ t5;    \
    t7 = d & e;     \
    t8 = t2 ^ e;    \
    t10 = t1 | e;   \
    f = t7 ^ t8;    \
    t11 = t2 | t7;  \
    t12 = t3 ^ t10; \
    t14 = b ^ t7;   \
    g = t11 ^ t12;  \
    t15 = f & t12;  \
    h = t14 ^ t15

/* 16 terms */

#define ib5(a,b,c,d,e,f,g,h)    \
    t1 = ~c;        \
    t2 = b & t1;    \
    t3 = d ^ t2;    \
    t4 = a & t3;    \
    t5 = b ^ t1;    \
    h = t4 ^ t5;    \
    t7 = b | h;     \
    t8 = a & t7;    \
    f = t3 ^ t8;    \
    t10 = a | d;    \
    t11 = t1 ^ t7;  \
    e = t10 ^ t11;  \
    t13 = a ^ c;    \
    t14 = b & t10;  \
    t15 = t4 | t13; \
    g = t14 ^ t15

/* 15 terms */

#define sb6(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = a ^ d;     \
    t3 = b ^ t2;    \
    t4 = t1 | t2;   \
    t5 = c ^ t4;    \
    f = b ^ t5;     \
    t13 = ~t5;      \
    t7 = t2 | f;    \
    t8 = d ^ t7;    \
    t9 = t5 & t8;   \
    g = t3 ^ t9;    \
    t11 = t5 ^ t8;  \
    e = g ^ t11;    \
    t14 = t3 & t11; \
    h = t13 ^ t14

/* 15 terms */

#define ib6(a,b,c,d,e,f,g,h)    \
    t1 = ~a;        \
    t2 = a ^ b;     \
    t3 = c ^ t2;    \
    t4 = c | t1;    \
    t5 = d ^ t4;    \
    t13 = d & t1;   \
    f = t3 ^ t5;    \
    t7 = t3 & t5;   \
    t8 = t2 ^ t7;   \
    t9 = b | t8;    \
    h = t5 ^ t9;    \
    t11 = b | h;    \
    e = t8 ^ t11;   \
    t14 = t3 ^ t11; \
    g = t13 ^ t14

/* 17 terms */

#define sb7(a,b,c,d,e,f,g,h)    \
    t1 = ~c;        \
    t2 = b ^ c;     \
    t3 = b | t1;    \
    t4 = d ^ t3;    \
    t5 = a & t4;    \
    t7 = a ^ d;     \
    h = t2 ^ t5;    \
    t8 = b ^ t5;    \
    t9 = t2 | t8;   \
    t11 = d & t3;   \
    f = t7 ^ t9;    \
    t12 = t5 ^ f;   \
    t15 = t1 | t4;  \
    t13 = h & t12;  \
    g = t11 ^ t13;  \
    t16 = t12 ^ g;  \
    e = t15 ^ t16

/* 17 terms */

#define ib7(a,b,c,d,e,f,g,h)    \
    t1 = a & b;     \
    t2 = a | b;     \
    t3 = c | t1;    \
    t4 = d & t2;    \
    h = t3 ^ t4;    \
    t6 = ~d;        \
    t7 = b ^ t4;    \
    t8 = h ^ t6;    \
    t11 = c ^ t7;   \
    t9 = t7 | t8;   \
    f = a ^ t9;     \
    t12 = d | f;    \
    e = t11 ^ t12;  \
    t14 = a & h;    \
    t15 = t3 ^ f;   \
    t16 = e ^ t14;  \
    g = t15 ^ t16

#define k_xor(r,a,b,c,d) \
    a ^= ks[4 * r +  8]; \
    b ^= ks[4 * r +  9]; \
    c ^= ks[4 * r + 10]; \
    d ^= ks[4 * r + 11]

#define k_set(r,a,b,c,d) \
    a = ks[4 * r +  8];  \
    b = ks[4 * r +  9];  \
    c = ks[4 * r + 10];  \
    d = ks[4 * r + 11]

#define k_get(r,a,b,c,d) \
    ks[4 * r +  8] = a;  \
    ks[4 * r +  9] = b;  \
    ks[4 * r + 10] = c;  \
    ks[4 * r + 11] = d

/* the linear transformation and its inverse    */

#define rot(a,b,c,d)        \
    a = hc_rotl32_S(a, 13);    \
    c = hc_rotl32_S(c, 3);     \
    d ^= c ^ (a << 3);      \
    b ^= a ^ c;             \
    d = hc_rotl32_S(d, 7);     \
    b = hc_rotl32_S(b, 1);     \
    a ^= b ^ d;             \
    c ^= d ^ (b << 7);      \
    a = hc_rotl32_S(a, 5);     \
    c = hc_rotl32_S(c, 22)

#define irot(a,b,c,d)       \
    c = hc_rotr32_S(c, 22);    \
    a = hc_rotr32_S(a, 5);     \
    c ^= d ^ (b << 7);      \
    a ^= b ^ d;             \
    d = hc_rotr32_S(d, 7);     \
    b = hc_rotr32_S(b, 1);     \
    d ^= c ^ (a << 3);      \
    b ^= a ^ c;             \
    c = hc_rotr32_S(c, 3);     \
    a = hc_rotr32_S(a, 13)

// 128 bit key

DECLSPEC void serpent128_set_key (u32 *ks, const u32 *ukey)
{
  ks[  0] = ukey[0];
  ks[  1] = ukey[1];
  ks[  2] = ukey[2];
  ks[  3] = ukey[3];
  ks[  4] = 1;
  ks[  5] = 0;
  ks[  6] = 0;
  ks[  7] = 0;
  ks[  8] = hc_rotl32_S ((ks[  7] ^ ks[  5] ^ ks[  3] ^ ks[  0] ^ 0x9e3779b9 ^   0), 11);
  ks[  9] = hc_rotl32_S ((ks[  8] ^ ks[  6] ^ ks[  4] ^ ks[  1] ^ 0x9e3779b9 ^   1), 11);
  ks[ 10] = hc_rotl32_S ((ks[  9] ^ ks[  7] ^ ks[  5] ^ ks[  2] ^ 0x9e3779b9 ^   2), 11);
  ks[ 11] = hc_rotl32_S ((ks[ 10] ^ ks[  8] ^ ks[  6] ^ ks[  3] ^ 0x9e3779b9 ^   3), 11);
  ks[ 12] = hc_rotl32_S ((ks[ 11] ^ ks[  9] ^ ks[  7] ^ ks[  4] ^ 0x9e3779b9 ^   4), 11);
  ks[ 13] = hc_rotl32_S ((ks[ 12] ^ ks[ 10] ^ ks[  8] ^ ks[  5] ^ 0x9e3779b9 ^   5), 11);
  ks[ 14] = hc_rotl32_S ((ks[ 13] ^ ks[ 11] ^ ks[  9] ^ ks[  6] ^ 0x9e3779b9 ^   6), 11);
  ks[ 15] = hc_rotl32_S ((ks[ 14] ^ ks[ 12] ^ ks[ 10] ^ ks[  7] ^ 0x9e3779b9 ^   7), 11);
  ks[ 16] = hc_rotl32_S ((ks[ 15] ^ ks[ 13] ^ ks[ 11] ^ ks[  8] ^ 0x9e3779b9 ^   8), 11);
  ks[ 17] = hc_rotl32_S ((ks[ 16] ^ ks[ 14] ^ ks[ 12] ^ ks[  9] ^ 0x9e3779b9 ^   9), 11);
  ks[ 18] = hc_rotl32_S ((ks[ 17] ^ ks[ 15] ^ ks[ 13] ^ ks[ 10] ^ 0x9e3779b9 ^  10), 11);
  ks[ 19] = hc_rotl32_S ((ks[ 18] ^ ks[ 16] ^ ks[ 14] ^ ks[ 11] ^ 0x9e3779b9 ^  11), 11);
  ks[ 20] = hc_rotl32_S ((ks[ 19] ^ ks[ 17] ^ ks[ 15] ^ ks[ 12] ^ 0x9e3779b9 ^  12), 11);
  ks[ 21] = hc_rotl32_S ((ks[ 20] ^ ks[ 18] ^ ks[ 16] ^ ks[ 13] ^ 0x9e3779b9 ^  13), 11);
  ks[ 22] = hc_rotl32_S ((ks[ 21] ^ ks[ 19] ^ ks[ 17] ^ ks[ 14] ^ 0x9e3779b9 ^  14), 11);
  ks[ 23] = hc_rotl32_S ((ks[ 22] ^ ks[ 20] ^ ks[ 18] ^ ks[ 15] ^ 0x9e3779b9 ^  15), 11);
  ks[ 24] = hc_rotl32_S ((ks[ 23] ^ ks[ 21] ^ ks[ 19] ^ ks[ 16] ^ 0x9e3779b9 ^  16), 11);
  ks[ 25] = hc_rotl32_S ((ks[ 24] ^ ks[ 22] ^ ks[ 20] ^ ks[ 17] ^ 0x9e3779b9 ^  17), 11);
  ks[ 26] = hc_rotl32_S ((ks[ 25] ^ ks[ 23] ^ ks[ 21] ^ ks[ 18] ^ 0x9e3779b9 ^  18), 11);
  ks[ 27] = hc_rotl32_S ((ks[ 26] ^ ks[ 24] ^ ks[ 22] ^ ks[ 19] ^ 0x9e3779b9 ^  19), 11);
  ks[ 28] = hc_rotl32_S ((ks[ 27] ^ ks[ 25] ^ ks[ 23] ^ ks[ 20] ^ 0x9e3779b9 ^  20), 11);
  ks[ 29] = hc_rotl32_S ((ks[ 28] ^ ks[ 26] ^ ks[ 24] ^ ks[ 21] ^ 0x9e3779b9 ^  21), 11);
  ks[ 30] = hc_rotl32_S ((ks[ 29] ^ ks[ 27] ^ ks[ 25] ^ ks[ 22] ^ 0x9e3779b9 ^  22), 11);
  ks[ 31] = hc_rotl32_S ((ks[ 30] ^ ks[ 28] ^ ks[ 26] ^ ks[ 23] ^ 0x9e3779b9 ^  23), 11);
  ks[ 32] = hc_rotl32_S ((ks[ 31] ^ ks[ 29] ^ ks[ 27] ^ ks[ 24] ^ 0x9e3779b9 ^  24), 11);
  ks[ 33] = hc_rotl32_S ((ks[ 32] ^ ks[ 30] ^ ks[ 28] ^ ks[ 25] ^ 0x9e3779b9 ^  25), 11);
  ks[ 34] = hc_rotl32_S ((ks[ 33] ^ ks[ 31] ^ ks[ 29] ^ ks[ 26] ^ 0x9e3779b9 ^  26), 11);
  ks[ 35] = hc_rotl32_S ((ks[ 34] ^ ks[ 32] ^ ks[ 30] ^ ks[ 27] ^ 0x9e3779b9 ^  27), 11);
  ks[ 36] = hc_rotl32_S ((ks[ 35] ^ ks[ 33] ^ ks[ 31] ^ ks[ 28] ^ 0x9e3779b9 ^  28), 11);
  ks[ 37] = hc_rotl32_S ((ks[ 36] ^ ks[ 34] ^ ks[ 32] ^ ks[ 29] ^ 0x9e3779b9 ^  29), 11);
  ks[ 38] = hc_rotl32_S ((ks[ 37] ^ ks[ 35] ^ ks[ 33] ^ ks[ 30] ^ 0x9e3779b9 ^  30), 11);
  ks[ 39] = hc_rotl32_S ((ks[ 38] ^ ks[ 36] ^ ks[ 34] ^ ks[ 31] ^ 0x9e3779b9 ^  31), 11);
  ks[ 40] = hc_rotl32_S ((ks[ 39] ^ ks[ 37] ^ ks[ 35] ^ ks[ 32] ^ 0x9e3779b9 ^  32), 11);
  ks[ 41] = hc_rotl32_S ((ks[ 40] ^ ks[ 38] ^ ks[ 36] ^ ks[ 33] ^ 0x9e3779b9 ^  33), 11);
  ks[ 42] = hc_rotl32_S ((ks[ 41] ^ ks[ 39] ^ ks[ 37] ^ ks[ 34] ^ 0x9e3779b9 ^  34), 11);
  ks[ 43] = hc_rotl32_S ((ks[ 42] ^ ks[ 40] ^ ks[ 38] ^ ks[ 35] ^ 0x9e3779b9 ^  35), 11);
  ks[ 44] = hc_rotl32_S ((ks[ 43] ^ ks[ 41] ^ ks[ 39] ^ ks[ 36] ^ 0x9e3779b9 ^  36), 11);
  ks[ 45] = hc_rotl32_S ((ks[ 44] ^ ks[ 42] ^ ks[ 40] ^ ks[ 37] ^ 0x9e3779b9 ^  37), 11);
  ks[ 46] = hc_rotl32_S ((ks[ 45] ^ ks[ 43] ^ ks[ 41] ^ ks[ 38] ^ 0x9e3779b9 ^  38), 11);
  ks[ 47] = hc_rotl32_S ((ks[ 46] ^ ks[ 44] ^ ks[ 42] ^ ks[ 39] ^ 0x9e3779b9 ^  39), 11);
  ks[ 48] = hc_rotl32_S ((ks[ 47] ^ ks[ 45] ^ ks[ 43] ^ ks[ 40] ^ 0x9e3779b9 ^  40), 11);
  ks[ 49] = hc_rotl32_S ((ks[ 48] ^ ks[ 46] ^ ks[ 44] ^ ks[ 41] ^ 0x9e3779b9 ^  41), 11);
  ks[ 50] = hc_rotl32_S ((ks[ 49] ^ ks[ 47] ^ ks[ 45] ^ ks[ 42] ^ 0x9e3779b9 ^  42), 11);
  ks[ 51] = hc_rotl32_S ((ks[ 50] ^ ks[ 48] ^ ks[ 46] ^ ks[ 43] ^ 0x9e3779b9 ^  43), 11);
  ks[ 52] = hc_rotl32_S ((ks[ 51] ^ ks[ 49] ^ ks[ 47] ^ ks[ 44] ^ 0x9e3779b9 ^  44), 11);
  ks[ 53] = hc_rotl32_S ((ks[ 52] ^ ks[ 50] ^ ks[ 48] ^ ks[ 45] ^ 0x9e3779b9 ^  45), 11);
  ks[ 54] = hc_rotl32_S ((ks[ 53] ^ ks[ 51] ^ ks[ 49] ^ ks[ 46] ^ 0x9e3779b9 ^  46), 11);
  ks[ 55] = hc_rotl32_S ((ks[ 54] ^ ks[ 52] ^ ks[ 50] ^ ks[ 47] ^ 0x9e3779b9 ^  47), 11);
  ks[ 56] = hc_rotl32_S ((ks[ 55] ^ ks[ 53] ^ ks[ 51] ^ ks[ 48] ^ 0x9e3779b9 ^  48), 11);
  ks[ 57] = hc_rotl32_S ((ks[ 56] ^ ks[ 54] ^ ks[ 52] ^ ks[ 49] ^ 0x9e3779b9 ^  49), 11);
  ks[ 58] = hc_rotl32_S ((ks[ 57] ^ ks[ 55] ^ ks[ 53] ^ ks[ 50] ^ 0x9e3779b9 ^  50), 11);
  ks[ 59] = hc_rotl32_S ((ks[ 58] ^ ks[ 56] ^ ks[ 54] ^ ks[ 51] ^ 0x9e3779b9 ^  51), 11);
  ks[ 60] = hc_rotl32_S ((ks[ 59] ^ ks[ 57] ^ ks[ 55] ^ ks[ 52] ^ 0x9e3779b9 ^  52), 11);
  ks[ 61] = hc_rotl32_S ((ks[ 60] ^ ks[ 58] ^ ks[ 56] ^ ks[ 53] ^ 0x9e3779b9 ^  53), 11);
  ks[ 62] = hc_rotl32_S ((ks[ 61] ^ ks[ 59] ^ ks[ 57] ^ ks[ 54] ^ 0x9e3779b9 ^  54), 11);
  ks[ 63] = hc_rotl32_S ((ks[ 62] ^ ks[ 60] ^ ks[ 58] ^ ks[ 55] ^ 0x9e3779b9 ^  55), 11);
  ks[ 64] = hc_rotl32_S ((ks[ 63] ^ ks[ 61] ^ ks[ 59] ^ ks[ 56] ^ 0x9e3779b9 ^  56), 11);
  ks[ 65] = hc_rotl32_S ((ks[ 64] ^ ks[ 62] ^ ks[ 60] ^ ks[ 57] ^ 0x9e3779b9 ^  57), 11);
  ks[ 66] = hc_rotl32_S ((ks[ 65] ^ ks[ 63] ^ ks[ 61] ^ ks[ 58] ^ 0x9e3779b9 ^  58), 11);
  ks[ 67] = hc_rotl32_S ((ks[ 66] ^ ks[ 64] ^ ks[ 62] ^ ks[ 59] ^ 0x9e3779b9 ^  59), 11);
  ks[ 68] = hc_rotl32_S ((ks[ 67] ^ ks[ 65] ^ ks[ 63] ^ ks[ 60] ^ 0x9e3779b9 ^  60), 11);
  ks[ 69] = hc_rotl32_S ((ks[ 68] ^ ks[ 66] ^ ks[ 64] ^ ks[ 61] ^ 0x9e3779b9 ^  61), 11);
  ks[ 70] = hc_rotl32_S ((ks[ 69] ^ ks[ 67] ^ ks[ 65] ^ ks[ 62] ^ 0x9e3779b9 ^  62), 11);
  ks[ 71] = hc_rotl32_S ((ks[ 70] ^ ks[ 68] ^ ks[ 66] ^ ks[ 63] ^ 0x9e3779b9 ^  63), 11);
  ks[ 72] = hc_rotl32_S ((ks[ 71] ^ ks[ 69] ^ ks[ 67] ^ ks[ 64] ^ 0x9e3779b9 ^  64), 11);
  ks[ 73] = hc_rotl32_S ((ks[ 72] ^ ks[ 70] ^ ks[ 68] ^ ks[ 65] ^ 0x9e3779b9 ^  65), 11);
  ks[ 74] = hc_rotl32_S ((ks[ 73] ^ ks[ 71] ^ ks[ 69] ^ ks[ 66] ^ 0x9e3779b9 ^  66), 11);
  ks[ 75] = hc_rotl32_S ((ks[ 74] ^ ks[ 72] ^ ks[ 70] ^ ks[ 67] ^ 0x9e3779b9 ^  67), 11);
  ks[ 76] = hc_rotl32_S ((ks[ 75] ^ ks[ 73] ^ ks[ 71] ^ ks[ 68] ^ 0x9e3779b9 ^  68), 11);
  ks[ 77] = hc_rotl32_S ((ks[ 76] ^ ks[ 74] ^ ks[ 72] ^ ks[ 69] ^ 0x9e3779b9 ^  69), 11);
  ks[ 78] = hc_rotl32_S ((ks[ 77] ^ ks[ 75] ^ ks[ 73] ^ ks[ 70] ^ 0x9e3779b9 ^  70), 11);
  ks[ 79] = hc_rotl32_S ((ks[ 78] ^ ks[ 76] ^ ks[ 74] ^ ks[ 71] ^ 0x9e3779b9 ^  71), 11);
  ks[ 80] = hc_rotl32_S ((ks[ 79] ^ ks[ 77] ^ ks[ 75] ^ ks[ 72] ^ 0x9e3779b9 ^  72), 11);
  ks[ 81] = hc_rotl32_S ((ks[ 80] ^ ks[ 78] ^ ks[ 76] ^ ks[ 73] ^ 0x9e3779b9 ^  73), 11);
  ks[ 82] = hc_rotl32_S ((ks[ 81] ^ ks[ 79] ^ ks[ 77] ^ ks[ 74] ^ 0x9e3779b9 ^  74), 11);
  ks[ 83] = hc_rotl32_S ((ks[ 82] ^ ks[ 80] ^ ks[ 78] ^ ks[ 75] ^ 0x9e3779b9 ^  75), 11);
  ks[ 84] = hc_rotl32_S ((ks[ 83] ^ ks[ 81] ^ ks[ 79] ^ ks[ 76] ^ 0x9e3779b9 ^  76), 11);
  ks[ 85] = hc_rotl32_S ((ks[ 84] ^ ks[ 82] ^ ks[ 80] ^ ks[ 77] ^ 0x9e3779b9 ^  77), 11);
  ks[ 86] = hc_rotl32_S ((ks[ 85] ^ ks[ 83] ^ ks[ 81] ^ ks[ 78] ^ 0x9e3779b9 ^  78), 11);
  ks[ 87] = hc_rotl32_S ((ks[ 86] ^ ks[ 84] ^ ks[ 82] ^ ks[ 79] ^ 0x9e3779b9 ^  79), 11);
  ks[ 88] = hc_rotl32_S ((ks[ 87] ^ ks[ 85] ^ ks[ 83] ^ ks[ 80] ^ 0x9e3779b9 ^  80), 11);
  ks[ 89] = hc_rotl32_S ((ks[ 88] ^ ks[ 86] ^ ks[ 84] ^ ks[ 81] ^ 0x9e3779b9 ^  81), 11);
  ks[ 90] = hc_rotl32_S ((ks[ 89] ^ ks[ 87] ^ ks[ 85] ^ ks[ 82] ^ 0x9e3779b9 ^  82), 11);
  ks[ 91] = hc_rotl32_S ((ks[ 90] ^ ks[ 88] ^ ks[ 86] ^ ks[ 83] ^ 0x9e3779b9 ^  83), 11);
  ks[ 92] = hc_rotl32_S ((ks[ 91] ^ ks[ 89] ^ ks[ 87] ^ ks[ 84] ^ 0x9e3779b9 ^  84), 11);
  ks[ 93] = hc_rotl32_S ((ks[ 92] ^ ks[ 90] ^ ks[ 88] ^ ks[ 85] ^ 0x9e3779b9 ^  85), 11);
  ks[ 94] = hc_rotl32_S ((ks[ 93] ^ ks[ 91] ^ ks[ 89] ^ ks[ 86] ^ 0x9e3779b9 ^  86), 11);
  ks[ 95] = hc_rotl32_S ((ks[ 94] ^ ks[ 92] ^ ks[ 90] ^ ks[ 87] ^ 0x9e3779b9 ^  87), 11);
  ks[ 96] = hc_rotl32_S ((ks[ 95] ^ ks[ 93] ^ ks[ 91] ^ ks[ 88] ^ 0x9e3779b9 ^  88), 11);
  ks[ 97] = hc_rotl32_S ((ks[ 96] ^ ks[ 94] ^ ks[ 92] ^ ks[ 89] ^ 0x9e3779b9 ^  89), 11);
  ks[ 98] = hc_rotl32_S ((ks[ 97] ^ ks[ 95] ^ ks[ 93] ^ ks[ 90] ^ 0x9e3779b9 ^  90), 11);
  ks[ 99] = hc_rotl32_S ((ks[ 98] ^ ks[ 96] ^ ks[ 94] ^ ks[ 91] ^ 0x9e3779b9 ^  91), 11);
  ks[100] = hc_rotl32_S ((ks[ 99] ^ ks[ 97] ^ ks[ 95] ^ ks[ 92] ^ 0x9e3779b9 ^  92), 11);
  ks[101] = hc_rotl32_S ((ks[100] ^ ks[ 98] ^ ks[ 96] ^ ks[ 93] ^ 0x9e3779b9 ^  93), 11);
  ks[102] = hc_rotl32_S ((ks[101] ^ ks[ 99] ^ ks[ 97] ^ ks[ 94] ^ 0x9e3779b9 ^  94), 11);
  ks[103] = hc_rotl32_S ((ks[102] ^ ks[100] ^ ks[ 98] ^ ks[ 95] ^ 0x9e3779b9 ^  95), 11);
  ks[104] = hc_rotl32_S ((ks[103] ^ ks[101] ^ ks[ 99] ^ ks[ 96] ^ 0x9e3779b9 ^  96), 11);
  ks[105] = hc_rotl32_S ((ks[104] ^ ks[102] ^ ks[100] ^ ks[ 97] ^ 0x9e3779b9 ^  97), 11);
  ks[106] = hc_rotl32_S ((ks[105] ^ ks[103] ^ ks[101] ^ ks[ 98] ^ 0x9e3779b9 ^  98), 11);
  ks[107] = hc_rotl32_S ((ks[106] ^ ks[104] ^ ks[102] ^ ks[ 99] ^ 0x9e3779b9 ^  99), 11);
  ks[108] = hc_rotl32_S ((ks[107] ^ ks[105] ^ ks[103] ^ ks[100] ^ 0x9e3779b9 ^ 100), 11);
  ks[109] = hc_rotl32_S ((ks[108] ^ ks[106] ^ ks[104] ^ ks[101] ^ 0x9e3779b9 ^ 101), 11);
  ks[110] = hc_rotl32_S ((ks[109] ^ ks[107] ^ ks[105] ^ ks[102] ^ 0x9e3779b9 ^ 102), 11);
  ks[111] = hc_rotl32_S ((ks[110] ^ ks[108] ^ ks[106] ^ ks[103] ^ 0x9e3779b9 ^ 103), 11);
  ks[112] = hc_rotl32_S ((ks[111] ^ ks[109] ^ ks[107] ^ ks[104] ^ 0x9e3779b9 ^ 104), 11);
  ks[113] = hc_rotl32_S ((ks[112] ^ ks[110] ^ ks[108] ^ ks[105] ^ 0x9e3779b9 ^ 105), 11);
  ks[114] = hc_rotl32_S ((ks[113] ^ ks[111] ^ ks[109] ^ ks[106] ^ 0x9e3779b9 ^ 106), 11);
  ks[115] = hc_rotl32_S ((ks[114] ^ ks[112] ^ ks[110] ^ ks[107] ^ 0x9e3779b9 ^ 107), 11);
  ks[116] = hc_rotl32_S ((ks[115] ^ ks[113] ^ ks[111] ^ ks[108] ^ 0x9e3779b9 ^ 108), 11);
  ks[117] = hc_rotl32_S ((ks[116] ^ ks[114] ^ ks[112] ^ ks[109] ^ 0x9e3779b9 ^ 109), 11);
  ks[118] = hc_rotl32_S ((ks[117] ^ ks[115] ^ ks[113] ^ ks[110] ^ 0x9e3779b9 ^ 110), 11);
  ks[119] = hc_rotl32_S ((ks[118] ^ ks[116] ^ ks[114] ^ ks[111] ^ 0x9e3779b9 ^ 111), 11);
  ks[120] = hc_rotl32_S ((ks[119] ^ ks[117] ^ ks[115] ^ ks[112] ^ 0x9e3779b9 ^ 112), 11);
  ks[121] = hc_rotl32_S ((ks[120] ^ ks[118] ^ ks[116] ^ ks[113] ^ 0x9e3779b9 ^ 113), 11);
  ks[122] = hc_rotl32_S ((ks[121] ^ ks[119] ^ ks[117] ^ ks[114] ^ 0x9e3779b9 ^ 114), 11);
  ks[123] = hc_rotl32_S ((ks[122] ^ ks[120] ^ ks[118] ^ ks[115] ^ 0x9e3779b9 ^ 115), 11);
  ks[124] = hc_rotl32_S ((ks[123] ^ ks[121] ^ ks[119] ^ ks[116] ^ 0x9e3779b9 ^ 116), 11);
  ks[125] = hc_rotl32_S ((ks[124] ^ ks[122] ^ ks[120] ^ ks[117] ^ 0x9e3779b9 ^ 117), 11);
  ks[126] = hc_rotl32_S ((ks[125] ^ ks[123] ^ ks[121] ^ ks[118] ^ 0x9e3779b9 ^ 118), 11);
  ks[127] = hc_rotl32_S ((ks[126] ^ ks[124] ^ ks[122] ^ ks[119] ^ 0x9e3779b9 ^ 119), 11);
  ks[128] = hc_rotl32_S ((ks[127] ^ ks[125] ^ ks[123] ^ ks[120] ^ 0x9e3779b9 ^ 120), 11);
  ks[129] = hc_rotl32_S ((ks[128] ^ ks[126] ^ ks[124] ^ ks[121] ^ 0x9e3779b9 ^ 121), 11);
  ks[130] = hc_rotl32_S ((ks[129] ^ ks[127] ^ ks[125] ^ ks[122] ^ 0x9e3779b9 ^ 122), 11);
  ks[131] = hc_rotl32_S ((ks[130] ^ ks[128] ^ ks[126] ^ ks[123] ^ 0x9e3779b9 ^ 123), 11);
  ks[132] = hc_rotl32_S ((ks[131] ^ ks[129] ^ ks[127] ^ ks[124] ^ 0x9e3779b9 ^ 124), 11);
  ks[133] = hc_rotl32_S ((ks[132] ^ ks[130] ^ ks[128] ^ ks[125] ^ 0x9e3779b9 ^ 125), 11);
  ks[134] = hc_rotl32_S ((ks[133] ^ ks[131] ^ ks[129] ^ ks[126] ^ 0x9e3779b9 ^ 126), 11);
  ks[135] = hc_rotl32_S ((ks[134] ^ ks[132] ^ ks[130] ^ ks[127] ^ 0x9e3779b9 ^ 127), 11);
  ks[136] = hc_rotl32_S ((ks[135] ^ ks[133] ^ ks[131] ^ ks[128] ^ 0x9e3779b9 ^ 128), 11);
  ks[137] = hc_rotl32_S ((ks[136] ^ ks[134] ^ ks[132] ^ ks[129] ^ 0x9e3779b9 ^ 129), 11);
  ks[138] = hc_rotl32_S ((ks[137] ^ ks[135] ^ ks[133] ^ ks[130] ^ 0x9e3779b9 ^ 130), 11);
  ks[139] = hc_rotl32_S ((ks[138] ^ ks[136] ^ ks[134] ^ ks[131] ^ 0x9e3779b9 ^ 131), 11);

  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  k_set( 0,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get( 0,e,f,g,h);
  k_set( 1,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get( 1,e,f,g,h);
  k_set( 2,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get( 2,e,f,g,h);
  k_set( 3,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get( 3,e,f,g,h);
  k_set( 4,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get( 4,e,f,g,h);
  k_set( 5,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get( 5,e,f,g,h);
  k_set( 6,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get( 6,e,f,g,h);
  k_set( 7,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get( 7,e,f,g,h);
  k_set( 8,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get( 8,e,f,g,h);
  k_set( 9,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get( 9,e,f,g,h);
  k_set(10,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(10,e,f,g,h);
  k_set(11,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(11,e,f,g,h);
  k_set(12,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(12,e,f,g,h);
  k_set(13,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(13,e,f,g,h);
  k_set(14,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(14,e,f,g,h);
  k_set(15,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(15,e,f,g,h);
  k_set(16,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(16,e,f,g,h);
  k_set(17,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get(17,e,f,g,h);
  k_set(18,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(18,e,f,g,h);
  k_set(19,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(19,e,f,g,h);
  k_set(20,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(20,e,f,g,h);
  k_set(21,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(21,e,f,g,h);
  k_set(22,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(22,e,f,g,h);
  k_set(23,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(23,e,f,g,h);
  k_set(24,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(24,e,f,g,h);
  k_set(25,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get(25,e,f,g,h);
  k_set(26,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(26,e,f,g,h);
  k_set(27,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(27,e,f,g,h);
  k_set(28,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(28,e,f,g,h);
  k_set(29,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(29,e,f,g,h);
  k_set(30,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(30,e,f,g,h);
  k_set(31,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(31,e,f,g,h);
  k_set(32,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(32,e,f,g,h);
}

DECLSPEC void serpent128_encrypt (const u32 *ks, const u32 *in, u32 *out)
{
  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  a = in[0];
  b = in[1];
  c = in[2];
  d = in[3];

  k_xor( 0,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 1,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 2,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 3,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 4,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 5,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 6,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 7,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 8,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 9,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(10,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(11,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(12,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(13,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(14,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(15,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(16,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(17,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(18,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(19,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(20,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(21,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(22,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(23,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(24,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(25,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(26,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(27,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(28,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(29,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(30,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(31,e,f,g,h); sb7(e,f,g,h,a,b,c,d);
  k_xor(32,a,b,c,d);

  out[0] = a;
  out[1] = b;
  out[2] = c;
  out[3] = d;
}

DECLSPEC void serpent128_decrypt (const u32 *ks, const u32 *in, u32 *out)
{
  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  a = in[0];
  b = in[1];
  c = in[2];
  d = in[3];

                                       k_xor(32,a,b,c,d);
                 ib7(a,b,c,d,e,f,g,h); k_xor(31,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(30,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(29,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(28,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(27,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(26,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(25,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(24,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(23,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(22,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(21,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(20,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(19,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(18,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(17,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(16,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(15,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(14,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(13,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(12,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(11,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(10,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 9,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 8,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor( 7,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor( 6,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor( 5,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor( 4,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor( 3,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor( 2,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 1,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 0,a,b,c,d);

  out[0] = a;
  out[1] = b;
  out[2] = c;
  out[3] = d;
}

// 256 bit key

DECLSPEC void serpent256_set_key (u32 *ks, const u32 *ukey)
{
  ks[  0] = ukey[0];
  ks[  1] = ukey[1];
  ks[  2] = ukey[2];
  ks[  3] = ukey[3];
  ks[  4] = ukey[4];
  ks[  5] = ukey[5];
  ks[  6] = ukey[6];
  ks[  7] = ukey[7];
  ks[  8] = hc_rotl32_S ((ks[  7] ^ ks[  5] ^ ks[  3] ^ ks[  0] ^ 0x9e3779b9 ^   0), 11);
  ks[  9] = hc_rotl32_S ((ks[  8] ^ ks[  6] ^ ks[  4] ^ ks[  1] ^ 0x9e3779b9 ^   1), 11);
  ks[ 10] = hc_rotl32_S ((ks[  9] ^ ks[  7] ^ ks[  5] ^ ks[  2] ^ 0x9e3779b9 ^   2), 11);
  ks[ 11] = hc_rotl32_S ((ks[ 10] ^ ks[  8] ^ ks[  6] ^ ks[  3] ^ 0x9e3779b9 ^   3), 11);
  ks[ 12] = hc_rotl32_S ((ks[ 11] ^ ks[  9] ^ ks[  7] ^ ks[  4] ^ 0x9e3779b9 ^   4), 11);
  ks[ 13] = hc_rotl32_S ((ks[ 12] ^ ks[ 10] ^ ks[  8] ^ ks[  5] ^ 0x9e3779b9 ^   5), 11);
  ks[ 14] = hc_rotl32_S ((ks[ 13] ^ ks[ 11] ^ ks[  9] ^ ks[  6] ^ 0x9e3779b9 ^   6), 11);
  ks[ 15] = hc_rotl32_S ((ks[ 14] ^ ks[ 12] ^ ks[ 10] ^ ks[  7] ^ 0x9e3779b9 ^   7), 11);
  ks[ 16] = hc_rotl32_S ((ks[ 15] ^ ks[ 13] ^ ks[ 11] ^ ks[  8] ^ 0x9e3779b9 ^   8), 11);
  ks[ 17] = hc_rotl32_S ((ks[ 16] ^ ks[ 14] ^ ks[ 12] ^ ks[  9] ^ 0x9e3779b9 ^   9), 11);
  ks[ 18] = hc_rotl32_S ((ks[ 17] ^ ks[ 15] ^ ks[ 13] ^ ks[ 10] ^ 0x9e3779b9 ^  10), 11);
  ks[ 19] = hc_rotl32_S ((ks[ 18] ^ ks[ 16] ^ ks[ 14] ^ ks[ 11] ^ 0x9e3779b9 ^  11), 11);
  ks[ 20] = hc_rotl32_S ((ks[ 19] ^ ks[ 17] ^ ks[ 15] ^ ks[ 12] ^ 0x9e3779b9 ^  12), 11);
  ks[ 21] = hc_rotl32_S ((ks[ 20] ^ ks[ 18] ^ ks[ 16] ^ ks[ 13] ^ 0x9e3779b9 ^  13), 11);
  ks[ 22] = hc_rotl32_S ((ks[ 21] ^ ks[ 19] ^ ks[ 17] ^ ks[ 14] ^ 0x9e3779b9 ^  14), 11);
  ks[ 23] = hc_rotl32_S ((ks[ 22] ^ ks[ 20] ^ ks[ 18] ^ ks[ 15] ^ 0x9e3779b9 ^  15), 11);
  ks[ 24] = hc_rotl32_S ((ks[ 23] ^ ks[ 21] ^ ks[ 19] ^ ks[ 16] ^ 0x9e3779b9 ^  16), 11);
  ks[ 25] = hc_rotl32_S ((ks[ 24] ^ ks[ 22] ^ ks[ 20] ^ ks[ 17] ^ 0x9e3779b9 ^  17), 11);
  ks[ 26] = hc_rotl32_S ((ks[ 25] ^ ks[ 23] ^ ks[ 21] ^ ks[ 18] ^ 0x9e3779b9 ^  18), 11);
  ks[ 27] = hc_rotl32_S ((ks[ 26] ^ ks[ 24] ^ ks[ 22] ^ ks[ 19] ^ 0x9e3779b9 ^  19), 11);
  ks[ 28] = hc_rotl32_S ((ks[ 27] ^ ks[ 25] ^ ks[ 23] ^ ks[ 20] ^ 0x9e3779b9 ^  20), 11);
  ks[ 29] = hc_rotl32_S ((ks[ 28] ^ ks[ 26] ^ ks[ 24] ^ ks[ 21] ^ 0x9e3779b9 ^  21), 11);
  ks[ 30] = hc_rotl32_S ((ks[ 29] ^ ks[ 27] ^ ks[ 25] ^ ks[ 22] ^ 0x9e3779b9 ^  22), 11);
  ks[ 31] = hc_rotl32_S ((ks[ 30] ^ ks[ 28] ^ ks[ 26] ^ ks[ 23] ^ 0x9e3779b9 ^  23), 11);
  ks[ 32] = hc_rotl32_S ((ks[ 31] ^ ks[ 29] ^ ks[ 27] ^ ks[ 24] ^ 0x9e3779b9 ^  24), 11);
  ks[ 33] = hc_rotl32_S ((ks[ 32] ^ ks[ 30] ^ ks[ 28] ^ ks[ 25] ^ 0x9e3779b9 ^  25), 11);
  ks[ 34] = hc_rotl32_S ((ks[ 33] ^ ks[ 31] ^ ks[ 29] ^ ks[ 26] ^ 0x9e3779b9 ^  26), 11);
  ks[ 35] = hc_rotl32_S ((ks[ 34] ^ ks[ 32] ^ ks[ 30] ^ ks[ 27] ^ 0x9e3779b9 ^  27), 11);
  ks[ 36] = hc_rotl32_S ((ks[ 35] ^ ks[ 33] ^ ks[ 31] ^ ks[ 28] ^ 0x9e3779b9 ^  28), 11);
  ks[ 37] = hc_rotl32_S ((ks[ 36] ^ ks[ 34] ^ ks[ 32] ^ ks[ 29] ^ 0x9e3779b9 ^  29), 11);
  ks[ 38] = hc_rotl32_S ((ks[ 37] ^ ks[ 35] ^ ks[ 33] ^ ks[ 30] ^ 0x9e3779b9 ^  30), 11);
  ks[ 39] = hc_rotl32_S ((ks[ 38] ^ ks[ 36] ^ ks[ 34] ^ ks[ 31] ^ 0x9e3779b9 ^  31), 11);
  ks[ 40] = hc_rotl32_S ((ks[ 39] ^ ks[ 37] ^ ks[ 35] ^ ks[ 32] ^ 0x9e3779b9 ^  32), 11);
  ks[ 41] = hc_rotl32_S ((ks[ 40] ^ ks[ 38] ^ ks[ 36] ^ ks[ 33] ^ 0x9e3779b9 ^  33), 11);
  ks[ 42] = hc_rotl32_S ((ks[ 41] ^ ks[ 39] ^ ks[ 37] ^ ks[ 34] ^ 0x9e3779b9 ^  34), 11);
  ks[ 43] = hc_rotl32_S ((ks[ 42] ^ ks[ 40] ^ ks[ 38] ^ ks[ 35] ^ 0x9e3779b9 ^  35), 11);
  ks[ 44] = hc_rotl32_S ((ks[ 43] ^ ks[ 41] ^ ks[ 39] ^ ks[ 36] ^ 0x9e3779b9 ^  36), 11);
  ks[ 45] = hc_rotl32_S ((ks[ 44] ^ ks[ 42] ^ ks[ 40] ^ ks[ 37] ^ 0x9e3779b9 ^  37), 11);
  ks[ 46] = hc_rotl32_S ((ks[ 45] ^ ks[ 43] ^ ks[ 41] ^ ks[ 38] ^ 0x9e3779b9 ^  38), 11);
  ks[ 47] = hc_rotl32_S ((ks[ 46] ^ ks[ 44] ^ ks[ 42] ^ ks[ 39] ^ 0x9e3779b9 ^  39), 11);
  ks[ 48] = hc_rotl32_S ((ks[ 47] ^ ks[ 45] ^ ks[ 43] ^ ks[ 40] ^ 0x9e3779b9 ^  40), 11);
  ks[ 49] = hc_rotl32_S ((ks[ 48] ^ ks[ 46] ^ ks[ 44] ^ ks[ 41] ^ 0x9e3779b9 ^  41), 11);
  ks[ 50] = hc_rotl32_S ((ks[ 49] ^ ks[ 47] ^ ks[ 45] ^ ks[ 42] ^ 0x9e3779b9 ^  42), 11);
  ks[ 51] = hc_rotl32_S ((ks[ 50] ^ ks[ 48] ^ ks[ 46] ^ ks[ 43] ^ 0x9e3779b9 ^  43), 11);
  ks[ 52] = hc_rotl32_S ((ks[ 51] ^ ks[ 49] ^ ks[ 47] ^ ks[ 44] ^ 0x9e3779b9 ^  44), 11);
  ks[ 53] = hc_rotl32_S ((ks[ 52] ^ ks[ 50] ^ ks[ 48] ^ ks[ 45] ^ 0x9e3779b9 ^  45), 11);
  ks[ 54] = hc_rotl32_S ((ks[ 53] ^ ks[ 51] ^ ks[ 49] ^ ks[ 46] ^ 0x9e3779b9 ^  46), 11);
  ks[ 55] = hc_rotl32_S ((ks[ 54] ^ ks[ 52] ^ ks[ 50] ^ ks[ 47] ^ 0x9e3779b9 ^  47), 11);
  ks[ 56] = hc_rotl32_S ((ks[ 55] ^ ks[ 53] ^ ks[ 51] ^ ks[ 48] ^ 0x9e3779b9 ^  48), 11);
  ks[ 57] = hc_rotl32_S ((ks[ 56] ^ ks[ 54] ^ ks[ 52] ^ ks[ 49] ^ 0x9e3779b9 ^  49), 11);
  ks[ 58] = hc_rotl32_S ((ks[ 57] ^ ks[ 55] ^ ks[ 53] ^ ks[ 50] ^ 0x9e3779b9 ^  50), 11);
  ks[ 59] = hc_rotl32_S ((ks[ 58] ^ ks[ 56] ^ ks[ 54] ^ ks[ 51] ^ 0x9e3779b9 ^  51), 11);
  ks[ 60] = hc_rotl32_S ((ks[ 59] ^ ks[ 57] ^ ks[ 55] ^ ks[ 52] ^ 0x9e3779b9 ^  52), 11);
  ks[ 61] = hc_rotl32_S ((ks[ 60] ^ ks[ 58] ^ ks[ 56] ^ ks[ 53] ^ 0x9e3779b9 ^  53), 11);
  ks[ 62] = hc_rotl32_S ((ks[ 61] ^ ks[ 59] ^ ks[ 57] ^ ks[ 54] ^ 0x9e3779b9 ^  54), 11);
  ks[ 63] = hc_rotl32_S ((ks[ 62] ^ ks[ 60] ^ ks[ 58] ^ ks[ 55] ^ 0x9e3779b9 ^  55), 11);
  ks[ 64] = hc_rotl32_S ((ks[ 63] ^ ks[ 61] ^ ks[ 59] ^ ks[ 56] ^ 0x9e3779b9 ^  56), 11);
  ks[ 65] = hc_rotl32_S ((ks[ 64] ^ ks[ 62] ^ ks[ 60] ^ ks[ 57] ^ 0x9e3779b9 ^  57), 11);
  ks[ 66] = hc_rotl32_S ((ks[ 65] ^ ks[ 63] ^ ks[ 61] ^ ks[ 58] ^ 0x9e3779b9 ^  58), 11);
  ks[ 67] = hc_rotl32_S ((ks[ 66] ^ ks[ 64] ^ ks[ 62] ^ ks[ 59] ^ 0x9e3779b9 ^  59), 11);
  ks[ 68] = hc_rotl32_S ((ks[ 67] ^ ks[ 65] ^ ks[ 63] ^ ks[ 60] ^ 0x9e3779b9 ^  60), 11);
  ks[ 69] = hc_rotl32_S ((ks[ 68] ^ ks[ 66] ^ ks[ 64] ^ ks[ 61] ^ 0x9e3779b9 ^  61), 11);
  ks[ 70] = hc_rotl32_S ((ks[ 69] ^ ks[ 67] ^ ks[ 65] ^ ks[ 62] ^ 0x9e3779b9 ^  62), 11);
  ks[ 71] = hc_rotl32_S ((ks[ 70] ^ ks[ 68] ^ ks[ 66] ^ ks[ 63] ^ 0x9e3779b9 ^  63), 11);
  ks[ 72] = hc_rotl32_S ((ks[ 71] ^ ks[ 69] ^ ks[ 67] ^ ks[ 64] ^ 0x9e3779b9 ^  64), 11);
  ks[ 73] = hc_rotl32_S ((ks[ 72] ^ ks[ 70] ^ ks[ 68] ^ ks[ 65] ^ 0x9e3779b9 ^  65), 11);
  ks[ 74] = hc_rotl32_S ((ks[ 73] ^ ks[ 71] ^ ks[ 69] ^ ks[ 66] ^ 0x9e3779b9 ^  66), 11);
  ks[ 75] = hc_rotl32_S ((ks[ 74] ^ ks[ 72] ^ ks[ 70] ^ ks[ 67] ^ 0x9e3779b9 ^  67), 11);
  ks[ 76] = hc_rotl32_S ((ks[ 75] ^ ks[ 73] ^ ks[ 71] ^ ks[ 68] ^ 0x9e3779b9 ^  68), 11);
  ks[ 77] = hc_rotl32_S ((ks[ 76] ^ ks[ 74] ^ ks[ 72] ^ ks[ 69] ^ 0x9e3779b9 ^  69), 11);
  ks[ 78] = hc_rotl32_S ((ks[ 77] ^ ks[ 75] ^ ks[ 73] ^ ks[ 70] ^ 0x9e3779b9 ^  70), 11);
  ks[ 79] = hc_rotl32_S ((ks[ 78] ^ ks[ 76] ^ ks[ 74] ^ ks[ 71] ^ 0x9e3779b9 ^  71), 11);
  ks[ 80] = hc_rotl32_S ((ks[ 79] ^ ks[ 77] ^ ks[ 75] ^ ks[ 72] ^ 0x9e3779b9 ^  72), 11);
  ks[ 81] = hc_rotl32_S ((ks[ 80] ^ ks[ 78] ^ ks[ 76] ^ ks[ 73] ^ 0x9e3779b9 ^  73), 11);
  ks[ 82] = hc_rotl32_S ((ks[ 81] ^ ks[ 79] ^ ks[ 77] ^ ks[ 74] ^ 0x9e3779b9 ^  74), 11);
  ks[ 83] = hc_rotl32_S ((ks[ 82] ^ ks[ 80] ^ ks[ 78] ^ ks[ 75] ^ 0x9e3779b9 ^  75), 11);
  ks[ 84] = hc_rotl32_S ((ks[ 83] ^ ks[ 81] ^ ks[ 79] ^ ks[ 76] ^ 0x9e3779b9 ^  76), 11);
  ks[ 85] = hc_rotl32_S ((ks[ 84] ^ ks[ 82] ^ ks[ 80] ^ ks[ 77] ^ 0x9e3779b9 ^  77), 11);
  ks[ 86] = hc_rotl32_S ((ks[ 85] ^ ks[ 83] ^ ks[ 81] ^ ks[ 78] ^ 0x9e3779b9 ^  78), 11);
  ks[ 87] = hc_rotl32_S ((ks[ 86] ^ ks[ 84] ^ ks[ 82] ^ ks[ 79] ^ 0x9e3779b9 ^  79), 11);
  ks[ 88] = hc_rotl32_S ((ks[ 87] ^ ks[ 85] ^ ks[ 83] ^ ks[ 80] ^ 0x9e3779b9 ^  80), 11);
  ks[ 89] = hc_rotl32_S ((ks[ 88] ^ ks[ 86] ^ ks[ 84] ^ ks[ 81] ^ 0x9e3779b9 ^  81), 11);
  ks[ 90] = hc_rotl32_S ((ks[ 89] ^ ks[ 87] ^ ks[ 85] ^ ks[ 82] ^ 0x9e3779b9 ^  82), 11);
  ks[ 91] = hc_rotl32_S ((ks[ 90] ^ ks[ 88] ^ ks[ 86] ^ ks[ 83] ^ 0x9e3779b9 ^  83), 11);
  ks[ 92] = hc_rotl32_S ((ks[ 91] ^ ks[ 89] ^ ks[ 87] ^ ks[ 84] ^ 0x9e3779b9 ^  84), 11);
  ks[ 93] = hc_rotl32_S ((ks[ 92] ^ ks[ 90] ^ ks[ 88] ^ ks[ 85] ^ 0x9e3779b9 ^  85), 11);
  ks[ 94] = hc_rotl32_S ((ks[ 93] ^ ks[ 91] ^ ks[ 89] ^ ks[ 86] ^ 0x9e3779b9 ^  86), 11);
  ks[ 95] = hc_rotl32_S ((ks[ 94] ^ ks[ 92] ^ ks[ 90] ^ ks[ 87] ^ 0x9e3779b9 ^  87), 11);
  ks[ 96] = hc_rotl32_S ((ks[ 95] ^ ks[ 93] ^ ks[ 91] ^ ks[ 88] ^ 0x9e3779b9 ^  88), 11);
  ks[ 97] = hc_rotl32_S ((ks[ 96] ^ ks[ 94] ^ ks[ 92] ^ ks[ 89] ^ 0x9e3779b9 ^  89), 11);
  ks[ 98] = hc_rotl32_S ((ks[ 97] ^ ks[ 95] ^ ks[ 93] ^ ks[ 90] ^ 0x9e3779b9 ^  90), 11);
  ks[ 99] = hc_rotl32_S ((ks[ 98] ^ ks[ 96] ^ ks[ 94] ^ ks[ 91] ^ 0x9e3779b9 ^  91), 11);
  ks[100] = hc_rotl32_S ((ks[ 99] ^ ks[ 97] ^ ks[ 95] ^ ks[ 92] ^ 0x9e3779b9 ^  92), 11);
  ks[101] = hc_rotl32_S ((ks[100] ^ ks[ 98] ^ ks[ 96] ^ ks[ 93] ^ 0x9e3779b9 ^  93), 11);
  ks[102] = hc_rotl32_S ((ks[101] ^ ks[ 99] ^ ks[ 97] ^ ks[ 94] ^ 0x9e3779b9 ^  94), 11);
  ks[103] = hc_rotl32_S ((ks[102] ^ ks[100] ^ ks[ 98] ^ ks[ 95] ^ 0x9e3779b9 ^  95), 11);
  ks[104] = hc_rotl32_S ((ks[103] ^ ks[101] ^ ks[ 99] ^ ks[ 96] ^ 0x9e3779b9 ^  96), 11);
  ks[105] = hc_rotl32_S ((ks[104] ^ ks[102] ^ ks[100] ^ ks[ 97] ^ 0x9e3779b9 ^  97), 11);
  ks[106] = hc_rotl32_S ((ks[105] ^ ks[103] ^ ks[101] ^ ks[ 98] ^ 0x9e3779b9 ^  98), 11);
  ks[107] = hc_rotl32_S ((ks[106] ^ ks[104] ^ ks[102] ^ ks[ 99] ^ 0x9e3779b9 ^  99), 11);
  ks[108] = hc_rotl32_S ((ks[107] ^ ks[105] ^ ks[103] ^ ks[100] ^ 0x9e3779b9 ^ 100), 11);
  ks[109] = hc_rotl32_S ((ks[108] ^ ks[106] ^ ks[104] ^ ks[101] ^ 0x9e3779b9 ^ 101), 11);
  ks[110] = hc_rotl32_S ((ks[109] ^ ks[107] ^ ks[105] ^ ks[102] ^ 0x9e3779b9 ^ 102), 11);
  ks[111] = hc_rotl32_S ((ks[110] ^ ks[108] ^ ks[106] ^ ks[103] ^ 0x9e3779b9 ^ 103), 11);
  ks[112] = hc_rotl32_S ((ks[111] ^ ks[109] ^ ks[107] ^ ks[104] ^ 0x9e3779b9 ^ 104), 11);
  ks[113] = hc_rotl32_S ((ks[112] ^ ks[110] ^ ks[108] ^ ks[105] ^ 0x9e3779b9 ^ 105), 11);
  ks[114] = hc_rotl32_S ((ks[113] ^ ks[111] ^ ks[109] ^ ks[106] ^ 0x9e3779b9 ^ 106), 11);
  ks[115] = hc_rotl32_S ((ks[114] ^ ks[112] ^ ks[110] ^ ks[107] ^ 0x9e3779b9 ^ 107), 11);
  ks[116] = hc_rotl32_S ((ks[115] ^ ks[113] ^ ks[111] ^ ks[108] ^ 0x9e3779b9 ^ 108), 11);
  ks[117] = hc_rotl32_S ((ks[116] ^ ks[114] ^ ks[112] ^ ks[109] ^ 0x9e3779b9 ^ 109), 11);
  ks[118] = hc_rotl32_S ((ks[117] ^ ks[115] ^ ks[113] ^ ks[110] ^ 0x9e3779b9 ^ 110), 11);
  ks[119] = hc_rotl32_S ((ks[118] ^ ks[116] ^ ks[114] ^ ks[111] ^ 0x9e3779b9 ^ 111), 11);
  ks[120] = hc_rotl32_S ((ks[119] ^ ks[117] ^ ks[115] ^ ks[112] ^ 0x9e3779b9 ^ 112), 11);
  ks[121] = hc_rotl32_S ((ks[120] ^ ks[118] ^ ks[116] ^ ks[113] ^ 0x9e3779b9 ^ 113), 11);
  ks[122] = hc_rotl32_S ((ks[121] ^ ks[119] ^ ks[117] ^ ks[114] ^ 0x9e3779b9 ^ 114), 11);
  ks[123] = hc_rotl32_S ((ks[122] ^ ks[120] ^ ks[118] ^ ks[115] ^ 0x9e3779b9 ^ 115), 11);
  ks[124] = hc_rotl32_S ((ks[123] ^ ks[121] ^ ks[119] ^ ks[116] ^ 0x9e3779b9 ^ 116), 11);
  ks[125] = hc_rotl32_S ((ks[124] ^ ks[122] ^ ks[120] ^ ks[117] ^ 0x9e3779b9 ^ 117), 11);
  ks[126] = hc_rotl32_S ((ks[125] ^ ks[123] ^ ks[121] ^ ks[118] ^ 0x9e3779b9 ^ 118), 11);
  ks[127] = hc_rotl32_S ((ks[126] ^ ks[124] ^ ks[122] ^ ks[119] ^ 0x9e3779b9 ^ 119), 11);
  ks[128] = hc_rotl32_S ((ks[127] ^ ks[125] ^ ks[123] ^ ks[120] ^ 0x9e3779b9 ^ 120), 11);
  ks[129] = hc_rotl32_S ((ks[128] ^ ks[126] ^ ks[124] ^ ks[121] ^ 0x9e3779b9 ^ 121), 11);
  ks[130] = hc_rotl32_S ((ks[129] ^ ks[127] ^ ks[125] ^ ks[122] ^ 0x9e3779b9 ^ 122), 11);
  ks[131] = hc_rotl32_S ((ks[130] ^ ks[128] ^ ks[126] ^ ks[123] ^ 0x9e3779b9 ^ 123), 11);
  ks[132] = hc_rotl32_S ((ks[131] ^ ks[129] ^ ks[127] ^ ks[124] ^ 0x9e3779b9 ^ 124), 11);
  ks[133] = hc_rotl32_S ((ks[132] ^ ks[130] ^ ks[128] ^ ks[125] ^ 0x9e3779b9 ^ 125), 11);
  ks[134] = hc_rotl32_S ((ks[133] ^ ks[131] ^ ks[129] ^ ks[126] ^ 0x9e3779b9 ^ 126), 11);
  ks[135] = hc_rotl32_S ((ks[134] ^ ks[132] ^ ks[130] ^ ks[127] ^ 0x9e3779b9 ^ 127), 11);
  ks[136] = hc_rotl32_S ((ks[135] ^ ks[133] ^ ks[131] ^ ks[128] ^ 0x9e3779b9 ^ 128), 11);
  ks[137] = hc_rotl32_S ((ks[136] ^ ks[134] ^ ks[132] ^ ks[129] ^ 0x9e3779b9 ^ 129), 11);
  ks[138] = hc_rotl32_S ((ks[137] ^ ks[135] ^ ks[133] ^ ks[130] ^ 0x9e3779b9 ^ 130), 11);
  ks[139] = hc_rotl32_S ((ks[138] ^ ks[136] ^ ks[134] ^ ks[131] ^ 0x9e3779b9 ^ 131), 11);

  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  k_set( 0,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get( 0,e,f,g,h);
  k_set( 1,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get( 1,e,f,g,h);
  k_set( 2,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get( 2,e,f,g,h);
  k_set( 3,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get( 3,e,f,g,h);
  k_set( 4,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get( 4,e,f,g,h);
  k_set( 5,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get( 5,e,f,g,h);
  k_set( 6,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get( 6,e,f,g,h);
  k_set( 7,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get( 7,e,f,g,h);
  k_set( 8,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get( 8,e,f,g,h);
  k_set( 9,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get( 9,e,f,g,h);
  k_set(10,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(10,e,f,g,h);
  k_set(11,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(11,e,f,g,h);
  k_set(12,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(12,e,f,g,h);
  k_set(13,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(13,e,f,g,h);
  k_set(14,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(14,e,f,g,h);
  k_set(15,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(15,e,f,g,h);
  k_set(16,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(16,e,f,g,h);
  k_set(17,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get(17,e,f,g,h);
  k_set(18,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(18,e,f,g,h);
  k_set(19,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(19,e,f,g,h);
  k_set(20,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(20,e,f,g,h);
  k_set(21,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(21,e,f,g,h);
  k_set(22,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(22,e,f,g,h);
  k_set(23,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(23,e,f,g,h);
  k_set(24,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(24,e,f,g,h);
  k_set(25,a,b,c,d); sb2(a,b,c,d,e,f,g,h); k_get(25,e,f,g,h);
  k_set(26,a,b,c,d); sb1(a,b,c,d,e,f,g,h); k_get(26,e,f,g,h);
  k_set(27,a,b,c,d); sb0(a,b,c,d,e,f,g,h); k_get(27,e,f,g,h);
  k_set(28,a,b,c,d); sb7(a,b,c,d,e,f,g,h); k_get(28,e,f,g,h);
  k_set(29,a,b,c,d); sb6(a,b,c,d,e,f,g,h); k_get(29,e,f,g,h);
  k_set(30,a,b,c,d); sb5(a,b,c,d,e,f,g,h); k_get(30,e,f,g,h);
  k_set(31,a,b,c,d); sb4(a,b,c,d,e,f,g,h); k_get(31,e,f,g,h);
  k_set(32,a,b,c,d); sb3(a,b,c,d,e,f,g,h); k_get(32,e,f,g,h);
}

DECLSPEC void serpent256_encrypt (const u32 *ks, const u32 *in, u32 *out)
{
  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  a = in[0];
  b = in[1];
  c = in[2];
  d = in[3];

  k_xor( 0,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 1,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 2,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 3,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 4,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 5,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 6,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 7,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor( 8,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor( 9,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(10,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(11,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(12,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(13,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(14,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(15,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(16,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(17,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(18,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(19,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(20,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(21,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(22,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(23,e,f,g,h); sb7(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(24,a,b,c,d); sb0(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(25,e,f,g,h); sb1(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(26,a,b,c,d); sb2(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(27,e,f,g,h); sb3(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(28,a,b,c,d); sb4(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(29,e,f,g,h); sb5(e,f,g,h,a,b,c,d); rot(a,b,c,d);
  k_xor(30,a,b,c,d); sb6(a,b,c,d,e,f,g,h); rot(e,f,g,h);
  k_xor(31,e,f,g,h); sb7(e,f,g,h,a,b,c,d);
  k_xor(32,a,b,c,d);

  out[0] = a;
  out[1] = b;
  out[2] = c;
  out[3] = d;
}

DECLSPEC void serpent256_decrypt (const u32 *ks, const u32 *in, u32 *out)
{
  u32  a,b,c,d,e,f,g,h;
  u32  t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,t16;

  a = in[0];
  b = in[1];
  c = in[2];
  d = in[3];

                                       k_xor(32,a,b,c,d);
                 ib7(a,b,c,d,e,f,g,h); k_xor(31,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(30,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(29,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(28,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(27,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(26,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(25,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(24,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(23,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(22,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(21,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(20,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(19,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(18,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor(17,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor(16,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor(15,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor(14,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor(13,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor(12,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor(11,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor(10,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 9,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 8,a,b,c,d);
  irot(a,b,c,d); ib7(a,b,c,d,e,f,g,h); k_xor( 7,e,f,g,h);
  irot(e,f,g,h); ib6(e,f,g,h,a,b,c,d); k_xor( 6,a,b,c,d);
  irot(a,b,c,d); ib5(a,b,c,d,e,f,g,h); k_xor( 5,e,f,g,h);
  irot(e,f,g,h); ib4(e,f,g,h,a,b,c,d); k_xor( 4,a,b,c,d);
  irot(a,b,c,d); ib3(a,b,c,d,e,f,g,h); k_xor( 3,e,f,g,h);
  irot(e,f,g,h); ib2(e,f,g,h,a,b,c,d); k_xor( 2,a,b,c,d);
  irot(a,b,c,d); ib1(a,b,c,d,e,f,g,h); k_xor( 1,e,f,g,h);
  irot(e,f,g,h); ib0(e,f,g,h,a,b,c,d); k_xor( 0,a,b,c,d);

  out[0] = a;
  out[1] = b;
  out[2] = c;
  out[3] = d;
}

#undef sb0
#undef ib0
#undef sb1
#undef ib1
#undef sb2
#undef ib2
#undef sb3
#undef ib3
#undef sb4
#undef ib4
#undef sb5
#undef ib5
#undef sb6
#undef ib6
#undef sb7
#undef ib7
#undef k_xor
#undef k_set
#undef k_get
#undef rot
#undef irot
