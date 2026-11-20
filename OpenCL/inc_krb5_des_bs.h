/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_KRB5_DES_BS_H
#define INC_KRB5_DES_BS_H

// Bitslice helpers for the Kerberos 5 DES string-to-key. A slice is a u32 that holds one bit of 32
// candidates. A 64 bit block is an array of 64 slices in DES bit order, so index 0 is the most
// significant bit of byte 0. The 56 bits of a key that DES uses are an array of 56 slices, seven to
// a byte and in the same order, which is the order the key schedule of the bitslice kernels reads.
//
// The rounds work on a block after its initial permutation and leave it before the final one, with
// its halves swapped: D[0..31] is L and D[32..63] is R going in, and R16 sits in D[32..63] coming
// out. Chaining a CBC block therefore swaps the halves and XORs the next block in permuted form,
// and neither permutation is ever computed: both are an index table.

// one bit of a word, spread over all 32 candidates of a slice

#define KRB5_DES_BS_M(w,q) (0u - (((w) >> (q)) & 1u))

// D = IP (block), the block given as its two little endian words

#define KRB5_DES_BS_LOAD_IP(D,w0,w1)    \
  {                                     \
    (D)[ 0] = KRB5_DES_BS_M ((w1), 30); \
    (D)[ 1] = KRB5_DES_BS_M ((w1), 22); \
    (D)[ 2] = KRB5_DES_BS_M ((w1), 14); \
    (D)[ 3] = KRB5_DES_BS_M ((w1),  6); \
    (D)[ 4] = KRB5_DES_BS_M ((w0), 30); \
    (D)[ 5] = KRB5_DES_BS_M ((w0), 22); \
    (D)[ 6] = KRB5_DES_BS_M ((w0), 14); \
    (D)[ 7] = KRB5_DES_BS_M ((w0),  6); \
    (D)[ 8] = KRB5_DES_BS_M ((w1), 28); \
    (D)[ 9] = KRB5_DES_BS_M ((w1), 20); \
    (D)[10] = KRB5_DES_BS_M ((w1), 12); \
    (D)[11] = KRB5_DES_BS_M ((w1),  4); \
    (D)[12] = KRB5_DES_BS_M ((w0), 28); \
    (D)[13] = KRB5_DES_BS_M ((w0), 20); \
    (D)[14] = KRB5_DES_BS_M ((w0), 12); \
    (D)[15] = KRB5_DES_BS_M ((w0),  4); \
    (D)[16] = KRB5_DES_BS_M ((w1), 26); \
    (D)[17] = KRB5_DES_BS_M ((w1), 18); \
    (D)[18] = KRB5_DES_BS_M ((w1), 10); \
    (D)[19] = KRB5_DES_BS_M ((w1),  2); \
    (D)[20] = KRB5_DES_BS_M ((w0), 26); \
    (D)[21] = KRB5_DES_BS_M ((w0), 18); \
    (D)[22] = KRB5_DES_BS_M ((w0), 10); \
    (D)[23] = KRB5_DES_BS_M ((w0),  2); \
    (D)[24] = KRB5_DES_BS_M ((w1), 24); \
    (D)[25] = KRB5_DES_BS_M ((w1), 16); \
    (D)[26] = KRB5_DES_BS_M ((w1),  8); \
    (D)[27] = KRB5_DES_BS_M ((w1),  0); \
    (D)[28] = KRB5_DES_BS_M ((w0), 24); \
    (D)[29] = KRB5_DES_BS_M ((w0), 16); \
    (D)[30] = KRB5_DES_BS_M ((w0),  8); \
    (D)[31] = KRB5_DES_BS_M ((w0),  0); \
    (D)[32] = KRB5_DES_BS_M ((w1), 31); \
    (D)[33] = KRB5_DES_BS_M ((w1), 23); \
    (D)[34] = KRB5_DES_BS_M ((w1), 15); \
    (D)[35] = KRB5_DES_BS_M ((w1),  7); \
    (D)[36] = KRB5_DES_BS_M ((w0), 31); \
    (D)[37] = KRB5_DES_BS_M ((w0), 23); \
    (D)[38] = KRB5_DES_BS_M ((w0), 15); \
    (D)[39] = KRB5_DES_BS_M ((w0),  7); \
    (D)[40] = KRB5_DES_BS_M ((w1), 29); \
    (D)[41] = KRB5_DES_BS_M ((w1), 21); \
    (D)[42] = KRB5_DES_BS_M ((w1), 13); \
    (D)[43] = KRB5_DES_BS_M ((w1),  5); \
    (D)[44] = KRB5_DES_BS_M ((w0), 29); \
    (D)[45] = KRB5_DES_BS_M ((w0), 21); \
    (D)[46] = KRB5_DES_BS_M ((w0), 13); \
    (D)[47] = KRB5_DES_BS_M ((w0),  5); \
    (D)[48] = KRB5_DES_BS_M ((w1), 27); \
    (D)[49] = KRB5_DES_BS_M ((w1), 19); \
    (D)[50] = KRB5_DES_BS_M ((w1), 11); \
    (D)[51] = KRB5_DES_BS_M ((w1),  3); \
    (D)[52] = KRB5_DES_BS_M ((w0), 27); \
    (D)[53] = KRB5_DES_BS_M ((w0), 19); \
    (D)[54] = KRB5_DES_BS_M ((w0), 11); \
    (D)[55] = KRB5_DES_BS_M ((w0),  3); \
    (D)[56] = KRB5_DES_BS_M ((w1), 25); \
    (D)[57] = KRB5_DES_BS_M ((w1), 17); \
    (D)[58] = KRB5_DES_BS_M ((w1),  9); \
    (D)[59] = KRB5_DES_BS_M ((w1),  1); \
    (D)[60] = KRB5_DES_BS_M ((w0), 25); \
    (D)[61] = KRB5_DES_BS_M ((w0), 17); \
    (D)[62] = KRB5_DES_BS_M ((w0),  9); \
    (D)[63] = KRB5_DES_BS_M ((w0),  1); \
  }

// D = swap (D) ^ IP (block), which is what CBC feeds the rounds for the block after the one they just did

#define KRB5_DES_BS_CHAIN_IP(D,w0,w1)                                                                                          \
  {                                                                                                                            \
    u32 krb5_des_bs_t;                                                                                                         \
    krb5_des_bs_t = (D)[ 0]; (D)[ 0] = (D)[32] ^ KRB5_DES_BS_M ((w1), 30); (D)[32] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 31); \
    krb5_des_bs_t = (D)[ 1]; (D)[ 1] = (D)[33] ^ KRB5_DES_BS_M ((w1), 22); (D)[33] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 23); \
    krb5_des_bs_t = (D)[ 2]; (D)[ 2] = (D)[34] ^ KRB5_DES_BS_M ((w1), 14); (D)[34] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 15); \
    krb5_des_bs_t = (D)[ 3]; (D)[ 3] = (D)[35] ^ KRB5_DES_BS_M ((w1),  6); (D)[35] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1),  7); \
    krb5_des_bs_t = (D)[ 4]; (D)[ 4] = (D)[36] ^ KRB5_DES_BS_M ((w0), 30); (D)[36] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 31); \
    krb5_des_bs_t = (D)[ 5]; (D)[ 5] = (D)[37] ^ KRB5_DES_BS_M ((w0), 22); (D)[37] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 23); \
    krb5_des_bs_t = (D)[ 6]; (D)[ 6] = (D)[38] ^ KRB5_DES_BS_M ((w0), 14); (D)[38] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 15); \
    krb5_des_bs_t = (D)[ 7]; (D)[ 7] = (D)[39] ^ KRB5_DES_BS_M ((w0),  6); (D)[39] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0),  7); \
    krb5_des_bs_t = (D)[ 8]; (D)[ 8] = (D)[40] ^ KRB5_DES_BS_M ((w1), 28); (D)[40] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 29); \
    krb5_des_bs_t = (D)[ 9]; (D)[ 9] = (D)[41] ^ KRB5_DES_BS_M ((w1), 20); (D)[41] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 21); \
    krb5_des_bs_t = (D)[10]; (D)[10] = (D)[42] ^ KRB5_DES_BS_M ((w1), 12); (D)[42] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 13); \
    krb5_des_bs_t = (D)[11]; (D)[11] = (D)[43] ^ KRB5_DES_BS_M ((w1),  4); (D)[43] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1),  5); \
    krb5_des_bs_t = (D)[12]; (D)[12] = (D)[44] ^ KRB5_DES_BS_M ((w0), 28); (D)[44] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 29); \
    krb5_des_bs_t = (D)[13]; (D)[13] = (D)[45] ^ KRB5_DES_BS_M ((w0), 20); (D)[45] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 21); \
    krb5_des_bs_t = (D)[14]; (D)[14] = (D)[46] ^ KRB5_DES_BS_M ((w0), 12); (D)[46] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 13); \
    krb5_des_bs_t = (D)[15]; (D)[15] = (D)[47] ^ KRB5_DES_BS_M ((w0),  4); (D)[47] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0),  5); \
    krb5_des_bs_t = (D)[16]; (D)[16] = (D)[48] ^ KRB5_DES_BS_M ((w1), 26); (D)[48] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 27); \
    krb5_des_bs_t = (D)[17]; (D)[17] = (D)[49] ^ KRB5_DES_BS_M ((w1), 18); (D)[49] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 19); \
    krb5_des_bs_t = (D)[18]; (D)[18] = (D)[50] ^ KRB5_DES_BS_M ((w1), 10); (D)[50] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 11); \
    krb5_des_bs_t = (D)[19]; (D)[19] = (D)[51] ^ KRB5_DES_BS_M ((w1),  2); (D)[51] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1),  3); \
    krb5_des_bs_t = (D)[20]; (D)[20] = (D)[52] ^ KRB5_DES_BS_M ((w0), 26); (D)[52] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 27); \
    krb5_des_bs_t = (D)[21]; (D)[21] = (D)[53] ^ KRB5_DES_BS_M ((w0), 18); (D)[53] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 19); \
    krb5_des_bs_t = (D)[22]; (D)[22] = (D)[54] ^ KRB5_DES_BS_M ((w0), 10); (D)[54] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 11); \
    krb5_des_bs_t = (D)[23]; (D)[23] = (D)[55] ^ KRB5_DES_BS_M ((w0),  2); (D)[55] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0),  3); \
    krb5_des_bs_t = (D)[24]; (D)[24] = (D)[56] ^ KRB5_DES_BS_M ((w1), 24); (D)[56] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 25); \
    krb5_des_bs_t = (D)[25]; (D)[25] = (D)[57] ^ KRB5_DES_BS_M ((w1), 16); (D)[57] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1), 17); \
    krb5_des_bs_t = (D)[26]; (D)[26] = (D)[58] ^ KRB5_DES_BS_M ((w1),  8); (D)[58] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1),  9); \
    krb5_des_bs_t = (D)[27]; (D)[27] = (D)[59] ^ KRB5_DES_BS_M ((w1),  0); (D)[59] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w1),  1); \
    krb5_des_bs_t = (D)[28]; (D)[28] = (D)[60] ^ KRB5_DES_BS_M ((w0), 24); (D)[60] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 25); \
    krb5_des_bs_t = (D)[29]; (D)[29] = (D)[61] ^ KRB5_DES_BS_M ((w0), 16); (D)[61] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0), 17); \
    krb5_des_bs_t = (D)[30]; (D)[30] = (D)[62] ^ KRB5_DES_BS_M ((w0),  8); (D)[62] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0),  9); \
    krb5_des_bs_t = (D)[31]; (D)[31] = (D)[63] ^ KRB5_DES_BS_M ((w0),  0); (D)[63] = krb5_des_bs_t ^ KRB5_DES_BS_M ((w0),  1); \
  }

// B = FP (swap (D)), the block the rounds stand for

#define KRB5_DES_BS_FP(B,D) \
  {                         \
    (B)[ 0] = (D)[ 7];      \
    (B)[ 1] = (D)[39];      \
    (B)[ 2] = (D)[15];      \
    (B)[ 3] = (D)[47];      \
    (B)[ 4] = (D)[23];      \
    (B)[ 5] = (D)[55];      \
    (B)[ 6] = (D)[31];      \
    (B)[ 7] = (D)[63];      \
    (B)[ 8] = (D)[ 6];      \
    (B)[ 9] = (D)[38];      \
    (B)[10] = (D)[14];      \
    (B)[11] = (D)[46];      \
    (B)[12] = (D)[22];      \
    (B)[13] = (D)[54];      \
    (B)[14] = (D)[30];      \
    (B)[15] = (D)[62];      \
    (B)[16] = (D)[ 5];      \
    (B)[17] = (D)[37];      \
    (B)[18] = (D)[13];      \
    (B)[19] = (D)[45];      \
    (B)[20] = (D)[21];      \
    (B)[21] = (D)[53];      \
    (B)[22] = (D)[29];      \
    (B)[23] = (D)[61];      \
    (B)[24] = (D)[ 4];      \
    (B)[25] = (D)[36];      \
    (B)[26] = (D)[12];      \
    (B)[27] = (D)[44];      \
    (B)[28] = (D)[20];      \
    (B)[29] = (D)[52];      \
    (B)[30] = (D)[28];      \
    (B)[31] = (D)[60];      \
    (B)[32] = (D)[ 3];      \
    (B)[33] = (D)[35];      \
    (B)[34] = (D)[11];      \
    (B)[35] = (D)[43];      \
    (B)[36] = (D)[19];      \
    (B)[37] = (D)[51];      \
    (B)[38] = (D)[27];      \
    (B)[39] = (D)[59];      \
    (B)[40] = (D)[ 2];      \
    (B)[41] = (D)[34];      \
    (B)[42] = (D)[10];      \
    (B)[43] = (D)[42];      \
    (B)[44] = (D)[18];      \
    (B)[45] = (D)[50];      \
    (B)[46] = (D)[26];      \
    (B)[47] = (D)[58];      \
    (B)[48] = (D)[ 1];      \
    (B)[49] = (D)[33];      \
    (B)[50] = (D)[ 9];      \
    (B)[51] = (D)[41];      \
    (B)[52] = (D)[17];      \
    (B)[53] = (D)[49];      \
    (B)[54] = (D)[25];      \
    (B)[55] = (D)[57];      \
    (B)[56] = (D)[ 0];      \
    (B)[57] = (D)[32];      \
    (B)[58] = (D)[ 8];      \
    (B)[59] = (D)[40];      \
    (B)[60] = (D)[16];      \
    (B)[61] = (D)[48];      \
    (B)[62] = (D)[24];      \
    (B)[63] = (D)[56];      \
  }

// B ^= block

#define KRB5_DES_BS_XOR(B,w0,w1)         \
  {                                      \
    (B)[ 0] ^= KRB5_DES_BS_M ((w0),  7); \
    (B)[ 1] ^= KRB5_DES_BS_M ((w0),  6); \
    (B)[ 2] ^= KRB5_DES_BS_M ((w0),  5); \
    (B)[ 3] ^= KRB5_DES_BS_M ((w0),  4); \
    (B)[ 4] ^= KRB5_DES_BS_M ((w0),  3); \
    (B)[ 5] ^= KRB5_DES_BS_M ((w0),  2); \
    (B)[ 6] ^= KRB5_DES_BS_M ((w0),  1); \
    (B)[ 7] ^= KRB5_DES_BS_M ((w0),  0); \
    (B)[ 8] ^= KRB5_DES_BS_M ((w0), 15); \
    (B)[ 9] ^= KRB5_DES_BS_M ((w0), 14); \
    (B)[10] ^= KRB5_DES_BS_M ((w0), 13); \
    (B)[11] ^= KRB5_DES_BS_M ((w0), 12); \
    (B)[12] ^= KRB5_DES_BS_M ((w0), 11); \
    (B)[13] ^= KRB5_DES_BS_M ((w0), 10); \
    (B)[14] ^= KRB5_DES_BS_M ((w0),  9); \
    (B)[15] ^= KRB5_DES_BS_M ((w0),  8); \
    (B)[16] ^= KRB5_DES_BS_M ((w0), 23); \
    (B)[17] ^= KRB5_DES_BS_M ((w0), 22); \
    (B)[18] ^= KRB5_DES_BS_M ((w0), 21); \
    (B)[19] ^= KRB5_DES_BS_M ((w0), 20); \
    (B)[20] ^= KRB5_DES_BS_M ((w0), 19); \
    (B)[21] ^= KRB5_DES_BS_M ((w0), 18); \
    (B)[22] ^= KRB5_DES_BS_M ((w0), 17); \
    (B)[23] ^= KRB5_DES_BS_M ((w0), 16); \
    (B)[24] ^= KRB5_DES_BS_M ((w0), 31); \
    (B)[25] ^= KRB5_DES_BS_M ((w0), 30); \
    (B)[26] ^= KRB5_DES_BS_M ((w0), 29); \
    (B)[27] ^= KRB5_DES_BS_M ((w0), 28); \
    (B)[28] ^= KRB5_DES_BS_M ((w0), 27); \
    (B)[29] ^= KRB5_DES_BS_M ((w0), 26); \
    (B)[30] ^= KRB5_DES_BS_M ((w0), 25); \
    (B)[31] ^= KRB5_DES_BS_M ((w0), 24); \
    (B)[32] ^= KRB5_DES_BS_M ((w1),  7); \
    (B)[33] ^= KRB5_DES_BS_M ((w1),  6); \
    (B)[34] ^= KRB5_DES_BS_M ((w1),  5); \
    (B)[35] ^= KRB5_DES_BS_M ((w1),  4); \
    (B)[36] ^= KRB5_DES_BS_M ((w1),  3); \
    (B)[37] ^= KRB5_DES_BS_M ((w1),  2); \
    (B)[38] ^= KRB5_DES_BS_M ((w1),  1); \
    (B)[39] ^= KRB5_DES_BS_M ((w1),  0); \
    (B)[40] ^= KRB5_DES_BS_M ((w1), 15); \
    (B)[41] ^= KRB5_DES_BS_M ((w1), 14); \
    (B)[42] ^= KRB5_DES_BS_M ((w1), 13); \
    (B)[43] ^= KRB5_DES_BS_M ((w1), 12); \
    (B)[44] ^= KRB5_DES_BS_M ((w1), 11); \
    (B)[45] ^= KRB5_DES_BS_M ((w1), 10); \
    (B)[46] ^= KRB5_DES_BS_M ((w1),  9); \
    (B)[47] ^= KRB5_DES_BS_M ((w1),  8); \
    (B)[48] ^= KRB5_DES_BS_M ((w1), 23); \
    (B)[49] ^= KRB5_DES_BS_M ((w1), 22); \
    (B)[50] ^= KRB5_DES_BS_M ((w1), 21); \
    (B)[51] ^= KRB5_DES_BS_M ((w1), 20); \
    (B)[52] ^= KRB5_DES_BS_M ((w1), 19); \
    (B)[53] ^= KRB5_DES_BS_M ((w1), 18); \
    (B)[54] ^= KRB5_DES_BS_M ((w1), 17); \
    (B)[55] ^= KRB5_DES_BS_M ((w1), 16); \
    (B)[56] ^= KRB5_DES_BS_M ((w1), 31); \
    (B)[57] ^= KRB5_DES_BS_M ((w1), 30); \
    (B)[58] ^= KRB5_DES_BS_M ((w1), 29); \
    (B)[59] ^= KRB5_DES_BS_M ((w1), 28); \
    (B)[60] ^= KRB5_DES_BS_M ((w1), 27); \
    (B)[61] ^= KRB5_DES_BS_M ((w1), 26); \
    (B)[62] ^= KRB5_DES_BS_M ((w1), 25); \
    (B)[63] ^= KRB5_DES_BS_M ((w1), 24); \
  }

// The 32 bits of the first word of the candidate that the mask varies, masked to the bytes the
// password really has. b is the table the tm kernel built, one slice for every bit of the word.

#define KRB5_DES_BS_LOAD_V(V,b,m)                \
  {                                              \
    (V)[ 0] = (b)[ 0] & KRB5_DES_BS_M ((m),  0); \
    (V)[ 1] = (b)[ 1] & KRB5_DES_BS_M ((m),  1); \
    (V)[ 2] = (b)[ 2] & KRB5_DES_BS_M ((m),  2); \
    (V)[ 3] = (b)[ 3] & KRB5_DES_BS_M ((m),  3); \
    (V)[ 4] = (b)[ 4] & KRB5_DES_BS_M ((m),  4); \
    (V)[ 5] = (b)[ 5] & KRB5_DES_BS_M ((m),  5); \
    (V)[ 6] = (b)[ 6] & KRB5_DES_BS_M ((m),  6); \
    (V)[ 7] = (b)[ 7] & KRB5_DES_BS_M ((m),  7); \
    (V)[ 8] = (b)[ 8] & KRB5_DES_BS_M ((m),  8); \
    (V)[ 9] = (b)[ 9] & KRB5_DES_BS_M ((m),  9); \
    (V)[10] = (b)[10] & KRB5_DES_BS_M ((m), 10); \
    (V)[11] = (b)[11] & KRB5_DES_BS_M ((m), 11); \
    (V)[12] = (b)[12] & KRB5_DES_BS_M ((m), 12); \
    (V)[13] = (b)[13] & KRB5_DES_BS_M ((m), 13); \
    (V)[14] = (b)[14] & KRB5_DES_BS_M ((m), 14); \
    (V)[15] = (b)[15] & KRB5_DES_BS_M ((m), 15); \
    (V)[16] = (b)[16] & KRB5_DES_BS_M ((m), 16); \
    (V)[17] = (b)[17] & KRB5_DES_BS_M ((m), 17); \
    (V)[18] = (b)[18] & KRB5_DES_BS_M ((m), 18); \
    (V)[19] = (b)[19] & KRB5_DES_BS_M ((m), 19); \
    (V)[20] = (b)[20] & KRB5_DES_BS_M ((m), 20); \
    (V)[21] = (b)[21] & KRB5_DES_BS_M ((m), 21); \
    (V)[22] = (b)[22] & KRB5_DES_BS_M ((m), 22); \
    (V)[23] = (b)[23] & KRB5_DES_BS_M ((m), 23); \
    (V)[24] = (b)[24] & KRB5_DES_BS_M ((m), 24); \
    (V)[25] = (b)[25] & KRB5_DES_BS_M ((m), 25); \
    (V)[26] = (b)[26] & KRB5_DES_BS_M ((m), 26); \
    (V)[27] = (b)[27] & KRB5_DES_BS_M ((m), 27); \
    (V)[28] = (b)[28] & KRB5_DES_BS_M ((m), 28); \
    (V)[29] = (b)[29] & KRB5_DES_BS_M ((m), 29); \
    (V)[30] = (b)[30] & KRB5_DES_BS_M ((m), 30); \
    (V)[31] = (b)[31] & KRB5_DES_BS_M ((m), 31); \
  }

// The fan-folded key. f0 and f1 are the fold without the varying bits, and bit p of a key byte is
// bit p - 1 of the fold, so the four bytes the first word reaches follow V and the other four are
// the same for every candidate.

#define KRB5_DES_BS_KEY(K,V,f0,f1)                \
  {                                               \
    (K)[ 0] = (V)[ 6] ^ KRB5_DES_BS_M ((f0),  6); \
    (K)[ 1] = (V)[ 5] ^ KRB5_DES_BS_M ((f0),  5); \
    (K)[ 2] = (V)[ 4] ^ KRB5_DES_BS_M ((f0),  4); \
    (K)[ 3] = (V)[ 3] ^ KRB5_DES_BS_M ((f0),  3); \
    (K)[ 4] = (V)[ 2] ^ KRB5_DES_BS_M ((f0),  2); \
    (K)[ 5] = (V)[ 1] ^ KRB5_DES_BS_M ((f0),  1); \
    (K)[ 6] = (V)[ 0] ^ KRB5_DES_BS_M ((f0),  0); \
    (K)[ 7] = (V)[14] ^ KRB5_DES_BS_M ((f0), 14); \
    (K)[ 8] = (V)[13] ^ KRB5_DES_BS_M ((f0), 13); \
    (K)[ 9] = (V)[12] ^ KRB5_DES_BS_M ((f0), 12); \
    (K)[10] = (V)[11] ^ KRB5_DES_BS_M ((f0), 11); \
    (K)[11] = (V)[10] ^ KRB5_DES_BS_M ((f0), 10); \
    (K)[12] = (V)[ 9] ^ KRB5_DES_BS_M ((f0),  9); \
    (K)[13] = (V)[ 8] ^ KRB5_DES_BS_M ((f0),  8); \
    (K)[14] = (V)[22] ^ KRB5_DES_BS_M ((f0), 22); \
    (K)[15] = (V)[21] ^ KRB5_DES_BS_M ((f0), 21); \
    (K)[16] = (V)[20] ^ KRB5_DES_BS_M ((f0), 20); \
    (K)[17] = (V)[19] ^ KRB5_DES_BS_M ((f0), 19); \
    (K)[18] = (V)[18] ^ KRB5_DES_BS_M ((f0), 18); \
    (K)[19] = (V)[17] ^ KRB5_DES_BS_M ((f0), 17); \
    (K)[20] = (V)[16] ^ KRB5_DES_BS_M ((f0), 16); \
    (K)[21] = (V)[30] ^ KRB5_DES_BS_M ((f0), 30); \
    (K)[22] = (V)[29] ^ KRB5_DES_BS_M ((f0), 29); \
    (K)[23] = (V)[28] ^ KRB5_DES_BS_M ((f0), 28); \
    (K)[24] = (V)[27] ^ KRB5_DES_BS_M ((f0), 27); \
    (K)[25] = (V)[26] ^ KRB5_DES_BS_M ((f0), 26); \
    (K)[26] = (V)[25] ^ KRB5_DES_BS_M ((f0), 25); \
    (K)[27] = (V)[24] ^ KRB5_DES_BS_M ((f0), 24); \
    (K)[28] = KRB5_DES_BS_M ((f1),  6);           \
    (K)[29] = KRB5_DES_BS_M ((f1),  5);           \
    (K)[30] = KRB5_DES_BS_M ((f1),  4);           \
    (K)[31] = KRB5_DES_BS_M ((f1),  3);           \
    (K)[32] = KRB5_DES_BS_M ((f1),  2);           \
    (K)[33] = KRB5_DES_BS_M ((f1),  1);           \
    (K)[34] = KRB5_DES_BS_M ((f1),  0);           \
    (K)[35] = KRB5_DES_BS_M ((f1), 14);           \
    (K)[36] = KRB5_DES_BS_M ((f1), 13);           \
    (K)[37] = KRB5_DES_BS_M ((f1), 12);           \
    (K)[38] = KRB5_DES_BS_M ((f1), 11);           \
    (K)[39] = KRB5_DES_BS_M ((f1), 10);           \
    (K)[40] = KRB5_DES_BS_M ((f1),  9);           \
    (K)[41] = KRB5_DES_BS_M ((f1),  8);           \
    (K)[42] = KRB5_DES_BS_M ((f1), 22);           \
    (K)[43] = KRB5_DES_BS_M ((f1), 21);           \
    (K)[44] = KRB5_DES_BS_M ((f1), 20);           \
    (K)[45] = KRB5_DES_BS_M ((f1), 19);           \
    (K)[46] = KRB5_DES_BS_M ((f1), 18);           \
    (K)[47] = KRB5_DES_BS_M ((f1), 17);           \
    (K)[48] = KRB5_DES_BS_M ((f1), 16);           \
    (K)[49] = KRB5_DES_BS_M ((f1), 30);           \
    (K)[50] = KRB5_DES_BS_M ((f1), 29);           \
    (K)[51] = KRB5_DES_BS_M ((f1), 28);           \
    (K)[52] = KRB5_DES_BS_M ((f1), 27);           \
    (K)[53] = KRB5_DES_BS_M ((f1), 26);           \
    (K)[54] = KRB5_DES_BS_M ((f1), 25);           \
    (K)[55] = KRB5_DES_BS_M ((f1), 24);           \
  }

// The odd parity bit of each key byte, which the CBC-MAC needs because the key is also its IV

#define KRB5_DES_BS_PARITY(P,K)                                                      \
  {                                                                                  \
    (P)[0] = ~((K)[ 0] ^ (K)[ 1] ^ (K)[ 2] ^ (K)[ 3] ^ (K)[ 4] ^ (K)[ 5] ^ (K)[ 6]); \
    (P)[1] = ~((K)[ 7] ^ (K)[ 8] ^ (K)[ 9] ^ (K)[10] ^ (K)[11] ^ (K)[12] ^ (K)[13]); \
    (P)[2] = ~((K)[14] ^ (K)[15] ^ (K)[16] ^ (K)[17] ^ (K)[18] ^ (K)[19] ^ (K)[20]); \
    (P)[3] = ~((K)[21] ^ (K)[22] ^ (K)[23] ^ (K)[24] ^ (K)[25] ^ (K)[26] ^ (K)[27]); \
    (P)[4] = ~((K)[28] ^ (K)[29] ^ (K)[30] ^ (K)[31] ^ (K)[32] ^ (K)[33] ^ (K)[34]); \
    (P)[5] = ~((K)[35] ^ (K)[36] ^ (K)[37] ^ (K)[38] ^ (K)[39] ^ (K)[40] ^ (K)[41]); \
    (P)[6] = ~((K)[42] ^ (K)[43] ^ (K)[44] ^ (K)[45] ^ (K)[46] ^ (K)[47] ^ (K)[48]); \
    (P)[7] = ~((K)[49] ^ (K)[50] ^ (K)[51] ^ (K)[52] ^ (K)[53] ^ (K)[54] ^ (K)[55]); \
  }

// D = IP (key ^ block 0). Only the first word of the block varies: l is that word without the
// varying bits, w1 is the word after it.

#define KRB5_DES_BS_LOAD_FIRST(D,K,P,V,l,w1)                    \
  {                                                             \
    (D)[ 0] = (K)[50] ^ KRB5_DES_BS_M ((w1), 30);               \
    (D)[ 1] = (K)[43] ^ KRB5_DES_BS_M ((w1), 22);               \
    (D)[ 2] = (K)[36] ^ KRB5_DES_BS_M ((w1), 14);               \
    (D)[ 3] = (K)[29] ^ KRB5_DES_BS_M ((w1),  6);               \
    (D)[ 4] = (K)[22] ^ ((V)[30] | KRB5_DES_BS_M ((l), 30));    \
    (D)[ 5] = (K)[15] ^ ((V)[22] | KRB5_DES_BS_M ((l), 22));    \
    (D)[ 6] = (K)[ 8] ^ ((V)[14] | KRB5_DES_BS_M ((l), 14));    \
    (D)[ 7] = (K)[ 1] ^ ((V)[ 6] | KRB5_DES_BS_M ((l),  6));    \
    (D)[ 8] = (K)[52] ^ KRB5_DES_BS_M ((w1), 28);               \
    (D)[ 9] = (K)[45] ^ KRB5_DES_BS_M ((w1), 20);               \
    (D)[10] = (K)[38] ^ KRB5_DES_BS_M ((w1), 12);               \
    (D)[11] = (K)[31] ^ KRB5_DES_BS_M ((w1),  4);               \
    (D)[12] = (K)[24] ^ ((V)[28] | KRB5_DES_BS_M ((l), 28));    \
    (D)[13] = (K)[17] ^ ((V)[20] | KRB5_DES_BS_M ((l), 20));    \
    (D)[14] = (K)[10] ^ ((V)[12] | KRB5_DES_BS_M ((l), 12));    \
    (D)[15] = (K)[ 3] ^ ((V)[ 4] | KRB5_DES_BS_M ((l),  4));    \
    (D)[16] = (K)[54] ^ KRB5_DES_BS_M ((w1), 26);               \
    (D)[17] = (K)[47] ^ KRB5_DES_BS_M ((w1), 18);               \
    (D)[18] = (K)[40] ^ KRB5_DES_BS_M ((w1), 10);               \
    (D)[19] = (K)[33] ^ KRB5_DES_BS_M ((w1),  2);               \
    (D)[20] = (K)[26] ^ ((V)[26] | KRB5_DES_BS_M ((l), 26));    \
    (D)[21] = (K)[19] ^ ((V)[18] | KRB5_DES_BS_M ((l), 18));    \
    (D)[22] = (K)[12] ^ ((V)[10] | KRB5_DES_BS_M ((l), 10));    \
    (D)[23] = (K)[ 5] ^ ((V)[ 2] | KRB5_DES_BS_M ((l),  2));    \
    (D)[24] = (P)[7]     ^ KRB5_DES_BS_M ((w1), 24);            \
    (D)[25] = (P)[6]     ^ KRB5_DES_BS_M ((w1), 16);            \
    (D)[26] = (P)[5]     ^ KRB5_DES_BS_M ((w1),  8);            \
    (D)[27] = (P)[4]     ^ KRB5_DES_BS_M ((w1),  0);            \
    (D)[28] = (P)[3]     ^ ((V)[24] | KRB5_DES_BS_M ((l), 24)); \
    (D)[29] = (P)[2]     ^ ((V)[16] | KRB5_DES_BS_M ((l), 16)); \
    (D)[30] = (P)[1]     ^ ((V)[ 8] | KRB5_DES_BS_M ((l),  8)); \
    (D)[31] = (P)[0]     ^ ((V)[ 0] | KRB5_DES_BS_M ((l),  0)); \
    (D)[32] = (K)[49] ^ KRB5_DES_BS_M ((w1), 31);               \
    (D)[33] = (K)[42] ^ KRB5_DES_BS_M ((w1), 23);               \
    (D)[34] = (K)[35] ^ KRB5_DES_BS_M ((w1), 15);               \
    (D)[35] = (K)[28] ^ KRB5_DES_BS_M ((w1),  7);               \
    (D)[36] = (K)[21] ^ ((V)[31] | KRB5_DES_BS_M ((l), 31));    \
    (D)[37] = (K)[14] ^ ((V)[23] | KRB5_DES_BS_M ((l), 23));    \
    (D)[38] = (K)[ 7] ^ ((V)[15] | KRB5_DES_BS_M ((l), 15));    \
    (D)[39] = (K)[ 0] ^ ((V)[ 7] | KRB5_DES_BS_M ((l),  7));    \
    (D)[40] = (K)[51] ^ KRB5_DES_BS_M ((w1), 29);               \
    (D)[41] = (K)[44] ^ KRB5_DES_BS_M ((w1), 21);               \
    (D)[42] = (K)[37] ^ KRB5_DES_BS_M ((w1), 13);               \
    (D)[43] = (K)[30] ^ KRB5_DES_BS_M ((w1),  5);               \
    (D)[44] = (K)[23] ^ ((V)[29] | KRB5_DES_BS_M ((l), 29));    \
    (D)[45] = (K)[16] ^ ((V)[21] | KRB5_DES_BS_M ((l), 21));    \
    (D)[46] = (K)[ 9] ^ ((V)[13] | KRB5_DES_BS_M ((l), 13));    \
    (D)[47] = (K)[ 2] ^ ((V)[ 5] | KRB5_DES_BS_M ((l),  5));    \
    (D)[48] = (K)[53] ^ KRB5_DES_BS_M ((w1), 27);               \
    (D)[49] = (K)[46] ^ KRB5_DES_BS_M ((w1), 19);               \
    (D)[50] = (K)[39] ^ KRB5_DES_BS_M ((w1), 11);               \
    (D)[51] = (K)[32] ^ KRB5_DES_BS_M ((w1),  3);               \
    (D)[52] = (K)[25] ^ ((V)[27] | KRB5_DES_BS_M ((l), 27));    \
    (D)[53] = (K)[18] ^ ((V)[19] | KRB5_DES_BS_M ((l), 19));    \
    (D)[54] = (K)[11] ^ ((V)[11] | KRB5_DES_BS_M ((l), 11));    \
    (D)[55] = (K)[ 4] ^ ((V)[ 3] | KRB5_DES_BS_M ((l),  3));    \
    (D)[56] = (K)[55] ^ KRB5_DES_BS_M ((w1), 25);               \
    (D)[57] = (K)[48] ^ KRB5_DES_BS_M ((w1), 17);               \
    (D)[58] = (K)[41] ^ KRB5_DES_BS_M ((w1),  9);               \
    (D)[59] = (K)[34] ^ KRB5_DES_BS_M ((w1),  1);               \
    (D)[60] = (K)[27] ^ ((V)[25] | KRB5_DES_BS_M ((l), 25));    \
    (D)[61] = (K)[20] ^ ((V)[17] | KRB5_DES_BS_M ((l), 17));    \
    (D)[62] = (K)[13] ^ ((V)[ 9] | KRB5_DES_BS_M ((l),  9));    \
    (D)[63] = (K)[ 6] ^ ((V)[ 1] | KRB5_DES_BS_M ((l),  1));    \
  }

// The key a block holds, without its parity bits

#define KRB5_DES_BS_KEY_OF(K,B) \
  {                             \
    (K)[ 0] = (B)[ 0];          \
    (K)[ 1] = (B)[ 1];          \
    (K)[ 2] = (B)[ 2];          \
    (K)[ 3] = (B)[ 3];          \
    (K)[ 4] = (B)[ 4];          \
    (K)[ 5] = (B)[ 5];          \
    (K)[ 6] = (B)[ 6];          \
    (K)[ 7] = (B)[ 8];          \
    (K)[ 8] = (B)[ 9];          \
    (K)[ 9] = (B)[10];          \
    (K)[10] = (B)[11];          \
    (K)[11] = (B)[12];          \
    (K)[12] = (B)[13];          \
    (K)[13] = (B)[14];          \
    (K)[14] = (B)[16];          \
    (K)[15] = (B)[17];          \
    (K)[16] = (B)[18];          \
    (K)[17] = (B)[19];          \
    (K)[18] = (B)[20];          \
    (K)[19] = (B)[21];          \
    (K)[20] = (B)[22];          \
    (K)[21] = (B)[24];          \
    (K)[22] = (B)[25];          \
    (K)[23] = (B)[26];          \
    (K)[24] = (B)[27];          \
    (K)[25] = (B)[28];          \
    (K)[26] = (B)[29];          \
    (K)[27] = (B)[30];          \
    (K)[28] = (B)[32];          \
    (K)[29] = (B)[33];          \
    (K)[30] = (B)[34];          \
    (K)[31] = (B)[35];          \
    (K)[32] = (B)[36];          \
    (K)[33] = (B)[37];          \
    (K)[34] = (B)[38];          \
    (K)[35] = (B)[40];          \
    (K)[36] = (B)[41];          \
    (K)[37] = (B)[42];          \
    (K)[38] = (B)[43];          \
    (K)[39] = (B)[44];          \
    (K)[40] = (B)[45];          \
    (K)[41] = (B)[46];          \
    (K)[42] = (B)[48];          \
    (K)[43] = (B)[49];          \
    (K)[44] = (B)[50];          \
    (K)[45] = (B)[51];          \
    (K)[46] = (B)[52];          \
    (K)[47] = (B)[53];          \
    (K)[48] = (B)[54];          \
    (K)[49] = (B)[56];          \
    (K)[50] = (B)[57];          \
    (K)[51] = (B)[58];          \
    (K)[52] = (B)[59];          \
    (K)[53] = (B)[60];          \
    (K)[54] = (B)[61];          \
    (K)[55] = (B)[62];          \
  }

// Every byte of a weak or semi-weak key has bits 1 to 3 alike, see krb5_des_key_correction (). These
// give the candidates of a slice whose key could be one, which is one in 65536, from the 56 bits of
// a key and from the 64 bits of a block.

#define KRB5_DES_BS_WEAK_KEY(K)                   \
  ( ~(((K)[ 6] ^ (K)[ 5]) | ((K)[ 5] ^ (K)[ 4]))  \
  & ~(((K)[13] ^ (K)[12]) | ((K)[12] ^ (K)[11]))  \
  & ~(((K)[20] ^ (K)[19]) | ((K)[19] ^ (K)[18]))  \
  & ~(((K)[27] ^ (K)[26]) | ((K)[26] ^ (K)[25]))  \
  & ~(((K)[34] ^ (K)[33]) | ((K)[33] ^ (K)[32]))  \
  & ~(((K)[41] ^ (K)[40]) | ((K)[40] ^ (K)[39]))  \
  & ~(((K)[48] ^ (K)[47]) | ((K)[47] ^ (K)[46]))  \
  & ~(((K)[55] ^ (K)[54]) | ((K)[54] ^ (K)[53])))

#define KRB5_DES_BS_WEAK_BLOCK(K)                 \
  ( ~(((K)[ 6] ^ (K)[ 5]) | ((K)[ 5] ^ (K)[ 4]))  \
  & ~(((K)[14] ^ (K)[13]) | ((K)[13] ^ (K)[12]))  \
  & ~(((K)[22] ^ (K)[21]) | ((K)[21] ^ (K)[20]))  \
  & ~(((K)[30] ^ (K)[29]) | ((K)[29] ^ (K)[28]))  \
  & ~(((K)[38] ^ (K)[37]) | ((K)[37] ^ (K)[36]))  \
  & ~(((K)[46] ^ (K)[45]) | ((K)[45] ^ (K)[44]))  \
  & ~(((K)[54] ^ (K)[53]) | ((K)[53] ^ (K)[52]))  \
  & ~(((K)[62] ^ (K)[61]) | ((K)[61] ^ (K)[60])))

// The candidates of a slice in which byte n of a block is v

#define KRB5_DES_BS_EQ8(B,n,v)                    \
  ( ~((B)[8 * (n) + 0] ^ KRB5_DES_BS_M ((v), 7))  \
  & ~((B)[8 * (n) + 1] ^ KRB5_DES_BS_M ((v), 6))  \
  & ~((B)[8 * (n) + 2] ^ KRB5_DES_BS_M ((v), 5))  \
  & ~((B)[8 * (n) + 3] ^ KRB5_DES_BS_M ((v), 4))  \
  & ~((B)[8 * (n) + 4] ^ KRB5_DES_BS_M ((v), 3))  \
  & ~((B)[8 * (n) + 5] ^ KRB5_DES_BS_M ((v), 2))  \
  & ~((B)[8 * (n) + 6] ^ KRB5_DES_BS_M ((v), 1))  \
  & ~((B)[8 * (n) + 7] ^ KRB5_DES_BS_M ((v), 0)))

// The candidates of a slice whose key is the one in the two words w0 and w1, parity bits aside

#define KRB5_DES_BS_EQ_KEY(B,w0,w1)        \
  ( ~((B)[ 0] ^ KRB5_DES_BS_M ((w0),  7))  \
  & ~((B)[ 1] ^ KRB5_DES_BS_M ((w0),  6))  \
  & ~((B)[ 2] ^ KRB5_DES_BS_M ((w0),  5))  \
  & ~((B)[ 3] ^ KRB5_DES_BS_M ((w0),  4))  \
  & ~((B)[ 4] ^ KRB5_DES_BS_M ((w0),  3))  \
  & ~((B)[ 5] ^ KRB5_DES_BS_M ((w0),  2))  \
  & ~((B)[ 6] ^ KRB5_DES_BS_M ((w0),  1))  \
  & ~((B)[ 8] ^ KRB5_DES_BS_M ((w0), 15))  \
  & ~((B)[ 9] ^ KRB5_DES_BS_M ((w0), 14))  \
  & ~((B)[10] ^ KRB5_DES_BS_M ((w0), 13))  \
  & ~((B)[11] ^ KRB5_DES_BS_M ((w0), 12))  \
  & ~((B)[12] ^ KRB5_DES_BS_M ((w0), 11))  \
  & ~((B)[13] ^ KRB5_DES_BS_M ((w0), 10))  \
  & ~((B)[14] ^ KRB5_DES_BS_M ((w0),  9))  \
  & ~((B)[16] ^ KRB5_DES_BS_M ((w0), 23))  \
  & ~((B)[17] ^ KRB5_DES_BS_M ((w0), 22))  \
  & ~((B)[18] ^ KRB5_DES_BS_M ((w0), 21))  \
  & ~((B)[19] ^ KRB5_DES_BS_M ((w0), 20))  \
  & ~((B)[20] ^ KRB5_DES_BS_M ((w0), 19))  \
  & ~((B)[21] ^ KRB5_DES_BS_M ((w0), 18))  \
  & ~((B)[22] ^ KRB5_DES_BS_M ((w0), 17))  \
  & ~((B)[24] ^ KRB5_DES_BS_M ((w0), 31))  \
  & ~((B)[25] ^ KRB5_DES_BS_M ((w0), 30))  \
  & ~((B)[26] ^ KRB5_DES_BS_M ((w0), 29))  \
  & ~((B)[27] ^ KRB5_DES_BS_M ((w0), 28))  \
  & ~((B)[28] ^ KRB5_DES_BS_M ((w0), 27))  \
  & ~((B)[29] ^ KRB5_DES_BS_M ((w0), 26))  \
  & ~((B)[30] ^ KRB5_DES_BS_M ((w0), 25))  \
  & ~((B)[32] ^ KRB5_DES_BS_M ((w1),  7))  \
  & ~((B)[33] ^ KRB5_DES_BS_M ((w1),  6))  \
  & ~((B)[34] ^ KRB5_DES_BS_M ((w1),  5))  \
  & ~((B)[35] ^ KRB5_DES_BS_M ((w1),  4))  \
  & ~((B)[36] ^ KRB5_DES_BS_M ((w1),  3))  \
  & ~((B)[37] ^ KRB5_DES_BS_M ((w1),  2))  \
  & ~((B)[38] ^ KRB5_DES_BS_M ((w1),  1))  \
  & ~((B)[40] ^ KRB5_DES_BS_M ((w1), 15))  \
  & ~((B)[41] ^ KRB5_DES_BS_M ((w1), 14))  \
  & ~((B)[42] ^ KRB5_DES_BS_M ((w1), 13))  \
  & ~((B)[43] ^ KRB5_DES_BS_M ((w1), 12))  \
  & ~((B)[44] ^ KRB5_DES_BS_M ((w1), 11))  \
  & ~((B)[45] ^ KRB5_DES_BS_M ((w1), 10))  \
  & ~((B)[46] ^ KRB5_DES_BS_M ((w1),  9))  \
  & ~((B)[48] ^ KRB5_DES_BS_M ((w1), 23))  \
  & ~((B)[49] ^ KRB5_DES_BS_M ((w1), 22))  \
  & ~((B)[50] ^ KRB5_DES_BS_M ((w1), 21))  \
  & ~((B)[51] ^ KRB5_DES_BS_M ((w1), 20))  \
  & ~((B)[52] ^ KRB5_DES_BS_M ((w1), 19))  \
  & ~((B)[53] ^ KRB5_DES_BS_M ((w1), 18))  \
  & ~((B)[54] ^ KRB5_DES_BS_M ((w1), 17))  \
  & ~((B)[56] ^ KRB5_DES_BS_M ((w1), 31))  \
  & ~((B)[57] ^ KRB5_DES_BS_M ((w1), 30))  \
  & ~((B)[58] ^ KRB5_DES_BS_M ((w1), 29))  \
  & ~((B)[59] ^ KRB5_DES_BS_M ((w1), 28))  \
  & ~((B)[60] ^ KRB5_DES_BS_M ((w1), 27))  \
  & ~((B)[61] ^ KRB5_DES_BS_M ((w1), 26))  \
  & ~((B)[62] ^ KRB5_DES_BS_M ((w1), 25)))

// The first word of candidate lane of a slice, read back out of the table

#define KRB5_DES_BS_UNSLICE(b,lane)     \
  ( ((((b)[ 0] >> (lane)) & 1u) <<  0)  \
  | ((((b)[ 1] >> (lane)) & 1u) <<  1)  \
  | ((((b)[ 2] >> (lane)) & 1u) <<  2)  \
  | ((((b)[ 3] >> (lane)) & 1u) <<  3)  \
  | ((((b)[ 4] >> (lane)) & 1u) <<  4)  \
  | ((((b)[ 5] >> (lane)) & 1u) <<  5)  \
  | ((((b)[ 6] >> (lane)) & 1u) <<  6)  \
  | ((((b)[ 7] >> (lane)) & 1u) <<  7)  \
  | ((((b)[ 8] >> (lane)) & 1u) <<  8)  \
  | ((((b)[ 9] >> (lane)) & 1u) <<  9)  \
  | ((((b)[10] >> (lane)) & 1u) << 10)  \
  | ((((b)[11] >> (lane)) & 1u) << 11)  \
  | ((((b)[12] >> (lane)) & 1u) << 12)  \
  | ((((b)[13] >> (lane)) & 1u) << 13)  \
  | ((((b)[14] >> (lane)) & 1u) << 14)  \
  | ((((b)[15] >> (lane)) & 1u) << 15)  \
  | ((((b)[16] >> (lane)) & 1u) << 16)  \
  | ((((b)[17] >> (lane)) & 1u) << 17)  \
  | ((((b)[18] >> (lane)) & 1u) << 18)  \
  | ((((b)[19] >> (lane)) & 1u) << 19)  \
  | ((((b)[20] >> (lane)) & 1u) << 20)  \
  | ((((b)[21] >> (lane)) & 1u) << 21)  \
  | ((((b)[22] >> (lane)) & 1u) << 22)  \
  | ((((b)[23] >> (lane)) & 1u) << 23)  \
  | ((((b)[24] >> (lane)) & 1u) << 24)  \
  | ((((b)[25] >> (lane)) & 1u) << 25)  \
  | ((((b)[26] >> (lane)) & 1u) << 26)  \
  | ((((b)[27] >> (lane)) & 1u) << 27)  \
  | ((((b)[28] >> (lane)) & 1u) << 28)  \
  | ((((b)[29] >> (lane)) & 1u) << 29)  \
  | ((((b)[30] >> (lane)) & 1u) << 30)  \
  | ((((b)[31] >> (lane)) & 1u) << 31))

DECLSPEC void krb5_des_bs_encrypt (PRIVATE_AS const u32 *K, PRIVATE_AS u32 *D);
DECLSPEC void krb5_des_bs_decrypt (PRIVATE_AS const u32 *K, PRIVATE_AS u32 *D);

#endif // INC_KRB5_DES_BS_H
