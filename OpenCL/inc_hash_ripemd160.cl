
// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (ripemd160 = LE, sha1 = BE, etc)
// input buf needs to be 64 byte aligned when using ripemd160_update()

typedef struct ripemd160_ctx
{
  u32 h[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} ripemd160_ctx_t;

DECLSPEC void ripemd160_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
  u32 a1 = digest[0];
  u32 b1 = digest[1];
  u32 c1 = digest[2];
  u32 d1 = digest[3];
  u32 e1 = digest[4];

  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w0[0], RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w0[1], RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w0[2], RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w0[3], RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w1[0], RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w1[1], RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w1[2], RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w1[3], RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w2[0], RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w2[1], RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w2[2], RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w2[3], RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w3[0], RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w3[1], RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w3[2], RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w3[3], RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w1[3], RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w1[0], RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w3[1], RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, w0[1], RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, w2[2], RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w1[2], RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w3[3], RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w0[3], RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, w3[0], RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, w0[0], RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w2[1], RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w1[1], RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w0[2], RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, w3[2], RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, w2[3], RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w2[0], RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w0[3], RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w2[2], RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, w3[2], RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w1[0], RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w2[1], RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w3[3], RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w2[0], RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, w0[1], RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w0[2], RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w1[3], RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w0[0], RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w1[2], RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, w3[1], RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w2[3], RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w1[1], RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w3[0], RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w0[1], RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, w2[1], RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, w2[3], RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, w2[2], RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w0[0], RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w2[0], RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, w3[0], RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, w1[0], RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, w3[1], RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w0[3], RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w1[3], RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, w3[3], RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, w3[2], RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, w1[1], RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w1[2], RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w0[2], RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w1[0], RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w0[0], RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, w1[1], RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w2[1], RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w1[3], RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w3[0], RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w0[2], RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, w2[2], RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w3[2], RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w0[1], RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w0[3], RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w2[0], RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, w2[3], RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w1[2], RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w3[3], RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w3[1], RIPEMD160C40, RIPEMD160S4F);

  u32 a2 = digest[0];
  u32 b2 = digest[1];
  u32 c2 = digest[2];
  u32 d2 = digest[3];
  u32 e2 = digest[4];

  RIPEMD160_STEP_S_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w1[1], RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, w3[2], RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w1[3], RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, w0[0], RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w2[1], RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, w0[2], RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, w2[3], RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w1[0], RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, w3[1], RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w1[2], RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, w3[3], RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, w2[0], RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w0[1], RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, w2[2], RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w0[3], RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, w3[0], RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w1[2], RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, w2[3], RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w0[3], RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w1[3], RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w0[0], RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w3[1], RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, w1[1], RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w2[2], RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w3[2], RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w3[3], RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w2[0], RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, w3[0], RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w1[0], RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w2[1], RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w0[1], RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w0[2], RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, w3[3], RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w1[1], RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w0[1], RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w0[3], RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w1[3], RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, w3[2], RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w1[2], RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w2[1], RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w2[3], RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w2[0], RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, w3[0], RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w0[2], RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w2[2], RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w0[0], RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w1[0], RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, w3[1], RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w2[0], RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, w1[2], RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w1[0], RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w0[1], RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, w0[3], RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w2[3], RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, w3[3], RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w0[0], RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w1[1], RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, w3[0], RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w0[2], RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, w3[1], RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w2[1], RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w1[3], RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, w2[2], RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w3[2], RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w3[0], RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, w3[3], RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w2[2], RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w1[0], RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w0[1], RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w1[1], RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, w2[0], RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w1[3], RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w1[2], RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w0[2], RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w3[1], RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, w3[2], RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w0[0], RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w0[3], RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w2[1], RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w2[3], RIPEMD160C90, RIPEMD160S9F);

  const u32 a = digest[1] + c1 + d2;
  const u32 b = digest[2] + d1 + e2;
  const u32 c = digest[3] + e1 + a2;
  const u32 d = digest[4] + a1 + b2;
  const u32 e = digest[0] + b1 + c2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
}

DECLSPEC void ripemd160_init (ripemd160_ctx_t *ctx)
{
  ctx->h[0] = RIPEMD160M_A;
  ctx->h[1] = RIPEMD160M_B;
  ctx->h[2] = RIPEMD160M_C;
  ctx->h[3] = RIPEMD160M_D;
  ctx->h[4] = RIPEMD160M_E;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;

  ctx->len = 0;
}

DECLSPEC void ripemd160_update_64 (ripemd160_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  MAYBE_VOLATILE const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_le_S (w0, w1, w2, w3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };

    switch_buffer_by_offset_carry_le_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];

    ripemd160_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
  }
}

DECLSPEC void ripemd160_update (ripemd160_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd160_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_swap (ripemd160_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_utf16le (ripemd160_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_update_utf16le_swap (ripemd160_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_update_global (ripemd160_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd160_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_global_swap (ripemd160_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_global_utf16le (ripemd160_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_update_global_utf16le_swap (ripemd160_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);

    ripemd160_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  ripemd160_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_final (ripemd160_ctx_t *ctx)
{
  MAYBE_VOLATILE const int pos = ctx->len & 63;

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos);

  if (pos >= 56)
  {
    ripemd160_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = ctx->len * 8;
  ctx->w3[3] = 0;

  ripemd160_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// ripemd160_hmac

typedef struct ripemd160_hmac_ctx
{
  ripemd160_ctx_t ipad;
  ripemd160_ctx_t opad;

} ripemd160_hmac_ctx_t;

DECLSPEC void ripemd160_hmac_init_64 (ripemd160_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  // ipad

  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;

  ripemd160_init (&ctx->ipad);

  ripemd160_update_64 (&ctx->ipad, t0, t1, t2, t3, 64);

  // opad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;

  ripemd160_init (&ctx->opad);

  ripemd160_update_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void ripemd160_hmac_init (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd160_ctx_t tmp;

    ripemd160_init (&tmp);

    ripemd160_update (&tmp, w, len);

    ripemd160_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd160_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd160_hmac_init_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd160_ctx_t tmp;

    ripemd160_init (&tmp);

    ripemd160_update_swap (&tmp, w, len);

    ripemd160_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = swap32_S (w[ 0]);
    w0[1] = swap32_S (w[ 1]);
    w0[2] = swap32_S (w[ 2]);
    w0[3] = swap32_S (w[ 3]);
    w1[0] = swap32_S (w[ 4]);
    w1[1] = swap32_S (w[ 5]);
    w1[2] = swap32_S (w[ 6]);
    w1[3] = swap32_S (w[ 7]);
    w2[0] = swap32_S (w[ 8]);
    w2[1] = swap32_S (w[ 9]);
    w2[2] = swap32_S (w[10]);
    w2[3] = swap32_S (w[11]);
    w3[0] = swap32_S (w[12]);
    w3[1] = swap32_S (w[13]);
    w3[2] = swap32_S (w[14]);
    w3[3] = swap32_S (w[15]);
  }

  ripemd160_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd160_hmac_init_global (ripemd160_hmac_ctx_t *ctx, __global const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd160_ctx_t tmp;

    ripemd160_init (&tmp);

    ripemd160_update_global (&tmp, w, len);

    ripemd160_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd160_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd160_hmac_init_global_swap (ripemd160_hmac_ctx_t *ctx, __global const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd160_ctx_t tmp;

    ripemd160_init (&tmp);

    ripemd160_update_global_swap (&tmp, w, len);

    ripemd160_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = swap32_S (w[ 0]);
    w0[1] = swap32_S (w[ 1]);
    w0[2] = swap32_S (w[ 2]);
    w0[3] = swap32_S (w[ 3]);
    w1[0] = swap32_S (w[ 4]);
    w1[1] = swap32_S (w[ 5]);
    w1[2] = swap32_S (w[ 6]);
    w1[3] = swap32_S (w[ 7]);
    w2[0] = swap32_S (w[ 8]);
    w2[1] = swap32_S (w[ 9]);
    w2[2] = swap32_S (w[10]);
    w2[3] = swap32_S (w[11]);
    w3[0] = swap32_S (w[12]);
    w3[1] = swap32_S (w[13]);
    w3[2] = swap32_S (w[14]);
    w3[3] = swap32_S (w[15]);
  }

  ripemd160_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd160_hmac_update_64 (ripemd160_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  ripemd160_update_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void ripemd160_hmac_update (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  ripemd160_update (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  ripemd160_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_utf16le (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  ripemd160_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_utf16le_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  ripemd160_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_global (ripemd160_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  ripemd160_update_global (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_global_swap (ripemd160_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  ripemd160_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_global_utf16le (ripemd160_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  ripemd160_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_update_global_utf16le_swap (ripemd160_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  ripemd160_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_final (ripemd160_hmac_ctx_t *ctx)
{
  ripemd160_final (&ctx->ipad);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = ctx->ipad.h[0];
  t0[1] = ctx->ipad.h[1];
  t0[2] = ctx->ipad.h[2];
  t0[3] = ctx->ipad.h[3];
  t1[0] = ctx->ipad.h[4];
  t1[1] = 0;
  t1[2] = 0;
  t1[3] = 0;
  t2[0] = 0;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;
  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = 0;

  ripemd160_update_64 (&ctx->opad, t0, t1, t2, t3, 20);

  ripemd160_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

typedef struct ripemd160_ctx_vector
{
  u32x h[5];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} ripemd160_ctx_vector_t;

DECLSPEC void ripemd160_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest)
{
  u32x a1 = digest[0];
  u32x b1 = digest[1];
  u32x c1 = digest[2];
  u32x d1 = digest[3];
  u32x e1 = digest[4];

  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w0[0], RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w0[1], RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w0[2], RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w0[3], RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w1[0], RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w1[1], RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w1[2], RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w1[3], RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w2[0], RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w2[1], RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w2[2], RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w2[3], RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w3[0], RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w3[1], RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w3[2], RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w3[3], RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w1[3], RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w1[0], RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w3[1], RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w0[1], RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w2[2], RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w1[2], RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w3[3], RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w0[3], RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w3[0], RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w0[0], RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w2[1], RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w1[1], RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w0[2], RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w3[2], RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w2[3], RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w2[0], RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w0[3], RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w2[2], RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w3[2], RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w1[0], RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w2[1], RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w3[3], RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w2[0], RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w0[1], RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w0[2], RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w1[3], RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w0[0], RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w1[2], RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w3[1], RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w2[3], RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w1[1], RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w3[0], RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w0[1], RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w2[1], RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w2[3], RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w2[2], RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w0[0], RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w2[0], RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w3[0], RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w1[0], RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w3[1], RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w0[3], RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w1[3], RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w3[3], RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w3[2], RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w1[1], RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w1[2], RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w0[2], RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w1[0], RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w0[0], RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w1[1], RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w2[1], RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w1[3], RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w3[0], RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w0[2], RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w2[2], RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w3[2], RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w0[1], RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w0[3], RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w2[0], RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w2[3], RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w1[2], RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w3[3], RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w3[1], RIPEMD160C40, RIPEMD160S4F);

  u32x a2 = digest[0];
  u32x b2 = digest[1];
  u32x c2 = digest[2];
  u32x d2 = digest[3];
  u32x e2 = digest[4];

  RIPEMD160_STEP_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w1[1], RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w3[2], RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w1[3], RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w0[0], RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w2[1], RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w0[2], RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w2[3], RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w1[0], RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w3[1], RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w1[2], RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w3[3], RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w2[0], RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w0[1], RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w2[2], RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w0[3], RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w3[0], RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w1[2], RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w2[3], RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w0[3], RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w1[3], RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w0[0], RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w3[1], RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w1[1], RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w2[2], RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w3[2], RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w3[3], RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w2[0], RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w3[0], RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w1[0], RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w2[1], RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w0[1], RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w0[2], RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w3[3], RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w1[1], RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w0[1], RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w0[3], RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w1[3], RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w3[2], RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w1[2], RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w2[1], RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w2[3], RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w2[0], RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w3[0], RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w0[2], RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w2[2], RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w0[0], RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w1[0], RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w3[1], RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w2[0], RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w1[2], RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w1[0], RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w0[1], RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w0[3], RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w2[3], RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w3[3], RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w0[0], RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w1[1], RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w3[0], RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w0[2], RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w3[1], RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w2[1], RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w1[3], RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w2[2], RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w3[2], RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w3[0], RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w3[3], RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w2[2], RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w1[0], RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w0[1], RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w1[1], RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w2[0], RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w1[3], RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w1[2], RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w0[2], RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w3[1], RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w3[2], RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w0[0], RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w0[3], RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w2[1], RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w2[3], RIPEMD160C90, RIPEMD160S9F);

  const u32x a = digest[1] + c1 + d2;
  const u32x b = digest[2] + d1 + e2;
  const u32x c = digest[3] + e1 + a2;
  const u32x d = digest[4] + a1 + b2;
  const u32x e = digest[0] + b1 + c2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
}

DECLSPEC void ripemd160_init_vector (ripemd160_ctx_vector_t *ctx)
{
  ctx->h[0] = RIPEMD160M_A;
  ctx->h[1] = RIPEMD160M_B;
  ctx->h[2] = RIPEMD160M_C;
  ctx->h[3] = RIPEMD160M_D;
  ctx->h[4] = RIPEMD160M_E;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;

  ctx->len = 0;
}

DECLSPEC void ripemd160_init_vector_from_scalar (ripemd160_ctx_vector_t *ctx, ripemd160_ctx_t *ctx0)
{
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];

  ctx->w0[0] = ctx0->w0[0];
  ctx->w0[1] = ctx0->w0[1];
  ctx->w0[2] = ctx0->w0[2];
  ctx->w0[3] = ctx0->w0[3];
  ctx->w1[0] = ctx0->w1[0];
  ctx->w1[1] = ctx0->w1[1];
  ctx->w1[2] = ctx0->w1[2];
  ctx->w1[3] = ctx0->w1[3];
  ctx->w2[0] = ctx0->w2[0];
  ctx->w2[1] = ctx0->w2[1];
  ctx->w2[2] = ctx0->w2[2];
  ctx->w2[3] = ctx0->w2[3];
  ctx->w3[0] = ctx0->w3[0];
  ctx->w3[1] = ctx0->w3[1];
  ctx->w3[2] = ctx0->w3[2];
  ctx->w3[3] = ctx0->w3[3];

  ctx->len = ctx0->len;
}

DECLSPEC void ripemd160_update_vector_64 (ripemd160_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len)
{
  MAYBE_VOLATILE const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_le (w0, w1, w2, w3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
  }
  else
  {
    u32x c0[4] = { 0 };
    u32x c1[4] = { 0 };
    u32x c2[4] = { 0 };
    u32x c3[4] = { 0 };

    switch_buffer_by_offset_carry_le (w0, w1, w2, w3, c0, c1, c2, c3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];

    ripemd160_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
  }
}

DECLSPEC void ripemd160_update_vector (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_vector_swap (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);

    ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);

  ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd160_update_vector_utf16le (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_update_vector_utf16le_swap (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);

    ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);

  ripemd160_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd160_final_vector (ripemd160_ctx_vector_t *ctx)
{
  MAYBE_VOLATILE const int pos = ctx->len & 63;

  append_0x80_4x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos);

  if (pos >= 56)
  {
    ripemd160_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = ctx->len * 8;
  ctx->w3[3] = 0;

  ripemd160_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// HMAC + Vector

typedef struct ripemd160_hmac_ctx_vector
{
  ripemd160_ctx_vector_t ipad;
  ripemd160_ctx_vector_t opad;

} ripemd160_hmac_ctx_vector_t;

DECLSPEC void ripemd160_hmac_init_vector_64 (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3)
{
  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

  // ipad

  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;

  ripemd160_init_vector (&ctx->ipad);

  ripemd160_update_vector_64 (&ctx->ipad, t0, t1, t2, t3, 64);

  // opad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;

  ripemd160_init_vector (&ctx->opad);

  ripemd160_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void ripemd160_hmac_init_vector (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    ripemd160_ctx_vector_t tmp;

    ripemd160_init_vector (&tmp);

    ripemd160_update_vector (&tmp, w, len);

    ripemd160_final_vector (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd160_hmac_init_vector_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd160_hmac_update_vector_64 (ripemd160_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len)
{
  ripemd160_update_vector_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void ripemd160_hmac_update_vector (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  ripemd160_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void ripemd160_hmac_final_vector (ripemd160_hmac_ctx_vector_t *ctx)
{
  ripemd160_final_vector (&ctx->ipad);

  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

  t0[0] = ctx->ipad.h[0];
  t0[1] = ctx->ipad.h[1];
  t0[2] = ctx->ipad.h[2];
  t0[3] = ctx->ipad.h[3];
  t1[0] = ctx->ipad.h[4];
  t1[1] = 0;
  t1[2] = 0;
  t1[3] = 0;
  t2[0] = 0;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;
  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = 0;

  ripemd160_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 20);

  ripemd160_final_vector (&ctx->opad);
}
