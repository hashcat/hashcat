/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef BCRYPT_EK_H
#define BCRYPT_EK_H
#include <stdint.h>
#include <string.h>
#include "bf_const.h"

typedef struct { uint32_t P[18]; uint32_t S[4][256]; } bf_t;

static uint32_t bf_F(const bf_t*st, uint32_t x){
  uint32_t a=(x>>24)&0xff,b=(x>>16)&0xff,c=(x>>8)&0xff,d=x&0xff;
  return ((st->S[0][a]+st->S[1][b])^st->S[2][c])+st->S[3][d];
}
static void bf_enc(const bf_t*st, uint32_t*l_, uint32_t*r_){
  uint32_t l=*l_,r=*r_;
  for(int i=0;i<16;i++){ l^=st->P[i]; r^=bf_F(st,l); uint32_t t=l; l=r; r=t; }
  uint32_t t=l; l=r; r=t;
  r^=st->P[16]; l^=st->P[17];
  *l_=l; *r_=r;
}
static void bf_expandkey(bf_t*st, const uint32_t*key, int keyw, const uint32_t*salt, int nsalt){
  for(int i=0;i<18;i++) st->P[i]^=key[i%keyw];
  uint32_t l=0,r=0; int si=0;
  for(int i=0;i<18;i+=2){
    if(nsalt){ l^=salt[si%nsalt]; r^=salt[(si+1)%nsalt]; si=(si+2)%nsalt; }
    bf_enc(st,&l,&r); st->P[i]=l; st->P[i+1]=r;
  }
  for(int bi=0;bi<4;bi++) for(int j=0;j<256;j+=2){
    if(nsalt){ l^=salt[si%nsalt]; r^=salt[(si+1)%nsalt]; si=(si+2)%nsalt; }
    bf_enc(st,&l,&r); st->S[bi][j]=l; st->S[bi][j+1]=r;
  }
}
static void bcrypt_raw_ek(const uint32_t ek18[18], const uint8_t salt16[16], int rounds, uint8_t out[24]){
  bf_t st; memcpy(st.P,BF_P_INIT,sizeof st.P); memcpy(st.S,BF_S_INIT,sizeof st.S);
  uint32_t sw[4]; for(int i=0;i<4;i++) sw[i]=((uint32_t)salt16[4*i]<<24)|((uint32_t)salt16[4*i+1]<<16)|((uint32_t)salt16[4*i+2]<<8)|salt16[4*i+3];
  bf_expandkey(&st, ek18, 18, sw, 4);
  for(int it=0; it<rounds; it++){ bf_expandkey(&st, ek18, 18, 0, 0); bf_expandkey(&st, sw, 4, 0, 0); }
  const char*mag="OrpheanBeholderScryDoubt";
  uint32_t ct[6]; for(int k=0;k<6;k++) ct[k]=((uint32_t)(uint8_t)mag[4*k]<<24)|((uint32_t)(uint8_t)mag[4*k+1]<<16)|((uint32_t)(uint8_t)mag[4*k+2]<<8)|(uint8_t)mag[4*k+3];
  for(int r=0;r<64;r++) for(int k=0;k<6;k+=2) bf_enc(&st,&ct[k],&ct[k+1]);
  for(int k=0;k<6;k++){ out[4*k]=ct[k]>>24; out[4*k+1]=ct[k]>>16; out[4*k+2]=ct[k]>>8; out[4*k+3]=ct[k]; }
}
#endif
