#ifndef _RAR_RS_
#define _RAR_RS_

#define MAXPAR 255 // Maximum parity data size.
#define MAXPOL 512 // Maximum polynomial degree.

class RSCoder
{
  private:
    void gfInit();
    int gfMult(int a,int b);
    void pnInit();
    void pnMult(int *p1,int *p2,int *r);

    int gfExp[MAXPOL];   // Galois field exponents.
    int gfLog[MAXPAR+1]; // Galois field logarithms.

    int GXPol[MAXPOL*2]; // Generator polynomial g(x).

    int ErrorLocs[MAXPAR+1],ErrCount;
    int Dnm[MAXPAR+1];

    int ParSize; // Parity bytes size and so the number of recovery volumes.
    int ELPol[MAXPOL]; // Error locator polynomial.
    bool FirstBlockDone;
  public:
    void Init(int ParSize);
    void Encode(byte *Data,int DataSize,byte *DestData);
    bool Decode(byte *Data,int DataSize,int *EraLoc,int EraSize);
};

#endif
