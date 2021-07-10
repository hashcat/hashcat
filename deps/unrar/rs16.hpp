#ifndef _RAR_RS16_
#define _RAR_RS16_

class RSCoder16
{
  private:
    static const uint gfSize=65535;   // Galois field size.
    void gfInit();                    // Galois field inititalization.
    inline uint gfAdd(uint a,uint b); // Addition in Galois field. 
    inline uint gfMul(uint a,uint b); // Multiplication in Galois field. 
    inline uint gfInv(uint a);        // Inverse element in Galois field.
    uint *gfExp;                      // Galois field exponents.
    uint *gfLog;                      // Galois field logarithms.

    void MakeEncoderMatrix();
    void MakeDecoderMatrix();
    void InvertDecoderMatrix();

#ifdef USE_SSE
    bool SSE_UpdateECC(uint DataNum, uint ECCNum, const byte *Data, byte *ECC, size_t BlockSize);
#endif

    bool Decoding;    // If we are decoding or encoding data.
    uint ND;          // Number of data units.
    uint NR;          // Number of Reed-Solomon code units.
    uint NE;          // Number of erasures.
    bool *ValidFlags; // Validity flags for data and ECC units.
    uint *MX;         // Cauchy based coding or decoding matrix.

    uint *DataLog; // Buffer to store data logarithms for UpdateECC.
    size_t DataLogSize;

  public:
    RSCoder16();
    ~RSCoder16();

    bool Init(uint DataCount, uint RecCount, bool *ValidityFlags);
#if 0 // We use only UpdateECC now.
    void Process(const uint *Data, uint *Out);
#endif
    void UpdateECC(uint DataNum, uint ECCNum, const byte *Data, byte *ECC, size_t BlockSize);
};

#endif
