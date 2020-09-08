#include "rar.hpp"

#define Clean(D,S)  {for (int I=0;I<(S);I++) (D)[I]=0;}

void RSCoder::Init(int ParSize)
{
  RSCoder::ParSize=ParSize; // Store the number of recovery volumes.
  FirstBlockDone=false;
  gfInit();
  pnInit();
}


// Initialize logarithms and exponents Galois field tables.
void RSCoder::gfInit()
{
  for (int I=0,J=1;I<MAXPAR;I++)
  {
    gfLog[J]=I;
    gfExp[I]=J;
    J<<=1;
    if (J > MAXPAR)
      J^=0x11D; // 0x11D field-generator polynomial (x^8+x^4+x^3+x^2+1).
  }
  for (int I=MAXPAR;I<MAXPOL;I++) // Avoid gfExp overflow check.
    gfExp[I]=gfExp[I-MAXPAR];
}


// Multiplication over Galois field. 
inline int RSCoder::gfMult(int a,int b)
{
  return(a==0 || b == 0 ? 0:gfExp[gfLog[a]+gfLog[b]]);
}


// Create the generator polynomial g(x).
// g(x)=(x-a)(x-a^2)(x-a^3)..(x-a^N)
void RSCoder::pnInit()
{
  int p2[MAXPAR+1]; // Currently calculated part of g(x).

  Clean(p2,ParSize);
  p2[0]=1; // Set p2 polynomial to 1.

  for (int I=1;I<=ParSize;I++)
  {
    int p1[MAXPAR+1]; // We use p1 as current (x+a^i) expression.
    Clean(p1,ParSize);
    p1[0]=gfExp[I];
    p1[1]=1; // Set p1 polynomial to x+a^i.

    // Multiply the already calucated part of g(x) to next (x+a^i).
    pnMult(p1,p2,GXPol);

    // p2=g(x).
    for (int J=0;J<ParSize;J++)
      p2[J]=GXPol[J];
  }
}


// Multiply polynomial 'p1' to 'p2' and store the result in 'r'.
void RSCoder::pnMult(int *p1,int *p2,int *r)
{
  Clean(r,ParSize);
  for (int I=0;I<ParSize;I++)
    if (p1[I]!=0)
      for(int J=0;J<ParSize-I;J++)
        r[I+J]^=gfMult(p1[I],p2[J]);
}


void RSCoder::Encode(byte *Data,int DataSize,byte *DestData)
{
  int ShiftReg[MAXPAR+1]; // Linear Feedback Shift Register.

  Clean(ShiftReg,ParSize+1);
  for (int I=0;I<DataSize;I++)
  {
    int D=Data[I]^ShiftReg[ParSize-1];

    // Use g(x) to define feedback taps.
    for (int J=ParSize-1;J>0;J--)
      ShiftReg[J]=ShiftReg[J-1]^gfMult(GXPol[J],D);
    ShiftReg[0]=gfMult(GXPol[0],D);
  }
  for (int I=0;I<ParSize;I++)
    DestData[I]=ShiftReg[ParSize-I-1];
}


bool RSCoder::Decode(byte *Data,int DataSize,int *EraLoc,int EraSize)
{
  int SynData[MAXPOL]; // Syndrome data.

  bool AllZeroes=true;
  for (int I=0;I<ParSize;I++)
  {
    int Sum=0;
    for (int J=0;J<DataSize;J++)
      Sum=Data[J]^gfMult(gfExp[I+1],Sum);
    if ((SynData[I]=Sum)!=0)
      AllZeroes=false;
  }

  // If all syndrome numbers are zero, message does not have errors.
  if (AllZeroes)
    return(true);

  if (!FirstBlockDone) // Do things which we need to do once for all data.
  {
    FirstBlockDone=true;

    // Calculate the error locator polynomial.
    Clean(ELPol,ParSize+1);
    ELPol[0]=1;

    for (int EraPos=0;EraPos<EraSize;EraPos++)
      for (int I=ParSize,M=gfExp[DataSize-EraLoc[EraPos]-1];I>0;I--)
        ELPol[I]^=gfMult(M,ELPol[I-1]);

    ErrCount=0;

    // Find roots of error locator polynomial.
    for (int Root=MAXPAR-DataSize;Root<MAXPAR+1;Root++)
    {
      int Sum=0;
      for (int B=0;B<ParSize+1;B++)
        Sum^=gfMult(gfExp[(B*Root)%MAXPAR],ELPol[B]);
      if (Sum==0) // Root found.
      {
        ErrorLocs[ErrCount]=MAXPAR-Root; // Location of error.

        // Calculate the denominator for every error location.
        Dnm[ErrCount]=0;
        for (int I=1;I<ParSize+1;I+=2)
          Dnm[ErrCount]^= gfMult(ELPol[I],gfExp[Root*(I-1)%MAXPAR]);

        ErrCount++;
      }
    }
  }

  int EEPol[MAXPOL]; // Error Evaluator Polynomial.
  pnMult(ELPol,SynData,EEPol);
  // If errors are present and their number is correctable.
  if ((ErrCount<=ParSize) && ErrCount>0)
    for (int I=0;I<ErrCount;I++)
    {
      int Loc=ErrorLocs[I],DLoc=MAXPAR-Loc,N=0;
      for (int J=0;J<ParSize;J++) 
        N^=gfMult(EEPol[J],gfExp[DLoc*J%MAXPAR]);
      int DataPos=DataSize-Loc-1;
      // Perform bounds check and correct the data error.
      if (DataPos>=0 && DataPos<DataSize)
        Data[DataPos]^=gfMult(N,gfExp[MAXPAR-gfLog[Dnm[I]]]);
    }
  return(ErrCount<=ParSize); // Return true if success.
}
