#include "rar.hpp"

int ToPercent(int64 N1,int64 N2)
{
  if (N2<N1)
    return 100;
  return ToPercentUnlim(N1,N2);
}


// Allows the percent larger than 100.
int ToPercentUnlim(int64 N1,int64 N2)
{
  if (N2==0)
    return 0;
  return (int)(N1*100/N2);
}


