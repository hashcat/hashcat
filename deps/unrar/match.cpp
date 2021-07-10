#include "rar.hpp"

static bool match(const wchar *pattern,const wchar *string,bool ForceCase);
static int mwcsicompc(const wchar *Str1,const wchar *Str2,bool ForceCase);
static int mwcsnicompc(const wchar *Str1,const wchar *Str2,size_t N,bool ForceCase);

inline uint touppercw(uint ch,bool ForceCase)
{
  if (ForceCase)
    return ch;
#if defined(_UNIX)
  return ch;
#else
  return toupperw(ch);
#endif
}


bool CmpName(const wchar *Wildcard,const wchar *Name,int CmpMode)
{
  bool ForceCase=(CmpMode&MATCH_FORCECASESENSITIVE)!=0;

  CmpMode&=MATCH_MODEMASK;

  if (CmpMode!=MATCH_NAMES)
  {
    size_t WildLength=wcslen(Wildcard);
    if (CmpMode!=MATCH_EXACT && CmpMode!=MATCH_EXACTPATH && CmpMode!=MATCH_ALLWILD &&
        mwcsnicompc(Wildcard,Name,WildLength,ForceCase)==0)
    {
      // For all modes except MATCH_NAMES, MATCH_EXACT, MATCH_EXACTPATH, MATCH_ALLWILD,
      // "path1" mask must match "path1\path2\filename.ext" and "path1" names.
      wchar NextCh=Name[WildLength];
      if (NextCh==L'\\' || NextCh==L'/' || NextCh==0)
        return(true);
    }

    // Nothing more to compare for MATCH_SUBPATHONLY.
    if (CmpMode==MATCH_SUBPATHONLY)
      return(false);

    wchar Path1[NM],Path2[NM];
    GetFilePath(Wildcard,Path1,ASIZE(Path1));
    GetFilePath(Name,Path2,ASIZE(Path2));

    if ((CmpMode==MATCH_EXACT || CmpMode==MATCH_EXACTPATH) &&
        mwcsicompc(Path1,Path2,ForceCase)!=0)
      return(false);
    if (CmpMode==MATCH_ALLWILD)
      return match(Wildcard,Name,ForceCase);
    if (CmpMode==MATCH_SUBPATH || CmpMode==MATCH_WILDSUBPATH)
      if (IsWildcard(Path1))
        return(match(Wildcard,Name,ForceCase));
      else
        if (CmpMode==MATCH_SUBPATH || IsWildcard(Wildcard))
        {
          if (*Path1 && mwcsnicompc(Path1,Path2,wcslen(Path1),ForceCase)!=0)
            return(false);
        }
        else
          if (mwcsicompc(Path1,Path2,ForceCase)!=0)
            return(false);
  }
  wchar *Name1=PointToName(Wildcard);
  wchar *Name2=PointToName(Name);

  // Always return false for RAR temporary files to exclude them
  // from archiving operations.
//  if (mwcsnicompc(L"__rar_",Name2,6,false)==0)
//    return(false);

  if (CmpMode==MATCH_EXACT)
    return(mwcsicompc(Name1,Name2,ForceCase)==0);

  return(match(Name1,Name2,ForceCase));
}


bool match(const wchar *pattern,const wchar *string,bool ForceCase)
{
  for (;; ++string)
  {
    wchar stringc=touppercw(*string,ForceCase);
    wchar patternc=touppercw(*pattern++,ForceCase);
    switch (patternc)
    {
      case 0:
        return(stringc==0);
      case '?':
        if (stringc == 0)
          return(false);
        break;
      case '*':
        if (*pattern==0)
          return(true);
        if (*pattern=='.')
        {
          if (pattern[1]=='*' && pattern[2]==0)
            return(true);
          const wchar *dot=wcschr(string,'.');
          if (pattern[1]==0)
            return (dot==NULL || dot[1]==0);
          if (dot!=NULL)
          {
            string=dot;
            if (wcspbrk(pattern,L"*?")==NULL && wcschr(string+1,'.')==NULL)
              return(mwcsicompc(pattern+1,string+1,ForceCase)==0);
          }
        }

        while (*string)
          if (match(pattern,string++,ForceCase))
            return(true);
        return(false);
      default:
        if (patternc != stringc)
        {
          // Allow "name." mask match "name" and "name.\" match "name\".
          if (patternc=='.' && (stringc==0 || stringc=='\\' || stringc=='.'))
            return(match(pattern,string,ForceCase));
          else
            return(false);
        }
        break;
    }
  }
}


int mwcsicompc(const wchar *Str1,const wchar *Str2,bool ForceCase)
{
  if (ForceCase)
    return wcscmp(Str1,Str2);
  return wcsicompc(Str1,Str2);
}


int mwcsnicompc(const wchar *Str1,const wchar *Str2,size_t N,bool ForceCase)
{
  if (ForceCase)
    return wcsncmp(Str1,Str2,N);
#if defined(_UNIX)
  return wcsncmp(Str1,Str2,N);
#else
  return wcsnicomp(Str1,Str2,N);
#endif
}
