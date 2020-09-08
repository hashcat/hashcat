#include "rar.hpp"

StringList::StringList()
{
  Reset();
}


void StringList::Reset()
{
  Rewind();
  StringData.Reset();
  StringsCount=0;
  SavePosNumber=0;
}


void StringList::AddStringA(const char *Str)
{
  Array<wchar> StrW(strlen(Str));
  CharToWide(Str,&StrW[0],StrW.Size());
  AddString(&StrW[0]);
}


void StringList::AddString(const wchar *Str)
{
  if (Str==NULL)
    Str=L"";

  size_t PrevSize=StringData.Size();
  StringData.Add(wcslen(Str)+1);
  wcscpy(&StringData[PrevSize],Str);

  StringsCount++;
}


bool StringList::GetStringA(char *Str,size_t MaxLength)
{
  Array<wchar> StrW(MaxLength);
  if (!GetString(&StrW[0],StrW.Size()))
    return false;
  WideToChar(&StrW[0],Str,MaxLength);
  return true;
}


bool StringList::GetString(wchar *Str,size_t MaxLength)
{
  wchar *StrPtr;
  if (!GetString(&StrPtr))
    return false;
  wcsncpyz(Str,StrPtr,MaxLength);
  return true;
}


#ifndef SFX_MODULE
bool StringList::GetString(wchar *Str,size_t MaxLength,int StringNum)
{
  SavePosition();
  Rewind();
  bool RetCode=true;
  while (StringNum-- >=0)
    if (!GetString(Str,MaxLength))
    {
      RetCode=false;
      break;
    }
  RestorePosition();
  return RetCode;
}
#endif


wchar* StringList::GetString()
{
  wchar *Str;
  GetString(&Str);
  return Str;
}


bool StringList::GetString(wchar **Str)
{
  if (CurPos>=StringData.Size()) // No more strings left unprocessed.
  {
    if (Str!=NULL)
      *Str=NULL;
    return false;
  }

  wchar *CurStr=&StringData[CurPos];
  CurPos+=wcslen(CurStr)+1;
  if (Str!=NULL)
    *Str=CurStr;

  return true;
}


void StringList::Rewind()
{
  CurPos=0;
}


#ifndef SFX_MODULE
bool StringList::Search(const wchar *Str,bool CaseSensitive)
{
  SavePosition();
  Rewind();
  bool Found=false;
  wchar *CurStr;
  while (GetString(&CurStr))
  {
    if (Str!=NULL && CurStr!=NULL)
      if ((CaseSensitive ? wcscmp(Str,CurStr):wcsicomp(Str,CurStr))!=0)
        continue;
    Found=true;
    break;
  }
  RestorePosition();
  return Found;
}
#endif


#ifndef SFX_MODULE
void StringList::SavePosition()
{
  if (SavePosNumber<ASIZE(SaveCurPos))
  {
    SaveCurPos[SavePosNumber]=CurPos;
    SavePosNumber++;
  }
}
#endif


#ifndef SFX_MODULE
void StringList::RestorePosition()
{
  if (SavePosNumber>0)
  {
    SavePosNumber--;
    CurPos=SaveCurPos[SavePosNumber];
  }
}
#endif
