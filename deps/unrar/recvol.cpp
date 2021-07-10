#include "rar.hpp"

#include "recvol3.cpp"
#include "recvol5.cpp"



bool RecVolumesRestore(RAROptions *Cmd,const wchar *Name,bool Silent)
{
  Archive Arc(Cmd);
  if (!Arc.Open(Name))
  {
    if (!Silent)
      ErrHandler.OpenErrorMsg(Name);
    return false;
  }

  RARFORMAT Fmt=RARFMT15;
  if (Arc.IsArchive(true))
    Fmt=Arc.Format;
  else
  {
    byte Sign[REV5_SIGN_SIZE];
    Arc.Seek(0,SEEK_SET);
    if (Arc.Read(Sign,REV5_SIGN_SIZE)==REV5_SIGN_SIZE && memcmp(Sign,REV5_SIGN,REV5_SIGN_SIZE)==0)
      Fmt=RARFMT50;
  }
  Arc.Close();

  // We define RecVol as local variable for proper stack unwinding when
  // handling exceptions. So it can close and delete files on Cancel.
  if (Fmt==RARFMT15)
  {
    RecVolumes3 RecVol(Cmd,false);
    return RecVol.Restore(Cmd,Name,Silent);
  }
  else
  {
    RecVolumes5 RecVol(Cmd,false);
    return RecVol.Restore(Cmd,Name,Silent);
  }
}


void RecVolumesTest(RAROptions *Cmd,Archive *Arc,const wchar *Name)
{
  wchar RevName[NM];
  *RevName=0;
  if (Arc!=NULL)
  {
    // We received .rar or .exe volume as a parameter, trying to find
    // the matching .rev file number 1.
    bool NewNumbering=Arc->NewNumbering;

    wchar ArcName[NM];
    wcsncpyz(ArcName,Name,ASIZE(ArcName));

    wchar *VolNumStart=VolNameToFirstName(ArcName,ArcName,ASIZE(ArcName),NewNumbering);
    wchar RecVolMask[NM];
    wcsncpyz(RecVolMask,ArcName,ASIZE(RecVolMask));
    size_t BaseNamePartLength=VolNumStart-ArcName;
    wcsncpyz(RecVolMask+BaseNamePartLength,L"*.rev",ASIZE(RecVolMask)-BaseNamePartLength);

    FindFile Find;
    Find.SetMask(RecVolMask);
    FindData RecData;

    while (Find.Next(&RecData))
    {
      wchar *Num=GetVolNumPart(RecData.Name);
      if (*Num!='1') // Name must have "0...01" numeric part.
        continue;
      bool FirstVol=true;
      while (--Num>=RecData.Name && IsDigit(*Num))
        if (*Num!='0')
        {
          FirstVol=false;
          break;
        }
      if (FirstVol)
      {
        wcsncpyz(RevName,RecData.Name,ASIZE(RevName));
        Name=RevName;
        break;
      }
    }
    if (*RevName==0) // First .rev file not found.
      return;
  }
  
  File RevFile;
  if (!RevFile.Open(Name))
  {
    ErrHandler.OpenErrorMsg(Name); // It also sets RARX_OPEN.
    return;
  }
  mprintf(L"\n");
  byte Sign[REV5_SIGN_SIZE];
  bool Rev5=RevFile.Read(Sign,REV5_SIGN_SIZE)==REV5_SIGN_SIZE && memcmp(Sign,REV5_SIGN,REV5_SIGN_SIZE)==0;
  RevFile.Close();
  if (Rev5)
  {
    RecVolumes5 RecVol(Cmd,true);
    RecVol.Test(Cmd,Name);
  }
  else
  {
    RecVolumes3 RecVol(Cmd,true);
    RecVol.Test(Cmd,Name);
  }
}
