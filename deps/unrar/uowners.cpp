

void ExtractUnixOwner20(Archive &Arc,const wchar *FileName)
{
  char NameA[NM];
  WideToChar(FileName,NameA,ASIZE(NameA));

  if (Arc.BrokenHeader)
  {
    uiMsg(UIERROR_UOWNERBROKEN,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    return;
  }

  struct passwd *pw;
  errno=0; // Required by getpwnam specification if we need to check errno.
  if ((pw=getpwnam(Arc.UOHead.OwnerName))==NULL)
  {
    uiMsg(UIERROR_UOWNERGETOWNERID,Arc.FileName,GetWide(Arc.UOHead.OwnerName));
    ErrHandler.SysErrMsg();
    ErrHandler.SetErrorCode(RARX_WARNING);
    return;
  }
  uid_t OwnerID=pw->pw_uid;

  struct group *gr;
  errno=0; // Required by getgrnam specification if we need to check errno.
  if ((gr=getgrnam(Arc.UOHead.GroupName))==NULL)
  {
    uiMsg(UIERROR_UOWNERGETGROUPID,Arc.FileName,GetWide(Arc.UOHead.GroupName));
    ErrHandler.SysErrMsg();
    ErrHandler.SetErrorCode(RARX_CRC);
    return;
  }
  uint Attr=GetFileAttr(FileName);
  gid_t GroupID=gr->gr_gid;
#if defined(SAVE_LINKS) && !defined(_APPLE)
  if (lchown(NameA,OwnerID,GroupID)!=0)
#else
  if (chown(NameA,OwnerID,GroupID)!=0)
#endif
  {
    uiMsg(UIERROR_UOWNERSET,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CREATE);
  }
  SetFileAttr(FileName,Attr);
}


void ExtractUnixOwner30(Archive &Arc,const wchar *FileName)
{
  char NameA[NM];
  WideToChar(FileName,NameA,ASIZE(NameA));

  char *OwnerName=(char *)&Arc.SubHead.SubData[0];
  int OwnerSize=strlen(OwnerName)+1;
  int GroupSize=Arc.SubHead.SubData.Size()-OwnerSize;
  char GroupName[NM];
  strncpy(GroupName,(char *)&Arc.SubHead.SubData[OwnerSize],GroupSize);
  GroupName[GroupSize]=0;

  struct passwd *pw;
  if ((pw=getpwnam(OwnerName))==NULL)
  {
    uiMsg(UIERROR_UOWNERGETOWNERID,Arc.FileName,GetWide(OwnerName));
    ErrHandler.SetErrorCode(RARX_WARNING);
    return;
  }
  uid_t OwnerID=pw->pw_uid;

  struct group *gr;
  if ((gr=getgrnam(GroupName))==NULL)
  {
    uiMsg(UIERROR_UOWNERGETGROUPID,Arc.FileName,GetWide(GroupName));
    ErrHandler.SetErrorCode(RARX_WARNING);
    return;
  }
  uint Attr=GetFileAttr(FileName);
  gid_t GroupID=gr->gr_gid;
#if defined(SAVE_LINKS) && !defined(_APPLE)
  if (lchown(NameA,OwnerID,GroupID)!=0)
#else
  if (chown(NameA,OwnerID,GroupID)!=0)
#endif
  {
    uiMsg(UIERROR_UOWNERSET,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CREATE);
  }
  SetFileAttr(FileName,Attr);
}


void SetUnixOwner(Archive &Arc,const wchar *FileName)
{
  char NameA[NM];
  WideToChar(FileName,NameA,ASIZE(NameA));

  // First, we try to resolve symbolic names. If they are missing or cannot
  // be resolved, we try to use numeric values if any. If numeric values
  // are missing too, function fails.
  FileHeader &hd=Arc.FileHead;
  if (*hd.UnixOwnerName!=0)
  {
    struct passwd *pw;
    if ((pw=getpwnam(hd.UnixOwnerName))==NULL)
    {
      if (!hd.UnixOwnerNumeric)
      {
        uiMsg(UIERROR_UOWNERGETOWNERID,Arc.FileName,GetWide(hd.UnixOwnerName));
        ErrHandler.SetErrorCode(RARX_WARNING);
        return;
      }
    }
    else
      hd.UnixOwnerID=pw->pw_uid;
  }
  if (*hd.UnixGroupName!=0)
  {
    struct group *gr;
    if ((gr=getgrnam(hd.UnixGroupName))==NULL)
    {
      if (!hd.UnixGroupNumeric)
      {
        uiMsg(UIERROR_UOWNERGETGROUPID,Arc.FileName,GetWide(hd.UnixGroupName));
        ErrHandler.SetErrorCode(RARX_WARNING);
        return;
      }
    }
    else
      hd.UnixGroupID=gr->gr_gid;
  }
#if defined(SAVE_LINKS) && !defined(_APPLE)
  if (lchown(NameA,hd.UnixOwnerID,hd.UnixGroupID)!=0)
#else
  if (chown(NameA,hd.UnixOwnerID,hd.UnixGroupID)!=0)
#endif
  {
    uiMsg(UIERROR_UOWNERSET,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CREATE);
  }
}
