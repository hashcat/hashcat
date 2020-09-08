void CommandData::OutTitle()
{
  if (BareOutput || DisableCopyright)
    return;
#if defined(__GNUC__) && defined(SFX_MODULE)
  mprintf(St(MCopyrightS));
#else
#ifndef SILENT
  static bool TitleShown=false;
  if (TitleShown)
    return;
  TitleShown=true;

  wchar Version[80];
  if (RARVER_BETA!=0)
    swprintf(Version,ASIZE(Version),L"%d.%02d %ls %d",RARVER_MAJOR,RARVER_MINOR,St(MBeta),RARVER_BETA);
  else
    swprintf(Version,ASIZE(Version),L"%d.%02d",RARVER_MAJOR,RARVER_MINOR);
#if defined(_WIN_32) || defined(_WIN_64)
  wcsncatz(Version,L" ",ASIZE(Version));
#endif
#ifdef _WIN_32
  wcsncatz(Version,St(Mx86),ASIZE(Version));
#endif
#ifdef _WIN_64
  wcsncatz(Version,St(Mx64),ASIZE(Version));
#endif
  if (PrintVersion)
  {
    mprintf(L"%s",Version);
    exit(0);
  }
  mprintf(St(MUCopyright),Version,RARVER_YEAR);
#endif
#endif
}


inline bool CmpMSGID(MSGID i1,MSGID i2)
{
#ifdef MSGID_INT
  return i1==i2;
#else
  // If MSGID is const char*, we cannot compare pointers only.
  // Pointers to different instances of same string can differ,
  // so we need to compare complete strings.
  return wcscmp(i1,i2)==0;
#endif
}

void CommandData::OutHelp(RAR_EXIT ExitCode)
{
#if !defined(SILENT)
  OutTitle();
  static MSGID Help[]={
#ifdef SFX_MODULE
    // Console SFX switches definition.
    MCHelpCmd,MSHelpCmdE,MSHelpCmdT,MSHelpCmdV
#else
    // UnRAR switches definition.
    MUNRARTitle1,MRARTitle2,MCHelpCmd,MCHelpCmdE,MCHelpCmdL,
    MCHelpCmdP,MCHelpCmdT,MCHelpCmdV,MCHelpCmdX,MCHelpSw,MCHelpSwm,
    MCHelpSwAT,MCHelpSwAC,MCHelpSwAD,MCHelpSwAG,MCHelpSwAI,MCHelpSwAP,
    MCHelpSwCm,MCHelpSwCFGm,MCHelpSwCL,MCHelpSwCU,
    MCHelpSwDH,MCHelpSwEP,MCHelpSwEP3,MCHelpSwF,MCHelpSwIDP,MCHelpSwIERR,
    MCHelpSwINUL,MCHelpSwIOFF,MCHelpSwKB,MCHelpSwN,MCHelpSwNa,MCHelpSwNal,
    MCHelpSwO,MCHelpSwOC,MCHelpSwOL,MCHelpSwOR,MCHelpSwOW,MCHelpSwP,
    MCHelpSwPm,MCHelpSwR,MCHelpSwRI,MCHelpSwSC,MCHelpSwSL,MCHelpSwSM,
    MCHelpSwTA,MCHelpSwTB,MCHelpSwTN,MCHelpSwTO,MCHelpSwTS,MCHelpSwU,
    MCHelpSwVUnr,MCHelpSwVER,MCHelpSwVP,MCHelpSwX,MCHelpSwXa,MCHelpSwXal,
    MCHelpSwY
#endif
  };

  for (uint I=0;I<ASIZE(Help);I++)
  {
#ifndef SFX_MODULE
    if (CmpMSGID(Help[I],MCHelpSwV))
      continue;
#ifndef _WIN_ALL
    static MSGID Win32Only[]={
      MCHelpSwIEML,MCHelpSwVD,MCHelpSwAO,MCHelpSwOS,MCHelpSwIOFF,
      MCHelpSwEP2,MCHelpSwOC,MCHelpSwONI,MCHelpSwDR,MCHelpSwRI
    };
    bool Found=false;
    for (uint J=0;J<ASIZE(Win32Only);J++)
      if (CmpMSGID(Help[I],Win32Only[J]))
      {
        Found=true;
        break;
      }
    if (Found)
      continue;
#endif
#if !defined(_UNIX) && !defined(_WIN_ALL)
    if (CmpMSGID(Help[I],MCHelpSwOW))
      continue;
#endif
#if !defined(_WIN_ALL) && !defined(_EMX)
    if (CmpMSGID(Help[I],MCHelpSwAC))
      continue;
#endif
#ifndef SAVE_LINKS
    if (CmpMSGID(Help[I],MCHelpSwOL))
      continue;
#endif
#ifndef RAR_SMP
    if (CmpMSGID(Help[I],MCHelpSwMT))
      continue;
#endif
#endif
    mprintf(St(Help[I]));
  }
  mprintf(L"\n");
  ErrHandler.Exit(ExitCode);
#endif
}

