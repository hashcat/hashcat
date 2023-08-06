#ifndef _RAR_EXTRACT_
#define _RAR_EXTRACT_

enum EXTRACT_ARC_CODE {EXTRACT_ARC_NEXT,EXTRACT_ARC_REPEAT};

class CmdExtract
{
  private:
    struct ExtractRef
    {
      wchar *RefName;
      wchar *TmpName;
      uint64 RefCount;
    };
    Array<ExtractRef> RefList;

    struct AnalyzeData
    {
      wchar StartName[NM];
      uint64 StartPos;
      wchar EndName[NM];
      uint64 EndPos;
    } *Analyze;

    bool ArcAnalyzed;

    void FreeAnalyzeData();
    EXTRACT_ARC_CODE ExtractArchive();
    bool ExtractFileCopy(File &New,wchar *ArcName,const wchar *RedirName,wchar *NameNew,wchar *NameExisting,size_t NameExistingSize,int64 UnpSize);
    void ExtrPrepareName(Archive &Arc,const wchar *ArcFileName,wchar *DestName,size_t DestSize);
#ifdef RARDLL
    bool ExtrDllGetPassword();
#else
    bool ExtrGetPassword(Archive &Arc,const wchar *ArcFileName,RarCheckPassword *CheckPwd);
#endif
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
    void ConvertDosPassword(Archive &Arc,SecPassword &DestPwd);
#endif
    void ExtrCreateDir(Archive &Arc,const wchar *ArcFileName);
    bool ExtrCreateFile(Archive &Arc,File &CurFile);
    bool CheckUnpVer(Archive &Arc,const wchar *ArcFileName);
#ifndef SFX_MODULE
    void AnalyzeArchive(const wchar *ArcName,bool Volume,bool NewNumbering);
    void GetFirstVolIfFullSet(const wchar *SrcName,bool NewNumbering,wchar *DestName,size_t DestSize);
#endif

    RarTime StartTime; // Time when extraction started.

    CommandData *Cmd;

    ComprDataIO DataIO;
    Unpack *Unp;
    unsigned long TotalFileCount;

    unsigned long FileCount;
    unsigned long MatchedArgs;
    bool FirstFile;
    bool AllMatchesExact;
    bool ReconstructDone;
    bool UseExactVolName;

    // If any non-zero solid file was successfully unpacked before current.
    // If true and if current encrypted file is broken, obviously
    // the password is correct and we can report broken CRC without
    // any wrong password hints.
    bool AnySolidDataUnpackedWell;

    wchar ArcName[NM];

    bool GlobalPassword;
    bool PrevProcessed; // If previous file was successfully extracted or tested.
    wchar DestFileName[NM];
    bool PasswordCancelled;

    // In Windows it is set to true if at least one symlink with ".."
    // in target was extracted.
    bool ConvertSymlinkPaths;

    // Last path checked for symlinks. We use it to improve the performance,
    // so we do not check recently checked folders again.
    std::wstring LastCheckedSymlink;

#if defined(_WIN_ALL) && !defined(SFX_MODULE) && !defined(SILENT)
    bool Fat32,NotFat32;
#endif
  public:
    CmdExtract(CommandData *Cmd);
    ~CmdExtract();
    void DoExtract();
    void ExtractArchiveInit(Archive &Arc);
    bool ExtractCurrentFile(Archive &Arc,size_t HeaderSize,bool &Repeat);
    static void UnstoreFile(ComprDataIO &DataIO,int64 DestUnpSize);
};

#endif
