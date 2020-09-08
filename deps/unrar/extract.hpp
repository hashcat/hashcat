#ifndef _RAR_EXTRACT_
#define _RAR_EXTRACT_

enum EXTRACT_ARC_CODE {EXTRACT_ARC_NEXT,EXTRACT_ARC_REPEAT};

class CmdExtract
{
  private:
    EXTRACT_ARC_CODE ExtractArchive();
    bool ExtractFileCopy(File &New,wchar *ArcName,wchar *NameNew,wchar *NameExisting,size_t NameExistingSize);
    void ExtrPrepareName(Archive &Arc,const wchar *ArcFileName,wchar *DestName,size_t DestSize);
#ifdef RARDLL
    bool ExtrDllGetPassword();
#else
    bool ExtrGetPassword(Archive &Arc,const wchar *ArcFileName);
#endif
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
    void ConvertDosPassword(Archive &Arc,SecPassword &DestPwd);
#endif
    void ExtrCreateDir(Archive &Arc,const wchar *ArcFileName);
    bool ExtrCreateFile(Archive &Arc,File &CurFile);
    bool CheckUnpVer(Archive &Arc,const wchar *ArcFileName);

    RarTime StartTime; // time when extraction started

    CommandData *Cmd;

    ComprDataIO DataIO;
    Unpack *Unp;
    unsigned long TotalFileCount;

    unsigned long FileCount;
    unsigned long MatchedArgs;
    bool FirstFile;
    bool AllMatchesExact;
    bool ReconstructDone;

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
