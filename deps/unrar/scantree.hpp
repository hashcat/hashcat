#ifndef _RAR_SCANTREE_
#define _RAR_SCANTREE_

enum SCAN_DIRS 
{ 
  SCAN_SKIPDIRS,     // Skip directories, but recurse for files if recursion mode is enabled.
  SCAN_GETDIRS,      // Get subdirectories in recurse mode.
  SCAN_GETDIRSTWICE, // Get the directory name both before and after the list of files it contains.
  SCAN_GETCURDIRS    // Get subdirectories in current directory even in RECURSE_NONE mode.
};

enum SCAN_CODE { SCAN_SUCCESS,SCAN_DONE,SCAN_ERROR,SCAN_NEXT };

#define MAXSCANDEPTH    (NM/2)

class CommandData;

class ScanTree
{
  private:
    bool ExpandFolderMask();
    bool GetFilteredMask();
    bool GetNextMask();
    SCAN_CODE FindProc(FindData *FD);
    void ScanError(bool &Error);

    FindFile *FindStack[MAXSCANDEPTH];
    int Depth;

    int SetAllMaskDepth;

    StringList *FileMasks;
    RECURSE_MODE Recurse;
    bool GetLinks;
    SCAN_DIRS GetDirs;
    int Errors;

    // Set when processing paths like c:\ (root directory without wildcards).
    bool ScanEntireDisk;

    wchar CurMask[NM];
    wchar OrigCurMask[NM];

    // Store all folder masks generated from folder wildcard mask in non-recursive mode.
    StringList ExpandedFolderList;

    // Store a filter string for folder wildcard in recursive mode.
    StringList FilterList;

    // Save the list of unreadable dirs here.
    StringList *ErrDirList;
    Array<uint> *ErrDirSpecPathLength;

    // Set if processing a folder wildcard mask.
    bool FolderWildcards;

    bool SearchAllInRoot;
    size_t SpecPathLength;

    wchar ErrArcName[NM];

    CommandData *Cmd;
  public:
    ScanTree(StringList *FileMasks,RECURSE_MODE Recurse,bool GetLinks,SCAN_DIRS GetDirs);
    ~ScanTree();
    SCAN_CODE GetNext(FindData *FindData);
    size_t GetSpecPathLength() {return SpecPathLength;}
    int GetErrors() {return Errors;};
    void SetErrArcName(const wchar *Name) {wcsncpyz(ErrArcName,Name,ASIZE(ErrArcName));}
    void SetCommandData(CommandData *Cmd) {ScanTree::Cmd=Cmd;}
    void SetErrDirList(StringList *List,Array<uint> *Lengths)
    {
      ErrDirList=List;
      ErrDirSpecPathLength=Lengths;
    }
};

#endif
