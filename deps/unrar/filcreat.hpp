#ifndef _RAR_FILECREATE_
#define _RAR_FILECREATE_

bool FileCreate(CommandData *Cmd,File *NewFile,wchar *Name,size_t MaxNameSize,
                bool *UserReject,int64 FileSize=INT64NDF,
                RarTime *FileTime=NULL,bool WriteOnly=false);

bool GetAutoRenamedName(wchar *Name,size_t MaxNameSize);

#if defined(_WIN_ALL)
bool UpdateExistingShortName(const wchar *Name);
#endif

#endif
