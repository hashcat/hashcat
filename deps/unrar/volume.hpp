#ifndef _RAR_VOLUME_
#define _RAR_VOLUME_

void SplitArchive(Archive &Arc,FileHeader *fh,int64 *HeaderPos,
                  ComprDataIO *DataIO);
bool MergeArchive(Archive &Arc,ComprDataIO *DataIO,bool ShowFileName,
                  wchar Command);
void SetVolWrite(Archive &Dest,int64 VolSize);

#endif
