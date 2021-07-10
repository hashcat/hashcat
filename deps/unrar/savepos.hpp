#ifndef _RAR_SAVEPOS_
#define _RAR_SAVEPOS_

class SaveFilePos
{
  private:
    File *SaveFile;
    int64 SavePos;
  public:
    SaveFilePos(File &Src)
    {
      SaveFile=&Src;
      SavePos=Src.Tell();
    }
    ~SaveFilePos()
    {
      // Unless the file is already closed either by current exception
      // processing or intentionally by external code.
      if (SaveFile->IsOpened())
      {
        try
        {
          SaveFile->Seek(SavePos,SEEK_SET);
        }
        catch(RAR_EXIT)
        {
          // Seek() can throw an exception and it terminates process
          // if we are already processing another exception. Also in C++ 11
          // an exception in destructor always terminates process unless
          // we mark destructor with noexcept(false). So we do not want to
          // throw here. To prevent data loss we do not want to continue
          // execution after seek error, so we close the file.
          // Any next access to this file will return an error.
          SaveFile->Close();
        }
      }
    }
};

#endif
