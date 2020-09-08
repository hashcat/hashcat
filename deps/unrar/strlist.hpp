#ifndef _RAR_STRLIST_
#define _RAR_STRLIST_

class StringList
{
  private:
    Array<wchar> StringData;
    size_t CurPos;

    size_t StringsCount;

    size_t SaveCurPos[16],SavePosNumber;
  public:
    StringList();
    void Reset();
    void AddStringA(const char *Str);
    void AddString(const wchar *Str);
    bool GetStringA(char *Str,size_t MaxLength);
    bool GetString(wchar *Str,size_t MaxLength);
    bool GetString(wchar *Str,size_t MaxLength,int StringNum);
    wchar* GetString();
    bool GetString(wchar **Str);
    void Rewind();
    size_t ItemsCount() {return StringsCount;};
    size_t GetCharCount() {return StringData.Size();}
    bool Search(const wchar *Str,bool CaseSensitive);
    void SavePosition();
    void RestorePosition();
};

#endif
