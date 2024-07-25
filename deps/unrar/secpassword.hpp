#ifndef _RAR_SECURE_PASSWORD_
#define _RAR_SECURE_PASSWORD_

// Store a password securely (if data encryption is provided by OS)
// or obfuscated to make search for password in memory dump less trivial.
class SecPassword
{
  private:
    void Process(const wchar *Src,size_t SrcSize,wchar *Dst,size_t DstSize,bool Encode);

    std::vector<wchar> Password = std::vector<wchar>(MAXPASSWORD);
    bool PasswordSet;
  public:
    SecPassword();
    ~SecPassword();
    void Clean();
    void Get(wchar *Psw,size_t MaxSize);
    void Set(const wchar *Psw);
    bool IsSet() {return PasswordSet;}
    size_t Length();
    bool operator == (SecPassword &psw);
};


void cleandata(void *data,size_t size);
void SecHideData(void *Data,size_t DataSize,bool Encode,bool CrossProcess);

#endif
