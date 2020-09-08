#ifndef _RAR_TIMEFN_
#define _RAR_TIMEFN_

struct RarLocalTime
{
  uint Year;
  uint Month;
  uint Day;
  uint Hour;
  uint Minute;
  uint Second;
  uint Reminder; // Part of time smaller than 1 second, represented in 1/REMINDER_PRECISION intervals.
  uint wDay;
  uint yDay;
};


class RarTime
{
  private:
    static const uint TICKS_PER_SECOND = 1000000000; // Internal precision.

    // Internal time representation in 1/TICKS_PER_SECOND since 01.01.1601.
    // We use nanoseconds here to handle the high precision Unix time.
    uint64 itime;
  public:
    // RarLocalTime::Reminder precision. Must be equal to TICKS_PER_SECOND.
    // Unlike TICKS_PER_SECOND, it is a public field.
    static const uint REMINDER_PRECISION = TICKS_PER_SECOND;
  public:
    RarTime() {Reset();}
    bool operator == (RarTime &rt) {return itime==rt.itime;}
    bool operator != (RarTime &rt) {return itime!=rt.itime;}
    bool operator < (RarTime &rt)  {return itime<rt.itime;}
    bool operator <= (RarTime &rt) {return itime<rt.itime || itime==rt.itime;}
    bool operator > (RarTime &rt)  {return itime>rt.itime;}
    bool operator >= (RarTime &rt) {return itime>rt.itime || itime==rt.itime;}

    void GetLocal(RarLocalTime *lt);
    void SetLocal(RarLocalTime *lt);
#ifdef _WIN_ALL
    void GetWinFT(FILETIME *ft);
    void SetWinFT(FILETIME *ft);
#endif
    uint64 GetWin();
    void SetWin(uint64 WinTime);
    time_t GetUnix();
    void SetUnix(time_t ut);
    uint64 GetUnixNS();
    void SetUnixNS(uint64 ns);
    uint GetDos();
    void SetDos(uint DosTime);
    void GetText(wchar *DateStr,size_t MaxSize,bool FullMS);
    void SetIsoText(const wchar *TimeText);
    void SetAgeText(const wchar *TimeText);
    void SetCurrentTime();
    void Reset() {itime=0;}
    bool IsSet() {return itime!=0;}
    void Adjust(int64 ns);
};

const wchar *GetMonthName(int Month);
bool IsLeapYear(int Year);

#endif
