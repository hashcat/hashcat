#ifndef _RAR_RAROS_
#define _RAR_RAROS_

#ifdef __EMX__
  #define _EMX
#endif

#ifdef __DJGPP__
  #define _DJGPP
  #define _EMX
#endif

#if defined(__WIN32__) || defined(_WIN32)
  #define _WIN_ALL // Defined for all Windows platforms, 32 and 64 bit, mobile and desktop.
  #ifdef _M_X64
    #define _WIN_64
  #else
    #define _WIN_32
  #endif
#endif

#if defined(ANDROID) || defined(__ANDROID__)
  #define _UNIX
  #define _ANDROID
#endif

#ifdef __APPLE__
  #define _UNIX
  #define _APPLE
#endif

#if !defined(_EMX) && !defined(_WIN_ALL) && !defined(_BEOS) && !defined(_APPLE)
  #define _UNIX
#endif

#endif
