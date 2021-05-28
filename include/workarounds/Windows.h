/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _WINDOWS_H
#define _WINDOWS_H

// This is a workaround for files asking to include Windows.h instead of windows.h
// The problem is that MinGW provides only windows.h
// LZMA SDK will fail to cross compile for Windows on Linux

#include <windows.h>

#endif // _WINDOWS_H
