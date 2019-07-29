/* DllSecur.h -- DLL loading for security
2018-02-19 : Igor Pavlov : Public domain */

#ifndef __DLL_SECUR_H
#define __DLL_SECUR_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#ifdef _WIN32

void My_SetDefaultDllDirectories();
void LoadSecurityDlls();

#endif

EXTERN_C_END

#endif
