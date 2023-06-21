#include "rar.hpp"

#ifdef _WIN_ALL
DWORD WinNT()
{
  static int dwPlatformId=-1;
  static DWORD dwMajorVersion,dwMinorVersion;
  if (dwPlatformId==-1)
  {
    OSVERSIONINFO WinVer;
    WinVer.dwOSVersionInfoSize=sizeof(WinVer);
    GetVersionEx(&WinVer);
    dwPlatformId=WinVer.dwPlatformId;
    dwMajorVersion=WinVer.dwMajorVersion;
    dwMinorVersion=WinVer.dwMinorVersion;

  }
  DWORD Result=0;
  if (dwPlatformId==VER_PLATFORM_WIN32_NT)
    Result=dwMajorVersion*0x100+dwMinorVersion;


  return Result;
}


// Replace it with documented Windows 11 check when available.
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

static bool WMI_IsWindows10()
{
  IWbemLocator *pLoc = NULL;

  HRESULT hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator,(LPVOID *)&pLoc);
 
  if (FAILED(hres))
    return false;

  IWbemServices *pSvc = NULL;

  BSTR bstr_root_cimv2 = SysAllocString(L"ROOT\\CIMV2");

  hres = pLoc->ConnectServer(bstr_root_cimv2,NULL,NULL,NULL,0,0,0,&pSvc);
    
  if (FAILED(hres))
  {
    pLoc->Release();     
    return false;
  }

  hres = CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,
         RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);

  if (FAILED(hres))
  {
    pSvc->Release();
    pLoc->Release();     
    return false;
  }

  IEnumWbemClassObject *pEnumerator = NULL;

  BSTR bstr_wql = SysAllocString(L"WQL");
  BSTR bstr_sql = SysAllocString(L"SELECT * FROM Win32_OperatingSystem");

  hres = pSvc->ExecQuery(bstr_wql, bstr_sql,
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    
  if (FAILED(hres))
  {
    pSvc->Release();
    pLoc->Release();
    return false;
  }

  IWbemClassObject *pclsObj = NULL;
  ULONG uReturn = 0;
   
  bool Win10=false;
  while (pEnumerator!=NULL)
  {
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

    if (uReturn==0)
      break;

    VARIANT vtProp;

    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
    Win10|=wcsstr(vtProp.bstrVal,L"Windows 10")!=NULL;
    VariantClear(&vtProp);

    pclsObj->Release();
  }

  pSvc->Release();
  pLoc->Release();
  pEnumerator->Release();

  return Win10;
}


// Replace it with actual check when available.
bool IsWindows11OrGreater()
{
  static bool IsSet=false,IsWin11=false;
  if (!IsSet)
  {
    OSVERSIONINFO WinVer;
    WinVer.dwOSVersionInfoSize=sizeof(WinVer);
    GetVersionEx(&WinVer);
    IsWin11=WinVer.dwMajorVersion>10 || 
          WinVer.dwMajorVersion==10 && WinVer.dwBuildNumber >= 22000 && !WMI_IsWindows10();
    IsSet=true;
  }
  return IsWin11;
}

#endif // _WIN_ALL
