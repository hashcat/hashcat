/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_hiprtc.h"

#include "dynloader.h"


char* hiprtcDllPath(char* hipSDKPath)
{
  /*
      AMD HIP RTC DLLs is stored at "C:\Program Files\ROCm\X.Y\bin\hiprtc0X0Y.dll"
      Tried using regex to simplify, but had compilation issues on mingw64 (linker
      had troubles with pcre.h)

      This function can return complete dll path based on major release version
      X.Y parsed from the ENV variable HIP_PATH.
  */

    // Identifying major release version X.Y
    char* majorVersion = malloc(strlen("X.Y")+1);
    memcpy(majorVersion, hipSDKPath + (strlen(hipSDKPath) - 4), 3);
    memcpy(majorVersion+0x3, "\0", 1);

    // Preparing DLL name "hiprtc0X0Y.dll"
    char* hiprtcDllName = malloc(strlen("hiprtcXXXX.dll")+1);
    memcpy(hiprtcDllName, "hiprtc0", strlen("hiprtc0"));
 
    memcpy(hiprtcDllName + 0x7, majorVersion, 1);
    memcpy(hiprtcDllName + 0x8, "0", 1);
    memcpy(hiprtcDllName + 0x9, majorVersion + 2, 1);
    memcpy(hiprtcDllName + 0xa, ".dll\0", 5);

    // Preparing complete path as "C:\Program Files\ROCm\X.Y\bin\hiprtc0X0Y.dll" to 
    // return to the caller.
    char* hiprtcDllPath = malloc(strlen(hipSDKPath) + strlen("bin/") + strlen("hiprtcXXXX.dll") + 1);
    strcpy(hiprtcDllPath, hipSDKPath);
    strcat(hiprtcDllPath, "bin\\");
    strcat(hiprtcDllPath, hiprtcDllName);
    return(hiprtcDllPath);   
}


int hiprtc_make_options_array_from_string (char *string, char **options)
{
  char *saveptr = NULL;

  char *next = strtok_r (string, " ", &saveptr);

  int cnt = 0;

  do
  {
    options[cnt] = next;

    cnt++;

  } while ((next = strtok_r ((char *) NULL, " ", &saveptr)) != NULL);

  return cnt;
}

int hiprtc_init (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  memset (hiprtc, 0, sizeof (HIPRTC_PTR));

  #if   defined (_WIN)
  hiprtc->lib = hc_dlopen ("hiprtc.dll");

  // Check for HIP SDK installation from ENV
  const char* hipSDKPath = getenv("HIP_PATH");
  if (hipSDKPath != NULL && hiprtc->lib == NULL) 
  {
    hiprtc->lib = hc_dlopen (hiprtcDllPath(hipSDKPath));
  }
  if (hiprtc->lib == NULL) hiprtc->lib = hc_dlopen ("amdhip64.dll");
  #elif defined (__APPLE__)
  hiprtc->lib = hc_dlopen ("fixme.dylib");
  #elif defined (__CYGWIN__)
  hiprtc->lib = hc_dlopen ("hiprtc.dll");
  // Check for HIP SDK installation from ENV
  const char* hipSDKPath = getenv("HIP_PATH");
  if (hipSDKPath != NULL && hiprtc->lib == NULL) 
  {
    hiprtc->lib = hc_dlopen (hiprtcDllPath(hipSDKPath));
  }
  if (hiprtc->lib == NULL) hiprtc->lib = hc_dlopen ("amdhip64.dll");
  #else
  hiprtc->lib = hc_dlopen ("libhiprtc.so");
  #endif

  if (hiprtc->lib == NULL) return -1;

  HC_LOAD_FUNC (hiprtc, hiprtcCompileProgram,     HIPRTC_HIPRTCCOMPILEPROGRAM,    HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcCreateProgram,      HIPRTC_HIPRTCCREATEPROGRAM,     HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcDestroyProgram,     HIPRTC_HIPRTCDESTROYPROGRAM,    HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcGetCode,            HIPRTC_HIPRTCGETCODE,           HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcGetCodeSize,        HIPRTC_HIPRTCGETCODESIZE,       HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcGetProgramLog,      HIPRTC_HIPRTCGETPROGRAMLOG,     HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcGetProgramLogSize,  HIPRTC_HIPRTCGETPROGRAMLOGSIZE, HIPRTC, 1);
  HC_LOAD_FUNC (hiprtc, hiprtcGetErrorString,     HIPRTC_HIPRTCGETERRORSTRING,    HIPRTC, 1);

  return 0;
}

void hiprtc_close (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  if (hiprtc)
  {
    if (hiprtc->lib)
    {
      hc_dlclose (hiprtc->lib);
    }

    hcfree (backend_ctx->hiprtc);

    backend_ctx->hiprtc = NULL;
  }
}

int hc_hiprtcCreateProgram (void *hashcat_ctx, hiprtcProgram *prog, const char *src, const char *name, int numHeaders, const char * const *headers, const char * const *includeNames)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcCreateProgram (prog, src, name, numHeaders, headers, includeNames);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcCreateProgram(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcDestroyProgram (void *hashcat_ctx, hiprtcProgram *prog)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcDestroyProgram (prog);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcDestroyProgram(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcCompileProgram (void *hashcat_ctx, hiprtcProgram prog, int numOptions, const char * const *options)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcCompileProgram (prog, numOptions, options);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcCompileProgram(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcGetProgramLogSize (void *hashcat_ctx, hiprtcProgram prog, size_t *logSizeRet)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcGetProgramLogSize (prog, logSizeRet);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcGetProgramLogSize(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcGetProgramLog (void *hashcat_ctx, hiprtcProgram prog, char *log)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcGetProgramLog (prog, log);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcGetProgramLog(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcGetCodeSize (void *hashcat_ctx, hiprtcProgram prog, size_t *codeSizeRet)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcGetCodeSize (prog, codeSizeRet);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcGetCodeSize(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}

int hc_hiprtcGetCode (void *hashcat_ctx, hiprtcProgram prog, char *code)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) backend_ctx->hiprtc;

  const hiprtcResult HIPRTC_err = hiprtc->hiprtcGetCode (prog, code);

  if (HIPRTC_err != HIPRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "hiprtcGetCode(): %s", hiprtc->hiprtcGetErrorString (HIPRTC_err));

    return -1;
  }

  return 0;
}
