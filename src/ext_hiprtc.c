/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_hip.h"
#include "ext_hiprtc.h"
#include "shared.h"

#include "dynloader.h"

char* hiprtcDllPath(char* hipSDKPath)
{
  /*
      AMD HIP RTC DLLs is stored at "C:\Program Files\ROCm\X.Y\bin\hiprtc0X0Y.dll"

      This function can return complete dll path based on major release version
      X.Y parsed from the ENV variable HIP_PATH.
  */

  const char *marker = "\\ROCm\\";

  int major = 0;
  int minor = 0;

  const char *version_start = strstr (hipSDKPath, marker);

  if (version_start == NULL) return NULL;

  version_start += strlen (marker); // now points at "6.2\\"

  if (sscanf (version_start, "%d.%d", &major, &minor) != 2) return NULL;

  char *hiprtcdllpath = NULL;

  hc_asprintf (&hiprtcdllpath, "%s\\bin\\hiprtc%02d%02d.dll", hipSDKPath, major, minor);

  return (hiprtcdllpath);
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

  // HIPRTC is paired with the HIP runtime. If HIP selected the Hygon DTK legacy
  // ABI, HIPRTC comes from the same DTK installation and needs the same
  // never-unload behaviour on close.
  if (backend_ctx->hip != NULL)
  {
    hiprtc->is_dtk = ((HIP_PTR *) backend_ctx->hip)->is_dtk;
  }

  #if   defined (_WIN)
  // hiprtc0702.dll for 7.2, the same numbering as the runtime library beside it. The name is read off
  // the disk rather than built, and the digit test in the helper is what keeps hiprtc-builtins from
  // being mistaken for it.

  char hip_bin[MAX_PATH];

  const char *hipSDKPath = getenv ("HIP_PATH");

  const char *dirs[1] = { NULL };

  if (hipSDKPath)
  {
    const size_t len = strlen (hipSDKPath);

    const char *sep = ((len > 0) && (hipSDKPath[len - 1] == '\\')) ? "" : "\\";

    snprintf (hip_bin, sizeof (hip_bin), "%s%sbin", hipSDKPath, sep);

    dirs[0] = hip_bin;
  }

  hiprtc->lib = hc_dynlib_open_newest_dll ("hiprtc", dirs, 1, NULL, 0);

  if (hiprtc->lib == NULL)
  {
    hiprtc->lib = hc_dlopen ("hiprtc.dll");
  }

  #elif defined (__APPLE__)
  hiprtc->lib = hc_dlopen ("fixme.dylib");
  #elif defined (__CYGWIN__)
  char *hipSDKPath = getenv ("HIP_PATH");

  if (hipSDKPath == NULL) return -1;

  char *hiprtcdllpath = hiprtcDllPath (hipSDKPath);

  if (hiprtcdllpath == NULL) return -1;

  hiprtc->lib = hc_dlopen (hiprtcdllpath);

  free (hiprtcdllpath);
  #else
  // Same as the runtime library: the versioned names are read off the disk and the newest wins,
  // because the unversioned link only comes with the development package.

  hiprtc->lib = hc_dynlib_open_newest ("libhiprtc", NULL, 0);
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
      // See hip_close(): DTK registers C++ exit handlers that call back into the
      // HIPRTC DSO, so closing it would crash the process during exit.
      if (hiprtc->is_dtk == false)
      {
        hc_dlclose (hiprtc->lib);
      }
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
