/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_nvrtc.h"

#include "dynloader.h"

int nvrtc_make_options_array_from_string (char *string, char **options)
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

// NVRTC

int nvrtc_init (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  memset (nvrtc, 0, sizeof (NVRTC_PTR));

  #if   defined (_WIN)
  nvrtc->lib = hc_dlopen ("nvrtc.dll");

  if (nvrtc->lib == NULL)
  {
    // NVIDIA puts the CUDA version in the file name, nvrtc64_130_0.dll for 13.0, and the version is
    // the toolkit's rather than the driver's, so nvcuda.dll cannot be asked what it is. The name used
    // to be guessed from two nested ranges, a few hundred LoadLibrary calls to arrive at a name that
    // was on disk all along. The toolkit directory is read instead, then whatever is on PATH.

    char cuda_bin[MAX_PATH];

    const char *cuda_path = getenv ("CUDA_PATH");

    const char *dirs[1] = { NULL };

    if (cuda_path)
    {
      snprintf (cuda_bin, sizeof (cuda_bin), "%s\\bin", cuda_path);

      dirs[0] = cuda_bin;
    }

    nvrtc->lib = hc_dynlib_open_newest_dll ("nvrtc64_", dirs, 1, NULL, 0);
  }
  #elif defined (__APPLE__)
  nvrtc->lib = hc_dlopen ("nvrtc.dylib");
  #elif defined (__CYGWIN__)
  nvrtc->lib = hc_dlopen ("nvrtc.dll");
  #else
  // libnvrtc.so is a link the development package ships and libnvrtc.so.1 has never existed, so a
  // machine carrying the runtime alone had neither. The versioned names are read off the disk
  // instead, and the newest CUDA present wins.

  nvrtc->lib = hc_dynlib_open_newest ("libnvrtc", NULL, 0);
  #endif

  if (nvrtc->lib == NULL) return -1;

  HC_LOAD_FUNC (nvrtc, nvrtcAddNameExpression,  NVRTC_NVRTCADDNAMEEXPRESSION, NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcCompileProgram,     NVRTC_NVRTCCOMPILEPROGRAM,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcCreateProgram,      NVRTC_NVRTCCREATEPROGRAM,     NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcDestroyProgram,     NVRTC_NVRTCDESTROYPROGRAM,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetLoweredName,     NVRTC_NVRTCGETLOWEREDNAME,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetPTX,             NVRTC_NVRTCGETPTX,            NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetPTXSize,         NVRTC_NVRTCGETPTXSIZE,        NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetProgramLog,      NVRTC_NVRTCGETPROGRAMLOG,     NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetProgramLogSize,  NVRTC_NVRTCGETPROGRAMLOGSIZE, NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetErrorString,     NVRTC_NVRTCGETERRORSTRING,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcVersion,            NVRTC_NVRTCVERSION,           NVRTC, 1);

  return 0;
}

void nvrtc_close (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  if (nvrtc)
  {
    if (nvrtc->lib)
    {
      hc_dlclose (nvrtc->lib);
    }

    hcfree (backend_ctx->nvrtc);

    backend_ctx->nvrtc = NULL;
  }
}

int hc_nvrtcCreateProgram (void *hashcat_ctx, nvrtcProgram *prog, const char *src, const char *name, int numHeaders, const char * const *headers, const char * const *includeNames)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcCreateProgram (prog, src, name, numHeaders, headers, includeNames);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcCreateProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcDestroyProgram (void *hashcat_ctx, nvrtcProgram *prog)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcDestroyProgram (prog);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcDestroyProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcCompileProgram (void *hashcat_ctx, nvrtcProgram prog, int numOptions, const char * const *options)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcCompileProgram (prog, numOptions, options);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcCompileProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetProgramLogSize (void *hashcat_ctx, nvrtcProgram prog, size_t *logSizeRet)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetProgramLogSize (prog, logSizeRet);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetProgramLogSize(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetProgramLog (void *hashcat_ctx, nvrtcProgram prog, char *log)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetProgramLog (prog, log);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetProgramLog(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetPTXSize (void *hashcat_ctx, nvrtcProgram prog, size_t *ptxSizeRet)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetPTXSize (prog, ptxSizeRet);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetPTXSize(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetPTX (void *hashcat_ctx, nvrtcProgram prog, char *ptx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetPTX (prog, ptx);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetPTX(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcVersion (void *hashcat_ctx, int *major, int *minor)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcVersion (major, minor);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcVersion(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}
