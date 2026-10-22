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

#if defined (_WIN)

// nvrtc loads nvrtc-builtins64_XYZ.dll by name when it first compiles, so Windows looks for it only
// along the DLL search order, and nvrtc's own directory is not on it. A toolkit found through
// CUDA_PATH rather than PATH then fails every build. Loading the builtins here by their full path
// settles it, because a DLL that is already loaded is reused by name. XYZ is the toolkit version,
// 133 for 13.3, so the name is built from the version of the nvrtc that was loaded, and a
// directory holding builtins of another toolkit as well cannot hand over the wrong one.

static hc_dynlib_t nvrtc_open_builtins (const hc_dynlib_t lib, const int major, const int minor)
{
  char dir[MAX_PATH];

  const DWORD len = GetModuleFileNameA (lib, dir, sizeof (dir));

  if (len == 0) return NULL;
  if (len >= sizeof (dir)) return NULL;

  bool cut = false;

  for (DWORD i = len; i > 0; i--)
  {
    if (dir[i - 1] != '\\') continue;

    dir[i - 1] = 0;

    cut = true;

    break;
  }

  if (cut == false) return NULL;

  char path[MAX_PATH];

  const int path_len = snprintf (path, sizeof (path), "%s\\nvrtc-builtins64_%d%d.dll", dir, major, minor);

  if (path_len < 0) return NULL;
  if ((size_t) path_len >= sizeof (path)) return NULL;

  const hc_dynlib_t builtins = hc_dlopen (path);

  return builtins;
}

#endif

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
    // CUDA 13 moved its DLLs from bin to bin\x64, so both are read.

    char cuda_bin_x64[MAX_PATH];
    char cuda_bin[MAX_PATH];

    const char *cuda_path = getenv ("CUDA_PATH");

    const char *dirs[2] = { NULL, NULL };

    if (cuda_path)
    {
      const size_t len = strlen (cuda_path);

      const char *sep = ((len > 0) && (cuda_path[len - 1] == '\\')) ? "" : "\\";

      snprintf (cuda_bin_x64, sizeof (cuda_bin_x64), "%s%sbin\\x64", cuda_path, sep);
      snprintf (cuda_bin,     sizeof (cuda_bin),     "%s%sbin",      cuda_path, sep);

      dirs[0] = cuda_bin_x64;
      dirs[1] = cuda_bin;
    }

    nvrtc->lib = hc_dynlib_open_newest_dll_tie ("nvrtc64_", "nvrtc-builtins64_", dirs, 2, NULL, 0);
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

  #if defined (_WIN)
  int major = 0;
  int minor = 0;

  if (nvrtc->nvrtcVersion (&major, &minor) == NVRTC_SUCCESS) nvrtc->lib_builtins = nvrtc_open_builtins (nvrtc->lib, major, minor);
  #endif

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

    if (nvrtc->lib_builtins)
    {
      hc_dlclose (nvrtc->lib_builtins);
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
