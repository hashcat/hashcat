/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_NVRTC_H
#define _EXT_NVRTC_H

/**
 * from cuda.h (/usr/local/cuda-10.1/targets/x86_64-linux/include/nvrtc.h)
 */

/**
 * \ingroup error
 * \brief   The enumerated type nvrtcResult defines API call result codes.
 *          NVRTC API functions return nvrtcResult to indicate the call
 *          result.
 */
typedef enum {
  NVRTC_SUCCESS = 0,
  NVRTC_ERROR_OUT_OF_MEMORY = 1,
  NVRTC_ERROR_PROGRAM_CREATION_FAILURE = 2,
  NVRTC_ERROR_INVALID_INPUT = 3,
  NVRTC_ERROR_INVALID_PROGRAM = 4,
  NVRTC_ERROR_INVALID_OPTION = 5,
  NVRTC_ERROR_COMPILATION = 6,
  NVRTC_ERROR_BUILTIN_OPERATION_FAILURE = 7,
  NVRTC_ERROR_NO_NAME_EXPRESSIONS_AFTER_COMPILATION = 8,
  NVRTC_ERROR_NO_LOWERED_NAMES_BEFORE_COMPILATION = 9,
  NVRTC_ERROR_NAME_EXPRESSION_NOT_VALID = 10,
  NVRTC_ERROR_INTERNAL_ERROR = 11
} nvrtcResult;

/**
 * \ingroup compilation
 * \brief   nvrtcProgram is the unit of compilation, and an opaque handle for
 *          a program.
 *
 * To compile a CUDA program string, an instance of nvrtcProgram must be
 * created first with ::nvrtcCreateProgram, then compiled with
 * ::nvrtcCompileProgram.
 */
typedef struct _nvrtcProgram *nvrtcProgram;

#ifdef _WIN32
#define NVRTCAPI __stdcall
#else
#define NVRTCAPI
#endif

#define NVRTC_API_CALL NVRTCAPI

typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCADDNAMEEXPRESSION)  (nvrtcProgram, const char * const);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCCOMPILEPROGRAM)     (nvrtcProgram, int, const char * const *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCCREATEPROGRAM)      (nvrtcProgram *, const char *, const char *, int, const char * const *, const char * const *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCDESTROYPROGRAM)     (nvrtcProgram *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCGETLOWEREDNAME)     (nvrtcProgram, const char * const, const char **);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCGETPTX)             (nvrtcProgram, char *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCGETPTXSIZE)         (nvrtcProgram, size_t *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCGETPROGRAMLOG)      (nvrtcProgram, char *);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCGETPROGRAMLOGSIZE)  (nvrtcProgram, size_t *);
typedef const char * (NVRTC_API_CALL *NVRTC_NVRTCGETERRORSTRING)     (nvrtcResult);
typedef nvrtcResult  (NVRTC_API_CALL *NVRTC_NVRTCVERSION)            (int *, int *);

typedef struct hc_nvrtc_lib
{
  hc_dynlib_t lib;

  NVRTC_NVRTCADDNAMEEXPRESSION  nvrtcAddNameExpression;
  NVRTC_NVRTCCOMPILEPROGRAM     nvrtcCompileProgram;
  NVRTC_NVRTCCREATEPROGRAM      nvrtcCreateProgram;
  NVRTC_NVRTCDESTROYPROGRAM     nvrtcDestroyProgram;
  NVRTC_NVRTCGETLOWEREDNAME     nvrtcGetLoweredName;
  NVRTC_NVRTCGETPTX             nvrtcGetPTX;
  NVRTC_NVRTCGETPTXSIZE         nvrtcGetPTXSize;
  NVRTC_NVRTCGETPROGRAMLOG      nvrtcGetProgramLog;
  NVRTC_NVRTCGETPROGRAMLOGSIZE  nvrtcGetProgramLogSize;
  NVRTC_NVRTCGETERRORSTRING     nvrtcGetErrorString;
  NVRTC_NVRTCVERSION            nvrtcVersion;

} hc_nvrtc_lib_t;

typedef hc_nvrtc_lib_t NVRTC_PTR;

int nvrtc_make_options_array_from_string (char *string, char **options);

#endif // _EXT_NVRTC_H
