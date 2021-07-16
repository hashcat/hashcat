/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_HIPRTC_H
#define _EXT_HIPRTC_H

/**
 * from hip_runtime.h (/opt/rocm/hip/include/hip/amd_detail/hiprtc.h)
 */

/**
 * \ingroup error
 * \brief   The enumerated type hiprtcResult defines API call result codes.
 *          HIPRTC API functions return hiprtcResult to indicate the call
 *          result.
 */
typedef enum {
  HIPRTC_SUCCESS = 0,
  HIPRTC_ERROR_OUT_OF_MEMORY = 1,
  HIPRTC_ERROR_PROGRAM_CREATION_FAILURE = 2,
  HIPRTC_ERROR_INVALID_INPUT = 3,
  HIPRTC_ERROR_INVALID_PROGRAM = 4,
  HIPRTC_ERROR_INVALID_OPTION = 5,
  HIPRTC_ERROR_COMPILATION = 6,
  HIPRTC_ERROR_BUILTIN_OPERATION_FAILURE = 7,
  HIPRTC_ERROR_NO_NAME_EXPRESSIONS_AFTER_COMPILATION = 8,
  HIPRTC_ERROR_NO_LOWERED_NAMES_BEFORE_COMPILATION = 9,
  HIPRTC_ERROR_NAME_EXPRESSION_NOT_VALID = 10,
  HIPRTC_ERROR_INTERNAL_ERROR = 11
} hiprtcResult;

/**
 * \ingroup compilation
 * \brief   hiprtcProgram is the unit of compilation, and an opaque handle for
 *          a program.
 *
 * To compile a CUDA program string, an instance of hiprtcProgram must be
 * created first with ::hiprtcCreateProgram, then compiled with
 * ::hiprtcCompileProgram.
 */
typedef struct _hiprtcProgram *hiprtcProgram;

#ifdef _WIN32
#define HIPRTCAPI __stdcall
#else
#define HIPRTCAPI
#endif

#define HIPRTC_API_CALL HIPRTCAPI

typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCADDNAMEEXPRESSION)  (hiprtcProgram, const char * const);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCCOMPILEPROGRAM)     (hiprtcProgram, int, const char * const *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCCREATEPROGRAM)      (hiprtcProgram *, const char *, const char *, int, const char * const *, const char * const *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCDESTROYPROGRAM)     (hiprtcProgram *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCGETLOWEREDNAME)     (hiprtcProgram, const char * const, const char **);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCGETPTX)             (hiprtcProgram, char *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCGETPTXSIZE)         (hiprtcProgram, size_t *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCGETPROGRAMLOG)      (hiprtcProgram, char *);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCGETPROGRAMLOGSIZE)  (hiprtcProgram, size_t *);
typedef const char * (HIPRTC_API_CALL *HIPRTC_HIPRTCGETERRORSTRING)      (hiprtcResult);
typedef hiprtcResult  (HIPRTC_API_CALL *HIPRTC_HIPRTCVERSION)            (int *, int *);

typedef struct hc_hiprtc_lib
{
  hc_dynlib_t lib;

  HIPRTC_HIPRTCADDNAMEEXPRESSION  hiprtcAddNameExpression;
  HIPRTC_HIPRTCCOMPILEPROGRAM     hiprtcCompileProgram;
  HIPRTC_HIPRTCCREATEPROGRAM      hiprtcCreateProgram;
  HIPRTC_HIPRTCDESTROYPROGRAM     hiprtcDestroyProgram;
  HIPRTC_HIPRTCGETLOWEREDNAME     hiprtcGetLoweredName;
  HIPRTC_HIPRTCGETPTX             hiprtcGetCode;
  HIPRTC_HIPRTCGETPTXSIZE         hiprtcGetCodeSize;
  HIPRTC_HIPRTCGETPROGRAMLOG      hiprtcGetProgramLog;
  HIPRTC_HIPRTCGETPROGRAMLOGSIZE  hiprtcGetProgramLogSize;
  HIPRTC_HIPRTCGETERRORSTRING     hiprtcGetErrorString;
  HIPRTC_HIPRTCVERSION            hiprtcVersion;

} hc_hiprtc_lib_t;

typedef hc_hiprtc_lib_t HIPRTC_PTR;

int hiprtc_make_options_array_from_string (char *string, char **options);

#endif // _EXT_HIPRTC_H
