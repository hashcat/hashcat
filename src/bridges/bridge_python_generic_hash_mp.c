/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "cpu_features.h"
#include "dynloader.h"

#if defined (_WIN)
#include "processenv.h"
#endif

// python interpreter

#define PY_SSIZE_T_CLEAN

#undef _GNU_SOURCE
#include <Python.h>

#define PYTHON_API_CALL

typedef void                (PYTHON_API_CALL *PY_INITIALIZE)                    ();
typedef void                (PYTHON_API_CALL *PY_FINALIZE)                      ();
typedef void                (PYTHON_API_CALL *PY_DECREF)                        (PyObject *);
typedef PyObject           *(PYTHON_API_CALL *PYBOOL_FROMLONG)                  (long);
typedef PyObject           *(PYTHON_API_CALL *PYBYTES_FROMSTRINGANDSIZE)        (const char *, Py_ssize_t);
typedef int                 (PYTHON_API_CALL *PYDICT_DELITEMSTRING)             (PyObject *, const char *);
typedef PyObject           *(PYTHON_API_CALL *PYDICT_GETITEMSTRING)             (PyObject *, const char *);
typedef PyObject           *(PYTHON_API_CALL *PYDICT_NEW)                       ();
typedef int                 (PYTHON_API_CALL *PYDICT_SETITEMSTRING)             (PyObject *, const char *, PyObject *);
typedef void                (PYTHON_API_CALL *PYERR_PRINT)                      ();
typedef PyObject           *(PYTHON_API_CALL *PYIMPORT_IMPORTMODULE)            (const char *);
typedef PyObject           *(PYTHON_API_CALL *PYIMPORT_IMPORT)                  (PyObject *);
typedef int                 (PYTHON_API_CALL *PYLIST_APPEND)                    (PyObject *, PyObject *);
typedef PyObject           *(PYTHON_API_CALL *PYLIST_GETITEM)                   (PyObject *, Py_ssize_t);
typedef PyObject           *(PYTHON_API_CALL *PYLIST_NEW)                       (Py_ssize_t);
typedef int                 (PYTHON_API_CALL *PYLIST_SETITEM)                   (PyObject *, Py_ssize_t, PyObject *);
typedef Py_ssize_t          (PYTHON_API_CALL *PYLIST_SIZE)                      (PyObject *);
typedef PyObject           *(PYTHON_API_CALL *PYLONG_FROMLONG)                  (long);
typedef PyObject           *(PYTHON_API_CALL *PYOBJECT_CALLOBJECT)              (PyObject *, PyObject *);
typedef PyObject           *(PYTHON_API_CALL *PYOBJECT_GETATTRSTRING)           (PyObject *, const char *);
typedef PyObject           *(PYTHON_API_CALL *PYTUPLE_NEW)                      (Py_ssize_t);
typedef int                 (PYTHON_API_CALL *PYTUPLE_SETITEM)                  (PyObject *, Py_ssize_t, PyObject *);
typedef const char         *(PYTHON_API_CALL *PYUNICODE_ASUTF8)                 (PyObject *);
typedef const char         *(PYTHON_API_CALL *PYUNICODE_ASUTF8ANDSIZE)          (PyObject *, Py_ssize_t *);
typedef PyObject           *(PYTHON_API_CALL *PYUNICODE_DECODEFSDEFAULTANDSIZE) (const char *, Py_ssize_t);
typedef PyObject           *(PYTHON_API_CALL *PYUNICODE_DECODEFSDEFAULT)        (const char *);
typedef PyObject           *(PYTHON_API_CALL *PYUNICODE_FROMSTRINGANDSIZE)      (const char *, Py_ssize_t);
typedef PyObject           *(PYTHON_API_CALL *PYUNICODE_FROMSTRING)             (const char *);
typedef void                (PYTHON_API_CALL *PYEVAL_ACQUIRELOCK)               (void);
typedef void                (PYTHON_API_CALL *PYEVAL_RELEASELOCK)               (void);
typedef PyThreadState      *(PYTHON_API_CALL *PYTHREADSTATE_SWAP)               (PyThreadState *);
typedef PyThreadState      *(PYTHON_API_CALL *PYNEWINTERPRETER)                 (void);
typedef void                (PYTHON_API_CALL *PYENDINTERPRETER)                 (PyThreadState *);
typedef PyGILState_STATE    (PYTHON_API_CALL *PYGILSTATE_ENSURE)                (void);
typedef void                (PYTHON_API_CALL *PYGILSTATE_RELEASE)               (PyGILState_STATE);
typedef void                (PYTHON_API_CALL *PYEVAL_ACQUIRETHREAD)             (PyThreadState *);
typedef void                (PYTHON_API_CALL *PYEVAL_RELEASETHREAD)             (PyThreadState *);
typedef void                (PYTHON_API_CALL *PYTHREADSTATE_CLEAR)              (PyThreadState *);
typedef void                (PYTHON_API_CALL *PYTHREADSTATE_DELETE)             (PyThreadState *);
typedef PyThreadState      *(PYTHON_API_CALL *PYTHREADSTATE_NEW)                (PyInterpreterState *);
typedef PyInterpreterState *(PYTHON_API_CALL *PYINTERPRETERSTATE_MAIN)          (void);
typedef void                (PYTHON_API_CALL *PYEVAL_INITTHREADS)               (void);
typedef PyThreadState      *(PYTHON_API_CALL *PYEVAL_SAVETHREAD)                (void);
//typedef PyStatus            (PYTHON_API_CALL *PYNEWINTERPRETERFROMCONFIG)       (PyThreadState **, const PyInterpreterConfig *);
typedef void                (PYTHON_API_CALL *PYEXITSTATUSEXCEPTION)            (PyStatus);
typedef PyStatus            (PYTHON_API_CALL *PYINITIALIZEFROMCONFIG)           (const PyConfig *);
typedef void                (PYTHON_API_CALL *PYEVAL_RESTORETHREAD)             (PyThreadState *);
typedef const char         *(PYTHON_API_CALL *PYGETVERSION)                     (void);

typedef struct hc_python_lib
{
  hc_dynlib_t lib;

  PY_INITIALIZE                     Py_Initialize;
  PY_FINALIZE                       Py_Finalize;
  PY_DECREF                         Py_DecRef;
  PYBOOL_FROMLONG                   PyBool_FromLong;
  PYBYTES_FROMSTRINGANDSIZE         PyBytes_FromStringAndSize;
  PYDICT_DELITEMSTRING              PyDict_DelItemString;
  PYDICT_GETITEMSTRING              PyDict_GetItemString;
  PYDICT_NEW                        PyDict_New;
  PYDICT_SETITEMSTRING              PyDict_SetItemString;
  PYERR_PRINT                       PyErr_Print;
  PYIMPORT_IMPORTMODULE             PyImport_ImportModule;
  PYIMPORT_IMPORT                   PyImport_Import;
  PYLIST_APPEND                     PyList_Append;
  PYLIST_GETITEM                    PyList_GetItem;
  PYLIST_NEW                        PyList_New;
  PYLIST_SETITEM                    PyList_SetItem;
  PYLIST_SIZE                       PyList_Size;
  PYLONG_FROMLONG                   PyLong_FromLong;
  PYOBJECT_CALLOBJECT               PyObject_CallObject;
  PYOBJECT_GETATTRSTRING            PyObject_GetAttrString;
  PYTUPLE_NEW                       PyTuple_New;
  PYTUPLE_SETITEM                   PyTuple_SetItem;
  PYUNICODE_ASUTF8                  PyUnicode_AsUTF8;
  PYUNICODE_ASUTF8ANDSIZE           PyUnicode_AsUTF8AndSize;
  PYUNICODE_DECODEFSDEFAULTANDSIZE  PyUnicode_DecodeFSDefaultAndSize;
  PYUNICODE_DECODEFSDEFAULT         PyUnicode_DecodeFSDefault;
  PYUNICODE_FROMSTRINGANDSIZE       PyUnicode_FromStringAndSize;
  PYUNICODE_FROMSTRING              PyUnicode_FromString;
  PYEVAL_ACQUIRELOCK                PyEval_AcquireLock;
  PYEVAL_RELEASELOCK                PyEval_ReleaseLock;
  PYTHREADSTATE_SWAP                PyThreadState_Swap;
  PYNEWINTERPRETER                  Py_NewInterpreter;
  PYENDINTERPRETER                  Py_EndInterpreter;
  PYGILSTATE_ENSURE                 PyGILState_Ensure;
  PYGILSTATE_RELEASE                PyGILState_Release;
  PYEVAL_ACQUIRETHREAD              PyEval_AcquireThread;
  PYEVAL_RELEASETHREAD              PyEval_ReleaseThread;
  PYTHREADSTATE_CLEAR               PyThreadState_Clear;
  PYTHREADSTATE_DELETE              PyThreadState_Delete;
  PYTHREADSTATE_NEW                 PyThreadState_New;
  PYINTERPRETERSTATE_MAIN           PyInterpreterState_Main;
  PYEVAL_INITTHREADS                PyEval_InitThreads;
  PYEVAL_SAVETHREAD                 PyEval_SaveThread;
  //PYNEWINTERPRETERFROMCONFIG        Py_NewInterpreterFromConfig;
  PYEXITSTATUSEXCEPTION             Py_ExitStatusException;
  PYINITIALIZEFROMCONFIG            Py_InitializeFromConfig;
  PYEVAL_RESTORETHREAD              PyEval_RestoreThread;
  PYGETVERSION                      Py_GetVersion;

} hc_python_lib_t;

// good: we can use this multiplier do reduce copy overhead to increase the guessing speed,
// bad: but we also increase the password candidate batch size.
// slow hashes which make use of this bridge probably are used with smaller wordlists,
// and therefore it's easier for hashcat to parallelize if this multiplier is low.
// in the end, it's a trade-off.

#define N_ACCEL 8

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_buf[64];
  u32 out_len;

} generic_io_tmp_t;

typedef struct
{
  // template

  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  size_t  workitem_size;

  // implementation specific

  int     parallelism;

  PyGILState_STATE gstate;

  PyObject *pArgs;
  PyObject *pContext;
  PyObject *pModule;
  PyObject *pFunc_Init;
  PyObject *pFunc_Term;
  PyObject *pFunc_kernel_loop;

} unit_t;

typedef struct
{
  unit_t *units_buf;
  int     units_cnt;

  hc_python_lib_t *python;

  PyThreadState *tstate;

  char *source_filename;

} python_interpreter_t;

#if defined (_WIN) || defined (__CYGWIN__) || defined (__APPLE__)
static char *DEFAULT_SOURCE_FILENAME = "generic_hash_sp";
#else
static char *DEFAULT_SOURCE_FILENAME = "generic_hash_mp";
#endif

#if defined (_WIN)
#define DEVNULL "NUL"
#else
#define DEVNULL "/dev/null"
#endif

static int suppress_stderr (void)
{
  int null_fd = open (DEVNULL, O_WRONLY);

  if (null_fd < 0) return -1;

  int saved_fd = dup (fileno (stderr));

  if (saved_fd < 0)
  {
    close (null_fd);

    return -1;
  }

  dup2 (null_fd, fileno (stderr));

  close (null_fd);

  return saved_fd;
}

static void restore_stderr (int saved_fd)
{
  if (saved_fd < 0) return;

  dup2 (saved_fd, fileno (stderr));

  close (saved_fd);
}

static char *expand_pyenv_libpath (const char *prefix, const int maj, const int min)
{
  char *out = NULL;

  #if defined (_WIN)
  const int len = asprintf (&out, "%s/python%d%d.dll",           prefix, maj, min); //untested
  #elif defined (__MSYS__)
  const int len = asprintf (&out, "%s/msys-python%d.%d.dll",     prefix, maj, min); //untested could be wrong
  #elif defined (__APPLE__)
  const int len = asprintf (&out, "%s/lib/libpython%d.%d.dylib", prefix, maj, min); //untested
  #elif defined (__CYGWIN__)
  const int len = asprintf (&out, "%s/lib/python%d%d.dll",       prefix, maj, min); //untested
  #else
  const int len = asprintf (&out, "%s/lib/libpython%d.%d.so",    prefix, maj, min);
  #endif

  if (len == -1) return NULL;

  struct stat st;

  if (stat (out, &st) != 0)
  {
    free (out);

    return NULL;
  }

  return out;
}

static int resolve_pyenv_libpath (char *out_buf, const size_t out_sz)
{
  // prefix

  FILE *fp1 = popen ("pyenv prefix", "r");

  if (fp1 == NULL) return -1;

  char prefix_path[PATH_MAX];

  if (fgets (prefix_path, sizeof (prefix_path), fp1) == NULL)
  {
    pclose (fp1);

    return -1;
  }

  pclose (fp1);

  superchop_with_length (prefix_path, strlen (prefix_path));

  int maj = 0;
  int min = 0;

  // local

  FILE *fp2 = popen ("pyenv local", "r");

  if (fp2 == NULL) return -1;

  if (fscanf (fp2, "%d.%d", &maj, &min) == 2)
  {
    pclose (fp2);

    char *pyenv_libpath = expand_pyenv_libpath (prefix_path, maj, min);

    if (pyenv_libpath != NULL)
    {
      strncpy (out_buf, pyenv_libpath, out_sz - 1);

      free (pyenv_libpath);

      return 0;
    }

    return -1;
  }

  pclose (fp2);

  // global

  FILE *fp3 = popen ("pyenv global", "r");

  if (fp3 == NULL) return -1;

  if (fscanf (fp3, "%d.%d", &maj, &min) == 2)
  {
    pclose (fp3);

    char *pyenv_libpath = expand_pyenv_libpath (prefix_path, maj, min);

    if (pyenv_libpath != NULL)
    {
      strncpy (out_buf, pyenv_libpath, out_sz - 1);

      free (pyenv_libpath);

      return 0;
    }

    return -1;
  }

  pclose (fp3);

  return -1;
}

static bool init_python (hc_python_lib_t *python)
{
  char pythondll_path[PATH_MAX];

  python->lib = NULL;

  // let's see if we have pyenv, that will save us a lot of guessing...

  int saved_stderr = suppress_stderr ();

  const int pyenv_rc = resolve_pyenv_libpath (pythondll_path, sizeof (pythondll_path));

  restore_stderr (saved_stderr);

  if (pyenv_rc == 0)
  {
    #if defined (_WIN)
    python->lib = hc_dlopen (pythondll_path);
    #elif defined (__MSYS__)
    python->lib = dlopen (pythondll_path, RTLD_NOW | RTLD_GLOBAL);
    #elif defined (__APPLE__)
    python->lib = dlopen (pythondll_path, RTLD_NOW | RTLD_GLOBAL);
    #elif defined (__CYGWIN__)
    python->lib = hc_dlopen (pythondll_path);
    #else
    python->lib = dlopen (pythondll_path, RTLD_NOW | RTLD_GLOBAL);
    #endif
  }

  #define MIN_MAJ 3
  #define MAX_MAJ 8

  #define MIN_MIN 0
  #define MAX_MIN 50

  for (int maj = MAX_MAJ; maj >= MIN_MAJ; --maj)
  {
    if (python->lib != NULL) break;

    for (int min = MAX_MIN; min >= MIN_MIN; --min)
    {
      #if defined (_WIN)

      // first try %LocalAppData% default path
      char expandedPath[MAX_PATH - 1];

      char *libpython_namelocal = NULL;

      hc_asprintf (&libpython_namelocal, "%%LocalAppData%%\\Programs\\Python\\Python%d%d\\python%d%d.dll", maj, min, maj, min);

      DWORD len = ExpandEnvironmentStringsA (libpython_namelocal, expandedPath, sizeof (expandedPath));

      if (len)
      {
        python->lib = hc_dlopen (expandedPath);

        if (python->lib != NULL)
        {
          strncpy (pythondll_path, expandedPath, sizeof (pythondll_path) - 1);

          hcfree (libpython_namelocal);

          break;
        }
        else
        {
          hcfree (libpython_namelocal);
        };
      }

      // use %PATH%
      char *libpython_namepath = NULL;

      hc_asprintf (&libpython_namepath, "python%d%d.dll", maj, min);

      python->lib = hc_dlopen (libpython_namepath);

      if (python->lib != NULL)
      {
        strncpy (pythondll_path, libpython_namepath, sizeof (pythondll_path) - 1);

        hcfree (libpython_namepath);

        break;
      }
      else
      {
        hcfree (libpython_namepath);
      };

      #elif defined (__MSYS__)

      char *libpython_name = NULL;

      hc_asprintf (&libpython_name, "msys-python%d.%d.dll", maj, min);

      python->lib = dlopen (libpython_name, RTLD_NOW | RTLD_GLOBAL);

      if (python->lib != NULL)
      {
        strncpy (pythondll_path, libpython_name, sizeof (pythondll_path) - 1);

        hcfree (libpython_name);

        break;
      }
      else
      {
        hcfree (libpython_name);
      };

      #elif defined (__APPLE__)

      char *libpython_name = NULL;

      hc_asprintf (&libpython_name, "libpython%d.%d.dylib", maj, min);

      python->lib = dlopen (libpython_name, RTLD_NOW | RTLD_GLOBAL);

      if (python->lib != NULL)
      {
        strncpy (pythondll_path, libpython_name, sizeof (pythondll_path) - 1);

        hcfree (libpython_name);

        break;
      }
      else
      {
        hcfree (libpython_name);
      };

      #elif defined (__CYGWIN__)

      char *libpython_name = NULL;

      hc_asprintf (&libpython_name, "python%d%d.dll", maj, min);

      python->lib = hc_dlopen (libpython_name);

      if (python->lib != NULL)
      {
        strncpy (pythondll_path, libpython_name, sizeof (pythondll_path) - 1);

        hcfree (libpython_name);

        break;
      }
      else
      {
        hcfree (libpython_name);
      };

      #else

      char *libpython_name = NULL;

      hc_asprintf (&libpython_name, "libpython%d.%d.so", maj, min);

      python->lib = dlopen (libpython_name, RTLD_NOW | RTLD_GLOBAL);

      if (python->lib != NULL)
      {
        strncpy (pythondll_path, libpython_name, sizeof (pythondll_path) - 1);

        hcfree (libpython_name);

        break;
      }
      else
      {
        hcfree (libpython_name);
      };

      #endif

      if (python->lib != NULL) break;
    }

    if (python->lib != NULL) break;
  }

  if (python->lib == NULL)
  {
    fprintf (stderr, "Awww, unable to find Python shared library.\n");

    return false;
  }
  else
  {
    printf ("Loaded python library from: %s\n\n", pythondll_path);
  }

  #define HC_LOAD_FUNC_PYTHON(ptr,name,pythonname,type,libname,noerr) \
    do { \
      ptr->name = (type) hc_dlsym ((ptr)->lib, #pythonname); \
      if ((noerr) != -1) { \
        if (!(ptr)->name) { \
          if ((noerr) == 1) { \
            fprintf (stderr, "%s is missing from %s shared library.", #name, #libname); \
            return false; \
          } \
          if ((noerr) != 1) { \
            fprintf (stderr, "%s is missing from %s shared library.", #name, #libname); \
            return true; \
          } \
        } \
      } \
    } while (0)

  HC_LOAD_FUNC_PYTHON (python, Py_GetVersion,                     Py_GetVersion,                      PYGETVERSION,                     PYTHON, 1);

  const char *version_str = python->Py_GetVersion ();

  int major = 0;
  int minor = 0;

  if (sscanf (version_str, "%d.%d", &major, &minor) != 2)
  {
    fprintf (stderr, "Python version string is not valid: %s\n", version_str);

    return false;
  }

  if ((major < 3) || (major == 3 && minor < 10))
  {
    fprintf (stderr, "Python version mismatch: Need at least v3.10\n");

    return false;
  }

  HC_LOAD_FUNC_PYTHON (python, Py_Initialize,                     Py_Initialize,                      PY_INITIALIZE,                    PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, Py_Finalize,                       Py_Finalize,                        PY_FINALIZE,                      PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, Py_DecRef,                         Py_DecRef,                          PY_DECREF,                        PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyBool_FromLong,                   PyBool_FromLong,                    PYBOOL_FROMLONG,                  PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyBytes_FromStringAndSize,         PyBytes_FromStringAndSize,          PYBYTES_FROMSTRINGANDSIZE,        PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyDict_DelItemString,              PyDict_DelItemString,               PYDICT_DELITEMSTRING,             PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyDict_GetItemString,              PyDict_GetItemString,               PYDICT_GETITEMSTRING,             PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyDict_New,                        PyDict_New,                         PYDICT_NEW,                       PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyDict_SetItemString,              PyDict_SetItemString,               PYDICT_SETITEMSTRING,             PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyErr_Print,                       PyErr_Print,                        PYERR_PRINT,                      PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyImport_ImportModule,             PyImport_ImportModule,              PYIMPORT_IMPORTMODULE,            PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyImport_Import,                   PyImport_Import,                    PYIMPORT_IMPORT,                  PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyList_Append,                     PyList_Append,                      PYLIST_APPEND,                    PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyList_GetItem,                    PyList_GetItem,                     PYLIST_GETITEM,                   PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyList_New,                        PyList_New,                         PYLIST_NEW,                       PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyList_SetItem,                    PyList_SetItem,                     PYLIST_SETITEM,                   PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyList_Size,                       PyList_Size,                        PYLIST_SIZE,                      PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyLong_FromLong,                   PyLong_FromLong,                    PYLONG_FROMLONG,                  PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyObject_CallObject,               PyObject_CallObject,                PYOBJECT_CALLOBJECT,              PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyObject_GetAttrString,            PyObject_GetAttrString,             PYOBJECT_GETATTRSTRING,           PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyTuple_New,                       PyTuple_New,                        PYTUPLE_NEW,                      PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyTuple_SetItem,                   PyTuple_SetItem,                    PYTUPLE_SETITEM,                  PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_AsUTF8,                  PyUnicode_AsUTF8,                   PYUNICODE_ASUTF8,                 PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_AsUTF8AndSize,           PyUnicode_AsUTF8AndSize,            PYUNICODE_ASUTF8ANDSIZE,          PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_DecodeFSDefaultAndSize,  PyUnicode_DecodeFSDefaultAndSize,   PYUNICODE_DECODEFSDEFAULTANDSIZE, PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_DecodeFSDefault,         PyUnicode_DecodeFSDefault,          PYUNICODE_DECODEFSDEFAULT,        PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_FromStringAndSize,       PyUnicode_FromStringAndSize,        PYUNICODE_FROMSTRINGANDSIZE,      PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyUnicode_FromString,              PyUnicode_FromString,               PYUNICODE_FROMSTRING,             PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyEval_AcquireLock,                PyEval_AcquireLock,                 PYEVAL_ACQUIRELOCK,               PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyEval_ReleaseLock,                PyEval_ReleaseLock,                 PYEVAL_RELEASELOCK,               PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyThreadState_Swap,                PyThreadState_Swap,                 PYTHREADSTATE_SWAP,               PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, Py_NewInterpreter,                 Py_NewInterpreter,                  PYNEWINTERPRETER,                 PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, Py_EndInterpreter,                 Py_EndInterpreter,                  PYENDINTERPRETER,                 PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyGILState_Ensure,                 PyGILState_Ensure,                  PYGILSTATE_ENSURE,                PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyGILState_Release,                PyGILState_Release,                 PYGILSTATE_RELEASE,               PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyEval_AcquireThread,              PyEval_AcquireThread,               PYEVAL_ACQUIRETHREAD,             PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyEval_ReleaseThread,              PyEval_ReleaseThread,               PYEVAL_RELEASETHREAD,             PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyThreadState_Clear,               PyThreadState_Clear,                PYTHREADSTATE_CLEAR,              PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyThreadState_Delete,              PyThreadState_Delete,               PYTHREADSTATE_DELETE,             PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyThreadState_New,                 PyThreadState_New,                  PYTHREADSTATE_NEW,                PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyInterpreterState_Main,           PyInterpreterState_Main,            PYINTERPRETERSTATE_MAIN,          PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, PyEval_InitThreads,                PyEval_InitThreads,                 PYEVAL_INITTHREADS,               PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyEval_SaveThread,                 PyEval_SaveThread,                  PYEVAL_SAVETHREAD,                PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, Py_NewInterpreterFromConfig,       Py_NewInterpreterFromConfig,        PYNEWINTERPRETERFROMCONFIG,       PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, Py_ExitStatusException,            Py_ExitStatusException,             PYEXITSTATUSEXCEPTION,            PYTHON, 1);
  //HC_LOAD_FUNC_PYTHON (python, Py_InitializeFromConfig,           Py_InitializeFromConfig,            PYINITIALIZEFROMCONFIG,           PYTHON, 1);
  HC_LOAD_FUNC_PYTHON (python, PyEval_RestoreThread,              PyEval_RestoreThread,               PYEVAL_RESTORETHREAD,             PYTHON, 1);

  return true;
}

static bool units_init (python_interpreter_t *python_interpreter)
{
  #if defined (_WIN)

  SYSTEM_INFO sysinfo;

  GetSystemInfo (&sysinfo);

  int num_devices = sysinfo.dwNumberOfProcessors;

  #else

  int num_devices = sysconf (_SC_NPROCESSORS_ONLN);

  #endif

  // This branch of python plugin handles threads through multiprocessing module, so we only need one thread
  // Bu we will multiply N_ACCEL later with the num_devices count to achieve the same workload size

  const int num_devices_sav = num_devices;

  num_devices = 1;

  unit_t *units_buf = (unit_t *) hccalloc (num_devices, sizeof (unit_t));

  int units_cnt = 0;

  for (int i = 0; i < num_devices; i++)
  {
    unit_t *unit_buf = &units_buf[i];

    hc_python_lib_t *python = python_interpreter->python;

    unit_buf->unit_info_len = snprintf (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf) - 1, "Python Interpreter (%s)", python->Py_GetVersion ());

    unit_buf->unit_info_buf[unit_buf->unit_info_len] = 0;

    unit_buf->parallelism = num_devices_sav;
    unit_buf->workitem_count = N_ACCEL * num_devices_sav;

    units_cnt++;
  }

  python_interpreter->units_buf = units_buf;
  python_interpreter->units_cnt = units_cnt;

  return true;
}

static void units_term (python_interpreter_t *python_interpreter)
{
  unit_t *units_buf = python_interpreter->units_buf;

  if (units_buf)
  {
    hcfree (python_interpreter->units_buf);
  }
}

void *platform_init (user_options_t *user_options)
{
  // Verify CPU features

  if (cpu_chipset_test () == -1) return NULL;

  // Allocate platform context

  python_interpreter_t *python_interpreter = (python_interpreter_t *) hcmalloc (sizeof (python_interpreter_t));

  hc_python_lib_t *python = (hc_python_lib_t *) hcmalloc (sizeof (hc_python_lib_t));

  python_interpreter->python = python;

  if (init_python (python) == false) return NULL;

  python->Py_Initialize ();

  PyObject *sys = python->PyImport_ImportModule ("sys");
  PyObject *path = python->PyObject_GetAttrString (sys, "path");
  python->PyList_Append (path, python->PyUnicode_FromString ("./Python"));
  python->Py_DecRef (path);
  python->Py_DecRef (sys);

  if (units_init (python_interpreter) == false)
  {
    hcfree (python_interpreter);

    return NULL;
  }

  unit_t *unit_buf = &python_interpreter->units_buf[0];

  #if defined (_WIN) || defined (__APPLE__)
  fprintf (stderr, "Attention!!! Falling back to single-threaded mode.\n");
  fprintf (stderr, " Windows and MacOS ds not support multiprocessing module cleanly!\n");
  fprintf (stderr, " For multithreading on Windows and MacOS, please use -m 72000 instead.\n\n");
  #endif

  python_interpreter->source_filename = (user_options->bridge_parameter1) ? user_options->bridge_parameter1 : DEFAULT_SOURCE_FILENAME;

  PyObject *pName = python->PyUnicode_DecodeFSDefault (python_interpreter->source_filename);

  if (pName == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  unit_buf->pModule = python->PyImport_Import (pName);

  if (unit_buf->pModule == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  python->Py_DecRef (pName);

  unit_buf->pFunc_Init = python->PyObject_GetAttrString (unit_buf->pModule, "init");

  if (unit_buf->pFunc_Init == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  unit_buf->pFunc_Term = python->PyObject_GetAttrString (unit_buf->pModule, "term");

  if (unit_buf->pFunc_Term == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  unit_buf->pFunc_kernel_loop = python->PyObject_GetAttrString (unit_buf->pModule, "kernel_loop");

  if (unit_buf->pFunc_kernel_loop == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  // Initialize Context (which also means copy salts because they are part of the context)

  unit_buf->pContext = python->PyDict_New ();

  if (unit_buf->pContext == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  // for later calls

  unit_buf->pArgs = python->PyTuple_New (4);

  if (unit_buf->pArgs == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  python->PyTuple_SetItem (unit_buf->pArgs, 0, unit_buf->pContext);
  python->PyTuple_SetItem (unit_buf->pArgs, 2, python->PyLong_FromLong (0));
  python->PyTuple_SetItem (unit_buf->pArgs, 3, python->PyBool_FromLong (false));

  python_interpreter->tstate = python->PyEval_SaveThread ();

  return python_interpreter;
}

void platform_term (void *platform_context)
{
  python_interpreter_t *python_interpreter = platform_context;

  hc_python_lib_t *python = python_interpreter->python;

  unit_t *unit_buf = &python_interpreter->units_buf[0];

  unit_buf->gstate = python->PyGILState_Ensure ();

  python->Py_DecRef (unit_buf->pArgs);
  python->Py_DecRef (unit_buf->pContext);
  python->Py_DecRef (unit_buf->pFunc_kernel_loop);
  python->Py_DecRef (unit_buf->pFunc_Term);
  python->Py_DecRef (unit_buf->pFunc_Init);
  python->Py_DecRef (unit_buf->pModule);

  //python->PyEval_RestoreThread (python_interpreter->tstate);

  python->Py_Finalize ();

  units_term (python_interpreter);

  hcfree (python_interpreter);
}

bool thread_init (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  python_interpreter_t *python_interpreter = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &python_interpreter->units_buf[unit_idx];

  hc_python_lib_t *python = python_interpreter->python;

  unit_buf->gstate = python->PyGILState_Ensure ();

  int rc = 0;

  rc |= python->PyDict_SetItemString (unit_buf->pContext, "parallelism",    python->PyLong_FromLong (unit_buf->parallelism));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "salts_cnt",      python->PyLong_FromLong (hashes->salts_cnt));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "salts_size",     python->PyLong_FromLong (sizeof (salt_t)));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "salts_buf",      python->PyBytes_FromStringAndSize ((const char *) hashes->salts_buf, sizeof (salt_t) * hashes->salts_cnt));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "esalts_cnt",     python->PyLong_FromLong (hashes->digests_cnt));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "esalts_size",    python->PyLong_FromLong (hashconfig->esalt_size));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "esalts_buf",     python->PyBytes_FromStringAndSize ((const char *) hashes->esalts_buf, hashconfig->esalt_size * hashes->digests_cnt));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_salts_cnt",   python->PyLong_FromLong (1));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_salts_size",  python->PyLong_FromLong (sizeof (salt_t)));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_salts_buf",   python->PyBytes_FromStringAndSize ((const char *) hashes->st_salts_buf, sizeof (salt_t) * 1));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_esalts_cnt",  python->PyLong_FromLong (1));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_esalts_size", python->PyLong_FromLong (hashconfig->esalt_size));
  rc |= python->PyDict_SetItemString (unit_buf->pContext, "st_esalts_buf",  python->PyBytes_FromStringAndSize ((const char *) hashes->st_esalts_buf, hashconfig->esalt_size * 1));

  if (rc != 0)
  {
    python->PyErr_Print ();

    return false;
  }

  PyObject *pArgs = python->PyTuple_New (1);

  if (pArgs == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  python->PyTuple_SetItem (pArgs, 0, unit_buf->pContext);

  PyObject *pReturn = python->PyObject_CallObject (unit_buf->pFunc_Init, pArgs);

  if (pReturn == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  python->Py_DecRef (pReturn);

  python->PyGILState_Release (unit_buf->gstate);

  return true;
}

void thread_term (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  python_interpreter_t *python_interpreter = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &python_interpreter->units_buf[unit_idx];

  hc_python_lib_t *python = python_interpreter->python;

  unit_buf->gstate = python->PyGILState_Ensure ();

  PyObject *pArgs = python->PyTuple_New (1);

  if (pArgs == NULL)
  {
    python->PyErr_Print ();

    return;
  }

  python->PyTuple_SetItem (pArgs, 0, unit_buf->pContext);

  python->PyObject_CallObject (unit_buf->pFunc_Term, pArgs);

  python->PyDict_DelItemString (unit_buf->pContext, "salts_cnt");
  python->PyDict_DelItemString (unit_buf->pContext, "salts_size");
  python->PyDict_DelItemString (unit_buf->pContext, "salts_buf");
  python->PyDict_DelItemString (unit_buf->pContext, "esalts_cnt");
  python->PyDict_DelItemString (unit_buf->pContext, "esalts_size");
  python->PyDict_DelItemString (unit_buf->pContext, "esalts_buf");
  python->PyDict_DelItemString (unit_buf->pContext, "st_salts_cnt");
  python->PyDict_DelItemString (unit_buf->pContext, "st_salts_size");
  python->PyDict_DelItemString (unit_buf->pContext, "st_salts_buf");
  python->PyDict_DelItemString (unit_buf->pContext, "st_esalts_cnt");
  python->PyDict_DelItemString (unit_buf->pContext, "st_esalts_size");
  python->PyDict_DelItemString (unit_buf->pContext, "st_esalts_buf");

  python->PyGILState_Release (unit_buf->gstate);
}

int get_unit_count (void *platform_context)
{
  python_interpreter_t *python_interpreter = platform_context;

  return python_interpreter->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (void *platform_context, const int unit_idx)
{
  python_interpreter_t *python_interpreter = platform_context;

  unit_t *unit_buf = &python_interpreter->units_buf[unit_idx];

  return unit_buf->workitem_count;
}

char *get_unit_info (void *platform_context, const int unit_idx)
{
  python_interpreter_t *python_interpreter = platform_context;

  unit_t *unit_buf = &python_interpreter->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool launch_loop (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  python_interpreter_t *python_interpreter = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &python_interpreter->units_buf[unit_idx];

  hc_python_lib_t *python = python_interpreter->python;

  unit_buf->gstate = python->PyGILState_Ensure ();

  generic_io_tmp_t *generic_io_tmp = (generic_io_tmp_t *) device_param->h_tmps;

  PyObject *pws = python->PyList_New (pws_cnt);

  if (pws == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  for (u64 i = 0; i < pws_cnt; i++)
  {
    PyObject *pw = python->PyBytes_FromStringAndSize ((char *) generic_io_tmp->pw_buf, generic_io_tmp->pw_len);

    if (pw == NULL) return false;

    python->PyList_SetItem (pws, i, pw);

    generic_io_tmp++;
  }

  python->PyTuple_SetItem (unit_buf->pArgs, 1, pws);
  python->PyTuple_SetItem (unit_buf->pArgs, 2, python->PyLong_FromLong (salt_pos));

  if (hashes->salts_buf == hashes->st_salts_buf)
  {
    python->PyTuple_SetItem (unit_buf->pArgs, 3, python->PyBool_FromLong (true));
  }
  else
  {
    python->PyTuple_SetItem (unit_buf->pArgs, 3, python->PyBool_FromLong (false));
  }

  PyObject *pReturn = python->PyObject_CallObject (unit_buf->pFunc_kernel_loop, unit_buf->pArgs);

  if (pReturn == NULL)
  {
    python->PyErr_Print ();

    return false;
  }

  Py_ssize_t retsz = python->PyList_Size (pReturn);

  if (retsz != (Py_ssize_t) pws_cnt) return false;

  generic_io_tmp = (generic_io_tmp_t *) device_param->h_tmps;

  for (Py_ssize_t i = 0; i < retsz; i++)
  {
    PyObject *hash = python->PyList_GetItem (pReturn, i);

    Py_ssize_t len;

    const char *s = python->PyUnicode_AsUTF8AndSize (hash, &len);

    if (s)
    {
      memcpy (generic_io_tmp->out_buf, s, len);

      generic_io_tmp->out_len = len;
    }

    generic_io_tmp++;
  }

  python->Py_DecRef (pReturn);

  python->PyGILState_Release (unit_buf->gstate);

  return true;
}

const char *st_update_hash (MAYBE_UNUSED void *platform_context)
{
  python_interpreter_t *python_interpreter = platform_context;

  hc_python_lib_t *python = python_interpreter->python;

  unit_t *unit_buf = &python_interpreter->units_buf[0];

  unit_buf->gstate = python->PyGILState_Ensure ();

  PyObject *constant = python->PyObject_GetAttrString (unit_buf->pModule, "ST_HASH");

  if (constant == NULL)
  {
    python->PyGILState_Release (unit_buf->gstate);

    return NULL;
  }

  const char *s = python->PyUnicode_AsUTF8 (constant);

  python->Py_DecRef (constant);

  python->PyGILState_Release (unit_buf->gstate);

  return s;
}

const char *st_update_pass (MAYBE_UNUSED void *platform_context)
{
  python_interpreter_t *python_interpreter = platform_context;

  hc_python_lib_t *python = python_interpreter->python;

  unit_t *unit_buf = &python_interpreter->units_buf[0];

  unit_buf->gstate = python->PyGILState_Ensure ();

  PyObject *constant = python->PyObject_GetAttrString (unit_buf->pModule, "ST_PASS");

  if (constant == NULL)
  {
    python->PyGILState_Release (unit_buf->gstate);

    return NULL;
  }

  const char *s = python->PyUnicode_AsUTF8 (constant);

  python->Py_DecRef (constant);

  python->PyGILState_Release (unit_buf->gstate);

  return s;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size       = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version  = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init       = platform_init;
  bridge_ctx->platform_term       = platform_term;
  bridge_ctx->get_unit_count      = get_unit_count;
  bridge_ctx->get_unit_info       = get_unit_info;
  bridge_ctx->get_workitem_count  = get_workitem_count;
  bridge_ctx->thread_init         = thread_init;
  bridge_ctx->thread_term         = thread_term;
  bridge_ctx->salt_prepare        = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy        = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop         = launch_loop;
  bridge_ctx->launch_loop2        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash      = st_update_hash;
  bridge_ctx->st_update_pass      = st_update_pass;
}
