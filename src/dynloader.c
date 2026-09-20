/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"

#ifndef _WIN
#include <glob.h>
#endif

#ifdef _WIN

// Take the working directory out of the library search order.
//
// LoadLibrary () given a bare file name searches the directory hashcat.exe lives in, the system
// directories, PATH, and the working directory. A library that is present in none of the others is
// therefore loaded from wherever hashcat happens to be started, and a file dropped next to a
// wordlist is a library hashcat will run. The libraries this matters most for are the compression
// ones, because Windows ships none of them.
//
// SetDllDirectory () given an empty string removes the working directory from that order and leaves
// the rest of it alone. We used SetDefaultDllDirectories (LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) before,
// which drops PATH as well. A CUDA toolkit puts nvrtc on PATH and nowhere else, so hashcat stopped
// finding the toolkit it had just reported as present, said none was installed, and fell back to
// OpenCL on every Windows machine that had one.
//
// Supplying a library the documented way, beside hashcat.exe, is the application directory and is
// unaffected either way. A library that only ever resolved out of the working directory stops being
// found, which is the point. A plugin is loaded by path and never went through this search order at
// all.

void hc_dynlib_harden_search_path (void)
{
  SetDllDirectoryA ("");
}

hc_dynlib_t hc_dlopen (LPCSTR lpLibFileName)
{
  return LoadLibraryA (lpLibFileName);
}

BOOL hc_dlclose (hc_dynlib_t hLibModule)
{
  return FreeLibrary (hLibModule);
}

hc_dynfunc_t hc_dlsym (hc_dynlib_t hModule, LPCSTR lpProcName)
{
  return GetProcAddress (hModule, lpProcName);
}

// the loader's reason, in the shape every caller already expects from dlerror (): a string the
// caller neither owns nor frees, good until this thread asks again. Windows hands out a buffer of
// its own and ends the sentence with a line break, so the text is copied out, trimmed, and the
// buffer handed back here instead of at each call site, where it was being leaked.

char *hc_dlerror ()
{
  static __thread char msg_buf[512];

  const DWORD rc = GetLastError ();

  char *msg = NULL;

  const DWORD msg_len = FormatMessageA
  (
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    rc,
    MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR) &msg,
    0,
    NULL
  );

  if (msg_len == 0)
  {
    snprintf (msg_buf, sizeof (msg_buf), "error %u", (unsigned int) rc);

    return msg_buf;
  }

  snprintf (msg_buf, sizeof (msg_buf), "%s", msg);

  LocalFree (msg);

  size_t trimmed = strlen (msg_buf);

  while (trimmed > 0)
  {
    const char c = msg_buf[trimmed - 1];

    if ((c != '\r') && (c != '\n') && (c != ' ')) break;

    msg_buf[trimmed - 1] = 0;

    trimmed--;
  }

  return msg_buf;
}

#else

hc_dynlib_t hc_dlopen (const char *filename)
{
  return dlopen (filename, RTLD_NOW);
}

int hc_dlclose (hc_dynlib_t handle)
{
  return dlclose (handle);
}

hc_dynfunc_t hc_dlsym (hc_dynlib_t handle, const char *symbol)
{
  return dlsym (handle, symbol);
}

char *hc_dlerror ()
{
  return dlerror ();
}

#endif

#ifdef _WIN

// The Windows half of the same problem. A CUDA or HIP DLL carries its version in the file name,
// nvrtc64_130_0.dll and amdhip64_7.dll and hiprtc0702.dll, so the loaders built a name and asked for
// it. NVRTC guessed a major and a minor from two nested ranges, which is a few hundred LoadLibrary
// calls on a machine that has no CUDA and a ceiling on the ones that do. HIP did not guess so much as
// assume, taking the number out of the HIP_PATH string, and the two numbers are not the same thing:
// ROCm 10.0 ships a HIP whose version is 7, so a name built from the ROCm release is a name that
// need not exist.
//
// The directory is read instead. Every digit in the file name after the fixed part counts toward the
// version, in order, which is enough to sort names that differ only there.

#define HC_DYNLIB_VER_MAX 4

static void hc_dynlib_ver_of_dll (const char *name, const size_t prefix_len, int *ver)
{
  for (int i = 0; i < HC_DYNLIB_VER_MAX; i++) ver[i] = 0;

  int idx = 0;

  bool in_run = false;

  for (const char *p = name + prefix_len; *p; p++)
  {
    if ((*p >= '0') && (*p <= '9'))
    {
      if (in_run == false)
      {
        if (idx == HC_DYNLIB_VER_MAX) break;

        in_run = true;
      }

      ver[idx] = (ver[idx] * 10) + (*p - '0');

      continue;
    }

    if (in_run == true)
    {
      idx++;

      in_run = false;
    }
  }
}

static int hc_dynlib_ver_cmp (const int *a, const int *b)
{
  for (int i = 0; i < HC_DYNLIB_VER_MAX; i++)
  {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }

  return 0;
}

// A candidate is a file whose name starts with the fixed part and carries a digit straight after it.
// That last condition is what keeps hiprtc-builtins0702.dll from being mistaken for hiprtc0702.dll.

static void hc_dynlib_best_dll (const char *dir, const char *prefix, char *best, const size_t best_size, int *best_ver, bool *have)
{
  const size_t prefix_len = strlen (prefix);

  char pattern[MAX_PATH];

  const int len = snprintf (pattern, sizeof (pattern), "%s\\%s*.dll", dir, prefix);

  if (len < 0) return;
  if ((size_t) len >= sizeof (pattern)) return;

  WIN32_FIND_DATAA fd;

  HANDLE h = FindFirstFileA (pattern, &fd);

  if (h == INVALID_HANDLE_VALUE) return;

  do
  {
    const char c = fd.cFileName[prefix_len];

    if ((c < '0') || (c > '9')) continue;

    int ver[HC_DYNLIB_VER_MAX];

    hc_dynlib_ver_of_dll (fd.cFileName, prefix_len, ver);

    if ((*have == true) && (hc_dynlib_ver_cmp (ver, best_ver) <= 0)) continue;

    snprintf (best, best_size, "%s\\%s", dir, fd.cFileName);

    memcpy (best_ver, ver, sizeof (ver));

    *have = true;

  } while (FindNextFileA (h, &fd) != 0);

  FindClose (h);
}

hc_dynlib_t hc_dynlib_open_newest_dll (const char *prefix, const char *const *dirs, const size_t dirs_cnt, char *err, const size_t err_size)
{
  if (prefix == NULL) return NULL;

  char best[MAX_PATH];

  int best_ver[HC_DYNLIB_VER_MAX];

  bool have = false;

  for (size_t i = 0; i < dirs_cnt; i++)
  {
    if (dirs[i] == NULL) continue;

    hc_dynlib_best_dll (dirs[i], prefix, best, sizeof (best), best_ver, &have);
  }

  // Whatever is on PATH, which is where a driver leaves its copy. The SDK directories above come
  // first, so a newer runtime beside the compiler still wins over an older one in System32.

  const char *env = getenv ("PATH");

  if (env)
  {
    const char *s = env;

    while (*s)
    {
      const char *e = strchr (s, ';');

      const size_t len = (e) ? (size_t) (e - s) : strlen (s);

      if ((len > 0) && (len < MAX_PATH))
      {
        char one[MAX_PATH];

        memcpy (one, s, len);

        one[len] = 0;

        hc_dynlib_best_dll (one, prefix, best, sizeof (best), best_ver, &have);
      }

      if (e == NULL) break;

      s = e + 1;
    }
  }

  if (have == true)
  {
    hc_dynlib_t lib = hc_dlopen (best);

    if (lib) return lib;
  }

  if (err == NULL) return NULL;
  if (err_size == 0) return NULL;

  if (have == true)
  {
    snprintf (err, err_size, "%s was found at %s but would not load", prefix, best);
  }
  else
  {
    snprintf (err, err_size, "no %s*.dll in the SDK directory or anywhere on PATH", prefix);
  }

  err[err_size - 1] = 0;

  return NULL;
}

#endif // _WIN

#ifndef _WIN

// Open the newest installed version of a library whose soname major moves with a vendor release.
//
// Three of them do. libnvrtc follows the CUDA major and is on 12 and 13 today, libamdhip64 and
// libhiprtc follow HIP's own major and are on 7. Every other library hashcat opens is pinned at .so.1
// by convention, libcuda and libOpenCL and libnvidia-ml among them, and none of this applies to an
// OpenCL implementation such as rusticl or Intel's, which is an ICD the loader finds by itself.
//
// The unversioned name is a link that only the development package ships, so a machine carrying just
// the runtime has libnvrtc.so.13 and no libnvrtc.so. dlopen () cannot be asked which majors exist, so
// the loaders used to guess: count a range downward and open the first name that answers. That put a
// ceiling on the version hashcat could find, and a release above it did not look like a new release,
// it looked like the runtime was not installed at all.
//
// The file names are read off the disk instead, from the directories the dynamic linker itself
// searches, so a library it could load is a library this finds. The newest wins, by the version in
// the resolved file name rather than by the soname major, because the major alone does not settle it:
// a machine can carry libamdhip64.so.7 twice, 7.15 under /opt/rocm and 7.1 from the distribution, and
// the two are different libraries.

#define HC_DYNLIB_DIR_MAX  64
#define HC_DYNLIB_PATH_MAX 512
#define HC_DYNLIB_VER_MAX  4

// A version out of a file name, as its numeric parts. Ordering these is the whole job, so a part
// that is missing counts as zero and anything the vendor appends, such as ROCm's -0000000 build tag,
// ends the number rather than joining it.

static bool hc_dynlib_ver_parse (const char *name, const char *stem, int *ver)
{
  const size_t stem_len = strlen (stem);

  if (strncmp (name, stem, stem_len) != 0) return false;
  if (strncmp (name + stem_len, ".so.", 4) != 0) return false;

  const char *v = name + stem_len + 4;

  if ((v[0] < '0') || (v[0] > '9')) return false;

  for (int i = 0; i < HC_DYNLIB_VER_MAX; i++) ver[i] = 0;

  int idx = 0;

  for (const char *p = v; *p; p++)
  {
    if ((*p >= '0') && (*p <= '9'))
    {
      ver[idx] = (ver[idx] * 10) + (*p - '0');

      continue;
    }

    if (*p != '.') break;

    idx++;

    if (idx == HC_DYNLIB_VER_MAX) break;
  }

  return true;
}

static int hc_dynlib_ver_cmp (const int *a, const int *b)
{
  for (int i = 0; i < HC_DYNLIB_VER_MAX; i++)
  {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }

  return 0;
}

static void hc_dynlib_dir_add (char dirs[][HC_DYNLIB_PATH_MAX], size_t *dirs_cnt, const char *dir)
{
  if (dir == NULL) return;
  if (dir[0] != '/') return;

  if (*dirs_cnt >= HC_DYNLIB_DIR_MAX) return;

  for (size_t i = 0; i < *dirs_cnt; i++)
  {
    if (strcmp (dirs[i], dir) == 0) return;
  }

  snprintf (dirs[*dirs_cnt], HC_DYNLIB_PATH_MAX, "%s", dir);

  (*dirs_cnt)++;
}

// LD_LIBRARY_PATH first, then whatever ldconfig was told, then the usual places. The multiarch
// directory is reached by a pattern because its name carries the architecture.

static size_t hc_dynlib_dirs (char dirs[][HC_DYNLIB_PATH_MAX])
{
  size_t dirs_cnt = 0;

  const char *env = getenv ("LD_LIBRARY_PATH");

  if (env)
  {
    const char *s = env;

    while (*s)
    {
      const char *e = strchr (s, ':');

      const size_t len = (e) ? (size_t) (e - s) : strlen (s);

      if ((len > 0) && (len < HC_DYNLIB_PATH_MAX))
      {
        char one[HC_DYNLIB_PATH_MAX];

        memcpy (one, s, len);

        one[len] = 0;

        hc_dynlib_dir_add (dirs, &dirs_cnt, one);
      }

      if (e == NULL) break;

      s = e + 1;
    }
  }

  glob_t gl;

  if (glob ("/etc/ld.so.conf.d/*.conf", 0, NULL, &gl) == 0)
  {
    for (size_t i = 0; i < gl.gl_pathc; i++)
    {
      FILE *fp = fopen (gl.gl_pathv[i], "r");

      if (fp == NULL) continue;

      char line[HC_DYNLIB_PATH_MAX];

      while (fgets (line, sizeof (line), fp))
      {
        char *end = strpbrk (line, "\r\n");

        if (end) *end = 0;

        hc_dynlib_dir_add (dirs, &dirs_cnt, line);
      }

      fclose (fp);
    }

    globfree (&gl);
  }

  hc_dynlib_dir_add (dirs, &dirs_cnt, "/lib");
  hc_dynlib_dir_add (dirs, &dirs_cnt, "/usr/lib");
  hc_dynlib_dir_add (dirs, &dirs_cnt, "/lib64");
  hc_dynlib_dir_add (dirs, &dirs_cnt, "/usr/lib64");

  return dirs_cnt;
}

static void hc_dynlib_best (const char *pattern, const char *stem, char *best, const size_t best_size, int *best_ver, bool *have)
{
  glob_t gl;

  if (glob (pattern, 0, NULL, &gl) != 0) return;

  for (size_t i = 0; i < gl.gl_pathc; i++)
  {
    const char *path = gl.gl_pathv[i];

    const char *base = strrchr (path, '/');

    base = (base) ? base + 1 : path;

    int ver[HC_DYNLIB_VER_MAX];

    if (hc_dynlib_ver_parse (base, stem, ver) == false) continue;

    if ((*have == true) && (hc_dynlib_ver_cmp (ver, best_ver) <= 0)) continue;

    snprintf (best, best_size, "%s", path);

    memcpy (best_ver, ver, sizeof (ver));

    *have = true;
  }

  globfree (&gl);
}

hc_dynlib_t hc_dynlib_open_newest (const char *stem, char *err, const size_t err_size)
{
  if (stem == NULL) return NULL;

  char dirs[HC_DYNLIB_DIR_MAX][HC_DYNLIB_PATH_MAX];

  const size_t dirs_cnt = hc_dynlib_dirs (dirs);

  char best[HC_DYNLIB_PATH_MAX];

  int best_ver[HC_DYNLIB_VER_MAX];

  bool have = false;

  char pattern[HC_DYNLIB_PATH_MAX];

  for (size_t i = 0; i < dirs_cnt; i++)
  {
    const int len = snprintf (pattern, sizeof (pattern), "%s/%s.so.*", dirs[i], stem);

    if (len < 0) continue;
    if ((size_t) len >= sizeof (pattern)) continue;

    hc_dynlib_best (pattern, stem, best, sizeof (best), best_ver, &have);
  }

  const int len = snprintf (pattern, sizeof (pattern), "/usr/lib/*-linux-gnu/%s.so.*", stem);

  if ((len > 0) && ((size_t) len < sizeof (pattern)))
  {
    hc_dynlib_best (pattern, stem, best, sizeof (best), best_ver, &have);
  }

  if (have == true)
  {
    hc_dynlib_t lib = hc_dlopen (best);

    if (lib) return lib;
  }

  // Nothing was found where the linker looks, or the newest one would not open. The plain name is
  // still worth a try, because it costs one call and it covers a layout this does not know about.

  char plain[HC_DYNLIB_PATH_MAX];

  snprintf (plain, sizeof (plain), "%s.so", stem);

  hc_dynlib_t lib = hc_dlopen (plain);

  if (lib) return lib;

  if (err == NULL) return NULL;
  if (err_size == 0) return NULL;

  if (have == true)
  {
    snprintf (err, err_size, "%s was found at %s but would not load: %s", stem, best, hc_dlerror ());
  }
  else
  {
    snprintf (err, err_size, "no %s.so or %s.so.<version> in any library directory", stem, stem);
  }

  err[err_size - 1] = 0;

  return NULL;
}

#endif // _WIN

// Open the first library in the list that will load.
//
// The list is in preference order and it is normally a versioned soname first, then the unversioned
// development name. A caller that wants a specific ABI names the versioned file: an unversioned
// name is whichever version the box happens to have a -dev package for, and on a box with none it
// does not exist at all, which is the case this whole helper is here to survive.
//
// Returns NULL and writes the reason when none of them open. The reason names every candidate,
// because "libzstd not found" sends a user to install a package they may already have, and the list
// of file names the loader actually wanted is the thing that tells them what is wrong.

hc_dynlib_t hc_dynlib_open (const char *const *sonames, const size_t sonames_cnt, char *err, const size_t err_size)
{
  if (sonames == NULL) return NULL;

  for (size_t i = 0; i < sonames_cnt; i++)
  {
    if (sonames[i] == NULL) continue;

    hc_dynlib_t lib = hc_dlopen (sonames[i]);

    if (lib) return lib;
  }

  if (err == NULL) return NULL;
  if (err_size == 0) return NULL;

  int off = snprintf (err, err_size, "no library could be loaded, tried:");

  if (off < 0) off = 0;

  for (size_t i = 0; i < sonames_cnt; i++)
  {
    if (sonames[i] == NULL) continue;

    if ((size_t) off >= err_size) break;

    const int add = snprintf (err + off, err_size - (size_t) off, " %s", sonames[i]);

    if (add < 0) break;

    off += add;
  }

  err[err_size - 1] = 0;

  return NULL;
}

// Fill a struct of function pointers from a table, and say which symbol was missing when one is.
//
// The table ends with a row whose name is NULL. dst is the caller's struct and each row carries the
// offsetof () of the field it belongs in, so one loop fills a struct this file knows nothing about.

bool hc_dynlib_syms (hc_dynlib_t lib, void *dst, const hc_dynlib_sym_t *syms, char *err, const size_t err_size)
{
  if (lib == NULL) return false;
  if (dst == NULL) return false;
  if (syms == NULL) return false;

  u8 *base = (u8 *) dst;

  for (size_t i = 0; syms[i].name != NULL; i++)
  {
    const hc_dynlib_sym_t *sym = &syms[i];

    const hc_dynfunc_t fn = hc_dlsym (lib, sym->name);

    if ((fn == NULL) && (sym->required == true))
    {
      if (err == NULL) return false;
      if (err_size == 0) return false;

      snprintf (err, err_size, "%s is missing from the shared library", sym->name);

      return false;
    }

    // An optional symbol that is not there leaves a null pointer in the field rather than whatever
    // the caller's struct held, so the caller can test the field instead of asking for a version.
    //
    // The write is a memcpy because the field is a function pointer of its own concrete type and
    // this only has a generic one. Copying the bytes is how that is done without telling the
    // compiler two incompatible pointer types live at one address.

    memcpy (base + sym->offset, &fn, sizeof (fn));
  }

  return true;
}

// Run init exactly once for this copy of the core, and make every other thread wait for it rather
// than see half of what it did.

#ifdef _WIN

static BOOL CALLBACK hc_once_run (PINIT_ONCE once, PVOID param, PVOID *context)
{
  void (*init) (void) = (void (*) (void)) param;

  init ();

  (void) once;
  (void) context;

  return TRUE;
}

void hc_once (hc_once_t *once, void (*init) (void))
{
  InitOnceExecuteOnce (once, hc_once_run, (PVOID) init, NULL);
}

#else

// pthread_once () calls a function that takes nothing, so which function to call is left where the
// thread that ends up running it can find it. Thread local, because the thread that runs it is the
// one that just wrote it, and any other thread waits inside pthread_once () until that is done.

static __thread void (*hc_once_init) (void);

static void hc_once_run (void)
{
  hc_once_init ();
}

void hc_once (hc_once_t *once, void (*init) (void))
{
  hc_once_init = init;

  pthread_once (once, hc_once_run);
}

#endif

// A plugin that will not load has almost always been built against a plugin interface this core no
// longer carries. The name it holds says which one, and it is in the file whether the plugin is an
// ELF or a PE, so it is read back here. The Unix loader already names the symbol it could not
// resolve. The Windows loader returns a code that says a procedure was not found and nothing else,
// which reads as a broken install rather than as a plugin that needs rebuilding.
//
// Returns the version the file was built against, or -1 when the file says nothing.
//
// Every caller runs this between a load that failed and the report of why it failed. Reading a file
// is a call that succeeds, and on Windows a call that succeeds clears the thread's last error, which
// is where hc_dlerror () reads the reason from. The last error is put back on the way out, so a
// caller reports what the loader said instead of reporting that the operation completed successfully.

int hc_dlplugin_abi (const char *path)
{
  #ifdef _WIN
  const DWORD last_error = GetLastError ();
  #endif

  FILE *fp = fopen (path, "rb");

  if (fp == NULL)
  {
    #ifdef _WIN
    SetLastError (last_error);
    #endif

    return -1;
  }

  const char marker[] = "HASHCAT_PLUGIN_";

  const size_t marker_len = sizeof (marker) - 1;

  // the tail of each chunk is carried into the next one, so a name lying across a chunk boundary is
  // still found. Ten digits is more version numbers than this project will ever have.

  const size_t keep = marker_len + 10;

  // 8 KB rather than a bigger number: the file is read in chunks and the tail is carried over, so
  // the size decides how many reads it takes and nothing else. This runs on the loader's stack for
  // every plugin in the directory, and a frame this size is also within what every compiler in the
  // release matrix can put stack probes into.

  char buf[8192];

  size_t carry = 0;

  int version = -1;

  while (version == -1)
  {
    const size_t nread = fread (buf + carry, 1, sizeof (buf) - carry, fp);

    if (nread == 0) break;

    const size_t have = carry + nread;

    for (size_t i = 0; (i + keep) <= have; i++)
    {
      if (memcmp (buf + i, marker, marker_len) != 0) continue;

      size_t pos = i + marker_len;

      int found = 0;

      while ((pos < have) && (buf[pos] >= '0') && (buf[pos] <= '9'))
      {
        found = (found * 10) + (buf[pos] - '0');

        pos++;
      }

      if (pos == (i + marker_len)) continue;

      version = found;

      break;
    }

    if (have < keep) break;

    memmove (buf, buf + have - keep, keep);

    carry = keep;
  }

  fclose (fp);

  #ifdef _WIN
  SetLastError (last_error);
  #endif

  return version;
}
