/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"

#ifdef _WIN

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

// A plugin that will not load has almost always been built against a plugin interface this core no
// longer carries. The name it holds says which one, and it is in the file whether the plugin is an
// ELF or a PE, so it is read back here. The Unix loader already names the symbol it could not
// resolve. The Windows loader returns a code that says a procedure was not found and nothing else,
// which reads as a broken install rather than as a plugin that needs rebuilding.
//
// Returns the version the file was built against, or -1 when the file says nothing.

int hc_dlplugin_abi (const char *path)
{
  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return -1;

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

  return version;
}
