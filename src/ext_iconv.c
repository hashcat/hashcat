/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "dynloader.h"
#include "ext_iconv.h"

// The files to try, in order, after the process itself. glibc and musl need none of them, because
// there iconv is part of the C library and the process already has it. This list is what the other
// platforms need, where iconv is a library of its own.

#if !defined (_WIN)

static const char *const ICONV_SONAMES[] =
{
  #if   defined (_WIN)
  "libiconv-2.dll",
  "iconv.dll",
  "libiconv.dll",
  #elif defined (__CYGWIN__)
  "cygiconv-2.dll",
  "msys-iconv-2.dll",
  "libiconv-2.dll",
  #elif defined (__APPLE__)
  "/usr/lib/libiconv.2.dylib",
  "libiconv.2.dylib",
  "/opt/homebrew/lib/libiconv.2.dylib",
  "/usr/local/lib/libiconv.2.dylib",
  "libiconv.dylib",
  #else
  "libiconv.so.2",
  "libiconv.so",
  #endif
};

// The same three functions under the two names they are published as. An implementation that is the
// system iconv exports them plainly. GNU libiconv beside a C library that has an iconv of its own
// cannot, because the two would collide, so it prefixes every name and its header renames the calls
// behind the program's back. A program that resolves the names itself has to ask for both.

static const hc_dynlib_sym_t ICONV_SYMS[] =
{
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv_open,  true),
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv,       true),
  HC_DYNLIB_SYM (hc_iconv_lib_t, iconv_close, true),
  HC_DYNLIB_SYM_LAST
};

static const hc_dynlib_sym_t ICONV_SYMS_PREFIXED[] =
{
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv_open,  "libiconv_open",  true),
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv,       "libiconv",       true),
  HC_DYNLIB_SYM_AS (hc_iconv_lib_t, iconv_close, "libiconv_close", true),
  HC_DYNLIB_SYM_LAST
};

#endif // !_WIN

#if defined (_WIN)

// Windows has no iconv, and the one usually installed for it is GNU libiconv, which is LGPL and has
// to be fetched separately. Everything hashcat asks of iconv is a conversion between a code page,
// UTF-8, and the UTF-16 and UTF-32 forms, and Windows converts all of those itself.
//
// MultiByteToWideChar and WideCharToMultiByte handle every installed code page and UTF-8. They
// refuse code pages 1200, 1201, 12000 and 12001 - the UTF-16 and UTF-32 ones - with
// ERROR_INVALID_PARAMETER, which is documented and deliberate. Those four are handled here instead,
// and they are the easy ones: UTF-16LE is already the form everything is converted through, UTF-16BE
// is that with the bytes swapped, and UTF-32 is a surrogate pair away.
//
// What this does not do is the rest of what GNU libiconv can: EBCDIC, ISO-2022, and the //TRANSLIT
// and //IGNORE suffixes. An encoding name that is not recognised is refused by name rather than
// converted approximately.

typedef enum
{
  WIN_ENC_CP = 0,      // anything MultiByteToWideChar takes, including UTF-8
  WIN_ENC_UTF16LE,
  WIN_ENC_UTF16BE,
  WIN_ENC_UTF32LE,
  WIN_ENC_UTF32BE,

} win_enc_kind_t;

typedef struct
{
  win_enc_kind_t kind;
  UINT           cp;

} win_enc_t;

typedef struct
{
  win_enc_t from;
  win_enc_t to;

} win_iconv_cd_t;

// Names arrive in whatever shape the user typed. Fold to upper case and drop the separators so that
// "utf-8", "UTF8" and "utf_8" are one name.

static void win_enc_normalize (const char *in, char *out, const size_t out_sz)
{
  size_t o = 0;

  for (size_t i = 0; in[i] != 0 && o + 1 < out_sz; i++)
  {
    const char c = in[i];

    if ((c == '-') || (c == '_') || (c == ' ')) continue;

    out[o++] = (char) toupper ((unsigned char) c);
  }

  out[o] = 0;
}

static bool win_enc_all_digits (const char *s)
{
  if (*s == 0) return false;

  for (size_t i = 0; s[i] != 0; i++) if (isdigit ((unsigned char) s[i]) == 0) return false;

  return true;
}

static bool win_enc_parse (const char *name, win_enc_t *enc)
{
  char n[64];

  win_enc_normalize (name, n, sizeof (n));

  // The forms Windows cannot be asked for, handled here.

  if ((strcmp (n, "UTF16") == 0) || (strcmp (n, "UTF16LE") == 0)
   || (strcmp (n, "UCS2")  == 0) || (strcmp (n, "UCS2LE")  == 0)) { enc->kind = WIN_ENC_UTF16LE; return true; }

  if ((strcmp (n, "UTF16BE") == 0) || (strcmp (n, "UCS2BE") == 0)) { enc->kind = WIN_ENC_UTF16BE; return true; }

  if ((strcmp (n, "UTF32") == 0) || (strcmp (n, "UTF32LE") == 0)
   || (strcmp (n, "UCS4")  == 0) || (strcmp (n, "UCS4LE")  == 0))  { enc->kind = WIN_ENC_UTF32LE; return true; }

  if ((strcmp (n, "UTF32BE") == 0) || (strcmp (n, "UCS4BE") == 0))  { enc->kind = WIN_ENC_UTF32BE; return true; }

  enc->kind = WIN_ENC_CP;

  if ((strcmp (n, "UTF8") == 0) || (strcmp (n, "UTF8MAC") == 0)) { enc->cp = CP_UTF8; return true; }
  if  (strcmp (n, "UTF7") == 0)                                  { enc->cp = CP_UTF7; return true; }

  if ((strcmp (n, "ASCII") == 0) || (strcmp (n, "USASCII") == 0) || (strcmp (n, "ANSIX3.41968") == 0)) { enc->cp = 20127; return true; }

  if ((strcmp (n, "LATIN1") == 0) || (strcmp (n, "ISO88591") == 0)) { enc->cp = 28591; return true; }

  // ISO-8859-n maps to 28590 + n, which is how Windows numbers that family.

  if (strncmp (n, "ISO8859", 7) == 0)
  {
    const char *rest = n + 7;

    if (win_enc_all_digits (rest) == true)
    {
      const unsigned long part = strtoul (rest, NULL, 10);

      if ((part >= 1) && (part <= 16)) { enc->cp = (UINT) (28590 + part); return true; }
    }
  }

  // A bare number, or the CP / WINDOWS / MS spellings of one.

  const char *digits = NULL;

  if      (win_enc_all_digits (n) == true)        digits = n;
  else if (strncmp (n, "CP", 2) == 0)             digits = n + 2;
  else if (strncmp (n, "WINDOWS", 7) == 0)        digits = n + 7;
  else if (strncmp (n, "MS", 2) == 0)             digits = n + 2;

  if ((digits != NULL) && (win_enc_all_digits (digits) == true))
  {
    enc->cp = (UINT) strtoul (digits, NULL, 10);

    return true;
  }

  return false;
}

// Everything is converted through UTF-16LE, which is what Windows converts to and from, and what
// two of the four hand-written forms already are.

static int win_to_utf16 (const win_enc_t *enc, const char *in, const size_t in_len, wchar_t *w, const int w_cap)
{
  switch (enc->kind)
  {
    case WIN_ENC_CP:
    {
      if (in_len == 0) return 0;

      return MultiByteToWideChar (enc->cp, MB_ERR_INVALID_CHARS, in, (int) in_len, w, w_cap);
    }

    case WIN_ENC_UTF16LE:
    case WIN_ENC_UTF16BE:
    {
      if ((in_len % 2) != 0) return -1;

      const int n = (int) (in_len / 2);

      if (n > w_cap) return -1;

      const unsigned char *b = (const unsigned char *) in;

      for (int i = 0; i < n; i++)
      {
        w[i] = (enc->kind == WIN_ENC_UTF16LE)
             ? (wchar_t) (b[i * 2] | (b[(i * 2) + 1] << 8))
             : (wchar_t) (b[(i * 2) + 1] | (b[i * 2] << 8));
      }

      return n;
    }

    case WIN_ENC_UTF32LE:
    case WIN_ENC_UTF32BE:
    {
      if ((in_len % 4) != 0) return -1;

      const size_t n = in_len / 4;

      const unsigned char *b = (const unsigned char *) in;

      int o = 0;

      for (size_t i = 0; i < n; i++)
      {
        const unsigned char *p = b + (i * 4);

        u32 cp = (enc->kind == WIN_ENC_UTF32LE)
               ? ((u32) p[0] | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24))
               : ((u32) p[3] | ((u32) p[2] << 8) | ((u32) p[1] << 16) | ((u32) p[0] << 24));

        if (cp > 0x10ffff) return -1;
        if ((cp >= 0xd800) && (cp <= 0xdfff)) return -1;   // a lone surrogate is not a character

        if (cp < 0x10000)
        {
          if (o + 1 > w_cap) return -1;

          w[o++] = (wchar_t) cp;
        }
        else
        {
          if (o + 2 > w_cap) return -1;

          cp -= 0x10000;

          w[o++] = (wchar_t) (0xd800 + (cp >> 10));
          w[o++] = (wchar_t) (0xdc00 + (cp & 0x3ff));
        }
      }

      return o;
    }
  }

  return -1;
}

static int win_from_utf16 (const win_enc_t *enc, const wchar_t *w, const int w_len, char *out, const size_t out_cap)
{
  switch (enc->kind)
  {
    case WIN_ENC_CP:
    {
      if (w_len == 0) return 0;

      return WideCharToMultiByte (enc->cp, 0, w, w_len, out, (int) out_cap, NULL, NULL);
    }

    case WIN_ENC_UTF16LE:
    case WIN_ENC_UTF16BE:
    {
      const size_t need = (size_t) w_len * 2;

      if (need > out_cap) return -1;

      unsigned char *b = (unsigned char *) out;

      for (int i = 0; i < w_len; i++)
      {
        const u32 v = (u32) w[i];

        if (enc->kind == WIN_ENC_UTF16LE)
        {
          b[i * 2]       = (unsigned char) (v & 0xff);
          b[(i * 2) + 1] = (unsigned char) (v >> 8);
        }
        else
        {
          b[i * 2]       = (unsigned char) (v >> 8);
          b[(i * 2) + 1] = (unsigned char) (v & 0xff);
        }
      }

      return (int) need;
    }

    case WIN_ENC_UTF32LE:
    case WIN_ENC_UTF32BE:
    {
      size_t o = 0;

      for (int i = 0; i < w_len; i++)
      {
        u32 cp = (u32) w[i];

        if ((cp >= 0xd800) && (cp <= 0xdbff))
        {
          if ((i + 1) >= w_len) return -1;

          const u32 lo = (u32) w[i + 1];

          if ((lo < 0xdc00) || (lo > 0xdfff)) return -1;

          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);

          i++;
        }
        else if ((cp >= 0xdc00) && (cp <= 0xdfff))
        {
          return -1;   // a trailing surrogate with nothing in front of it
        }

        if ((o + 4) > out_cap) return -1;

        unsigned char *p = (unsigned char *) out + o;

        if (enc->kind == WIN_ENC_UTF32LE)
        {
          p[0] = (unsigned char) (cp & 0xff); p[1] = (unsigned char) ((cp >> 8) & 0xff);
          p[2] = (unsigned char) ((cp >> 16) & 0xff); p[3] = (unsigned char) ((cp >> 24) & 0xff);
        }
        else
        {
          p[3] = (unsigned char) (cp & 0xff); p[2] = (unsigned char) ((cp >> 8) & 0xff);
          p[1] = (unsigned char) ((cp >> 16) & 0xff); p[0] = (unsigned char) ((cp >> 24) & 0xff);
        }

        o += 4;
      }

      return (int) o;
    }
  }

  return -1;
}

static hc_iconv_t win_iconv_open (const char *tocode, const char *fromcode)
{
  win_enc_t from;
  win_enc_t to;

  if (win_enc_parse (fromcode, &from) == false) { errno = EINVAL; return HC_ICONV_ERR; }
  if (win_enc_parse (tocode,   &to)   == false) { errno = EINVAL; return HC_ICONV_ERR; }

  win_iconv_cd_t *cd = (win_iconv_cd_t *) malloc (sizeof (win_iconv_cd_t));

  if (cd == NULL) { errno = ENOMEM; return HC_ICONV_ERR; }

  cd->from = from;
  cd->to   = to;

  return (hc_iconv_t) cd;
}

static int win_iconv_close (hc_iconv_t cd)
{
  free (cd);

  return 0;
}

// One candidate at a time, whole buffer in and whole buffer out, which is how hashcat calls this.
// No state is carried between calls, so a partial sequence at the end of a buffer is an error rather
// than something to remember.

#define WIN_ICONV_WIDE_MAX 8192

static size_t win_iconv (hc_iconv_t cd_, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
  win_iconv_cd_t *cd = (win_iconv_cd_t *) cd_;

  if ((cd == NULL) || (inbuf == NULL) || (*inbuf == NULL))
  {
    return 0;   // a reset request, which has nothing to reset here
  }

  wchar_t w[WIN_ICONV_WIDE_MAX];

  const int w_len = win_to_utf16 (&cd->from, *inbuf, *inbytesleft, w, WIN_ICONV_WIDE_MAX);

  if (w_len < 0)
  {
    errno = (GetLastError () == ERROR_INSUFFICIENT_BUFFER) ? E2BIG : EILSEQ;

    return (size_t) -1;
  }

  const int out_len = win_from_utf16 (&cd->to, w, w_len, *outbuf, *outbytesleft);

  if (out_len < 0)
  {
    errno = E2BIG;

    return (size_t) -1;
  }

  *inbuf        += *inbytesleft;
  *inbytesleft   = 0;
  *outbuf       += out_len;
  *outbytesleft -= (size_t) out_len;

  return 0;
}

#endif // _WIN

static hc_iconv_lib_t iconv_lib;

static bool iconv_ready = false;

static char iconv_err[512];

static hc_once_t iconv_once = HC_ONCE_INIT;

// Read the three functions out of one handle, under either set of names, and keep the handle when
// they are all there. A handle that does not carry a whole set is closed again and the search goes
// on, which is what makes trying the process itself first free on the platforms where that misses.

#if !defined (_WIN)

static bool iconv_adopt (hc_dynlib_t lib)
{
  if (lib == NULL) return false;

  if (hc_dynlib_syms (lib, &iconv_lib, ICONV_SYMS, NULL, 0) == false)
  {
    if (hc_dynlib_syms (lib, &iconv_lib, ICONV_SYMS_PREFIXED, NULL, 0) == false)
    {
      memset (&iconv_lib, 0, sizeof (iconv_lib));

      hc_dlclose (lib);

      return false;
    }
  }

  iconv_lib.lib = lib;

  iconv_ready = true;

  return true;
}

#endif // !_WIN

static void iconv_load (void)
{
  memset (&iconv_lib, 0, sizeof (iconv_lib));

  iconv_ready  = false;
  iconv_err[0] = 0;

  #if defined (_WIN)

  // Windows converts all of this itself, so there is nothing to look for and nothing for the user to
  // install. Cygwin is not this branch: it has an iconv of its own and keeps the search below.

  iconv_lib.iconv_open  = win_iconv_open;
  iconv_lib.iconv       = win_iconv;
  iconv_lib.iconv_close = win_iconv_close;
  iconv_lib.lib         = NULL;

  iconv_ready = true;

  return;

  #else

  // The process itself, which is where glibc and musl keep iconv. hc_dlopen () of a null name is
  // the handle for the running program and everything already loaded with it, so the symbols are
  // found without a file being opened. Windows has no such handle and no such iconv.

  #ifndef _WIN
  if (iconv_adopt (hc_dlopen (NULL)) == true) return;
  #endif

  const size_t sonames_cnt = sizeof (ICONV_SONAMES) / sizeof (ICONV_SONAMES[0]);

  hc_dynlib_t lib = hc_dynlib_open (ICONV_SONAMES, sonames_cnt, iconv_err, sizeof (iconv_err));

  if (lib == NULL) return;

  if (iconv_adopt (lib) == false)
  {
    snprintf (iconv_err, sizeof (iconv_err), "iconv_open, iconv and iconv_close are missing from the shared library");
  }

  #endif
}

void hc_iconv_boot (void)
{
  hc_once (&iconv_once, iconv_load);
}

void hc_iconv_shutdown (void)
{
  if (iconv_ready == false) return;

  hc_dlclose (iconv_lib.lib);

  memset (&iconv_lib, 0, sizeof (iconv_lib));

  iconv_ready = false;
}

const hc_iconv_lib_t *hc_iconv (void)
{
  hc_once (&iconv_once, iconv_load);

  if (iconv_ready == false) return NULL;

  return &iconv_lib;
}

const char *hc_iconv_error (void)
{
  hc_once (&iconv_once, iconv_load);

  if (iconv_err[0] != 0) return iconv_err;

  return "no iconv was loaded";
}

const char *hc_iconv_hint (void)
{
  #if   defined (_WIN)
  return "this should not be reachable on Windows, where the conversion is built in";
  #elif defined (__CYGWIN__)
  return "install the cygwin libiconv package";
  #elif defined (__APPLE__)
  return "install libiconv, for example with: brew install libiconv";
  #else
  return "install your distribution's libiconv runtime package, which a machine using the GNU C library or musl does not need because iconv is part of the C library there";
  #endif
}
