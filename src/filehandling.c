/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "limits.h"
#include "memory.h"
#include "shared.h"
#include "path.h"
#include "memchr.h"
#include "filehandling.h"
#include "ext_zlib.h"
#include "ext_lzma.h"
#include "ext_zstd.h"

#ifndef HCFILE_BUFFER_SIZE
#define HCFILE_BUFFER_SIZE 256 * 1024
#endif

#ifndef HCFILE_CHUNK_SIZE
#define HCFILE_CHUNK_SIZE 4 * 1024 * 1024
#endif

// zlib's own handle, and the library it came from. types.h can then name the type without
// including zlib.h, and a read reaches the function pointers without a lookup of its own.

struct gzfile
{
  const hc_zlib_lib_t *z;

  hc_gzfile_t fp;
};

// A reader over a buffer the caller owns. Nothing here copies and nothing here frees the buffer: one
// decompressed archive can back a reader per member, and the archive outlives them all.

struct memfile
{
  const u8 *buf;
  size_t    len;
  size_t    pos;
};

// The first 6 bytes of any .xz file.

static const u8 XZ_SIG[] = { 0xfd, '7', 'z', 'X', 'Z', 0x00 };

// The first 4 bytes of any .zst file, which is HC_ZSTD_MAGIC written little endian.

static const u8 ZSTD_SIG[] = { 0x28, 0xb5, 0x2f, 0xfd };

// An .xz reader over the descriptor hc_fopen already opened, so there is one handle for the file
// rather than the two the previous reader kept.
//
// out_size is the uncompressed length taken from the stream index, which is what lets hc_fstat ()
// answer for a compressed file. Reading the index needs a liblzma new enough to have the call, so
// out_size_known says whether the answer exists rather than a sentinel standing in for it.

struct xzfile
{
  const hc_lzma_lib_t *lz;

  int   fd;

  hc_lzma_stream strm;

  u8   *inbuf;

  bool  eof_in;
  bool  eof_out;

  u64   out_pos;
  u64   out_size;
  bool  out_size_known;
};

// Walk the stream index to the uncompressed size. liblzma asks to be seeked rather than reading
// the file itself, which is what LZMA_SEEK_NEEDED means.

static bool xz_read_index_size (const hc_lzma_lib_t *lz, const int fd, u64 *out_size)
{
  if (lz->lzma_file_info_decoder == NULL) return false;
  if (lz->lzma_index_uncompressed_size == NULL) return false;
  if (lz->lzma_index_end == NULL) return false;

  struct stat st;

  if (fstat (fd, &st) == -1) return false;

  hc_lzma_stream strm;

  memset (&strm, 0, sizeof (strm));

  void *index = NULL;

  if (lz->lzma_file_info_decoder (&strm, &index, HC_LZMA_MEMLIMIT_NONE, (u64) st.st_size) != HC_LZMA_OK) return false;

  u8 buf[HCFILE_BUFFER_SIZE];

  bool ok = false;

  while (true)
  {
    if (strm.avail_in == 0)
    {
      const ssize_t nread = read (fd, buf, sizeof (buf));

      if (nread <= 0) break;

      strm.next_in  = buf;
      strm.avail_in = (size_t) nread;
    }

    const int rc = lz->lzma_code (&strm, HC_LZMA_RUN);

    if (rc == HC_LZMA_STREAM_END)
    {
      ok = true;

      break;
    }

    if (rc == HC_LZMA_SEEK_NEEDED)
    {
      if (lseek (fd, (off_t) strm.seek_pos, SEEK_SET) == (off_t) -1) break;

      strm.avail_in = 0;

      continue;
    }

    if (rc != HC_LZMA_OK) break;
  }

  if (ok == true) *out_size = lz->lzma_index_uncompressed_size (index);

  if (index) lz->lzma_index_end (index, NULL);

  lz->lzma_end (&strm);

  return ok;
}

// A .zst reader, shaped the same way as the xz one above and over the same descriptor.

struct zstdfile
{
  const hc_zstd_lib_t *z;

  int   fd;

  hc_zstd_dstream_t zds;

  u8   *inbuf;

  hc_zstd_inbuf in;

  bool  eof_in;
  bool  eof_out;

  u64   out_pos;
};

static size_t zstd_read (zstdfile_t *zfp, u8 *out, const size_t out_len)
{
  const hc_zstd_lib_t *z = zfp->z;

  hc_zstd_outbuf outbuf;

  outbuf.dst  = out;
  outbuf.size = out_len;
  outbuf.pos  = 0;

  while (outbuf.pos < out_len)
  {
    if ((zfp->in.pos == zfp->in.size) && (zfp->eof_in == false))
    {
      const ssize_t nread = read (zfp->fd, zfp->inbuf, HCFILE_BUFFER_SIZE);

      if (nread > 0)
      {
        zfp->in.src  = zfp->inbuf;
        zfp->in.size = (size_t) nread;
        zfp->in.pos  = 0;
      }
      else
      {
        zfp->eof_in = true;
      }
    }

    // Nothing buffered and nothing left in the file is the end of it. Several .zst frames written
    // one after another are one file, and libzstd walks from one into the next on its own.

    if ((zfp->in.pos == zfp->in.size) && (zfp->eof_in == true))
    {
      zfp->eof_out = true;

      break;
    }

    const size_t rc = z->ZSTD_decompressStream (zfp->zds, &outbuf, &zfp->in);

    if (z->ZSTD_isError (rc)) break;
  }

  zfp->out_pos += outbuf.pos;

  return outbuf.pos;
}

// The one decode loop. hc_fread (), hc_fgetc () and hc_fgets () each used to carry their own copy of
// it, and the only thing that differed was how many bytes they wanted.

static size_t xz_read (xzfile_t *xfp, u8 *out, const size_t out_len)
{
  const hc_lzma_lib_t *lz = xfp->lz;

  xfp->strm.next_out  = out;
  xfp->strm.avail_out = out_len;

  while (xfp->strm.avail_out > 0)
  {
    if ((xfp->strm.avail_in == 0) && (xfp->eof_in == false))
    {
      const ssize_t nread = read (xfp->fd, xfp->inbuf, HCFILE_BUFFER_SIZE);

      if (nread > 0)
      {
        xfp->strm.next_in  = xfp->inbuf;
        xfp->strm.avail_in = (size_t) nread;
      }
      else
      {
        xfp->eof_in = true;
      }
    }

    const int action = (xfp->eof_in == true) ? HC_LZMA_FINISH : HC_LZMA_RUN;

    const int rc = lz->lzma_code (&xfp->strm, action);

    if (rc == HC_LZMA_STREAM_END)
    {
      xfp->eof_out = true;

      break;
    }

    if (rc != HC_LZMA_OK) break;
  }

  const size_t produced = out_len - xfp->strm.avail_out;

  xfp->out_pos += produced;

  return produced;
}

#if defined (__CYGWIN__)
// workaround for zlib with cygwin build
int _wopen (const char *path, int oflag, ...)
{
  va_list ap;
  va_start (ap, oflag);
  int r = open (path, oflag, ap);
  va_end (ap);
  return r;
}
#endif

// Set when an open failed for a reason errno has no number for. Thread local, because two devices
// can be opening their own files at the same time and each has to read back its own reason.

static __thread char fopen_err_buf[512];

static __thread bool fopen_err_set = false;

static void fopen_codec_missing (const char *format, const char *detail, const char *hint)
{
  snprintf (fopen_err_buf, sizeof (fopen_err_buf), "%s support is unavailable: %s. To fix this, %s", format, detail, hint);

  fopen_err_set = true;

  // so that a caller still reading errno directly gets something honest rather than whatever the
  // last unrelated system call left behind, which can read as "Success"

  errno = ENOSYS;
}

const char *hc_fopen_strerror (void)
{
  if (fopen_err_set == true) return fopen_err_buf;

  const char *msg = strerror (errno);

  return msg;
}

bool hc_fopen (HCFILE *fp, const char *path, const char *mode)
{
  if (fp == NULL || path == NULL || mode == NULL) return false;

  fopen_err_set = false;

  /* cleanup */
  fp->fd       = -1;
  fp->pfp      = NULL;
  fp->gfp      = NULL;
  fp->xfp      = NULL;
  fp->zfp      = NULL;
  fp->mfp      = NULL;
  fp->bom_size = 0;
  fp->path     = NULL;
  fp->mode     = NULL;

  fp->uncompressed_size = 0;

  int oflag = -1;

  int fmode = S_IRUSR|S_IWUSR;

  if (strncmp (mode, "a", 1) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_APPEND;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "ab", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "r", 1) == 0)
  {
    oflag = O_RDONLY;
    fmode = -1;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "rb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "w", 1) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_TRUNC;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "wb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else
  {
    // ADD more strncmp to handle more "mode"
    return false;
  }

  unsigned char check[8] = { 0 };

  bool is_gzip = false;
  bool is_xz   = false;
  bool is_zstd = false;
  bool is_fifo = hc_path_is_fifo (path);

  if (is_fifo == false)
  {
    int fd_tmp = open (path, O_RDONLY);

    if (fd_tmp != -1)
    {
      lseek (fd_tmp, 0, SEEK_SET);

      if (read (fd_tmp, check, sizeof (check)) > 0)
      {
        if (check[0] == 0x1f && check[1] == 0x8b && check[2] == 0x08) is_gzip = true;
        if (memcmp (check, XZ_SIG, sizeof (XZ_SIG)) == 0)            is_xz   = true;
        if (memcmp (check, ZSTD_SIG, sizeof (ZSTD_SIG)) == 0)        is_zstd = true;

        // compressed files with BOM will be undetected!

        if (is_gzip == false && is_xz == false && is_zstd == false)
        {
          fp->bom_size = hc_string_bom_size (check);
        }
      }

      close (fd_tmp);
    }
  }

  if (fmode == -1)
  {
    fp->fd = open (path, oflag);
  }
  else
  {
    fp->fd = open (path, oflag, fmode);
  }

  if (fp->fd == -1) return false;

  if (is_gzip)
  {
    const hc_zlib_lib_t *z = hc_zlib ();

    if (z == NULL)
    {
      fopen_codec_missing ("gzip", hc_zlib_error (), hc_zlib_hint ());

      close (fp->fd);

      return false;
    }

    gzfile_t *gfp = (gzfile_t *) hccalloc (1, sizeof (*gfp));

    if (gfp == NULL)
    {
      close (fp->fd);

      return false;
    }

    gfp->z = z;

    // zlib opens the file itself. It is not handed fp->fd, because a descriptor does not cross a
    // C runtime boundary on Windows, and hashcat's runtime is not the one zlib1.dll was built with.

    if ((gfp->fp = z->gzopen64 (path, mode)) == NULL)
    {
      hcfree (gfp);

      close (fp->fd);

      return false;
    }

    if (z->gzbuffer) z->gzbuffer (gfp->fp, HCFILE_BUFFER_SIZE);

    fp->gfp = gfp;
  }
  else if (is_xz)
  {
    const hc_lzma_lib_t *lz = hc_lzma ();

    if (lz == NULL)
    {
      fopen_codec_missing ("xz", hc_lzma_error (), hc_lzma_hint ());

      close (fp->fd);

      return false;
    }

    xzfile_t *xfp = (xzfile_t *) hccalloc (1, sizeof (*xfp));

    if (xfp == NULL)
    {
      close (fp->fd);

      return false;
    }

    xfp->lz = lz;
    xfp->fd = fp->fd;

    xfp->inbuf = (u8 *) hcmalloc (HCFILE_BUFFER_SIZE);

    if (xfp->inbuf == NULL)
    {
      hcfree (xfp);

      close (fp->fd);

      return false;
    }

    // The index is read first, because it lives at the end of the file and the reader has to start
    // at the beginning. A liblzma too old to have the call leaves the size unknown, which is a
    // question hc_fstat () is allowed to decline.

    xfp->out_size_known = xz_read_index_size (lz, fp->fd, &xfp->out_size);

    if (lseek (fp->fd, 0, SEEK_SET) == (off_t) -1)
    {
      hcfree (xfp->inbuf);
      hcfree (xfp);

      close (fp->fd);

      return false;
    }

    if (lz->lzma_stream_decoder (&xfp->strm, HC_LZMA_MEMLIMIT_NONE, HC_LZMA_CONCATENATED) != HC_LZMA_OK)
    {
      hcfree (xfp->inbuf);
      hcfree (xfp);

      close (fp->fd);

      return false;
    }

    fp->xfp = xfp;
  }
  else if (is_zstd)
  {
    const hc_zstd_lib_t *z = hc_zstd ();

    if (z == NULL)
    {
      fopen_codec_missing ("zstd", hc_zstd_error (), hc_zstd_hint ());

      close (fp->fd);

      return false;
    }

    zstdfile_t *zfp = (zstdfile_t *) hccalloc (1, sizeof (*zfp));

    if (zfp == NULL)
    {
      close (fp->fd);

      return false;
    }

    zfp->z  = z;
    zfp->fd = fp->fd;

    zfp->inbuf = (u8 *) hcmalloc (HCFILE_BUFFER_SIZE);

    if (zfp->inbuf == NULL)
    {
      hcfree (zfp);

      close (fp->fd);

      return false;
    }

    zfp->zds = z->ZSTD_createDStream ();

    if (zfp->zds == NULL)
    {
      hcfree (zfp->inbuf);
      hcfree (zfp);

      close (fp->fd);

      return false;
    }

    if (z->ZSTD_isError (z->ZSTD_initDStream (zfp->zds)))
    {
      z->ZSTD_freeDStream (zfp->zds);

      hcfree (zfp->inbuf);
      hcfree (zfp);

      close (fp->fd);

      return false;
    }

    fp->zfp = zfp;
  }
  else
  {
    if ((fp->pfp = fdopen (fp->fd, mode)) == NULL) return false;

    if (fp->bom_size)
    {
      // atm just skip bom

      const int nread = fread (check, sizeof (char), fp->bom_size, fp->pfp);

      if (nread != fp->bom_size) return false;
    }
  }

  fp->path = path;
  fp->mode = mode;

  return true;
}

// A read only file over a buffer that is already in memory.
//
// Nothing is copied and nothing is freed on close, so whatever produced the buffer owns it and has to
// outlive the handle. That is the whole point: one decompressed archive backs a reader per member
// without a copy apiece.

bool hc_fopen_mem (HCFILE *fp, const u8 *buf, const size_t len)
{
  if (fp == NULL) return false;

  fopen_err_set = false;
  if (buf == NULL && len > 0) return false;

  fp->fd       = -1;
  fp->pfp      = NULL;
  fp->gfp      = NULL;
  fp->xfp      = NULL;
  fp->zfp      = NULL;
  fp->mfp      = NULL;
  fp->bom_size = 0;
  fp->path     = NULL;
  fp->mode     = NULL;

  fp->uncompressed_size = (off_t) len;

  memfile_t *mfp = (memfile_t *) hccalloc (1, sizeof (*mfp));

  if (mfp == NULL) return false;

  mfp->buf = buf;
  mfp->len = len;
  mfp->pos = 0;

  fp->mfp  = mfp;
  fp->mode = "rb";

  return true;
}

bool hc_fopen_raw (HCFILE *fp, const char *path, const char *mode)
{
  if (fp == NULL || path == NULL || mode == NULL) return false;

  fopen_err_set = false;

  /* cleanup */
  fp->fd       = -1;
  fp->pfp      = NULL;
  fp->gfp      = NULL;
  fp->xfp      = NULL;
  fp->zfp      = NULL;
  fp->mfp      = NULL;
  fp->bom_size = 0;
  fp->path     = NULL;
  fp->mode     = NULL;

  int oflag = -1;

  int fmode = S_IRUSR|S_IWUSR;

  if (strncmp (mode, "a", 1) == 0 || strncmp (mode, "ab", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_APPEND;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "ab", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "r", 1) == 0 || strncmp (mode, "rb", 2) == 0)
  {
    oflag = O_RDONLY;
    fmode = -1;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "rb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "w", 1) == 0 || strncmp (mode, "wb", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_TRUNC;

    #if defined (MSDOS) || defined (OS2) || defined (WIN32) || defined (_WIN32) || defined (__CYGWIN__)
    if (strncmp (mode, "wb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else
  {
    // ADD more strncmp to handle more "mode"
    return false;
  }

  if (fmode == -1)
  {
    fp->fd = open (path, oflag);
  }
  else
  {
    fp->fd = open (path, oflag, fmode);
  }

  if (fp->fd == -1) return false;

  if ((fp->pfp = fdopen (fp->fd, mode)) == NULL) return false;

  fp->path = path;
  fp->mode = mode;

  return true;
}

size_t hc_fread (void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  size_t n = (size_t) -1;

  // The zero check comes first on purpose. Reading nothing is a no-op that never dereferences ptr, so
  // it succeeds even when the caller has no buffer, which is what an empty container looks like after
  // an allocation for zero elements returned NULL. Testing ptr first turned that into a failure return
  // of (size_t) -1, and a caller comparing it against its own count then reported a short read of
  // 18446744073709551600 bytes.

  if (size == 0 || nmemb == 0) return 0;

  if (ptr == NULL || fp == NULL) return n;

  if (fp->mfp)
  {
    memfile_t *mfp = fp->mfp;

    const size_t want = size * nmemb;
    const size_t left = mfp->len - mfp->pos;
    const size_t take = MIN (want, left);

    memcpy (ptr, mfp->buf + mfp->pos, take);

    mfp->pos += take;

    return take / size;
  }

  if (fp->pfp)
  {
    #ifdef _WIN
    u64 len = (u64) size * nmemb;

    #ifndef _WIN64
    /* check 2 GB limit with 32 bit build */
    if (len >= INT32_MAX) return n;
    #endif

    if (len <= HCFILE_CHUNK_SIZE)
    {
      n = fread (ptr, size, nmemb, fp->pfp);
    }
    else
    {
      size_t left = (size_t) len;
      size_t pos = 0;

      /* assume success */
      n = nmemb;

      do
      {
        size_t chunk = (left > HCFILE_CHUNK_SIZE) ? HCFILE_CHUNK_SIZE : left;
        size_t bytes = fread ((unsigned char *) ptr + pos, 1, chunk, fp->pfp);
        pos += bytes;
        left -= bytes;
        if (chunk != bytes)
        {
          /* partial read */
          n = pos / size;
          break;
        }
      } while (left);
    }
    #else
    n = fread (ptr, size, nmemb, fp->pfp);
    #endif
  }
  else if (fp->gfp)
  {
    const size_t want = size * nmemb;

    size_t done = 0;

    while (done < want)
    {
      // gzread takes an unsigned count, so a read larger than that is handed over in pieces

      const size_t left = want - done;

      const unsigned int chunk = (left > 0x40000000) ? 0x40000000 : (unsigned int) left;

      const int got = fp->gfp->z->gzread (fp->gfp->fp, (u8 *) ptr + done, chunk);

      if (got < 0) return (size_t) -1;
      if (got == 0) break;

      done += (size_t) got;
    }

    n = done / size;

    // Double check to make sure that it successfully read 0 bytes instead of erroring
    if (n == 0)
    {
      int errnum = HC_Z_OK;

      fp->gfp->z->gzerror (fp->gfp->fp, &errnum);

      if (errnum != HC_Z_OK)
      {
        return (size_t) -1;
      }
    }

    fp->uncompressed_size += n;
  }
  else if (fp->xfp)
  {
    const size_t want = size * nmemb;

    const size_t produced = xz_read (fp->xfp, (u8 *) ptr, want);

    n = produced / size;
  }
  else if (fp->zfp)
  {
    const size_t want = size * nmemb;

    const size_t produced = zstd_read (fp->zfp, (u8 *) ptr, want);

    fp->uncompressed_size += produced;

    n = produced / size;
  }

  return n;
}

size_t hc_fwrite (const void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  size_t n = -1;

  // Ordered the same way and for the same reason as hc_fread above.

  if (size == 0 || nmemb == 0) return 0;

  if (ptr == NULL || fp == NULL) return n;

  if (fp->pfp)
  {
    #ifdef _WIN
    u64 len = (u64) size * nmemb;

    #ifndef _WIN64
    /* check 2 GB limit with 32 bit build */
    if (len >= INT32_MAX)
    {
      return n;
    }
    #endif

    if (len <= HCFILE_CHUNK_SIZE)
    {
      n = fwrite (ptr, size, nmemb, fp->pfp);
    }
    else
    {
      size_t left = (size_t) len;
      size_t pos = 0;

      /* assume success */
      n = nmemb;

      do
      {
        size_t chunk = (left > HCFILE_CHUNK_SIZE) ? HCFILE_CHUNK_SIZE : left;
        size_t bytes = fwrite ((unsigned char *) ptr + pos, 1, chunk, fp->pfp);
        pos += bytes;
        left -= bytes;
        if (chunk != bytes) return -1;
      } while (left);
    }
    #else
    n = fwrite (ptr, size, nmemb, fp->pfp);
    #endif
  }
  else if (fp->gfp)
  {
    const size_t want = size * nmemb;

    size_t done = 0;

    while (done < want)
    {
      const size_t left = want - done;

      const unsigned int chunk = (left > 0x40000000) ? 0x40000000 : (unsigned int) left;

      const int got = fp->gfp->z->gzwrite (fp->gfp->fp, (const u8 *) ptr + done, chunk);

      if (got <= 0) break;

      done += (size_t) got;
    }

    n = done / size;
  }

  return n;
}

int hc_fseek (HCFILE *fp, off_t offset, int whence)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->pfp)
  {
    r = fseeko (fp->pfp, offset, whence);
  }
  else if (fp->gfp)
  {
    r = (int) fp->gfp->z->gzseek64 (fp->gfp->fp, offset, whence);
  }
  else if ((fp->xfp) || (fp->zfp))
  {
    // A compressed stream has no byte to seek to, so rewinding to the start is the only move that
    // can be answered without decoding everything in between.

    if (offset == 0 && whence == SEEK_SET)
    {
      hc_rewind (fp);

      r = 0;
    }
    else
    {
      r = -1;
    }
  }

  return r;
}

void hc_rewind (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->pfp)
  {
    rewind (fp->pfp);
  }
  else if (fp->gfp)
  {
    fp->gfp->z->gzrewind (fp->gfp->fp);
  }
  else if (fp->xfp)
  {
    xzfile_t *xfp = fp->xfp;

    xfp->lz->lzma_end (&xfp->strm);

    memset (&xfp->strm, 0, sizeof (xfp->strm));

    xfp->eof_in  = false;
    xfp->eof_out = false;
    xfp->out_pos = 0;

    if (lseek (xfp->fd, 0, SEEK_SET) == (off_t) -1) return;

    xfp->lz->lzma_stream_decoder (&xfp->strm, HC_LZMA_MEMLIMIT_NONE, HC_LZMA_CONCATENATED);
  }
  else if (fp->zfp)
  {
    zstdfile_t *zfp = fp->zfp;

    if (lseek (zfp->fd, 0, SEEK_SET) == (off_t) -1) return;

    zfp->in.src  = zfp->inbuf;
    zfp->in.size = 0;
    zfp->in.pos  = 0;

    zfp->eof_in  = false;
    zfp->eof_out = false;
    zfp->out_pos = 0;

    zfp->z->ZSTD_initDStream (zfp->zds);
  }
}

int hc_fstat (HCFILE *fp, struct stat *buf)
{
  int r = -1;

  if (fp == NULL || buf == NULL || fp->fd == -1) return r;

  r = fstat (fp->fd, buf);
  if (r != 0) return r;

  if (fp->gfp)
  {
    if (fp->uncompressed_size > 0)
    {
      buf->st_size = fp->uncompressed_size;
    }
  }
  else if (fp->xfp)
  {
    const xzfile_t *xfp = fp->xfp;

    if (xfp->out_size_known == true)
    {
      buf->st_size = (off_t) xfp->out_size;
    }
  }
  else if (fp->zfp)
  {
    // A .zst file carries no index, so there is nothing to read the total from without decoding the
    // whole file. What is known is what has been handed out, which is the answer gzip gives too.

    if (fp->uncompressed_size > 0)
    {
      buf->st_size = fp->uncompressed_size;
    }
  }

  return r;
}

off_t hc_ftell (HCFILE *fp)
{
  off_t n = 0;

  if (fp == NULL) return -1;

  if (fp->pfp)
  {
    n = ftello (fp->pfp);
  }
  else if (fp->gfp)
  {
    n = (off_t) fp->gfp->z->gztell64 (fp->gfp->fp);
  }
  else if (fp->xfp)
  {
    const xzfile_t *xfp = fp->xfp;

    n = (off_t) xfp->out_pos;
  }
  else if (fp->zfp)
  {
    const zstdfile_t *zfp = fp->zfp;

    n = (off_t) zfp->out_pos;
  }

  return n;
}

int hc_fputc (int c, HCFILE *fp)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->pfp)
  {
    r = fputc (c, fp->pfp);
  }
  else if (fp->gfp)
  {
    r = fp->gfp->z->gzputc (fp->gfp->fp, c);
  }

  return r;
}

int hc_fgetc (HCFILE *fp)
{
  int r = EOF;

  if (fp == NULL) return r;

  if (fp->mfp)
  {
    memfile_t *mfp = fp->mfp;

    if (mfp->pos >= mfp->len) return EOF;

    r = mfp->buf[mfp->pos];

    mfp->pos++;

    return r;
  }

  if (fp->pfp)
  {
    r = fgetc (fp->pfp);
  }
  else if (fp->gfp)
  {
    r = fp->gfp->z->gzgetc (fp->gfp->fp);
  }
  else if (fp->xfp)
  {
    u8 out;

    if (xz_read (fp->xfp, &out, 1) != 1) return r;

    r = (int) out;
  }
  else if (fp->zfp)
  {
    u8 out;

    if (zstd_read (fp->zfp, &out, 1) != 1) return r;

    r = (int) out;
  }

  return r;
}

char *hc_fgets (char *buf, int len, HCFILE *fp)
{
  char *r = NULL;

  if (fp == NULL || buf == NULL || len <= 0) return r;

  if (fp->mfp)
  {
    memfile_t *mfp = fp->mfp;

    if (mfp->pos >= mfp->len) return NULL;

    // fgets () keeps the newline, terminates, and stops one short of len so the terminator fits

    size_t i = 0;

    while ((i < (size_t) (len - 1)) && (mfp->pos < mfp->len))
    {
      const u8 c = mfp->buf[mfp->pos];

      mfp->pos++;

      buf[i] = (char) c;

      i++;

      if (c == '\n') break;
    }

    buf[i] = 0;

    return buf;
  }

  if (fp->pfp)
  {
    r = fgets (buf, len, fp->pfp);
  }
  else if (fp->gfp)
  {
    r = fp->gfp->z->gzgets (fp->gfp->fp, buf, len);
  }
  else if (fp->xfp)
  {
    u8 *outBuf = (u8 *) buf;

    int outLen = len - 1;

    // One byte at a time, because the line ending is the thing being looked for and a byte past it
    // belongs to the next line. r stays NULL unless a line ending was reached, which is what this
    // reader has always done: a last line with nothing after it is reported as no line at all.

    while (outLen > 0)
    {
      if (xz_read (fp->xfp, outBuf, 1) != 1) break;

      if (*outBuf++ == '\n')
      {
        r = buf;

        break;
      }

      outLen--;
    }

    *outBuf = 0;
  }
  else if (fp->zfp)
  {
    u8 *outBuf = (u8 *) buf;

    int outLen = len - 1;

    while (outLen > 0)
    {
      if (zstd_read (fp->zfp, outBuf, 1) != 1) break;

      if (*outBuf++ == '\n')
      {
        r = buf;

        break;
      }

      outLen--;
    }

    *outBuf = 0;
  }

  return r;
}

int hc_vfprintf (HCFILE *fp, const char *format, va_list ap)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->pfp)
  {
    r = vfprintf (fp->pfp, format, ap);
  }
  else if (fp->gfp)
  {
    if (fp->gfp->z->gzvprintf) r = fp->gfp->z->gzvprintf (fp->gfp->fp, format, ap);
  }

  return r;
}

int hc_fprintf (HCFILE *fp, const char *format, ...)
{
  int r = -1;

  if (fp == NULL) return r;

  va_list ap;

  va_start (ap, format);

  if (fp->pfp)
  {
    r = vfprintf (fp->pfp, format, ap);
  }
  else if (fp->gfp)
  {
    if (fp->gfp->z->gzvprintf) r = fp->gfp->z->gzvprintf (fp->gfp->fp, format, ap);
  }

  va_end (ap);

  return r;
}

int hc_fscanf (HCFILE *fp, const char *format, void *ptr)
{
  if (fp == NULL) return -1;

  char buf[HCBUFSIZ_TINY];

  char *b = hc_fgets (buf, HCBUFSIZ_TINY - 1, fp);

  if (b == NULL)
  {
    return -1;
  }

  sscanf (b, format, ptr);

  return 1;
}

int hc_feof (HCFILE *fp)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->mfp)
  {
    const memfile_t *mfp = fp->mfp;

    return (mfp->pos >= mfp->len);
  }

  if (fp->pfp)
  {
    r = feof (fp->pfp);
  }
  else if (fp->gfp)
  {
    r = fp->gfp->z->gzeof (fp->gfp->fp);
  }
  else if (fp->xfp)
  {
    const xzfile_t *xfp = fp->xfp;

    if (xfp->eof_out == true) return 1;

    r = ((xfp->eof_in == true) && (xfp->strm.avail_in == 0));
  }
  else if (fp->zfp)
  {
    const zstdfile_t *zfp = fp->zfp;

    if (zfp->eof_out == true) return 1;

    r = ((zfp->eof_in == true) && (zfp->in.pos == zfp->in.size));
  }

  return r;
}

void hc_fflush (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->pfp)
  {
    fflush (fp->pfp);
  }
  else if (fp->gfp)
  {
    fp->gfp->z->gzflush (fp->gfp->fp, HC_Z_SYNC_FLUSH);
  }
}

void hc_fsync (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->pfp)
  {
#if defined (_WIN)
    HANDLE h = (HANDLE) _get_osfhandle (fp->fd);

    FlushFileBuffers (h);
#else
    fsync (fp->fd);
#endif
  }
}

void hc_fclose (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->mfp)
  {
    // the buffer belongs to whoever opened this, so only the handle goes

    hcfree (fp->mfp);
  }
  else if (fp->pfp)
  {
    fclose (fp->pfp);
  }
  else if (fp->gfp)
  {
    fp->gfp->z->gzclose (fp->gfp->fp);

    hcfree (fp->gfp);

    // zlib opened its own handle, so this one is still ours to close

    close (fp->fd);
  }
  else if (fp->xfp)
  {
    xzfile_t *xfp = fp->xfp;

    xfp->lz->lzma_end (&xfp->strm);

    hcfree (xfp->inbuf);
    hcfree (xfp);

    close (fp->fd);
  }
  else if (fp->zfp)
  {
    zstdfile_t *zfp = fp->zfp;

    zfp->z->ZSTD_freeDStream (zfp->zds);

    hcfree (zfp->inbuf);
    hcfree (zfp);

    close (fp->fd);
  }

  fp->fd = -1;
  fp->pfp = NULL;
  fp->gfp = NULL;
  fp->xfp = NULL;
  fp->zfp = NULL;
  fp->mfp = NULL;

  fp->path = NULL;
  fp->mode = NULL;
}

// Taking the stream's lock once for a line rather than once for every byte. A plain file is what almost
// everything here is, and hc_fgetc () goes through four branches and a library call for each byte, with
// that call taking the lock every time.
//
// The compressed backends keep the general path. gzgetc () does its own buffering, and the xz one
// decodes a byte at a time whatever is asked of it, so there is nothing to hoist out of those.

#if defined (_WIN)
#define hc_flockfile(f)     _lock_file (f)
#define hc_funlockfile(f)   _unlock_file (f)
#define hc_getc_unlocked(f) _getc_nolock (f)
#else
#define hc_flockfile(f)     flockfile (f)
#define hc_funlockfile(f)   funlockfile (f)
#define hc_getc_unlocked(f) getc_unlocked (f)
#endif

// line_sz is the size of line_buf, and the line is terminated inside it. It used to be read as the
// number of characters that may be STORED, and the terminator then went one past that: a line of
// exactly line_sz bytes wrote line_buf[line_sz], one byte off the end of the buffer.
//
// Every one of the twelve callers passes the size of the buffer it allocated, so that is what the
// parameter already meant everywhere it is used, including a 64 byte stack buffer in ext_sysfs_cpu.c.
// A line long enough to reach the limit is one character shorter now and says so, which is what the
// truncation warning is for.

size_t fgetl (HCFILE *fp, char *line_buf, const size_t line_sz)
{
  if (line_sz == 0) return 0;

  const size_t line_max = line_sz - 1;

  int c;

  size_t line_len = 0;

  size_t line_truncated = 0;

  if (fp->pfp)
  {
    hc_flockfile (fp->pfp);

    while ((c = hc_getc_unlocked (fp->pfp)) != EOF)
    {
      if (c == '\n') break;

      if (line_len == line_max)
      {
        line_truncated++;
      }
      else
      {
        line_buf[line_len] = (char) c;

        line_len++;
      }
    }

    hc_funlockfile (fp->pfp);
  }
  else
  {
    while ((c = hc_fgetc (fp)) != EOF)
    {
      if (c == '\n') break;

      if (line_len == line_max)
      {
        line_truncated++;
      }
      else
      {
        line_buf[line_len] = (char) c;

        line_len++;
      }
    }
  }

  if (line_truncated > 0)
  {
    fprintf (stderr, "\nOversized line detected! Truncated %" PRIu64 " bytes\n", (u64) line_truncated);
  }
  else
  {
    while (line_len > 0 && line_buf[line_len - 1] == '\r')
    {
      line_len--;
    }
  }

  line_buf[line_len] = 0;

  return line_len;
}

// How many lines a file holds, which is how many line endings it has plus a last line that has none.
//
// The blocks were always read whole, but the line endings inside them were counted a byte at a time,
// and each step of that loop depended on the one before it so nothing could overlap. hc_memchr finds
// them a vector at a time instead.

u64 count_lines (HCFILE *fp)
{
  u64 cnt = 0;

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE + 1);

  hc_memchr_t hc_memchr = hc_memchr_get ();

  bool any  = false;
  char last = '\n';

  while (!hc_feof (fp))
  {
    const size_t nread = hc_fread (buf, sizeof (char), HCBUFSIZ_LARGE, fp);

    if (nread < 1) continue;

    any = true;

    size_t off = 0;

    while (off < nread)
    {
      const size_t step = hc_memchr ((const u8 *) buf + off, '\n', nread - off);

      if (step == (nread - off)) break;

      cnt++;

      off += step + 1;
    }

    last = buf[nread - 1];
  }

  // A file whose last line has no line ending after it still has that line in it. A file that ends on
  // one does not have an empty line after it.

  if ((any == true) && (last != '\n')) cnt++;

  hcfree (buf);

  return cnt;
}

size_t in_superchop (char *buf)
{
  size_t len = strlen (buf);

  while (len)
  {
    if (buf[len - 1] == '\n')
    {
      len--;

      buf[len] = 0;

      continue;
    }

    if (buf[len - 1] == '\r')
    {
      len--;

      buf[len] = 0;

      continue;
    }

    break;
  }

  return len;
}

size_t superchop_with_length (char *buf, const size_t len)
{
  size_t new_len = len;

  while (new_len)
  {
    if (buf[new_len - 1] == '\n')
    {
      new_len--;

      buf[new_len] = 0;

      continue;
    }

    if (buf[new_len - 1] == '\r')
    {
      new_len--;

      buf[new_len] = 0;

      continue;
    }

    break;
  }

  return new_len;
}

bool hc_path_has_bom (const char *path)
{
  u8 buf[8] = { 0 };

  HCFILE fp;

  if (hc_fopen_raw (&fp, path, "rb") == false) return false;

  const size_t nread = hc_fread (buf, 1, sizeof (buf), &fp);

  hc_fclose (&fp);

  if (nread < 1) return false;

  const int bom_size = hc_string_bom_size (buf);

  const bool has_bom = bom_size > 0;

  return has_bom;
}

bool hc_same_files (char *file1, char *file2)
{
  if ((file1 != NULL) && (file2 != NULL))
  {
    if (hc_path_is_fifo (file1) == true || hc_path_is_fifo (file2) == true)
    {
      return false;
    }

    struct stat tmpstat_file1;
    struct stat tmpstat_file2;

    memset (&tmpstat_file1, 0, sizeof (tmpstat_file1));
    memset (&tmpstat_file2, 0, sizeof (tmpstat_file2));

    int do_check = 0;

    HCFILE fp;

    if (hc_fopen (&fp, file1, "r") == true)
    {
      if (hc_fstat (&fp, &tmpstat_file1))
      {
        hc_fclose (&fp);

        return false;
      }

      hc_fclose (&fp);

      do_check++;
    }

    if (hc_fopen (&fp, file2, "r") == true)
    {
      if (hc_fstat (&fp, &tmpstat_file2))
      {
        hc_fclose (&fp);

        return false;
      }

      hc_fclose (&fp);

      do_check++;
    }

    if (do_check == 2)
    {
      tmpstat_file1.st_mode     = 0;
      tmpstat_file1.st_nlink    = 0;
      tmpstat_file1.st_uid      = 0;
      tmpstat_file1.st_gid      = 0;
      tmpstat_file1.st_rdev     = 0;
      tmpstat_file1.st_atime    = 0;

      #if defined (STAT_NANOSECONDS_ACCESS_TIME)
      tmpstat_file1.STAT_NANOSECONDS_ACCESS_TIME = 0;
      #endif

      #if defined (_POSIX)
      tmpstat_file1.st_blksize  = 0;
      tmpstat_file1.st_blocks   = 0;
      #endif

      tmpstat_file2.st_mode     = 0;
      tmpstat_file2.st_nlink    = 0;
      tmpstat_file2.st_uid      = 0;
      tmpstat_file2.st_gid      = 0;
      tmpstat_file2.st_rdev     = 0;
      tmpstat_file2.st_atime    = 0;

      #if defined (STAT_NANOSECONDS_ACCESS_TIME)
      tmpstat_file2.STAT_NANOSECONDS_ACCESS_TIME = 0;
      #endif

      #if defined (_POSIX)
      tmpstat_file2.st_blksize  = 0;
      tmpstat_file2.st_blocks   = 0;
      #endif

      if (memcmp (&tmpstat_file1, &tmpstat_file2, sizeof (struct stat)) == 0)
      {
        return true;
      }
    }
  }

  return false;
}

char *file_to_buffer (const char *filename)
{
  HCFILE fp;

  if (hc_fopen (&fp, filename, "r") == true)
  {
    struct stat st;

    memset (&st, 0, sizeof (st));

    if (hc_fstat (&fp, &st))
    {
      hc_fclose (&fp);

      return NULL;
    }

    char *buffer = malloc (st.st_size + 1);

    const size_t nread = hc_fread (buffer, 1, st.st_size, &fp);

    hc_fclose (&fp);

    buffer[nread] = 0;

    return buffer;
  }

  return NULL;
}
