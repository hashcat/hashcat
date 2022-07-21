/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "limits.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"

#include <Alloc.h>
#include <7zCrc.h>
#include <7zFile.h>
#include <Xz.h>
#include <XzCrc64.h>

/* Maybe _LZMA_NO_SYSTEM_SIZE_T defined? */
#if defined (__clang__) || defined (__GNUC__)
#include <assert.h>
_Static_assert(sizeof (size_t) == sizeof (SizeT), "Check why sizeof(size_t) != sizeof(SizeT)");
#endif

#ifndef HCFILE_BUFFER_SIZE
#define HCFILE_BUFFER_SIZE 256 * 1024
#endif

#ifndef HCFILE_CHUNK_SIZE
#define HCFILE_CHUNK_SIZE 4 * 1024 * 1024
#endif

static bool xz_initialized = false;

static const ISzAlloc xz_alloc = { hc_lzma_alloc, hc_lzma_free };

struct xzfile
{
  CAlignOffsetAlloc  alloc;
  UInt64             inBlocks;
  Byte              *inBuf;
  bool               inEof;
  SizeT              inLen;
  SizeT              inPos;
  Int64              inProcessed;
  CFileInStream      inStream;
  Int64              outProcessed;
  UInt64             outSize;
  CXzUnpacker        state;
  CXzs               streams;
};

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

bool hc_fopen (HCFILE *fp, const char *path, const char *mode)
{
  if (fp == NULL || path == NULL || mode == NULL) return false;

  /* cleanup */
  fp->fd       = -1;
  fp->pfp      = NULL;
  fp->gfp      = NULL;
  fp->ufp      = NULL;
  fp->xfp      = NULL;
  fp->bom_size = 0;
  fp->path     = NULL;
  fp->mode     = NULL;

  int oflag = -1;

  int fmode = S_IRUSR|S_IWUSR;

  if (strncmp (mode, "a", 1) == 0 || strncmp (mode, "ab", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_APPEND;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "ab", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "r", 1) == 0 || strncmp (mode, "rb", 2) == 0)
  {
    oflag = O_RDONLY;
    fmode = -1;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "rb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "w", 1) == 0 || strncmp (mode, "wb", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_TRUNC;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
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
  bool is_zip  = false;
  bool is_xz   = false;

  int fd_tmp = open (path, O_RDONLY);

  if (fd_tmp != -1)
  {
    lseek (fd_tmp, 0, SEEK_SET);

    if (read (fd_tmp, check, sizeof (check)) > 0)
    {
      if (check[0] == 0x1f && check[1] == 0x8b && check[2] == 0x08)                     is_gzip = true;
      if (check[0] == 0x50 && check[1] == 0x4b && check[2] == 0x03 && check[3] == 0x04) is_zip  = true;
      if (memcmp (check, XZ_SIG, XZ_SIG_SIZE) == 0)                                     is_xz   = true;

      // compressed files with BOM will be undetected!

      if (is_gzip == false && is_zip == false && is_xz == false)
      {
        fp->bom_size = hc_string_bom_size (check);
      }
    }

    close (fd_tmp);
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
    if ((fp->gfp = gzdopen (fp->fd, mode)) == NULL) return false;

    gzbuffer (fp->gfp, HCFILE_BUFFER_SIZE);
  }
  else if (is_zip)
  {
    if ((fp->ufp = unzOpen64 (path)) == NULL) return false;

    if (unzOpenCurrentFile (fp->ufp) != UNZ_OK) return false;
  }
  else if (is_xz)
  {
    /* thread safe on little endian */
    if (xz_initialized == false)
    {
      CrcGenerateTable ();
      Crc64GenerateTable ();
      Sha256Prepare ();
      xz_initialized = true;
    }

    xzfile_t *xfp = (xzfile_t *) hccalloc (1, sizeof (*xfp));
    if (xfp == NULL) return false;

    /* prepare cache line aligned memory allocator */
    AlignOffsetAlloc_CreateVTable (&xfp->alloc);
    xfp->alloc.numAlignBits = 7;
    xfp->alloc.baseAlloc = &xz_alloc;
    ISzAllocPtr alloc = &xfp->alloc.vt;
    xfp->inBuf = (Byte *) ISzAlloc_Alloc (alloc, HCFILE_BUFFER_SIZE);
    if (xfp->inBuf == NULL)
    {
      hcfree (xfp);
      close (fp->fd);
      return false;
    }

    /* open the file */
    CFileInStream *inStream = &xfp->inStream;
    FileInStream_CreateVTable (inStream);
    CSzFile *file = &inStream->file;
    File_Construct (file);
    WRes wres = InFile_Open (file, path);
    if (wres != SZ_OK)
    {
      ISzAlloc_Free (alloc, xfp->inBuf);
      hcfree (xfp);
      close (fp->fd);
      return false;
    }

    /* scan the file */
    CLookToRead2 lookStream;
    LookToRead2_CreateVTable (&lookStream, false);
    lookStream.buf = xfp->inBuf;
    lookStream.bufSize = HCFILE_BUFFER_SIZE;
    lookStream.realStream = &inStream->vt;
    LookToRead2_Init (&lookStream);
    Xzs_Construct (&xfp->streams);
    Int64 offset = 0;
    SRes res = Xzs_ReadBackward (&xfp->streams, &lookStream.vt, &offset, NULL, alloc);
    if (res != SZ_OK || offset != 0)
    {
      Xzs_Free (&xfp->streams, alloc);
      File_Close (file);
      ISzAlloc_Free (alloc, xfp->inBuf);
      hcfree (xfp);
      close (fp->fd);
      return false;
    }

    xfp->inBlocks = Xzs_GetNumBlocks (&xfp->streams);
    xfp->outSize = Xzs_GetUnpackSize (&xfp->streams);

    /* seek to start of the file and fill the buffer */
    SizeT inLen = HCFILE_BUFFER_SIZE;
    res = ISeekInStream_Seek (&inStream->vt, &offset, SZ_SEEK_SET);
    if (res == SZ_OK)
    {
      res = ISeekInStream_Read (&inStream->vt, xfp->inBuf, &inLen);
    }
    if (res != SZ_OK || inLen == 0)
    {
      Xzs_Free (&xfp->streams, alloc);
      File_Close (file);
      ISzAlloc_Free (alloc, xfp->inBuf);
      hcfree (xfp);
      close (fp->fd);
      return false;
    }

    xfp->inLen = inLen;

    /* read headers */
    SizeT outLen = 0;
    ECoderStatus status;
    CXzUnpacker *state = &xfp->state;
    XzUnpacker_Construct (state, alloc);
    res = XzUnpacker_Code (state, NULL, &outLen, xfp->inBuf, &inLen, false, CODER_FINISH_ANY, &status);
    if (res != SZ_OK)
    {
      XzUnpacker_Free (state);
      Xzs_Free (&xfp->streams, alloc);
      File_Close (file);
      ISzAlloc_Free (alloc, xfp->inBuf);
      hcfree (xfp);
      close (fp->fd);
      return false;
    }

    xfp->inPos = inLen;
    xfp->inProcessed = inLen;
    fp->xfp = xfp;
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

bool hc_fopen_raw (HCFILE *fp, const char *path, const char *mode)
{
  if (fp == NULL || path == NULL || mode == NULL) return false;

  /* cleanup */
  fp->fd       = -1;
  fp->pfp      = NULL;
  fp->gfp      = NULL;
  fp->ufp      = NULL;
  fp->xfp      = NULL;
  fp->bom_size = 0;
  fp->path     = NULL;
  fp->mode     = NULL;

  int oflag = -1;

  int fmode = S_IRUSR|S_IWUSR;

  if (strncmp (mode, "a", 1) == 0 || strncmp (mode, "ab", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_APPEND;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "ab", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "r", 1) == 0 || strncmp (mode, "rb", 2) == 0)
  {
    oflag = O_RDONLY;
    fmode = -1;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "rb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "w", 1) == 0 || strncmp (mode, "wb", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_TRUNC;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
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

  if (ptr == NULL || fp == NULL) return n;

  if (size == 0 || nmemb == 0) return 0;

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
    n = gzfread (ptr, size, nmemb, fp->gfp);
  }
  else if (fp->ufp)
  {
    u64 len = (u64) size * nmemb;
    u64 pos = 0;

    #if defined(_WIN) && !defined(_WIN64)
    /* check 2 GB limit with 32 bit build */
    if (len >= INT32_MAX) return n;
    #endif

    /* assume success */
    n = nmemb;

    do
    {
      unsigned chunk = (len > INT_MAX) ? INT_MAX : (unsigned) len;
      int result = unzReadCurrentFile (fp->ufp, (unsigned char *) ptr + pos, chunk);
      if (result < 0) return (size_t) -1;
      pos += (u64) result;
      len -= (u64) result;
      if (chunk != (unsigned) result)
      {
        /* partial read */
        n = pos / size;
        break;
      }
    } while (len);
  }
  else if (fp->xfp)
  {
    Byte *outBuf = (Byte *) ptr;
    SizeT outLen = (SizeT) size * nmemb;
    SizeT outPos = 0;
    SRes res = SZ_OK;
    xzfile_t *xfp = fp->xfp;

    #if defined(_WIN) && !defined(_WIN64)
    /* check 2 GB limit with 32 bit build */
    if (outLen >= INT32_MAX) return n;
    #endif

    /* assume success */
    n = nmemb;

    do
    {
      /* fill buffer if needed */
      if (xfp->inLen == xfp->inPos && !xfp->inEof)
      {
        xfp->inPos = 0;
        xfp->inLen = HCFILE_BUFFER_SIZE;
        res = ISeekInStream_Read (&xfp->inStream.vt, xfp->inBuf, &xfp->inLen);
        if (res != SZ_OK || xfp->inLen == 0) xfp->inEof = true;
      }

      /* decode */
      ECoderStatus status;
      SizeT inLeft  = xfp->inLen - xfp->inPos;
      SizeT outLeft = outLen - outPos;
      res = XzUnpacker_Code (&xfp->state, outBuf + outPos, &outLeft, xfp->inBuf + xfp->inPos, &inLeft, inLeft == 0, CODER_FINISH_ANY, &status);
      xfp->inPos += inLeft;
      xfp->inProcessed += inLeft;
      if (res != SZ_OK) return (size_t) -1;
      if (inLeft == 0 && outLeft == 0)
      {
        /* partial read */
        n = (size_t) (outPos / size);
        break;
      }
      outPos += outLeft;
      xfp->outProcessed += outLeft;
    } while (outPos < outLen);
  }

  return n;
}

size_t hc_fwrite (const void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  size_t n = -1;

  if (ptr == NULL || fp == NULL) return n;

  if (size == 0 || nmemb == 0) return 0;

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
    n = gzfwrite (ptr, size, nmemb, fp->gfp);
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
    r = gzseek (fp->gfp, offset, whence);
  }
  else if (fp->ufp)
  {
    /*
    // untested and not used in wordlist engine
    zlib_filefunc64_32_def *d = NULL;
    if (whence == SEEK_SET)
    {
      r = ZSEEK64 (*d, fp->ufp, offset, ZLIB_FILEFUNC_SEEK_SET);
    }
    else if (whence == SEEK_CUR)
    {
      r = ZSEEK64 (*d, fp->ufp, offset, ZLIB_FILEFUNC_SEEK_CUR);
    }
    else if (whence == SEEK_END)
    {
      r = ZSEEK64 (*d, fp->ufp, offset, ZLIB_FILEFUNC_SEEK_END);
    }
    // or
    // r = unzSetOffset (fp->ufp, offset);
    */
  }
  else if (fp->xfp)
  {
    /* TODO */
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
    gzrewind (fp->gfp);
  }
  else if (fp->ufp)
  {
    unzGoToFirstFile (fp->ufp);
  }
  else if (fp->xfp)
  {
    xzfile_t *xfp = fp->xfp;

    /* cleanup */
    xfp->inEof = false;
    xfp->inLen = 0;
    xfp->inPos = 0;
    xfp->inProcessed  = 0;
    xfp->outProcessed = 0;

    /* reset */
    Int64 offset = 0;
    CFileInStream *inStream = &xfp->inStream;
    SRes res = ISeekInStream_Seek (&inStream->vt, &offset, SZ_SEEK_SET);
    if (res != SZ_OK) return;
    CXzUnpacker *state = &xfp->state;
    XzUnpacker_Init (&xfp->state);

    /* fill the buffer */
    SizeT inLen = HCFILE_BUFFER_SIZE;
    res = ISeekInStream_Read (&inStream->vt, xfp->inBuf, &inLen);
    if (res != SZ_OK || inLen == 0) return;

    xfp->inLen = inLen;

    /* read headers */
    SizeT outLen = 0;
    ECoderStatus status;
    XzUnpacker_Code (state, NULL, &outLen, xfp->inBuf, &inLen, false, CODER_FINISH_ANY, &status);
    xfp->inPos = inLen;
    xfp->inProcessed = inLen;
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
    /* TODO: For compressed files hc_ftell() reports uncompressed bytes, but hc_fstat() reports compressed bytes */
  }
  else if (fp->ufp)
  {
    /* TODO: For compressed files hc_ftell() reports uncompressed bytes, but hc_fstat() reports compressed bytes */
  }
  else if (fp->xfp)
  {
    /* check that the uncompressed size is known */
    const xzfile_t *xfp = fp->xfp;
    if (xfp->outSize != (UInt64) ((Int64) -1))
    {
      buf->st_size = (off_t) xfp->outSize;
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
    n = (off_t) gztell (fp->gfp);
  }
  else if (fp->ufp)
  {
    n = unztell (fp->ufp);
  }
  else if (fp->xfp)
  {
    /* uncompressed bytes */
    const xzfile_t *xfp = fp->xfp;
    n = (off_t) xfp->outProcessed;
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
    r = gzputc (fp->gfp, c);
  }

  return r;
}

int hc_fgetc (HCFILE *fp)
{
  int r = EOF;

  if (fp == NULL) return r;

  if (fp->pfp)
  {
    r = fgetc (fp->pfp);
  }
  else if (fp->gfp)
  {
    r = gzgetc (fp->gfp);
  }
  else if (fp->ufp)
  {
    unsigned char c = 0;

    if (unzReadCurrentFile (fp->ufp, &c, 1) == 1) r = (int) c;
  }
  else if (fp->xfp)
  {
    Byte out;
    SRes res = SZ_OK;
    xzfile_t *xfp = fp->xfp;

    /* fill buffer if needed */
    if (xfp->inLen == xfp->inPos && !xfp->inEof)
    {
      xfp->inPos = 0;
      xfp->inLen = HCFILE_BUFFER_SIZE;
      res = ISeekInStream_Read (&xfp->inStream.vt, xfp->inBuf, &xfp->inLen);
      if (res != SZ_OK || xfp->inLen == 0) xfp->inEof = true;
    }

    /* decode single byte */
    ECoderStatus status;
    SizeT inLeft = xfp->inLen - xfp->inPos;
    SizeT outLeft = 1;
    res = XzUnpacker_Code (&xfp->state, &out, &outLeft, xfp->inBuf + xfp->inPos, &inLeft, inLeft == 0, CODER_FINISH_ANY, &status);
    if (inLeft == 0 && outLeft == 0) return r;
    xfp->inPos += inLeft;
    xfp->inProcessed += inLeft;
    if (res != SZ_OK) return r;
    xfp->outProcessed++;
    r = (int) out;
  }

  return r;
}

char *hc_fgets (char *buf, int len, HCFILE *fp)
{
  char *r = NULL;

  if (fp == NULL || buf == NULL || len <= 0) return r;

  if (fp->pfp)
  {
    r = fgets (buf, len, fp->pfp);
  }
  else if (fp->gfp)
  {
    r = gzgets (fp->gfp, buf, len);
  }
  else if (fp->ufp)
  {
    if (unzReadCurrentFile (fp->ufp, buf, len) > 0) r = buf;
  }
  else if (fp->xfp)
  {
    Byte *outBuf = (Byte *) buf;
    SizeT outLen = (SizeT) len - 1;
    SRes res = SZ_OK;
    xzfile_t *xfp = fp->xfp;

    while (outLen > 0)
    {
      /* fill buffer if needed */
      if (xfp->inLen == xfp->inPos && !xfp->inEof)
      {
        xfp->inPos = 0;
        xfp->inLen = HCFILE_BUFFER_SIZE;
        res = ISeekInStream_Read (&xfp->inStream.vt, xfp->inBuf, &xfp->inLen);
        if (res != SZ_OK || xfp->inLen == 0) xfp->inEof = true;
      }

      /* decode single byte */
      ECoderStatus status;
      SizeT inLeft = xfp->inLen - xfp->inPos;
      SizeT outLeft = 1;
      res = XzUnpacker_Code (&xfp->state, outBuf, &outLeft, xfp->inBuf + xfp->inPos, &inLeft, inLeft == 0, CODER_FINISH_ANY, &status);
      if (inLeft == 0 && outLeft == 0) break;
      xfp->inPos += inLeft;
      xfp->inProcessed += inLeft;
      if (res != SZ_OK) break;
      xfp->outProcessed++;
      if (*outBuf++ == '\n')
      {
        /* success */
        r = buf;
        break;
      }

      outLen--;
    }

    /* always NULL terminate */
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
    r = gzvprintf (fp->gfp, format, ap);
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
    r = gzvprintf (fp->gfp, format, ap);
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

  if (fp->pfp)
  {
    r = feof (fp->pfp);
  }
  else if (fp->gfp)
  {
    r = gzeof (fp->gfp);
  }
  else if (fp->ufp)
  {
    r = unzeof (fp->ufp);
  }
  else if (fp->xfp)
  {
    const xzfile_t *xfp = fp->xfp;
    r = (xfp->inEof && xfp->inPos == xfp->inLen);
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
    gzflush (fp->gfp, Z_SYNC_FLUSH);
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

  if (fp->pfp)
  {
    fclose (fp->pfp);
  }
  else if (fp->gfp)
  {
    gzclose (fp->gfp);
  }
  else if (fp->ufp)
  {
    unzCloseCurrentFile (fp->ufp);

    unzClose (fp->ufp);

    close (fp->fd);
  }
  else if (fp->xfp)
  {
    xzfile_t *xfp = fp->xfp;
    ISzAllocPtr alloc = &xfp->alloc.vt;
    XzUnpacker_Free (&xfp->state);
    Xzs_Free (&xfp->streams, alloc);
    File_Close (&xfp->inStream.file);
    ISzAlloc_Free (alloc, xfp->inBuf);
    hcfree (xfp);
    close (fp->fd);
  }

  fp->fd = -1;
  fp->pfp = NULL;
  fp->gfp = NULL;
  fp->ufp = NULL;
  fp->xfp = NULL;

  fp->path = NULL;
  fp->mode = NULL;
}

size_t fgetl (HCFILE *fp, char *line_buf, const size_t line_sz)
{
  int c;

  size_t line_len = 0;

  size_t line_truncated = 0;

  while ((c = hc_fgetc (fp)) != EOF)
  {
    if (c == '\n') break;

    if (line_len == line_sz)
    {
      line_truncated++;
    }
    else
    {
      line_buf[line_len] = (char) c;

      line_len++;
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

u64 count_lines (HCFILE *fp)
{
  u64 cnt = 0;

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE + 1);

  char prev = '\n';

  while (!hc_feof (fp))
  {
    size_t nread = hc_fread (buf, sizeof (char), HCBUFSIZ_LARGE, fp);

    if (nread < 1) continue;

    for (size_t i = 0; i < nread; i++)
    {
      if (prev == '\n') cnt++;

      prev = buf[i];
    }
  }

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
