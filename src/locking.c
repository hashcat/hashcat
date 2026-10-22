/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "locking.h"
#include "shared.h"

#if defined (F_SETLKW)

int hc_lockfile (HCFILE *fp)
{
  if (fp == NULL) return -1;

  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_WRLCK;

  while (fcntl (fp->fd, F_SETLKW, &lock))
  {
    // These shouldn't happen with F_SETLKW yet are (rarely) seen IRL. Recoverable!
    if (errno == EAGAIN || errno == ENOLCK)
    {
      struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };
      select (0, NULL, NULL, NULL, &tv);

      continue;
    }

    // A signal may interrupt a wait for lock with EINTR. Anything else is fatal
    if (errno != EINTR) return -1;
  }

  return 0;
}

int hc_unlockfile (HCFILE *fp)
{
  if (fp == NULL) return -1;

  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_UNLCK;

  if (fcntl (fp->fd, F_SETLK, &lock)) return -1;

  return 0;
}

#else

int hc_lockfile (HCFILE *fp)
{
  if (fp == NULL) return -1;

  HANDLE hFile = (HANDLE) _get_osfhandle (fp->fd);

  if (hFile == INVALID_HANDLE_VALUE) return -1;

  OVERLAPPED ov;

  memset (&ov, 0, sizeof (OVERLAPPED));

  if (LockFileEx (hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ov) == 0) return -1;

  return 0;
}

int hc_unlockfile (HCFILE *fp)
{
  if (fp == NULL) return -1;

  HANDLE hFile = (HANDLE) _get_osfhandle (fp->fd);

  if (hFile == INVALID_HANDLE_VALUE) return -1;

  OVERLAPPED ov;

  memset (&ov, 0, sizeof (OVERLAPPED));

  if (UnlockFileEx (hFile, 0, MAXDWORD, MAXDWORD, &ov) == 0) return -1;

  return 0;
}

#endif // F_SETLKW

// hc_lockfile () already retries EAGAIN and ENOLCK and tolerates EINTR, so a -1 out of it means a
// bad descriptor or a filesystem that refuses F_SETLKW outright. Such a filesystem refuses it on
// every attempt, not on one of them. The potfile, the outfile, the loopback file and the debug file
// are all written on the way out of a cracked hash, so a warning that spoke every time would put
// hundreds of thousands of lines on the terminal for a run against a large list. These two warn on
// the first failure for a file and stay quiet after it.
//
// The flag lives with the caller because it has to outlive the descriptor. The outfile is reopened
// around every write and logfile_append () opens a handle of its own on each call, so a flag carried
// in the HCFILE would be back to false before the next failure. One flag covers both directions: a
// file hashcat cannot lock is a file it cannot unlock either.

void hc_lockfile_warn (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *filename, bool *warned)
{
  if (hc_lockfile (fp) == 0) return;

  if (*warned == true) return;

  *warned = true;

  event_log_error (hashcat_ctx, "%s: Failed to lock file.", filename);
}

void hc_unlockfile_warn (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *filename, bool *warned)
{
  if (hc_unlockfile (fp) == 0) return;

  if (*warned == true) return;

  *warned = true;

  event_log_error (hashcat_ctx, "%s: Failed to unlock file.", filename);
}
