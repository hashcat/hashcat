/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "locking.h"
#include "shared.h"

#if defined (F_SETLKW)

int hc_lockfile (HCFILE *fp)
{
  if (fp == NULL) return -1;

  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_WRLCK;

  /* Needs this loop because a signal may interrupt a wait for lock */
  while (fcntl (hc_fileno (fp), F_SETLKW, &lock))
  {
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

  if (fcntl (hc_fileno (fp), F_SETLK, &lock)) return -1;

  return 0;
}

#else

int hc_lockfile (MAYBE_UNUSED HCFILE *fp)
{
  // we should put windows specific code here

  return 0;
}

int hc_unlockfile (MAYBE_UNUSED HCFILE *fp)
{
  // we should put windows specific code here

  return 0;
}

#endif // F_SETLKW
