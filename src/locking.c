/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "locking.h"

#if defined (F_SETLKW)

int lock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_WRLCK;

  /* Needs this loop because a signal may interrupt a wait for lock */
  while (fcntl (fileno (fp), F_SETLKW, &lock))
  {
    if (errno != EINTR) return -1;
  }

  return 0;
}

int unlock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_UNLCK;

  if (fcntl (fileno (fp), F_SETLK, &lock))
  {
    return -1;
  }

  return 0;
}

#else

int lock_file (MAYBE_UNUSED FILE *fp)
{
  // we should put windows specific code here

  return 0;
}

int unlock_file (MAYBE_UNUSED FILE *fp)
{
  // we should put windows specific code here

  return 0;
}

#endif // F_SETLKW
