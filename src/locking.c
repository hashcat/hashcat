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

  if (fcntl (fileno (fp), F_SETLKW, &lock)) return -1;

  return 0;
}

void unlock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_UNLCK;

  fcntl (fileno (fp), F_SETLK, &lock);
}

#endif // F_SETLKW
