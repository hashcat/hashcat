/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "logging.h"
#include "locking.h"

#ifdef F_SETLKW

void lock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_WRLCK;

  while (fcntl (fileno (fp), F_SETLKW, &lock))
  {
    if (errno != EINTR)
    {
      log_error ("ERROR: Failed acquiring write lock: %s", strerror (errno));

      exit (-1);
    }
  }
}

void unlock_file (FILE *fp)
{
  struct flock lock;

  memset (&lock, 0, sizeof (struct flock));

  lock.l_type = F_UNLCK;

  fcntl (fileno (fp), F_SETLK, &lock);
}

#endif // F_SETLKW
