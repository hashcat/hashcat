/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _LOCKING_H
#define _LOCKING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int hc_lockfile   (HCFILE *fp);
int hc_unlockfile (HCFILE *fp);

#endif // _LOCKING_H
