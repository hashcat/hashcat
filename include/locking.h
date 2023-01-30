/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_LOCKING_H
#define HC_LOCKING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int hc_lockfile   (HCFILE *fp);
int hc_unlockfile (HCFILE *fp);

#endif // HC_LOCKING_H
