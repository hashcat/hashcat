/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INDUCT_H
#define _INDUCT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define INDUCT_DIR "induct"

int sort_by_mtime (const void *p1, const void *p2);

#endif // _INDUCT_H
