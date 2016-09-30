/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _FILEHANDLING_H
#define _FILEHANDLING_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

u64 count_lines (FILE *fd);

int fgetl (FILE *fp, char *line_buf);

int in_superchop (char *buf);

#endif // _FILEHANDLING_H
