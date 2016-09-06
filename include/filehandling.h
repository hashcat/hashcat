/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _FILEHANDLING_H
#define _FILEHANDLING_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

uint count_lines (FILE *fd);

int fgetl (FILE *fp, char *line_buf);

int in_superchop (char *buf);

#endif // _FILEHANDLING_H
