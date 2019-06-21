/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _FILEHANDLING_H
#define _FILEHANDLING_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

//u64 count_lines (FILE *fd);
u64 count_lines (fp_tmp_t *fp_t);

//size_t fgetl (FILE *fp, char *line_buf);
size_t fgetl (fp_tmp_t *fp_t, char *line_buf);

size_t superchop_with_length (char *buf, const size_t len);

size_t in_superchop (char *buf);

#endif // _FILEHANDLING_H
