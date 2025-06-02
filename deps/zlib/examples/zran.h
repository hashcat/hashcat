/* zran.h -- example of deflated stream indexing and random access
 * Copyright (C) 2005, 2012, 2018, 2023, 2024 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 * Version 1.5  4 Feb 2024  Mark Adler */

#include <stdio.h>
#include "zlib.h"

// Access point.
typedef struct point {
    off_t out;          // offset in uncompressed data
    off_t in;           // offset in compressed file of first full byte
    int bits;           // 0, or number of bits (1-7) from byte at in-1
    unsigned dict;      // number of bytes in window to use as a dictionary
    unsigned char *window;  // preceding 32K (or less) of uncompressed data
} point_t;

// Access point list.
struct deflate_index {
    int have;           // number of access points in list
    int mode;           // -15 for raw, 15 for zlib, or 31 for gzip
    off_t length;       // total length of uncompressed data
    point_t *list;      // allocated list of access points
    z_stream strm;      // re-usable inflate engine for extraction
};

// Make one pass through a zlib, gzip, or raw deflate compressed stream and
// build an index, with access points about every span bytes of uncompressed
// output. gzip files with multiple members are fully indexed. span should be
// chosen to balance the speed of random access against the memory requirements
// of the list, which is about 32K bytes per access point. The return value is
// the number of access points on success (>= 1), Z_MEM_ERROR for out of
// memory, Z_BUF_ERROR for a premature end of input, Z_DATA_ERROR for a format
// or verification error in the input file, or Z_ERRNO for a file read error.
// On success, *built points to the resulting index, otherwise it's NULL.
int deflate_index_build(FILE *in, off_t span, struct deflate_index **built);

// Use the index to read len bytes from offset into buf. Return the number of
// bytes read or a negative error code. If data is requested past the end of
// the uncompressed data, then deflate_index_extract() will return a value less
// than len, indicating how much was actually read into buf. If given a valid
// index, this function should not return an error unless the file was modified
// somehow since the index was generated, given that deflate_index_build() had
// validated all of the input. If nevertheless there is a failure, Z_BUF_ERROR
// is returned if the compressed data ends prematurely, Z_DATA_ERROR if the
// deflate compressed data is not valid, Z_MEM_ERROR if out of memory,
// Z_STREAM_ERROR if the index is not valid, or Z_ERRNO if there is an error
// reading or seeking on the input file.
ptrdiff_t deflate_index_extract(FILE *in, struct deflate_index *index,
                                off_t offset, unsigned char *buf, size_t len);

// Deallocate an index built by deflate_index_build().
void deflate_index_free(struct deflate_index *index);
