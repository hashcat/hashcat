/*-
 * Copyright 2014 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _INSECURE_MEMZERO_H_
#define _INSECURE_MEMZERO_H_

#ifdef SKIP_MEMZERO
#define insecure_memzero(buf, len) /* empty */
#else

#include <stddef.h>

/* Pointer to memory-zeroing function. */
extern void (* volatile insecure_memzero_ptr)(volatile void *, size_t);

/**
 * insecure_memzero(buf, len):
 * Attempt to zero ${len} bytes at ${buf} in spite of optimizing compilers'
 * best (standards-compliant) attempts to remove the buffer-zeroing.  In
 * particular, to avoid performing the zeroing, a compiler would need to
 * use optimistic devirtualization; recognize that non-volatile objects do not
 * need to be treated as volatile, even if they are accessed via volatile
 * qualified pointers; and perform link-time optimization; in addition to the
 * dead-code elimination which often causes buffer-zeroing to be elided.
 *
 * Note however that zeroing a buffer does not guarantee that the data held
 * in the buffer is not stored elsewhere; in particular, there may be copies
 * held in CPU registers or in anonymous allocations on the stack, even if
 * every named variable is successfully sanitized.  Solving the "wipe data
 * from the system" problem will require a C language extension which does not
 * yet exist.
 *
 * For more information, see:
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 * http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html
 */
static inline void
insecure_memzero(volatile void * buf, size_t len)
{

	(insecure_memzero_ptr)(buf, len);
}

#endif

#endif /* !_INSECURE_MEMZERO_H_ */
