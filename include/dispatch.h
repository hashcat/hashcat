/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DISPATCH_H
#define _DISPATCH_H

#ifdef WITH_BRAIN
#if defined (_WIN)
#include <winsock.h>
#define SEND_FLAGS 0
#endif

#if defined (__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define SEND_FLAGS MSG_NOSIGNAL
#endif
#endif

HC_API_CALL void *thread_calc_stdin (void *p);
HC_API_CALL void *thread_calc (void *p);

#endif // _DISPATCH_H
