/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_DISPATCH_H
#define HC_DISPATCH_H

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

#endif // HC_DISPATCH_H
