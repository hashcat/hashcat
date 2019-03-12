/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BRAIN_H
#define _BRAIN_H

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <dirent.h>
#include <search.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#if defined (_WIN)
#define _WINNT_WIN32 0x0601
#include <ws2tcpip.h>
#include <winsock2.h>
#include <wincrypt.h>
#define SEND_FLAGS 0
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#if defined (__linux__)
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif
#endif

#include "xxhash.h"

static const int BRAIN_CLIENT_CONNECT_TIMEOUT     = 5;
static const int BRAIN_SERVER_DUMP_EVERY          = 5 * 60;
static const int BRAIN_SERVER_SESSIONS_MAX        = 64;
static const int BRAIN_SERVER_ATTACKS_MAX         = 64 * 1024;
static const int BRAIN_SERVER_CLIENTS_MAX         = 256;
static const int BRAIN_SERVER_REALLOC_HASH_SIZE   = 1024 * 1024;
static const int BRAIN_SERVER_REALLOC_ATTACK_SIZE = 1024;
static const int BRAIN_HASH_SIZE                  = 2 * sizeof (u32);
static const int BRAIN_LINK_VERSION_CUR           = 1;
static const int BRAIN_LINK_VERSION_MIN           = 1;
static const int BRAIN_LINK_CHUNK_SIZE            = 4 * 1024;
static const int BRAIN_LINK_CANDIDATES_MAX        = 128 * 1024 * 256; // units * threads * accel

typedef enum brain_operation
{
  BRAIN_OPERATION_COMMIT         = 1,
  BRAIN_OPERATION_HASH_LOOKUP    = 2,
  BRAIN_OPERATION_ATTACK_RESERVE = 3,

} brain_operation_t;

typedef enum brain_client_feature
{
  BRAIN_CLIENT_FEATURE_HASHES    = 1,
  BRAIN_CLIENT_FEATURE_ATTACKS   = 2,

} brain_client_feature_t;

typedef struct brain_server_attack_long
{
  u64 offset;
  u64 length;

} brain_server_attack_long_t;

typedef struct brain_server_attack_short
{
  u64 offset;
  u64 length;

  int client_idx;

} brain_server_attack_short_t;

typedef struct brain_server_hash_long
{
  u32 hash[2];

} brain_server_hash_long_t;

typedef struct brain_server_hash_short
{
  u32 hash[2];

} brain_server_hash_short_t;

typedef struct brain_server_hash_unique
{
  u32 hash[2];

  i64 hash_idx;

} brain_server_hash_unique_t;

typedef struct brain_server_db_attack
{
  u32 brain_attack;

  brain_server_attack_short_t *short_buf;

  i64 short_alloc;
  i64 short_cnt;

  brain_server_attack_long_t *long_buf;

  i64 long_alloc;
  i64 long_cnt;

  int ab;

  hc_thread_mutex_t mux_ar;
  hc_thread_mutex_t mux_ag;

  bool write_attacks;

} brain_server_db_attack_t;

typedef struct brain_server_db_hash
{
  u32 brain_session;

  brain_server_hash_long_t *long_buf;

  i64 long_alloc;
  i64 long_cnt;

  int hb;

  hc_thread_mutex_t mux_hr;
  hc_thread_mutex_t mux_hg;

  bool write_hashes;

} brain_server_db_hash_t;

typedef struct brain_server_db_short
{
  brain_server_hash_short_t *short_buf;

  i64 short_cnt;

} brain_server_db_short_t;

typedef struct brain_server_dbs
{
  // required for cyclic dump

  hc_thread_mutex_t mux_dbs;

  brain_server_db_hash_t   *hash_buf;
  brain_server_db_attack_t *attack_buf;

  int hash_cnt;
  int attack_cnt;

  int *client_slots;

} brain_server_dbs_t;

typedef struct brain_server_dumper_options
{
  brain_server_dbs_t *brain_server_dbs;

} brain_server_dumper_options_t;

typedef struct brain_server_client_options
{
  brain_server_dbs_t *brain_server_dbs;

  int client_idx;
  int client_fd;

  char *auth_password;

  u32 *session_whitelist_buf;
  int  session_whitelist_cnt;

} brain_server_client_options_t;

int   brain_logging                     (FILE *stream, const int client_idx, const char *format, ...);

u32   brain_compute_session             (hashcat_ctx_t *hashcat_ctx);
u32   brain_compute_attack              (hashcat_ctx_t *hashcat_ctx);
u64   brain_compute_attack_wordlist     (const char *filename);

u32   brain_auth_challenge              (void);
u64   brain_auth_hash                   (const u32 challenge, const char *pw_buf, const int pw_len);

int   brain_connect                     (int sockfd, const struct sockaddr *addr, socklen_t addrlen, const int timeout);
bool  brain_recv                        (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_send                        (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_recv_all                    (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_send_all                    (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);

bool  brain_client_reserve              (hc_device_param_t *device_param, const status_ctx_t *status_ctx, u64 words_off, u64 work, u64 *overlap);
bool  brain_client_commit               (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_client_lookup               (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_client_connect              (hc_device_param_t *device_param, const status_ctx_t *status_ctx, const char *host, const int port, const char *password, u32 brain_session, u32 brain_attack, i64 passwords_max, u64 *highest);
void  brain_client_disconnect           (hc_device_param_t *device_param);
void  brain_client_generate_hash        (u64 *hash, const char *line_buf, const size_t line_len);

int   brain_server                      (const char *listen_host, const int listen_port, const char *brain_password, const char *brain_session_whitelist);
bool  brain_server_read_hash_dumps      (brain_server_dbs_t *brain_server_dbs, const char *path);
bool  brain_server_write_hash_dumps     (brain_server_dbs_t *brain_server_dbs, const char *path);
bool  brain_server_read_hash_dump       (brain_server_db_hash_t *brain_server_db_hash, const char *file);
bool  brain_server_write_hash_dump      (brain_server_db_hash_t *brain_server_db_hash, const char *file);
bool  brain_server_read_attack_dumps    (brain_server_dbs_t *brain_server_dbs, const char *path);
bool  brain_server_write_attack_dumps   (brain_server_dbs_t *brain_server_dbs, const char *path);
bool  brain_server_read_attack_dump     (brain_server_db_attack_t *brain_server_db_attack, const char *file);
bool  brain_server_write_attack_dump    (brain_server_db_attack_t *brain_server_db_attack, const char *file);
int   brain_server_get_client_idx       (brain_server_dbs_t *brain_server_dbs);

u64   brain_server_highest_attack       (const brain_server_db_attack_t *buf);
u64   brain_server_highest_attack_long  (const brain_server_attack_long_t  *buf, const i64 cnt, const u64 start);
u64   brain_server_highest_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 start);
u64   brain_server_find_attack_long     (const brain_server_attack_long_t  *buf, const i64 cnt, const u64 offset, const u64 length);
u64   brain_server_find_attack_short    (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length);
i64   brain_server_find_hash_long       (const u32 *search, const brain_server_hash_long_t  *buf, const i64 cnt);
i64   brain_server_find_hash_short      (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt);
int   brain_server_sort_db_hash         (const void *v1, const void *v2);
int   brain_server_sort_db_attack       (const void *v1, const void *v2);
int   brain_server_sort_attack_long     (const void *v1, const void *v2);
int   brain_server_sort_attack_short    (const void *v1, const void *v2);
int   brain_server_sort_hash            (const void *v1, const void *v2);
int   brain_server_sort_hash_long       (const void *v1, const void *v2);
int   brain_server_sort_hash_short      (const void *v1, const void *v2);
int   brain_server_sort_hash_unique     (const void *v1, const void *v2);
void  brain_server_handle_signal        (int signo);
void *brain_server_handle_client        (void *p);
void *brain_server_handle_dumps         (void *p);
void  brain_server_db_hash_init         (brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session);
bool  brain_server_db_hash_realloc      (brain_server_db_hash_t *brain_server_db_hash, const i64 new_long_cnt);
void  brain_server_db_hash_free         (brain_server_db_hash_t *brain_server_db_hash);
void  brain_server_db_attack_init       (brain_server_db_attack_t *brain_server_db_attack, const u32 brain_attack);
bool  brain_server_db_attack_realloc    (brain_server_db_attack_t *brain_server_db_attack, const i64 new_long_cnt, const i64 new_short_cnt);
void  brain_server_db_attack_free       (brain_server_db_attack_t *brain_server_db_attack);

#endif // _BRAIN_H
