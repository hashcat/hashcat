/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRAIN_H
#define HC_BRAIN_H

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

// The macro is _WIN32_WINNT. It was spelled _WINNT_WIN32 here, so nothing ever read it.
// Its value selects Windows 7, and ws2tcpip.h only declares inet_ntop from Vista upwards.
// Recent mingw defaults above that line and declares it regardless, which kept this hidden.
// Below it the declaration is absent and the call in brain_server falls back to an implicit
// one. clang rejects that outright and C23 removes it.
//
// Only set when nothing has set it already. common.h reaches string.h and therefore the mingw
// headers, which pick their own value, so by the time this is read the macro is usually already
// defined and redefining it warns on every file that includes this one. Recent mingw chooses a
// HIGHER version than the floor wanted here, and a higher version declares everything a lower one
// does, so leaving it alone is correct as well as quieter.

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

// winsock2.h first, because ws2tcpip.h builds on it

#include <winsock2.h>
#include <ws2tcpip.h>
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
#include <sys/mman.h>
#if defined (__linux__)
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif
#endif

#include "xxhash.h"

static const int BRAIN_CLIENT_CONNECT_TIMEOUT     = 5;
static const int BRAIN_SERVER_TIMER               = 5 * 60;
static const int BRAIN_SERVER_SESSIONS_MAX        = 64;
static const int BRAIN_SERVER_ATTACKS_MAX         = 64 * 1024;
static const int BRAIN_SERVER_CLIENTS_MAX         = 256;
static const int BRAIN_SERVER_REALLOC_ATTACK_SIZE = 1024;
static const int BRAIN_HASH_SIZE                  = 2 * sizeof (u32);
static const int BRAIN_LINK_VERSION_CUR           = 1;
static const int BRAIN_LINK_VERSION_MIN           = 1;
static const int BRAIN_LINK_CHUNK_SIZE            = 4 * 1024;
static const int BRAIN_LINK_CANDIDATES_MAX        = 128 * 1024 * 256; // units * threads * accel

// The hash database of a session is split into shards on the top bits of the hash. Every operation
// is then bounded by one shard instead of by the whole session: a commit merges into one shard, a
// lookup searches one shard, and a dump writes one shard at a time. No lock is ever held for the
// length of the database.
//
// The sort order compares hash[1] first, so a shard is a contiguous run of the sorted order. Writing
// the shards back to back therefore produces exactly the file the unsharded server produced, and it
// reads that server's files without conversion.

#define BRAIN_SERVER_SHARD_BITS 10
#define BRAIN_SERVER_SHARD_CNT  (1 << BRAIN_SERVER_SHARD_BITS)

// A commit lands in the shard's overflow, and the overflow is folded into the main array only once
// it grows past a threshold. That is what turns the cost of a commit from the size of the database
// into the size of the overflow.
//
// The threshold is a fraction of the shard rather than a constant. Folding costs the whole shard, so
// a fixed threshold means the fold gets more expensive as the shard grows while happening just as
// often, and the commit stops being flat. Tying the two together keeps the cost per candidate the
// same at any size. The floor keeps small shards from folding constantly and the ceiling keeps the
// overflow small enough to stay cheap to search.

static const i64 BRAIN_SERVER_OVERFLOW_DIV = 32;
static const i64 BRAIN_SERVER_OVERFLOW_MIN = 4096;
static const i64 BRAIN_SERVER_OVERFLOW_MAX = 32768;

// Every shard buffer lives inside one address range reserved per session. Reserving costs address
// space and not memory: an anonymous page becomes real only when it is first written. So a shard is
// never reallocated, never copied when it grows, and never holds slack that another shard could have
// used. What it costs is a ceiling, which is what these two are.
//
// A session can therefore hold BRAIN_SERVER_SHARD_CNT * BRAIN_SERVER_SHARD_ENTRIES hashes, which at
// the values below is over four billion, and reserves 32 GB of address space to say so.

static const i64 BRAIN_SERVER_SHARD_ENTRIES = 4 * 1024 * 1024;

// The overflow is bounded because a run at least as large as the overflow goes straight into the
// main array instead of through it.

static const i64 BRAIN_SERVER_OVER_ENTRIES = 2 * 32768;

// How much of a buffer is committed at a time. Only Windows has to ask; on POSIX the pages are
// already there for the asking and this just tracks how far the shard has been used.

static const i64 BRAIN_SERVER_COMMIT_STEP = 4096;

// How many candidates --brain-feed hashes before handing them over. It is also what the feeder
// declares as its passwords_max at connect, because the server refuses a lookup larger than that,
// so the two cannot drift apart.
//
// Bigger is cheaper per candidate, and by more than it looks. The database is split into shards and
// a batch is answered one shard at a time, so a shard sees chunk/shards keys before the walk moves
// on, and a small chunk never amortises the cost of entering a shard. Measured against 300 million
// entries: 700 ns per candidate at 65,536, 401 at this value, 293 at four million.
//
// What it costs is server memory. The server sizes four per client buffers from this number, about
// 33 bytes per candidate, so a feeder holds 35 MB there for as long as it stays connected. Four
// million would be 138 MB for a further 1.37x, which is the wrong side of the trade on a shared
// server.

#define BRAIN_FEED_CHUNK 1048576

typedef enum brain_operation
{
  BRAIN_OPERATION_COMMIT         = 1,
  BRAIN_OPERATION_HASH_LOOKUP    = 2,
  BRAIN_OPERATION_ATTACK_RESERVE = 3,

} brain_operation_t;

// Below how many salts a fast hash is refused the hash feature.
//
// The brain stores one entry per candidate, so what decides whether it is worth using is the
// candidate rate, which is the device rate divided by the salt count. Asking the brain about a
// candidate costs the server roughly a microsecond of lookup plus eight bytes of memory it never
// gives back, and testing a candidate locally costs salts divided by the hash rate. Asking is only
// worth it when testing costs more, which puts the break even near one and a half million
// candidates a second.
//
// A hash computed inside the kernel runs at around a billion a second on one current GPU, so it
// takes roughly this many salts to fall under that break even. An unsalted mode collapses to a
// single salt and is therefore never close.

static const u32 BRAIN_CLIENT_MIN_SALTS = 1024;

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

typedef struct brain_server_db_shard
{
  brain_server_hash_long_t *long_buf;

  i64 long_alloc;
  i64 long_cnt;

  brain_server_hash_long_t *over_buf;

  i64 over_alloc;
  i64 over_cnt;

  hc_thread_mutex_t mux;

} brain_server_db_shard_t;

typedef struct brain_server_db_hash
{
  u32 brain_session;

  brain_server_db_shard_t *shard_buf;

  void *long_arena;
  void *over_arena;

  bool write_hashes;

} brain_server_db_hash_t;

typedef struct brain_server_db_short
{
  brain_server_hash_long_t *short_buf;

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

  u32 brain_server_timer;

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

void  brain_client_check_features       (hashcat_ctx_t *hashcat_ctx);
u32   brain_compute_session             (hashcat_ctx_t *hashcat_ctx);
u32   brain_compute_attack              (hashcat_ctx_t *hashcat_ctx);
u64   brain_compute_attack_wordlist     (const char *filename);

u32   brain_auth_challenge              (void);
u64   brain_auth_hash                   (const u32 challenge, const char *pw_buf, const int pw_len);

// returns 0 when connected, otherwise the errno-style reason. It does not log, so the caller owns the
// message and can name the host and port that failed.

int   brain_connect                     (int sockfd, const struct sockaddr *addr, socklen_t addrlen, const int timeout);
bool  brain_recv                        (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_send                        (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_recv_all                    (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_send_all                    (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);

bool  brain_client_reserve              (hc_device_param_t *device_param, const status_ctx_t *status_ctx, u64 words_off, u64 work, u64 *overlap);
bool  brain_client_commit               (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_client_lookup               (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool  brain_client_connect              (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const status_ctx_t *status_ctx, const char *host, const int port, const char *password, u32 brain_session, u32 brain_attack, i64 passwords_max, u64 *highest);
void  brain_client_disconnect           (hc_device_param_t *device_param);
void  brain_client_generate_hash        (u64 *hash, const char *line_buf, const size_t line_len);

HC_API int   brain_feed                        (hashcat_ctx_t *hashcat_ctx);
HC_API int   brain_server                      (const char *listen_host, const int listen_port, const char *brain_password, const char *brain_session_whitelist, const u32 brain_server_timer);
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
int   brain_server_sort_db_hash         (const void *v1, const void *v2);
int   brain_server_sort_db_attack       (const void *v1, const void *v2);
int   brain_server_sort_attack_long     (const void *v1, const void *v2);
int   brain_server_sort_attack_short    (const void *v1, const void *v2);
int   brain_server_sort_hash            (const void *v1, const void *v2);
int   brain_server_sort_hash_long       (const void *v1, const void *v2);
int   brain_server_sort_hash_unique     (const void *v1, const void *v2);
void  brain_server_handle_signal        (int signo);

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD brain_server_handle_client  (void *p);
HC_API_CALL DWORD brain_server_handle_dumps   (void *p);
#else
HC_API_CALL void *brain_server_handle_client  (void *p);
HC_API_CALL void *brain_server_handle_dumps   (void *p);
#endif

u32   brain_server_shard_idx            (const u32 *hash);
void *brain_server_arena_reserve        (const u64 size);
void  brain_server_arena_release        (void *buf, const u64 size);
bool  brain_server_shard_commit         (brain_server_hash_long_t *buf, i64 *alloc, const i64 need, const i64 ceiling);
i64   brain_server_merge_sorted         (brain_server_hash_long_t *dst, const i64 dst_cnt, const brain_server_hash_long_t *src, const i64 src_cnt);
i64   brain_server_shard_overflow_max (const brain_server_db_shard_t *shard);
bool  brain_server_shard_compact        (brain_server_db_shard_t *shard);
bool  brain_server_shard_add            (brain_server_db_shard_t *shard, const brain_server_hash_long_t *src, const i64 src_cnt);
bool  brain_server_shard_find           (const brain_server_db_shard_t *shard, const u32 *hash);

void  brain_server_db_hash_init         (brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session);
i64   brain_server_db_hash_cnt          (brain_server_db_hash_t *brain_server_db_hash);
void  brain_server_db_hash_free         (brain_server_db_hash_t *brain_server_db_hash);
void  brain_server_db_attack_init       (brain_server_db_attack_t *brain_server_db_attack, const u32 brain_attack);
bool  brain_server_db_attack_realloc    (brain_server_db_attack_t *brain_server_db_attack, const i64 new_long_cnt, const i64 new_short_cnt);
void  brain_server_db_attack_free       (brain_server_db_attack_t *brain_server_db_attack);

int   brain_ctx_init                    (hashcat_ctx_t *hashcat_ctx);
void  brain_ctx_destroy                 (hashcat_ctx_t *hashcat_ctx);

#endif // HC_BRAIN_H
