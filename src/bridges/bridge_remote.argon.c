/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#ifdef WIN32
#define _WIN32_WINNT 0x0A00
#endif

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "bitops.h"
#include "memory.h"
#include "shared.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR == 3
    #include <openssl/evp.h>
#else
    #include <openssl/md5.h>
#endif

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#if OPENSSL_VERSION_MAJOR == 3
#define md5_ctx_t EVP_MD_CTX
#else
#define md5_ctx_t MD5_CTX
#endif

#define HASH_MODE 71000

static md5_ctx_t *md5_new ()
{
#if OPENSSL_VERSION_MAJOR == 3
  return EVP_MD_CTX_new ();
#else
  return calloc (1, sizeof (md5_ctx_t));
#endif
}

static void md5_init (md5_ctx_t *ctx)
{
#if OPENSSL_VERSION_MAJOR == 3
  EVP_DigestInit_ex2 (ctx, EVP_md5 (), NULL);
#else
  MD5_Init (ctx);
#endif
}

static void md5_update (md5_ctx_t *ctx, const void *d, size_t cnt)
{
#if OPENSSL_VERSION_MAJOR == 3
  EVP_DigestUpdate (ctx, d, cnt);
#else
  MD5_Update (ctx, d, cnt);
#endif
}

static void md5_final (md5_ctx_t *ctx, uint8_t *md)
{
#if OPENSSL_VERSION_MAJOR == 3
  EVP_DigestFinal_ex (ctx, md, NULL);
#else
  MD5_Final (md, ctx);
#endif
}

static void md5_free (md5_ctx_t *ctx)
{
#if OPENSSL_VERSION_MAJOR == 3
  EVP_MD_CTX_free (ctx);
#else
  free (ctx);
#endif
}

typedef struct unit
{
  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  size_t  workitem_size;
  
  int     client_fd;
  
  bool    options_sent;

} unit_t;

typedef struct remote
{
  unit_t *units;
  int     units_cnt;

} remote_t;

typedef struct
{
  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;

  u32 digest_len;

} argon2id_hybrid_t;

typedef struct argon2id_tmp
{
  u32 first_block[16][256];
  u32 second_block[16][256];

  u32 final_block[256];

} argon2id_hybrid_tmp_t;

static bool units_init (remote_t *remote, int port, const char *servers, const int blockSize)
{
  const int max_num_devices = 16;

  unit_t *units = (unit_t *) hccalloc (max_num_devices, sizeof (unit_t));

  char *server_list = strdup (servers);
  char *server_list_saveptr = NULL;

  const char *address = strtok_r (server_list, ",", &server_list_saveptr);

  if (address == NULL)
  {
    printf ("[bridge-client]: No server addresses given\n");
    return false;
  }

#ifdef WIN32
  WSADATA wsaData;

  WSAStartup (0x202, &wsaData);
#endif

  int units_cnt = 0;

  for (int i = 0; i < max_num_devices; i++)
  {
    unit_t *unit = &units[i];

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port   = htons (port);

    if (inet_pton (AF_INET, address, &server_address.sin_addr) <= 0)
    {
      fprintf (stderr, "Invalid server address: %s\n", address);
      return false;
    }

    int client_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
      printf ("[bridge-client]: Unable to create socket\n");
      return false;
    }
    if (connect (client_fd, (struct sockaddr *) &server_address,  sizeof (server_address)) < 0)
    {
      printf ("[bridge-client]: Failed to create connection\n");
      return false;
    }

    unit->client_fd = client_fd;
    unit->workitem_count = blockSize;

    unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf) - 1, "Remote Argon @ %s:%d", address, port);
    unit->unit_info_buf[unit->unit_info_len] = 0;

    printf ("[bridge-client]: Connected to: %s:%d\n", address, port);

    units_cnt++;

    address = strtok_r (NULL, ",", &server_list_saveptr);

    if (address == NULL) break;
  }

  remote->units = units;
  remote->units_cnt = units_cnt;

  free (server_list);

  return true;
}

static void units_term (remote_t *remote)
{
  if (remote)
  {
    const int units_counts = remote->units_cnt;

    for (int i = 0; i < units_counts; i++)
    {
      unit_t *unit = &remote->units[i];
      int pws_cnt_no = 0;
      send (unit->client_fd, (const char *) &pws_cnt_no, sizeof (pws_cnt_no), 0);
      close (unit->client_fd);
    }

    hcfree (remote->units);

#ifdef WIN32
  WSACleanup ();
#endif
  }
}

void *platform_init (user_options_t *user_options)
{
  remote_t *remote = (remote_t *) hcmalloc (sizeof (remote_t));

  const int   port     = user_options->bridge_parameter1 ? hc_strtoul (user_options->bridge_parameter1, NULL, 10) : 0;
  const char *servers  = user_options->bridge_parameter2 ? user_options->bridge_parameter2 : "";
  const int block_size = user_options->bridge_parameter3 ? hc_strtoul (user_options->bridge_parameter3, NULL, 10) : 192;

  if (port == 0)
  {
    fprintf (stderr, "Invalid port: %d\n", port);
    exit (1);
  }

  if (block_size > 256)
  {
    fprintf (stderr, "To large blocksize, please select a blocksize smaller then 256: %d\n", block_size);
    exit (1);
  }

  if (units_init (remote, port, servers, block_size) == false)
  {
    hcfree (remote);

    return NULL;
  }

  return remote;
}

void platform_term (void *platform_context)
{
  remote_t *remote = platform_context;

  if (remote)
  {
    units_term (remote);

    hcfree (remote);
  }
}

int get_unit_count (void *platform_context)
{
  remote_t *remote = platform_context;

  return remote->units_cnt;
}

int get_workitem_count (void *platform_context, const int unit_idx)
{
  remote_t *remote = platform_context;
  
  unit_t *unit = &remote->units[unit_idx];

  return unit->workitem_count;
}

char *get_unit_info (void *platform_context, const int unit_idx)
{
  remote_t *remote = platform_context;

  unit_t *unit_buf = &remote->units[unit_idx];

  return unit_buf->unit_info_buf;
}

bool launch_loop (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  remote_t *remote = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit = &remote->units[unit_idx];

  argon2id_hybrid_t *esalts_buf = (argon2id_hybrid_t *) hashes->esalts_buf;

  argon2id_hybrid_t *argon2id_hybrid = &esalts_buf[salt_pos];

  argon2id_hybrid_tmp_t *argon2id_hybrid_tmp = (argon2id_hybrid_tmp_t *) device_param->h_tmps;

  if (!unit->options_sent)
  {
    const int hash_mode = htonl (HASH_MODE);

    const int iterations_no          = htonl (argon2id_hybrid->iterations);
    const int parallelism_no         = htonl (argon2id_hybrid->parallelism);
    const int memory_usage_in_kib_no = htonl (argon2id_hybrid->memory_usage_in_kib);

    send (unit->client_fd, (const char *) &hash_mode, sizeof (hash_mode), 0);
    send (unit->client_fd, (const char *) &iterations_no, sizeof (iterations_no), 0);
    send (unit->client_fd, (const char *) &parallelism_no, sizeof (parallelism_no), 0);
    send (unit->client_fd, (const char *) &memory_usage_in_kib_no, sizeof (memory_usage_in_kib_no), 0);

    unit->options_sent = true;
  }

  const int pws_cnt_no = htonl (pws_cnt);
  send (unit->client_fd, (const char *) &pws_cnt_no, sizeof (pws_cnt_no), 0);

  uint8_t actual_md5[16];
  uint8_t expected_md5[16];

  md5_ctx_t *ctx = md5_new ();
  md5_init (ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    const argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    for (u32 lane = 0; lane < argon2id_hybrid->parallelism; lane++)
    {
      send (unit->client_fd, (const char *) tmp->first_block[lane], sizeof (tmp->first_block[lane]), 0);
      send (unit->client_fd, (const char *) tmp->second_block[lane], sizeof (tmp->second_block[lane]), 0);

      md5_update (ctx, tmp->first_block[lane], sizeof (tmp->first_block[lane]));
      md5_update (ctx, tmp->second_block[lane], sizeof (tmp->second_block[lane]));
    }
  }

  md5_final (ctx, actual_md5);

  send (unit->client_fd, actual_md5, sizeof (actual_md5), 0);

  md5_init (ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    recv (unit->client_fd, (char *) tmp->final_block, sizeof (tmp->final_block), MSG_WAITALL);

    md5_update (ctx, tmp->final_block, sizeof (tmp->final_block));
  }

  md5_final (ctx, actual_md5);

  recv (unit->client_fd, expected_md5, 16, MSG_WAITALL);

  md5_free (ctx);

  if (memcmp (expected_md5, actual_md5, sizeof (expected_md5)) != 0)
  {
    printf ("[client]: MD5 is NOT correct!\n");
    return false;
  }

  return true;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size       = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version  = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init         = platform_init;
  bridge_ctx->platform_term         = platform_term;
  bridge_ctx->get_unit_count        = get_unit_count;
  bridge_ctx->get_unit_info         = get_unit_info;
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->thread_init           = BRIDGE_DEFAULT;
  bridge_ctx->thread_term           = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare          = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy          = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;  
  bridge_ctx->st_update_hash        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass        = BRIDGE_DEFAULT;
}
