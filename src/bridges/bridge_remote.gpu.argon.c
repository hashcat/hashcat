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
#include "emu_inc_hash_md5.h"

#ifdef WIN32
#include <ws2tcpip.h>
#define SOCK_RECV(s,b,l,f) recv (s, (char *) (b), l, f)
#define SOCK_SEND(s,b,l,f) send (s, (const char *) (b), l, f)
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define SOCK_RECV(s,b,l,f) recv (s, (b), l, f)
#define SOCK_SEND(s,b,l,f) send (s, (b), l, f)
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HASH_MODE 75000
#define MAX_BLOCK_SIZE 2048



typedef struct unit
{
  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  int     chunk_size;
  size_t  workitem_size;
  
  int     client_fd;

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

static bool units_init (remote_t *remote, const char *servers)
{
  const int max_num_devices = DEVICES_MAX;

  unit_t *units = (unit_t *) hccalloc (max_num_devices, sizeof (unit_t));

  char *server_list = strdup (servers);
  char *server_list_saveptr = NULL;

  char *address = strtok_r (server_list, ",", &server_list_saveptr);

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

    char *address_saveptr = NULL;
    char *ip = strtok_r(address, ":", &address_saveptr);
    char *port =strtok_r(NULL, ":", &address_saveptr);

    if (ip == NULL || port == NULL)
    {
      fprintf (stderr, "Invalid server address: %s\n", address);
      return false;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port   = htons (atoi(port));

    if (inet_pton (AF_INET, ip, &server_address.sin_addr) <= 0)
    {
      fprintf (stderr, "Invalid server IP: %s\n", ip);
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
    unit->workitem_count = MAX_BLOCK_SIZE;

    unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf) - 1, "Remote Argon @ %s", address);
    unit->unit_info_buf[unit->unit_info_len] = 0;

    printf ("[bridge-client]: Connected to: %s\n", address);

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
      SOCK_SEND (unit->client_fd, &pws_cnt_no, sizeof (pws_cnt_no), 0);
      close (unit->client_fd);
    }

    hcfree (remote->units);

#ifdef WIN32
  WSACleanup ();
#endif
  }
}

void *platform_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  remote_t *remote = (remote_t *) hcmalloc (sizeof (remote_t));

  user_options_t  *user_options  = hashcat_ctx->user_options;

  const char *servers  = user_options->bridge_parameter1 ? user_options->bridge_parameter1 : "";

  if (units_init (remote, servers) == false)
  {
    hcfree (remote);

    return NULL;
  }

  return remote;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  remote_t *remote = platform_context;

  if (remote)
  {
    units_term (remote);

    hcfree (remote);
  }
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  remote_t *remote = platform_context;

  return remote->units_cnt;
}

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  remote_t *remote = platform_context;
  
  unit_t *unit = &remote->units[unit_idx];

  return unit->workitem_count;
}

int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  remote_t *remote = platform_context;
  
  unit_t *unit = &remote->units[unit_idx];

  return unit->chunk_size;
}

char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  remote_t *remote = platform_context;

  unit_t *unit_buf = &remote->units[unit_idx];

  return unit_buf->unit_info_buf;
}

bool salt_prepare (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  remote_t *remote = platform_context;

  argon2id_hybrid_t *esalts_buf = (argon2id_hybrid_t *) hashes->esalts_buf;

  argon2id_hybrid_t *argon2id_hybrid = &esalts_buf[0];

  const int hash_mode = htonl (HASH_MODE);
  const int iterations_no          = htonl (argon2id_hybrid->iterations);
  const int parallelism_no         = htonl (argon2id_hybrid->parallelism);
  const int memory_usage_in_kib_no = htonl (argon2id_hybrid->memory_usage_in_kib);

  printf("[bridge-client]: Sending hash parameters\n"); 

  for (int unit_idx = 0; unit_idx < remote ->units_cnt; unit_idx++)
  {
    unit_t *unit = &remote->units[unit_idx];

    SOCK_SEND (unit->client_fd, &hash_mode, sizeof (hash_mode), 0);
    SOCK_SEND (unit->client_fd, &iterations_no, sizeof (iterations_no), 0);
    SOCK_SEND (unit->client_fd, &parallelism_no, sizeof (parallelism_no), 0);
    SOCK_SEND (unit->client_fd, &memory_usage_in_kib_no, sizeof (memory_usage_in_kib_no), 0);

    int chunk_size_no = 0; 
    SOCK_RECV (unit->client_fd, &chunk_size_no, sizeof (chunk_size_no), MSG_WAITALL);

    int chunk_size = ntohl(chunk_size_no);
    printf("[bridge-client]: Chunk size for unit %d will be %d\n", unit_idx, chunk_size);

    unit->chunk_size = chunk_size;
  }

  return true;
}

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  remote_t *remote = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit = &remote->units[unit_idx];

  argon2id_hybrid_t *esalts_buf = (argon2id_hybrid_t *) hashes->esalts_buf;

  argon2id_hybrid_t *argon2id_hybrid = &esalts_buf[salt_pos];

  argon2id_hybrid_tmp_t *argon2id_hybrid_tmp = (argon2id_hybrid_tmp_t *) device_param->h_tmps;

  const int pws_cnt_no = htonl (pws_cnt);
  SOCK_SEND (unit->client_fd, &pws_cnt_no, sizeof (pws_cnt_no), 0);

  md5_ctx_t md5_ctx;
  md5_init (&md5_ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    const argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    for (u32 lane = 0; lane < argon2id_hybrid->parallelism; lane++)
    {
      SOCK_SEND (unit->client_fd, tmp->first_block[lane], sizeof (tmp->first_block[lane]), 0);
      SOCK_SEND (unit->client_fd, tmp->second_block[lane], sizeof (tmp->second_block[lane]), 0);

      md5_update (&md5_ctx, tmp->first_block[lane], sizeof (tmp->first_block[lane]));
      md5_update (&md5_ctx, tmp->second_block[lane], sizeof (tmp->second_block[lane]));
    }
  }

  md5_final (&md5_ctx);

  SOCK_SEND (unit->client_fd, md5_ctx.h, sizeof (md5_ctx.h), 0);

  md5_init (&md5_ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    SOCK_RECV (unit->client_fd, tmp->final_block, sizeof (tmp->final_block), MSG_WAITALL);

    md5_update (&md5_ctx, tmp->final_block, sizeof (tmp->final_block));
  }

  md5_final (&md5_ctx);

  uint8_t expected_md5[16];
  SOCK_RECV (unit->client_fd, expected_md5, 16, MSG_WAITALL);

  if (memcmp (expected_md5,  md5_ctx.h, sizeof (expected_md5)) != 0)
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
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->thread_init           = BRIDGE_DEFAULT;
  bridge_ctx->thread_term           = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare          = salt_prepare;
  bridge_ctx->salt_destroy          = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;  
  bridge_ctx->st_update_hash        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass        = BRIDGE_DEFAULT;

  bridge_ctx->get_unit_temperature       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_str   = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_abort = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_fanspeed          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_utilization       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_corespeed         = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_memoryspeed       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_power             = BRIDGE_DEFAULT;
}
