/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "bridges.h"
#include "bitops.h"
#include "memory.h"
#include "shared.h"
#include "emu_inc_hash_md5.h"

#ifdef WIN32
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HASH_MODE 76000
#define MAX_BLOCK_SIZE 2048

typedef struct unit
{
  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  int     chunk_size;
  size_t  workitem_size;
#ifdef WIN32
  SOCKET  client_fd;
#else
  int     client_fd;
#endif
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

static bool units_init (hashcat_ctx_t *hashcat_ctx, remote_t *remote, const char *servers)
{
  const int max_num_devices = DEVICES_MAX;

  unit_t *units = (unit_t *) hccalloc (max_num_devices, sizeof (unit_t));

  char *server_list = strdup (servers);
  char *server_list_saveptr = NULL;

  char *address = strtok_r (server_list, ",", &server_list_saveptr);

  if (address == NULL)
  {
    event_log_error (hashcat_ctx, "[bridge-client]: No server addresses given");
    return false;
  }

  #if defined (WIN32)
  WSADATA wsaData;

  WORD wVersionRequested = MAKEWORD (2,2);

  if (WSAStartup (wVersionRequested, &wsaData) != 0)
  {
    event_log_error (hashcat_ctx, "[bridge-client]: WSAStartup failed: %d\n", WSAGetLastError ());
    return false;
  }
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
      event_log_error (hashcat_ctx, "Invalid server address: %s", address);
      return false;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port   = htons (atoi(port));

    if (inet_pton (AF_INET, ip, &server_address.sin_addr) <= 0)
    {
      event_log_error (hashcat_ctx, "Invalid server IP: %s", ip);
      return false;
    }

    int client_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
      event_log_error (hashcat_ctx, "[bridge-client]: Unable to create socket.");
      return false;
    }
    if (connect (client_fd, (struct sockaddr *) &server_address,  sizeof (server_address)) < 0)
    {
      event_log_error (hashcat_ctx, "[bridge-client]: Failed to create connection.");
      return false;
    }

    unit->client_fd = client_fd;
    unit->workitem_count = MAX_BLOCK_SIZE;

    unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf) - 1, "Remote Argon @ %s", address);
    unit->unit_info_buf[unit->unit_info_len] = 0;

    event_log_info (hashcat_ctx, "[bridge-client]: Connected to: %s", address);

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
      send (unit->client_fd, (void *) &pws_cnt_no, sizeof (pws_cnt_no), 0);
      close (unit->client_fd);
    }

    hcfree (remote->units);

  #if defined (WIN32)
  WSACleanup ();
  #endif
 }
}

void *platform_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  remote_t *remote = (remote_t *) hcmalloc (sizeof (remote_t));

  user_options_t  *user_options  = hashcat_ctx->user_options;

  const char *servers  = user_options->bridge_parameter1 ? user_options->bridge_parameter1 : "";

  if (units_init (hashcat_ctx, remote, servers) == false)
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

  event_log_info (hashcat_ctx, "[bridge-client]: Sending hash parameters"); 

  for (int unit_idx = 0; unit_idx < remote ->units_cnt; unit_idx++)
  {
    unit_t *unit = &remote->units[unit_idx];

    if (send (unit->client_fd, (void *) &hash_mode, sizeof (hash_mode), 0) != sizeof (hash_mode)) return false;
    if (send (unit->client_fd, (void *) &iterations_no, sizeof (iterations_no), 0) != sizeof (iterations_no)) return false;
    if (send (unit->client_fd, (void *) &parallelism_no, sizeof (parallelism_no), 0) != sizeof (parallelism_no)) return false;
    if (send (unit->client_fd, (void *) &memory_usage_in_kib_no, sizeof (memory_usage_in_kib_no), 0) != sizeof (memory_usage_in_kib_no)) return false;

    uint32_t chunk_size_no = 0;
    if (recv (unit->client_fd, (void *) &chunk_size_no, sizeof (chunk_size_no), MSG_WAITALL) != sizeof (chunk_size_no)) return false;

    uint32_t chunk_size = ntohl (chunk_size_no);
    unit->chunk_size = MIN (chunk_size, unit->workitem_count);

    event_log_info (hashcat_ctx, "[bridge-client]: Chunk size for unit %d will be %d", unit_idx, unit->chunk_size);
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
  if (send (unit->client_fd, (void *) &pws_cnt_no, sizeof (pws_cnt_no), 0) != sizeof (pws_cnt_no)) return false;

  md5_ctx_t md5_ctx;
  md5_init (&md5_ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    const argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    for (u32 lane = 0; lane < argon2id_hybrid->parallelism; lane++)
    {
      if (send (unit->client_fd, (void *) tmp->first_block[lane], sizeof (tmp->first_block[lane]), 0) != sizeof (tmp->first_block[lane])) return false;
      if (send (unit->client_fd, (void *) tmp->second_block[lane], sizeof (tmp->second_block[lane]), 0) != sizeof (tmp->second_block[lane])) return false;

      md5_update (&md5_ctx, tmp->first_block[lane], sizeof (tmp->first_block[lane]));
      md5_update (&md5_ctx, tmp->second_block[lane], sizeof (tmp->second_block[lane]));
    }
  }

  md5_final (&md5_ctx);

  if (send (unit->client_fd, (void *) md5_ctx.h, sizeof (md5_ctx.h), 0) != sizeof (md5_ctx.h)) return false;

  md5_init (&md5_ctx);

  for (u32 p = 0; p < pws_cnt; p++)
  {
    argon2id_hybrid_tmp_t *tmp = &argon2id_hybrid_tmp[p];

    if (recv (unit->client_fd, (void *) tmp->final_block, sizeof (tmp->final_block), MSG_WAITALL) != sizeof (tmp->final_block)) return false;

    md5_update (&md5_ctx, tmp->final_block, sizeof (tmp->final_block));
  }

  md5_final (&md5_ctx);

  uint8_t expected_md5[16];
  if (recv (unit->client_fd, (void *) expected_md5, sizeof (expected_md5), MSG_WAITALL) != sizeof (expected_md5)) return false;

  if (memcmp (expected_md5,  md5_ctx.h, sizeof (expected_md5)) != 0)
  {
    event_log_error (hashcat_ctx, "[client]: MD5 is NOT correct!");
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
