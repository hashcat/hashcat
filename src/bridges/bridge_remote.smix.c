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

#define HASH_MODE 71100

static void md5 (const uint8_t *data, size_t data_length, uint8_t *md5_bytes);

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


static bool units_init (remote_t *remote, int port, const char *servers, const int block_size)
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
    unit->workitem_count = block_size;

    unit->unit_info_len = snprintf (unit->unit_info_buf, sizeof (unit->unit_info_buf) - 1, "Remote Smix @ %s:%d", address, port);
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
  const int block_size = user_options->bridge_parameter3 ? hc_strtoul (user_options->bridge_parameter3, NULL, 10) : 2048;

  if (port == 0)
  {
    fprintf (stderr, "Invalid port: %d\n", port);
    exit (1);
  }

  if (block_size > 8192)
  {
    fprintf (stderr, "Too large blocksize, please select a blocksize smaller then 8192 : %d\n", block_size);
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

static void md5 (const uint8_t *data, size_t data_length, uint8_t *md5_bytes)
{
#if OPENSSL_VERSION_MAJOR == 3
    EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
    EVP_DigestInit_ex2 (ctx, EVP_md5 (), NULL);
    EVP_DigestUpdate (ctx, data, data_length);
    EVP_DigestFinal_ex (ctx, md5_bytes, NULL);
#else
    MD5_CTX ctx;
    MD5_Init (&ctx);
    MD5_Update (&ctx, data, data_length);
    MD5_Final (md5_bytes, &ctx);
#endif
}

static void byte_swap_temps (uint32_t *tmps, int size_in_bytes)
{
  const int elements = size_in_bytes / sizeof (uint32_t);
  for (int idx = 0; idx < elements; idx++)
  {
    tmps[idx] = byte_swap_32 (tmps[idx]);
  }
}

bool launch_loop (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  remote_t *remote = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit = &remote->units[unit_idx];

  if (!unit->options_sent)
  {
    const int hash_mode = htonl (HASH_MODE);

    const int scrypt_N_no = htonl (hashes->salts_buf[salt_pos].scrypt_N);
    const int scrypt_r_no = htonl (hashes->salts_buf[salt_pos].scrypt_r);
    const int scrypt_p_no = htonl (hashes->salts_buf[salt_pos].scrypt_p);

    send (unit->client_fd, (const char *) &hash_mode, sizeof (hash_mode), 0);
    send (unit->client_fd, (const char *) &scrypt_N_no, sizeof (scrypt_N_no), 0);
    send (unit->client_fd, (const char *) &scrypt_r_no, sizeof (scrypt_r_no), 0);
    send (unit->client_fd, (const char *) &scrypt_p_no, sizeof (scrypt_p_no), 0);
  
    unit->options_sent = true;
  }

  const int pws_cnt_no = htonl (pws_cnt);
  const size_t pbkdf_size = hashconfig->tmp_size * pws_cnt;

  byte_swap_temps (device_param->h_tmps, pbkdf_size);

  uint8_t actual_md5[16];
  uint8_t expected_md5[16];

  md5 (device_param->h_tmps, pbkdf_size, actual_md5);

  send (unit->client_fd, (const char *) &pws_cnt_no, sizeof (pws_cnt_no), 0);
  send (unit->client_fd, device_param->h_tmps, pbkdf_size, 0);
  send (unit->client_fd, actual_md5, sizeof (actual_md5), 0);

  recv (unit->client_fd, device_param->h_tmps, pbkdf_size, MSG_WAITALL);

  recv (unit->client_fd, expected_md5, 16, MSG_WAITALL);

  md5 (device_param->h_tmps, pbkdf_size, actual_md5);

  if (memcmp (expected_md5, actual_md5, sizeof (expected_md5)) != 0)
  {
    printf ("[client]: MD5 is NOT correct!\n");
    return false;
  }

  byte_swap_temps (device_param->h_tmps, pbkdf_size);

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
