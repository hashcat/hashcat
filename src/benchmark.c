/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
#include "memory.h"
#include "shared.h"
#include "benchmark.h"

static const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[] =
{
  0,
  100,
  1400,
  1700,
  2500,
  1000,
  3000,
  5500,
  5600,
  1500,
  500,
  3200,
  1800,
  7500,
  13100,
  15300,
  15900,
  7100,
  11600,
  12500,
  13000,
  6211,
  13400,
  6800,
  11300,
  -1,
};

int benchmark_next (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  static int cur = 0;

  if (user_options->benchmark_all == false)
  {
    const int hash_mode = DEFAULT_BENCHMARK_ALGORITHMS_BUF[cur];

    if (hash_mode == -1) return -1;

    cur++;

    return hash_mode;
  }

  char *modulefile = (char *) hcmalloc (HCBUFSIZ_TINY);

  for (int i = cur; i < MODULE_HASH_MODES_MAXIMUM; i++)
  {
    module_filename (folder_config, i, modulefile, HCBUFSIZ_TINY);

    if (hc_path_exist (modulefile) == true)
    {
      const int hash_mode = i;

      cur = hash_mode + 1;

      hcfree (modulefile);

      return hash_mode;
    }
  }

  hcfree (modulefile);

  return -1;
}
