/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
#include "memory.h"
#include "shared.h"
#include "path.h"
#include "benchmark.h"

static const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[] =
{
  900,
  0,
  100,
  1400,
  1700,
  17400,
  17600,
  31000,
  600,
  11700,
  11800,
  5100,
  31100,
  11500,
  18700,
  34000,
  8900,
  400,
  1000,
  3000,
  22000,
  13100,
  5500,
  5600,
  15300,
  15900,
  33700,
  28100,
  9200,
  9300,
  5700,
  1100,
  2100,
  7100,
  3200,
  500,
  1500,
  7400,
  1800,
  35100,
  14000,
  14100,
  26401,
  26403,
  12300,
  300,
  8300,
  1600,
  16700,
  18300,
  22100,
  29511,
  34100,
  29421,
  29341,
  12200,
  10400,
  10510,
  10500,
  10600,
  10700,
  9400,
  9500,
  9600,
  9700,
  9800,
  13400,
  6800,
  23400,
  26100,
  23100,
  11600,
  12500,
  23800,
  13000,
  17220,
  17200,
  20500,
  13600,
  18100,
  17010,
  17030,
  22921,
  25500,
  16300,
  15600,
  15700,
  22500,
  27700,
  22700,
  2611,
  2711,
  31900,
  26610,
  11300,
  16600,
  21700,
  21800,
  10,
  20,
  110,
  120,
  1410,
  1420,
  10810,
  10820,
  1710,
  1720,
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
