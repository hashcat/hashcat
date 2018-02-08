/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
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
  const user_options_t *user_options = hashcat_ctx->user_options;

  static int cur = 0;

  if (user_options->benchmark_all == false)
  {
    const int hash_mode = DEFAULT_BENCHMARK_ALGORITHMS_BUF[cur];

    if (hash_mode == -1) return -1;

    cur++;

    return hash_mode;
  }
  else
  {
    for (int i = cur; i < 99999; i++)
    {
      const char *name = strhashtype (i);

      if (name)
      {
        const int hash_mode = i;

        cur = hash_mode + 1;

        return hash_mode;
      }
    }
  }

  return -1;
}
