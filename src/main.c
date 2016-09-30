/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "types.h"
#include "hashcat.h"

int main (int argc, char **argv)
{
  hashcat_ctx_t *hashcat_ctx = malloc (sizeof (hashcat_ctx_t));

  const int rc = hashcat (hashcat_ctx, argc, argv);

  free (hashcat_ctx);

  return rc;
}
