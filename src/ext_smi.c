/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_smi.h>

int hc_nvidia_smi (int dev, int *temperature, int *gpu)
{
  char cmd[256] = { 0 };

  snprintf (cmd, sizeof (cmd) - 1, "nvidia-smi -q -g %d", dev);

  FILE *fp = popen (cmd, "r");

  if (fp == NULL)
  {
    log_info ("WARN: %s\n", "nvidia-smi is missing!");

    return SMI_NOBIN;
  }

  int temp_found = 0;
  int util_found = 0;

  char token[32];

  while (fscanf (fp, " %31s ", token) == 1)
  {
    if (strcmp (token, "Temperature") == 0)
    {
      if (fscanf (fp, " : %4s C", token) == 1) *temperature = atoi (token);

      temp_found = 1;
    }

    if (temp_found == 1)
    {
      if ((strcmp (token, "GPU") == 0) || (strcmp (token, "Gpu") == 0))
      {
        if (fscanf (fp, " : %4s C", token) == 1) *temperature = atoi (token);

        temp_found = 0;
      }
    }

    if (strcmp (token, "Utilization") == 0)
    {
      util_found = 1;

      temp_found = 0;
    }

    if (util_found == 1)
    {
      if ((strcmp (token, "GPU") == 0) || (strcmp (token, "Gpu") == 0))
      {
        if (fscanf (fp, " : %2s%%", token) == 1) *gpu = atoi (token);

        util_found = 0;
      }
    }
  }

  pclose (fp);

  return (SMI_OK);
}
