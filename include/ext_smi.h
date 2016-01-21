/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_SMI_H
#define EXT_SMI_H

#ifdef HAVE_HWMON

#include <common.h>

#define SMI_OK    0
#define SMI_NOBIN 1

int hc_nvidia_smi (int dev, int *temperature, int *gpu);

#endif // HAVE_HWMON

#endif
