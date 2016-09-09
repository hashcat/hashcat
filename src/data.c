/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "hwmon.h"
#include "interface.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "restore.h"
#include "opencl.h"
#include "data.h"

hc_global_data_t data;
