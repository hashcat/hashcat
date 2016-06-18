/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_xnvctrl.h>

int xnvctrl_init (XNVCTRL_PTR *xnvctrl)
{
  if (!xnvctrl) return (-1);

  memset (xnvctrl, 0, sizeof (XNVCTRL_PTR));

  #ifdef _WIN

  // unsupport platform?
  return (-1);

  #elif _POSIX

  xnvctrl->lib_x11 = dlopen ("libX11.so", RTLD_LAZY);

  if (xnvctrl->lib_x11 == NULL)
  {
    if (data.quiet == 0) log_info ("WARNING: load X11 library failed, proceed without X11 HWMon enabled.");

    return -1;
  }

  xnvctrl->lib_xnvctrl = dlopen ("libXNVCtrl.so", RTLD_LAZY);

  if (xnvctrl->lib_xnvctrl == NULL)
  {
    xnvctrl->lib_xnvctrl = dlopen ("libXNVCtrl.so.0", RTLD_LAZY);

    if (xnvctrl->lib_xnvctrl == NULL)
    {
      if (data.quiet == 0) log_info ("WARNING: load XNVCTRL library failed, proceed without XNVCTRL HWMon enabled.");

      return -1;
    }
  }

  xnvctrl->XOpenDisplay  = dlsym (xnvctrl->lib_x11, "XOpenDisplay");
  xnvctrl->XCloseDisplay = dlsym (xnvctrl->lib_x11, "XCloseDisplay");

  xnvctrl->XNVCTRLQueryTargetAttribute = dlsym (xnvctrl->lib_xnvctrl, "XNVCTRLQueryTargetAttribute");
  xnvctrl->XNVCTRLSetTargetAttribute   = dlsym (xnvctrl->lib_xnvctrl, "XNVCTRLSetTargetAttribute");

  #endif

  // not using HC_LOAD_FUNC() here, because we're using 2 libraries and therefore have 2 different variable names for them

  return 0;
}

void xnvctrl_close (XNVCTRL_PTR *xnvctrl)
{
  if (xnvctrl)
  {
    #if _POSIX

    if (xnvctrl->lib_x11)
    {
      dlclose (xnvctrl->lib_x11);
    }

    if (xnvctrl->lib_xnvctrl)
    {
      dlclose (xnvctrl->lib_xnvctrl);
    }

    #endif

    myfree (xnvctrl);
  }
}

int hm_XNVCTRL_XOpenDisplay (XNVCTRL_PTR *xnvctrl)
{
  void *dpy = xnvctrl->XOpenDisplay (NULL);

  if (dpy == NULL)
  {
    return -1;
  }

  xnvctrl->dpy = dpy;

  return 0;
}

void hm_XNVCTRL_XCloseDisplay (XNVCTRL_PTR *xnvctrl)
{
  xnvctrl->XCloseDisplay (xnvctrl->dpy);
}

int get_fan_control (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  if (!rc) return -1;

  return 0;
}

int set_fan_control (XNVCTRL_PTR *xnvctrl, int gpu, int val)
{
  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  int cur;

  int rc = get_fan_control (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

int get_core_threshold (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_CORE_THRESHOLD, val);

  if (!rc) return -1;

  return 0;
}

int get_fan_speed_current (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL, val);

  if (!rc) return -1;

  return 0;
}

int get_fan_speed_target (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  if (!rc) return -1;

  return 0;
}

int set_fan_speed_target (XNVCTRL_PTR *xnvctrl, int gpu, int val)
{
  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  int cur;

  int rc = get_fan_speed_target (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}
