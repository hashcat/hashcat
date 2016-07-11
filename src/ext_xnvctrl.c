/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_xnvctrl.h>

int xnvctrl_init (XNVCTRL_PTR *xnvctrl)
{
  if (!xnvctrl) return -1;

  memset (xnvctrl, 0, sizeof (XNVCTRL_PTR));

  #ifdef _WIN

  // unsupport platform?
  return -1;

  #elif _POSIX

  xnvctrl->lib_x11 = dlopen ("libX11.so", RTLD_LAZY);

  if (xnvctrl->lib_x11 == NULL)
  {
    if (data.quiet == 0) log_info ("WARNING: Failed loading the X11 library: %s", dlerror());
    if (data.quiet == 0) log_info ("         Please install libx11-dev package.");
    if (data.quiet == 0) log_info ("");

    return -1;
  }

  xnvctrl->lib_xnvctrl = dlopen ("libXNVCtrl.so", RTLD_LAZY);

  if (xnvctrl->lib_xnvctrl == NULL)
  {
    if (data.quiet == 0) log_info ("WARNING: Failed loading the XNVCTRL library: %s", dlerror());
    if (data.quiet == 0) log_info ("         Please install libxnvctrl-dev package.");
    if (data.quiet == 0) log_info ("");

    return -1;
  }

  HC_LOAD_FUNC2 (xnvctrl, XOpenDisplay,  XOPENDISPLAY,  lib_x11, X11, 0);
  HC_LOAD_FUNC2 (xnvctrl, XCloseDisplay, XCLOSEDISPLAY, lib_x11, X11, 0);

  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLQueryTargetAttribute, XNVCTRLQUERYTARGETATTRIBUTE, lib_xnvctrl, XNVCTRL, 0);
  HC_LOAD_FUNC2 (xnvctrl, XNVCTRLSetTargetAttribute,   XNVCTRLSETTARGETATTRIBUTE,   lib_xnvctrl, XNVCTRL, 0);

  #endif

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
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XOpenDisplay == NULL) return -1;

  void *dpy = xnvctrl->XOpenDisplay (NULL);

  if (dpy == NULL)
  {
    xnvctrl->dpy = NULL;

    return -1;
  }

  xnvctrl->dpy = dpy;

  return 0;
}

void hm_XNVCTRL_XCloseDisplay (XNVCTRL_PTR *xnvctrl)
{
  if (xnvctrl == NULL) return;

  if (xnvctrl->XCloseDisplay == NULL) return;

  if (xnvctrl->dpy == NULL) return;

  xnvctrl->XCloseDisplay (xnvctrl->dpy);
}

int get_fan_control (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  if (!rc) return -1;

  return 0;
}

int set_fan_control (XNVCTRL_PTR *xnvctrl, int gpu, int val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = get_fan_control (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_COOLER_MANUAL_CONTROL, val);

  rc = get_fan_control (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}

int get_core_threshold (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_GPU, gpu, 0, NV_CTRL_GPU_CORE_THRESHOLD, val);

  if (!rc) return -1;

  return 0;
}

int get_fan_speed_current (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL, val);

  if (!rc) return -1;

  return 0;
}

int get_fan_speed_target (XNVCTRL_PTR *xnvctrl, int gpu, int *val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLQueryTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int rc = xnvctrl->XNVCTRLQueryTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  if (!rc) return -1;

  return 0;
}

int set_fan_speed_target (XNVCTRL_PTR *xnvctrl, int gpu, int val)
{
  if (xnvctrl == NULL) return -1;

  if (xnvctrl->XNVCTRLSetTargetAttribute == NULL) return -1;

  if (xnvctrl->dpy == NULL) return -1;

  int cur;

  int rc = get_fan_speed_target (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  xnvctrl->XNVCTRLSetTargetAttribute (xnvctrl->dpy, NV_CTRL_TARGET_TYPE_COOLER, gpu, 0, NV_CTRL_THERMAL_COOLER_LEVEL, val);

  rc = get_fan_speed_target (xnvctrl, gpu, &cur);

  if (rc == -1) return -1;

  if (cur != val) return -1;

  return 0;
}
