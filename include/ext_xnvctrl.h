/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_XNVCTRL_H
#define EXT_XNVCTRL_H

#if defined(HAVE_HWMON)

#include <common.h>

/**
 * Stuff from X11/Xlib.h
 */

typedef void *(*XOPENDISPLAY)  (char *);
typedef int   (*XCLOSEDISPLAY) (void *);

/**
 * Declarations from NVCtrl.h
 */

#define NV_CTRL_TARGET_TYPE_GPU            1
#define NV_CTRL_TARGET_TYPE_COOLER         5 /* e.g., fan */

#define NV_CTRL_GPU_COOLER_MANUAL_CONTROL                       319 /* RW-G */
#define NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE                   0
#define NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE                    1

#define NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL                    417 /* R--C */
#define NV_CTRL_THERMAL_COOLER_LEVEL                            320 /* RW-C */

/*
 * NV_CTRL_GPU_CORE_THRESHOLD reflects the temperature at which the
 * GPU is throttled to prevent overheating.
 */

#define NV_CTRL_GPU_CORE_THRESHOLD                              61  /* R--G */

/**
 * hashcat stuff from here
 */

typedef int HM_ADAPTER_XNVCTRL;

#include <shared.h>

#if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#define XNVCTRL_API_CALL __stdcall
#else
#define XNVCTRL_API_CALL
#endif

typedef int  (*XNVCTRL_API_CALL XNVCTRLQUERYTARGETATTRIBUTE) (void *, int, int, unsigned int, unsigned int, int *);
typedef void (*XNVCTRL_API_CALL XNVCTRLSETTARGETATTRIBUTE)   (void *, int, int, unsigned int, unsigned int, int);

typedef struct
{
  void *dpy;

  XNVCTRL_LIB lib_x11;
  XNVCTRL_LIB lib_xnvctrl;

  XOPENDISPLAY  XOpenDisplay;
  XCLOSEDISPLAY XCloseDisplay;

  XNVCTRLQUERYTARGETATTRIBUTE XNVCTRLQueryTargetAttribute;
  XNVCTRLSETTARGETATTRIBUTE   XNVCTRLSetTargetAttribute;

} hm_xnvctrl_lib_t;

#define XNVCTRL_PTR hm_xnvctrl_lib_t

int  xnvctrl_init         (XNVCTRL_PTR *xnvctrl);
void xnvctrl_close        (XNVCTRL_PTR *xnvctrl);

int  hm_XNVCTRL_XOpenDisplay  (XNVCTRL_PTR *xnvctrl);
void hm_XNVCTRL_XCloseDisplay (XNVCTRL_PTR *xnvctrl);

int get_core_threshold    (XNVCTRL_PTR *xnvctrl, int gpu, int *val);

int get_fan_control       (XNVCTRL_PTR *xnvctrl, int gpu, int *val);
int set_fan_control       (XNVCTRL_PTR *xnvctrl, int gpu, int  val);

int get_fan_speed_current (XNVCTRL_PTR *xnvctrl, int gpu, int *val);
int get_fan_speed_target  (XNVCTRL_PTR *xnvctrl, int gpu, int *val);
int set_fan_speed_target  (XNVCTRL_PTR *xnvctrl, int gpu, int  val);

#endif // HAVE_HWMON

#endif // EXT_XNVCTRL_H
