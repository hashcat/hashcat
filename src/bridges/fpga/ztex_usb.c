/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"

#include "fpga/hcfpga.h"
#include "fpga/ztex_usb.h"

#if defined (__linux__)

#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#define ZTEX_BULK_TIMEOUT 5000

static u64 ztex_now_ms (void)
{
  const u64 ms = fpga_now_ns () / 1000000ull;

  return ms;
}

static int ztex_urb_reap (const int fd, struct usbdevfs_urb *want)
{
  struct usbdevfs_urb *done = NULL;

  if (ioctl (fd, USBDEVFS_REAPURBNDELAY, &done) == 0)
  {
    if (done == want) return 1;

    return 0;
  }

  if (errno == EAGAIN) return 0;
  if (errno == EINTR)  return 0;

  return -1;
}

int ztex_bulk_xfer (const int fd, const u8 ep, void *buf, const u32 len, const u32 timeout_ms)
{
  struct usbdevfs_urb urb;

  memset (&urb, 0, sizeof (urb));

  urb.type          = USBDEVFS_URB_TYPE_BULK;
  urb.endpoint      = ep;
  urb.buffer        = buf;
  urb.buffer_length = (int) len;

  if (ioctl (fd, USBDEVFS_SUBMITURB, &urb) < 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] submit ep 0x%02x len %u -> errno %d (%s)\n", ep, len, errno, strerror (errno));

    return -1;
  }

  const u64 deadline = ztex_now_ms () + timeout_ms;

  bool cancelled = false;
  bool broken    = false;
  bool lost      = false;
  bool stalled   = false;

  u32 spins = 0;

  for (;;)
  {
    const int reaped = ztex_urb_reap (fd, &urb);

    if (reaped == 1) break;

    if (reaped < 0)
    {
      lost = true;

      break;
    }

    spins++;

    if (spins > 100)
    {
      if ((stalled == false) && (cancelled == false) && (ztex_dbg () == true))
      {
        fprintf (stderr, "[ztex] urb ep 0x%02x len %u would not reap, cancelling it\n", ep, len);
      }

      stalled = true;
    }

    const u64 now = ztex_now_ms ();

    int wait_ms = 0;

    if (cancelled == true)      wait_ms = 100;
    else if (now < deadline)    wait_ms = (int) (deadline - now);

    struct pollfd pfd;

    pfd.fd      = fd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    const int pr = poll (&pfd, 1, wait_ms);

    if ((pr < 0) && (errno == EINTR)) continue;

    if ((pr < 0) || ((pfd.revents & (POLLERR | POLLHUP)) != 0)) broken = true;

    if ((pfd.revents & POLLOUT) != 0) continue;

    if (cancelled == true) continue;

    if ((broken == true) || (stalled == true) || (now >= deadline))
    {
      if ((ioctl (fd, USBDEVFS_DISCARDURB, &urb) < 0) && (errno != EINVAL))
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] discard ep 0x%02x -> errno %d (%s)\n", ep, errno, strerror (errno));
      }

      cancelled = true;
    }
  }

  if (lost == true)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] urb ep 0x%02x len %u was never collected, errno %d (%s)\n", ep, len, errno, strerror (errno));

    return -1;
  }

  if ((urb.status != 0) && (urb.status != -ECONNRESET) && (urb.status != -ENOENT))
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] urb ep 0x%02x len %u -> status %d, %d bytes\n", ep, len, urb.status, urb.actual_length);

    return -1;
  }

  return urb.actual_length;
}

int ztex_bulk_write_reading (const int fd, const u8 ep_out, void *src, const u32 len, const u8 ep_in, u8 *dst, const u32 dst_room, const u32 pkt, u32 *dst_got, const u32 timeout_ms)
{
  *dst_got = 0;

  struct usbdevfs_urb out;
  struct usbdevfs_urb in;

  memset (&out, 0, sizeof (out));
  memset (&in,  0, sizeof (in));

  out.type          = USBDEVFS_URB_TYPE_BULK;
  out.endpoint      = (u8) (ep_out & 0x7f);
  out.buffer        = src;
  out.buffer_length = (int) len;

  if (ioctl (fd, USBDEVFS_SUBMITURB, &out) < 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] submit ep 0x%02x len %u -> errno %d (%s)\n", out.endpoint, len, errno, strerror (errno));

    return -1;
  }

  const u64 deadline = ztex_now_ms () + timeout_ms;

  bool out_busy = true;
  bool in_busy  = false;

  bool cancelled = false;
  bool failed    = false;
  bool lost      = false;

  while ((out_busy == true) || (in_busy == true))
  {
    if ((out_busy == true) && (in_busy == false) && (cancelled == false) && ((dst_room - *dst_got) >= pkt))
    {
      memset (&in, 0, sizeof (in));

      in.type          = USBDEVFS_URB_TYPE_BULK;
      in.endpoint      = (u8) (ep_in | 0x80);
      in.buffer        = dst + *dst_got;
      in.buffer_length = (int) pkt;

      if (ioctl (fd, USBDEVFS_SUBMITURB, &in) == 0)
      {
        in_busy = true;
      }
      else
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] submit ep 0x%02x len %u -> errno %d (%s)\n", in.endpoint, pkt, errno, strerror (errno));

        failed = true;
      }
    }

    struct usbdevfs_urb *done = NULL;

    if (ioctl (fd, USBDEVFS_REAPURBNDELAY, &done) == 0)
    {
      if (done == &out)
      {
        out_busy = false;

        if ((out.status != 0) && (out.status != -ECONNRESET) && (out.status != -ENOENT)) failed = true;

        if ((in_busy == true) && (ioctl (fd, USBDEVFS_DISCARDURB, &in) < 0) && (errno != EINVAL))
        {
          if (ztex_dbg () == true) fprintf (stderr, "[ztex] discard ep 0x%02x -> errno %d (%s)\n", in.endpoint, errno, strerror (errno));
        }
      }
      else if (done == &in)
      {
        in_busy = false;

        if ((in.status != 0) && (in.status != -ECONNRESET) && (in.status != -ENOENT)) failed = true;

        if (in.actual_length > 0) *dst_got += (u32) in.actual_length;
      }

      continue;
    }

    if ((errno != EAGAIN) && (errno != EINTR))
    {
      lost = true;

      break;
    }

    const u64 now = ztex_now_ms ();

    const bool late = ((out_busy == true) && (now >= deadline)) ? true : false;

    if ((cancelled == false) && ((failed == true) || (late == true)))
    {
      if ((out_busy == true) && (ioctl (fd, USBDEVFS_DISCARDURB, &out) < 0) && (errno != EINVAL))
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] discard ep 0x%02x -> errno %d (%s)\n", out.endpoint, errno, strerror (errno));
      }

      if ((in_busy == true) && (ioctl (fd, USBDEVFS_DISCARDURB, &in) < 0) && (errno != EINVAL))
      {
        if (ztex_dbg () == true) fprintf (stderr, "[ztex] discard ep 0x%02x -> errno %d (%s)\n", in.endpoint, errno, strerror (errno));
      }

      if (late == true) failed = true;

      cancelled = true;

      continue;
    }

    int wait_ms = 100;

    if ((cancelled == false) && (out_busy == true) && ((deadline - now) < 100)) wait_ms = (int) (deadline - now);

    struct pollfd pfd;

    pfd.fd      = fd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    const int pr = poll (&pfd, 1, wait_ms);

    if ((pr < 0) && (errno == EINTR)) continue;

    if ((pr < 0) || ((pfd.revents & (POLLERR | POLLHUP)) != 0)) failed = true;
  }

  if ((lost == true) || (failed == true))
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] write ep 0x%02x len %u -> status %d, %d bytes, %u read\n", out.endpoint, len, out.status, out.actual_length, *dst_got);

    return -1;
  }

  return out.actual_length;
}

int ztex_control_read (const int fd, const u8 request, const u16 value, const u16 index, void *buf, const u16 len)
{
  struct usbdevfs_ctrltransfer ctrl;

  memset (&ctrl, 0, sizeof (ctrl));

  ctrl.bRequestType = 0xc0;
  ctrl.bRequest     = request;
  ctrl.wValue       = value;
  ctrl.wIndex       = index;
  ctrl.wLength      = len;
  ctrl.timeout      = 1000;
  ctrl.data         = buf;

  const int rc = ioctl (fd, USBDEVFS_CONTROL, &ctrl);

  return rc;
}

bool ztex_claim (const int fd)
{
  unsigned int interface = 0;

  if (ioctl (fd, USBDEVFS_CLAIMINTERFACE, &interface) < 0) return false;

  return true;
}

bool ztex_dbg (void)
{
  static int on = -1;

  if (on < 0) on = (getenv ("HCFPGA_DEBUG") != NULL) ? 1 : 0;

  return (on == 1) ? true : false;
}

bool ztex_bulk_write (const int fd, const u32 ep, void *src, const u32 len)
{
  const int rc = ztex_bulk_xfer (fd, (u8) ep, src, len, ZTEX_BULK_TIMEOUT);

  if (rc != (int) len)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] bulk_write ep 0x%02x len %u -> %d bytes, errno %d (%s)\n", ep, len, rc, errno, strerror (errno));

    return false;
  }

  return true;
}

bool ztex_control_write (const int fd, const u8 request, const u16 value, const u16 index)
{
  struct usbdevfs_ctrltransfer ctrl;

  memset (&ctrl, 0, sizeof (ctrl));

  ctrl.bRequestType = 0x40;
  ctrl.bRequest     = request;
  ctrl.wValue       = value;
  ctrl.wIndex       = index;
  ctrl.wLength      = 0;
  ctrl.timeout      = 1000;
  ctrl.data         = NULL;

  const int rc = ioctl (fd, USBDEVFS_CONTROL, &ctrl);

  if (rc < 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] control_write vr 0x%02x -> rc %d, errno %d (%s)\n", request, rc, errno, strerror (errno));

    return false;
  }

  return true;
}

bool ztex_sysfs_read (const char *dir, const char *name, char *out, const size_t out_size)
{
  char path[FPGA_PATH_MAX];

  snprintf (path, sizeof (path), "%s/%s", dir, name);

  const int fd = open (path, O_RDONLY);

  if (fd < 0) return false;

  const ssize_t got = read (fd, out, out_size - 1);

  close (fd);

  if (got <= 0) return false;

  out[got] = 0;

  for (ssize_t i = got - 1; i >= 0; i--)
  {
    if (out[i] != '\n') break;

    out[i] = 0;
  }

  return true;
}

void ztex_swap_bits (u8 *buf, const size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    const u8 b = buf[i];

    buf[i] = (u8) (((b & 0x80) >> 7) | ((b & 0x01) << 7)
                 | ((b & 0x40) >> 5) | ((b & 0x02) << 5)
                 | ((b & 0x20) >> 3) | ((b & 0x04) << 3)
                 | ((b & 0x10) >> 1) | ((b & 0x08) << 1));
  }
}

bool ztex_control_write_data (const int fd, const u8 request, const u16 value, const u16 index, void *buf, const u16 len)
{
  struct usbdevfs_ctrltransfer ctrl;

  memset (&ctrl, 0, sizeof (ctrl));

  ctrl.bRequestType = 0x40;
  ctrl.bRequest     = request;
  ctrl.wValue       = value;
  ctrl.wIndex       = index;
  ctrl.wLength      = len;
  ctrl.timeout      = 1000;
  ctrl.data         = buf;

  const int rc = ioctl (fd, USBDEVFS_CONTROL, &ctrl);

  if (rc < 0)
  {
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] control_write_data vr 0x%02x -> rc %d, errno %d (%s)\n", request, rc, errno, strerror (errno));

    return false;
  }

  return true;
}

int ztex_bulk_in (const int fd, const u32 ep, void *dst, const u32 len, const u32 timeout_ms)
{
  const int got = ztex_bulk_xfer (fd, (u8) (ep | 0x80), dst, len, timeout_ms);

  return got;
}

#define ZTEX_BIT_CHUNK 65536

bool ztex_hs_upload (const int fd, const u32 endpoint, const char *path)
{
  #define UPLOAD_FAILED(stage)                                                              \
  {                                                                                         \
    if (ztex_dbg () == true) fprintf (stderr, "[ztex] upload stopped at %s\n", stage);       \
                                                                                            \
    return false;                                                                           \
  }

  if (ztex_control_write (fd, ZTEX_VC_RESET_FPGA, 0, 0) == false) UPLOAD_FAILED ("RESET_FPGA")

  if (ztex_control_write (fd, ZTEX_VC_HS_CONF_INIT, 0, 0) == false) UPLOAD_FAILED ("HS_CONF_INIT")

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) UPLOAD_FAILED ("fopen")

  u8 *buf = (u8 *) hcmalloc (ZTEX_BIT_CHUNK);

  if (buf == NULL)
  {
    fclose (fp);

    UPLOAD_FAILED ("hcmalloc")
  }

  bool ok = true;

  while (feof (fp) == 0)
  {
    const size_t got = fread (buf, 1, ZTEX_BIT_CHUNK, fp);

    if (ferror (fp) != 0)
    {
      ok = false;

      break;
    }

    if (got == 0) break;

    ztex_swap_bits (buf, got);

    if (ztex_bulk_write (fd, endpoint, buf, (u32) got) == false)
    {
      ok = false;

      break;
    }
  }

  hcfree (buf);

  fclose (fp);

  if (ok == false) UPLOAD_FAILED ("bitstream data")

  if (ztex_control_write (fd, ZTEX_VC_HS_CONF_DONE, 0, 0) == false) UPLOAD_FAILED ("HS_CONF_DONE")

  #undef UPLOAD_FAILED

  return true;
}

bool ztex_fpga_is_configured (const int fd)
{
  u8 buf[9];

  if (ztex_control_read (fd, ZTEX_VR_FPGA_STATE, 0, 0, buf, sizeof (buf)) != (int) sizeof (buf)) return false;

  if (buf[0] != 0) return false;

  return true;
}

#endif
