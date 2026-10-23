/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_ZTEX_TOOL_CTX_H
#define HC_FPGA_ZTEX_TOOL_CTX_H

#include "common.h"
#include "types.h"
#include "event.h"

#include <stdio.h>
#include <string.h>

static event_ctx_t     ztex_tool_event_ctx;
static folder_config_t ztex_tool_folder_config;
static hashcat_ctx_t   ztex_tool_hashcat_ctx;

static void ztex_tool_event (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  (void) buf;
  (void) len;

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  switch (id)
  {
    case EVENT_LOG_INFO:
    case EVENT_LOG_WARNING:
    case EVENT_LOG_ERROR:
    case EVENT_LOG_ADVICE: break;

    default: return;
  }

  fprintf (stderr, "%s\n", event_ctx->msg_buf);
}

static hashcat_ctx_t *ztex_tool_ctx (const char *dir)
{
  memset (&ztex_tool_event_ctx,     0, sizeof (ztex_tool_event_ctx));
  memset (&ztex_tool_folder_config, 0, sizeof (ztex_tool_folder_config));
  memset (&ztex_tool_hashcat_ctx,   0, sizeof (ztex_tool_hashcat_ctx));

  ztex_tool_folder_config.profile_dir = (char *) dir;

  ztex_tool_hashcat_ctx.event_ctx     = &ztex_tool_event_ctx;
  ztex_tool_hashcat_ctx.folder_config = &ztex_tool_folder_config;
  ztex_tool_hashcat_ctx.event         = ztex_tool_event;

  return &ztex_tool_hashcat_ctx;
}

#endif
