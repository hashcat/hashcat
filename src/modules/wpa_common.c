/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "module_options.h"

// The command line options the WPA modes 2500, 2501, 22000 and 22001 read. Each of them includes this
// file and registers wpa_module_register_options (). The message pair and the nonce corrections decide
// which candidates are tested against which handshake, so both go into the brain attack identity.

#define OPTION_EAPOL_MESSAGE_PAIR      "eapol-message-pair"
#define OPTION_NONCE_ERROR_CORRECTIONS "nonce-error-corrections"

#define NONCE_ERROR_CORRECTIONS 8

const module_option_t *wpa_module_register_options (void)
{
  static const module_option_t options[] =
  {
    {
      .name         = OPTION_EAPOL_MESSAGE_PAIR,
      .type         = MODULE_OPTION_TYPE_U32,
      .flags        = MODULE_OPTION_FLAG_MAX,
      .max          = 5,
      .brain_slot   = 1,
      .excludes     = "remove",
      .help_type    = "Num",
      .help         = "Load only EAPOL message pairs matching X",
      .help_example = "--eapol-message-pair=2",
    },
    {
      .name         = "hccapx-message-pair",
      .type         = MODULE_OPTION_TYPE_U32,
      .flags        = MODULE_OPTION_FLAG_HIDDEN,
      .alias        = OPTION_EAPOL_MESSAGE_PAIR,
    },
    {
      .name         = OPTION_NONCE_ERROR_CORRECTIONS,
      .type         = MODULE_OPTION_TYPE_U32,
      .def          = NONCE_ERROR_CORRECTIONS,
      .brain_slot   = 2,
      .help_type    = "Num",
      .help         = "The BF size range to replace AP's nonce last bytes",
      .help_example = "--nonce-error-corrections=16",
    },
    { .name = NULL },
  };

  return options;
}
