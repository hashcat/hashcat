/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "path.h"
#include "keyboard_layout.h"
#include "module_options.h"

// The command line options the TrueCrypt and VeraCrypt modes read. VeraCrypt continues the TrueCrypt
// format and takes its keyfiles the same way, so both families share this file. A module registers the
// list that fits it: its own keyfiles, VeraCrypt's PIM range, and the keyboard layout mapping where the
// module sets OPTS_TYPE_KEYBOARD_MAPPING.

#define OPTION_TRUECRYPT_KEYFILES      "truecrypt-keyfiles"
#define OPTION_VERACRYPT_KEYFILES      "veracrypt-keyfiles"
#define OPTION_VERACRYPT_PIM_START     "veracrypt-pim-start"
#define OPTION_VERACRYPT_PIM_STOP      "veracrypt-pim-stop"
#define OPTION_KEYBOARD_LAYOUT_MAPPING "keyboard-layout-mapping"

bool keyfiles_check (const char *value, char *err, const size_t err_sz)
{
  char *keyfiles = hcstrdup (value);

  char *saveptr = NULL;

  char *keyfile = strtok_r (keyfiles, ",", &saveptr);

  bool readable = true;

  while (keyfile)
  {
    if (hc_path_read (keyfile) == false)
    {
      snprintf (err, err_sz, "%s: %s", keyfile, strerror (errno));

      readable = false;

      break;
    }

    keyfile = strtok_r ((char *) NULL, ",", &saveptr);
  }

  hcfree (keyfiles);

  return readable;
}

// The file is read here as well as in module_hash_decode_postprocess (), which loads the mapping into
// the esalt, because a result of that hook is never looked at. A file it could not use would convert
// nothing and print nothing, which is the failure this check exists to prevent. Reading it twice costs
// one pass over a file of at most 256 lines, once per run.

bool keyboard_layout_mapping_check (const char *value, char *err, const size_t err_sz)
{
  if (hc_path_read (value) == false)
  {
    snprintf (err, err_sz, "%s: %s", value, strerror (errno));

    return false;
  }

  keyboard_layout_mapping_t probe[256];

  int probe_cnt = 0;

  if (initialize_keyboard_layout_mapping (value, probe, &probe_cnt) == false)
  {
    snprintf (err, err_sz, "%s: no keyboard mappings in this file. A mapping is one source and one replacement separated by a single tab.", value);

    return false;
  }

  // A mapping converts each token to one other token, so a file that gives a token two replacements
  // is not one. The table attack takes such a file and offers both, and the reverse layout tables
  // are exactly that where two keys of one layout produce the same character on the other. Here the
  // lookup would find whichever came first and convert the other away silently.

  for (int i = 0; i < probe_cnt; i++)
  {
    for (int j = i + 1; j < probe_cnt; j++)
    {
      if (probe[i].src_len  != probe[j].src_len)  continue;
      if (probe[i].src_char != probe[j].src_char) continue;

      snprintf (err, err_sz, "%s: one source is given two replacements, so this is a table rather than a keyboard mapping. A mapping converts each token to exactly one other token.", value);

      return false;
    }
  }

  return true;
}

#define KEYBOARD_LAYOUT_MAPPING_OPTION                                                    \
  {                                                                                       \
    .name         = OPTION_KEYBOARD_LAYOUT_MAPPING,                                       \
    .type         = MODULE_OPTION_TYPE_STR,                                               \
    .check        = keyboard_layout_mapping_check,                                        \
    .help_type    = "File",                                                               \
    .help         = "Keyboard layout mapping table for special hash-modes",               \
    .help_example = "--keyb=tables/layouts/de.table",                                     \
  }

#define TRUECRYPT_KEYFILES_OPTION                                                         \
  {                                                                                       \
    .name         = OPTION_TRUECRYPT_KEYFILES,                                            \
    .type         = MODULE_OPTION_TYPE_STR,                                               \
    .check        = keyfiles_check,                                                       \
    .help_type    = "File",                                                               \
    .help         = "Keyfiles to use, separated with commas",                             \
    .help_example = "--truecrypt-keyf=x.png",                                             \
  }

#define VERACRYPT_OPTIONS                                                                 \
  {                                                                                       \
    .name         = OPTION_VERACRYPT_KEYFILES,                                            \
    .type         = MODULE_OPTION_TYPE_STR,                                               \
    .check        = keyfiles_check,                                                       \
    .help_type    = "File",                                                               \
    .help         = "Keyfiles to use, separated with commas",                             \
    .help_example = "--veracrypt-keyf=x.txt",                                             \
  },                                                                                      \
  {                                                                                       \
    .name         = OPTION_VERACRYPT_PIM_START,                                           \
    .type         = MODULE_OPTION_TYPE_U32,                                               \
    .def          = 485,                                                                  \
    .brain_slot   = 1,                                                                    \
    .le           = OPTION_VERACRYPT_PIM_STOP,                                            \
    .requires     = OPTION_VERACRYPT_PIM_STOP,                                            \
    .help_type    = "Num",                                                                \
    .help         = "VeraCrypt personal iterations multiplier start",                     \
    .help_example = "--veracrypt-pim-start=450",                                          \
  },                                                                                      \
  {                                                                                       \
    .name         = OPTION_VERACRYPT_PIM_STOP,                                            \
    .type         = MODULE_OPTION_TYPE_U32,                                               \
    .def          = 485,                                                                  \
    .brain_slot   = 2,                                                                    \
    .requires     = OPTION_VERACRYPT_PIM_START,                                           \
    .help_type    = "Num",                                                                \
    .help         = "VeraCrypt personal iterations multiplier stop",                      \
    .help_example = "--veracrypt-pim-stop=500",                                           \
  }

// The keyboard layout mapping goes first where a module takes it, so that its file is checked before
// the keyfiles, the order these checks have always run in.

const module_option_t *truecrypt_module_register_options (void)
{
  static const module_option_t options[] =
  {
    TRUECRYPT_KEYFILES_OPTION,
    { .name = NULL },
  };

  return options;
}

const module_option_t *truecrypt_keyboard_module_register_options (void)
{
  static const module_option_t options[] =
  {
    KEYBOARD_LAYOUT_MAPPING_OPTION,
    TRUECRYPT_KEYFILES_OPTION,
    { .name = NULL },
  };

  return options;
}

const module_option_t *veracrypt_module_register_options (void)
{
  static const module_option_t options[] =
  {
    VERACRYPT_OPTIONS,
    { .name = NULL },
  };

  return options;
}

const module_option_t *veracrypt_keyboard_module_register_options (void)
{
  static const module_option_t options[] =
  {
    KEYBOARD_LAYOUT_MAPPING_OPTION,
    VERACRYPT_OPTIONS,
    { .name = NULL },
  };

  return options;
}
