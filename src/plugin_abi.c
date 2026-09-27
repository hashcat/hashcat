/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The name that says which plugin interface this core implements. Every module, bridge and feed is
// linked to hold a reference to it, so raising MODULE_INTERFACE_VERSION renames it and every plugin
// built against the old number is refused by the loader, which names the symbol it could not find.
// The name is the whole of the check and nothing calls this.
//
// It is a function rather than a constant because a reference to a function is the one thing every
// linker imports the same way.
//
// It has a translation unit to itself so that it costs a plugin nothing to hold. Under SHARED=0 a
// plugin links the core as an archive, and a reference pulls in the member that answers it: sharing
// a file with the plugin loader would have pulled the loader, and the backend behind it, into every
// static module for the sake of one name.

#include "common.h"
#include "types.h"

HC_PLUGIN_API int HC_PLUGIN_ABI (void)
{
  return HC_PLUGIN_ABI_VERSION;
}
