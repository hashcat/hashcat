/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXPORT_H
#define HC_EXPORT_H

// What leaves the core, written on the thing that leaves.
//
// The core is compiled with hidden visibility, so a function it defines cannot be reached from
// outside the library unless its declaration carries one of the macros below. There is no list of
// exported names anywhere else and nothing measures which names are wanted. Putting a function into
// the contract means writing the macro in front of its declaration, and taking it out again means
// removing the macro.
//
// HC_API is what a program that embeds the core calls to run a session. It is promised for as long
// as the library file name stands, and that name carries the major version.
//
// HC_PLUGIN_API is what a module, a bridge or a feed calls. It is promised for as long as
// MODULE_INTERFACE_VERSION stands, which is a shorter promise: raising that number renames the
// symbol every plugin is linked to require, and every plugin built against the old number is then
// refused by the loader instead of running against an interface that has moved underneath it.
//
// A name that both of them call carries HC_API, because that is the longer of the two promises.
//
// HC_PLUGIN_ENTRY is the other direction. It is the one name a plugin hands the core, and a plugin
// is compiled hidden as well, so a built plugin exports that name and nothing else.
//
// The static arrangement has no library and nothing crosses a boundary, so the two API macros are
// empty there and every core function stays inside the artifact that copied it. HC_PLUGIN_ENTRY is
// not, because a plugin is a shared object in both arrangements.

#if defined (HC_CORE_STATIC)
#define HC_EXPORT
#elif defined (_WIN32) || defined (__CYGWIN__)
#if defined (HC_CORE_BUILD)
#define HC_EXPORT __declspec (dllexport)
#else
#define HC_EXPORT __declspec (dllimport)
#endif
#else
#define HC_EXPORT __attribute__ ((visibility ("default")))
#endif

// The core reads the plugin headers to know the shape of what it will call, and it never defines any
// of it, so there the entry macro says nothing.

#if defined (HC_CORE_BUILD)
#define HC_ENTRY
#elif defined (_WIN32) || defined (__CYGWIN__)
#define HC_ENTRY __declspec (dllexport)
#else
#define HC_ENTRY __attribute__ ((visibility ("default")))
#endif

#define HC_API          HC_EXPORT
#define HC_PLUGIN_API   HC_EXPORT
#define HC_PLUGIN_ENTRY HC_ENTRY

// The name that carries the plugin interface version. The core defines it and every plugin holds a
// reference to it, and the number in the name is the whole of the check: a core that has moved on
// defines a different name, so a plugin built against the old one cannot be loaded and the loader
// says which name it could not find.
//
// The reference is written here rather than asked for on the link line, because a name the linker
// was told to look up but that nothing refers to leaves no relocation behind, and a symbol with no
// relocation against it is one the loader never looks at. The plugin would load and the check would
// silently not happen. A pointer the plugin holds is a relocation, and holding it is also the
// honest statement: this artifact was built against that interface.
//
// HC_PLUGIN_ABI_VERSION is on the compile line of the core and of every plugin, and HC_CORE_BUILD is
// what tells the two apart. A program that only embeds the core has neither and takes no part in
// this: what it calls is HC_API, whose promise stands for as long as the library name does.
//
// The number has no default, because a default is a plugin that says nothing and is believed. A
// plugin compiled without it holds no reference, loads against any core, and discovers what has
// moved by running into it. The three headers a plugin includes, and only a plugin includes, refuse
// to compile in that case, so it is the plugin author's build that fails and not the user's run.
//
// The reference is held in both arrangements. Under SHARED=0 the core is copied into the plugin and
// the name resolves inside the artifact, which costs nothing and still fails the link when the
// plugin was built against a number the copied core does not carry.

#define HC_PLUGIN_ABI_JOIN(version) HASHCAT_PLUGIN_ ## version
#define HC_PLUGIN_ABI_NAME(version) HC_PLUGIN_ABI_JOIN (version)

#if !defined (HC_CORE_BUILD) && !defined (HC_PLUGIN_ABI_VERSION)
#define HC_PLUGIN_ABI_MISSING
#endif

#if defined (HC_PLUGIN_ABI_VERSION)
#define HC_PLUGIN_ABI HC_PLUGIN_ABI_NAME (HC_PLUGIN_ABI_VERSION)

#if !defined (HC_CORE_BUILD)
HC_PLUGIN_API int HC_PLUGIN_ABI (void);

static int (* const hc_plugin_abi) (void) __attribute__ ((used)) = HC_PLUGIN_ABI;
#endif
#endif

#endif // HC_EXPORT_H
