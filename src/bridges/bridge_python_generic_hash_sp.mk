BRIDGE_SRC_bridge_python_generic_hash_sp := src/bridges/bridge_python_generic_hash_sp.c src/cpu_features.c

PYTHON_SP_SKIP_SO  := false
PYTHON_SP_SKIP_DLL := false

# the headers of the python on this machine, for the plugin that will run on this machine. This one
# needs an interpreter that can give a subinterpreter its own GIL, so the headers are asked as well

ifneq (,$(PLUGIN_PLATFORM_so))
ifeq ($(shell command -v python3-config 2>/dev/null),)
PYTHON_SP_SKIP_SO  := true
endif
ifeq ($(PYTHON_SP_SKIP_SO),false)
PYTHON_SP_CFLAGS   := $(shell python3-config --includes 2>/dev/null)
ifeq ($(strip $(PYTHON_SP_CFLAGS)),)
PYTHON_SP_SKIP_SO  := true
endif
endif
ifeq ($(PYTHON_SP_SKIP_SO),false)
PYTHON_SP_INCLUDE  := $(shell echo "$(PYTHON_SP_CFLAGS)" | sed -n 's/-I\([^ ]*\).*/\1/p')
ifeq ($(PYTHON_SP_INCLUDE),)
PYTHON_SP_SKIP_SO  := true
endif
endif
# The bridge refuses anything below 3.13 at run time, because that is where a free-threaded build of
# Python first exists and it is a free-threaded library this loads. The build used to ask for less: it
# looked for PyInterpreterConfig_OWN_GIL, which arrived in 3.12, so 3.12 headers produced a plugin
# that built cleanly and then failed on every run. The two ask for the same version now.
#
# The version comes from the include directory python3-config named, python3.14 or python3.13t, so a
# trailing t for a free-threaded build is dropped before comparing. Building against a Python without
# free-threading is fine and is what the release package does, only running it needs one.

PYTHON_SP_MIN_VERSION := 3.13

ifeq ($(PYTHON_SP_SKIP_SO),false)
PYTHON_SP_VERSION  := $(patsubst %t,%,$(patsubst python%,%,$(notdir $(PYTHON_SP_INCLUDE))))
ifeq ($(shell printf '%s\n%s\n' '$(PYTHON_SP_MIN_VERSION)' '$(PYTHON_SP_VERSION)' | sort -V -C && echo true || echo false),false)
PYTHON_SP_SKIP_SO  := true
endif
endif
endif

# find whichever python the msys2 package under $(WIN_PYTHON) provides, rather than naming one
# version here. Pinning the version meant that bumping the msys2 package silently stopped the
# headers from being found, and the only symptom was the plugin quietly going missing

ifneq (,$(PLUGIN_PLATFORM_dll))
PYTHON_SP_INCLUDE_WIN := $(lastword $(sort $(wildcard $(WIN_PYTHON)/mingw64/include/python3.*)))
ifeq ($(PYTHON_SP_INCLUDE_WIN),)
PYTHON_SP_SKIP_DLL := true
endif
PYTHON_SP_CFLAGS_WIN  := -I$(PYTHON_SP_INCLUDE_WIN)/
endif

ifneq (,$(PLUGIN_PLATFORM_so))
BRIDGE_CFLAGS_bridge_python_generic_hash_sp_$(PLUGIN_PLATFORM_so)  := $(PYTHON_SP_CFLAGS)
endif

ifneq (,$(PLUGIN_PLATFORM_dll))
BRIDGE_CFLAGS_bridge_python_generic_hash_sp_$(PLUGIN_PLATFORM_dll) := $(PYTHON_SP_CFLAGS_WIN)
endif

RED = \033[1;31m
RESET = \033[0m

# where the headers were not found the plugin is not built at all. Saying so here is what keeps the
# warning below from being a second recipe for a file that also has a real one, which make resolves
# by overriding one of them and warning about it on every build

ifeq ($(PYTHON_SP_SKIP_SO),true)
BRIDGE_SKIP_bridge_python_generic_hash_sp_$(PLUGIN_PLATFORM_so) := 1

bridges/bridge_python_generic_hash_sp.so:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping freethreaded plugin 72000: Python $(PYTHON_SP_MIN_VERSION)+ headers not found."
	@echo "         To use -m 72000, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-python-plugin-requirements.md'."
	@echo ""
endif

ifeq ($(PYTHON_SP_SKIP_DLL),true)
BRIDGE_SKIP_bridge_python_generic_hash_sp_$(PLUGIN_PLATFORM_dll) := 1

bridges/bridge_python_generic_hash_sp.dll:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping freethreaded plugin 72000: Python Windows headers not found."
	@echo "         To use -m 72000, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         See BUILD_WSL.md how to prepare $(WIN_PYTHON)."
	@echo ""
endif
