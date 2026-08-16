BRIDGE_SRC_bridge_python_generic_hash_mp := src/bridges/bridge_python_generic_hash_mp.c src/cpu_features.c

PYTHON_MP_SKIP_SO  := false
PYTHON_MP_SKIP_DLL := false

# the headers of the python on this machine, for the plugin that will run on this machine

ifneq (,$(PLUGIN_PLATFORM_so))
ifeq ($(shell command -v python3-config 2>/dev/null),)
PYTHON_MP_SKIP_SO  := true
endif
ifeq ($(PYTHON_MP_SKIP_SO),false)
PYTHON_MP_CFLAGS   := $(shell python3-config --includes 2>/dev/null)
ifeq ($(strip $(PYTHON_MP_CFLAGS)),)
PYTHON_MP_SKIP_SO  := true
endif
endif
endif

# find whichever python the msys2 package under $(WIN_PYTHON) provides, rather than naming one
# version here. Pinning the version meant that bumping the msys2 package silently stopped the
# headers from being found, and the only symptom was the plugin quietly going missing

ifneq (,$(PLUGIN_PLATFORM_dll))
PYTHON_MP_INCLUDE_WIN := $(lastword $(sort $(wildcard $(WIN_PYTHON)/mingw64/include/python3.*)))
ifeq ($(PYTHON_MP_INCLUDE_WIN),)
PYTHON_MP_SKIP_DLL := true
endif
PYTHON_MP_CFLAGS_WIN  := -I$(PYTHON_MP_INCLUDE_WIN)/
endif

ifneq (,$(PLUGIN_PLATFORM_so))
BRIDGE_CFLAGS_bridge_python_generic_hash_mp_$(PLUGIN_PLATFORM_so)  := $(PYTHON_MP_CFLAGS)
endif

ifneq (,$(PLUGIN_PLATFORM_dll))
BRIDGE_CFLAGS_bridge_python_generic_hash_mp_$(PLUGIN_PLATFORM_dll) := $(PYTHON_MP_CFLAGS_WIN)
endif

RED = \033[1;31m
RESET = \033[0m

# where the headers were not found the plugin is not built at all. Saying so here is what keeps the
# warning below from being a second recipe for a file that also has a real one, which make resolves
# by overriding one of them and warning about it on every build

ifeq ($(PYTHON_MP_SKIP_SO),true)
BRIDGE_SKIP_bridge_python_generic_hash_mp_$(PLUGIN_PLATFORM_so) := 1

bridges/bridge_python_generic_hash_mp.so:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping regular plugin 73000: Python headers not found."
	@echo "         To use -m 73000, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-python-plugin-requirements.md'."
	@echo ""
endif

ifeq ($(PYTHON_MP_SKIP_DLL),true)
BRIDGE_SKIP_bridge_python_generic_hash_mp_$(PLUGIN_PLATFORM_dll) := 1

bridges/bridge_python_generic_hash_mp.dll:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping regular plugin 73000: Python Windows headers not found."
	@echo "         To use -m 73000, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         See BUILD_WSL.md how to prepare $(WIN_PYTHON)."
	@echo ""
endif
