
PYTHON_CFLAGS     := `python3-config --includes`
# See BUILD_WSL.md how to prepare $(WIN_PYTHON)
PYTHON_CFLAGS_WIN := -I$(WIN_PYTHON)/mingw64/include/python3.12/

ifeq ($(BUILD_MODE),cross)
bridges/bridge_python_generic_hash_sp.so:  src/bridges/bridge_python_generic_hash_sp.c src/cpu_features.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CFLAGS)
bridges/bridge_python_generic_hash_sp.dll: src/bridges/bridge_python_generic_hash_sp.c src/cpu_features.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CFLAGS_WIN)
else
ifeq ($(SHARED),1)
bridges/bridge_python_generic_hash_sp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_sp.c src/cpu_features.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CFLAGS)
else
bridges/bridge_python_generic_hash_sp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_sp.c src/cpu_features.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CFLAGS)
endif
endif

ifeq ($(BRIDGE_SUFFIX),so)

PYTHON_INCLUDE_PATH := $(shell echo "$(PYTHON_CFLAGS)" | sed -n 's/-I\([^ ]*\).*/\1/p')
PYTHON_HAS_OWN_GIL := $(shell grep -r -q 'PyInterpreterConfig_OWN_GIL' "$(PYTHON_INCLUDE_PATH)" && echo true || echo false)

REPORTS_MISSING := false

ifeq ($(PYTHON_INCLUDE_PATH),)
	REPORTS_MISSING := true
endif

ifeq ($(PYTHON_HAS_OWN_GIL),false)
	REPORTS_MISSING := true
endif

RED = \033[1;31m
RESET = \033[0m

ifeq ($(REPORTS_MISSING),true)
bridges/bridge_python_generic_hash_sp.so:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping freethreaded plugin 70200: Python 3.12+ headers not found."
	@echo "         To use -m 70200, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-python-plugin-requirements.md'."
	@echo ""
endif

endif
