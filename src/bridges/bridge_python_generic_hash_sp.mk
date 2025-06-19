REPORT_MISSING_SO  := false
REPORT_MISSING_DLL := false

ifeq ($(BRIDGE_SUFFIX),so)
ifeq ($(REPORT_MISSING_SO),false)
PYTHON_CONFIG := $(shell command -v python3-config 2>/dev/null)
ifeq ($(PYTHON_CONFIG),)
	REPORT_MISSING_SO := true
endif
endif
ifeq ($(REPORT_MISSING_SO),false)
PYTHON_CFLAGS := $(shell python3-config --includes 2>/dev/null)
ifeq ($(strip $(PYTHON_CFLAGS)),)
	REPORT_MISSING_SO := true
endif
endif
ifeq ($(REPORT_MISSING_SO),false)
PYTHON_INCLUDE_PATH := $(shell echo "$(PYTHON_CFLAGS)" | sed -n 's/-I\([^ ]*\).*/\1/p')
ifeq ($(PYTHON_INCLUDE_PATH),)
	REPORT_MISSING_SO := true
endif
endif
ifeq ($(REPORT_MISSING_SO),false)
PYTHON_HAS_OWN_GIL := $(shell grep -r -q 'PyInterpreterConfig_OWN_GIL' "$(PYTHON_INCLUDE_PATH)" && echo true || echo false)
ifeq ($(PYTHON_HAS_OWN_GIL),false)
	REPORT_MISSING_SO := true
endif
endif
endif

CHECK_DLL := false

ifeq ($(BRIDGE_SUFFIX),dll)
  CHECK_DLL := true
endif
ifeq ($(BUILD_MODE),cross)
  CHECK_DLL := true
endif

ifeq ($(CHECK_DLL),true)
ifeq ($(REPORT_MISSING_DLL),false)
PYTHON_CONFIG := $(shell ls $(WIN_PYTHON)/mingw64/include/python3.12/ 2>/dev/null)
ifeq ($(PYTHON_CONFIG),)
	REPORT_MISSING_DLL := true
endif
endif
PYTHON_CFLAGS_WIN := -I$(WIN_PYTHON)/mingw64/include/python3.12/
endif

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

RED = \033[1;31m
RESET = \033[0m

ifeq ($(REPORT_MISSING_DLL),true)
bridges/bridge_python_generic_hash_sp.dll:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping freethreaded plugin 70200: Python Windows headers not found."
	@echo "         To use -m 70200, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         See BUILD_WSL.md how to prepare $(WIN_PYTHON)."
	@echo ""
endif

ifeq ($(REPORT_MISSING_SO),true)
bridges/bridge_python_generic_hash_sp.so:
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping freethreaded plugin 70200: Python 3.12+ headers not found."
	@echo "         To use -m 70200, you must install the required Python headers."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-python-plugin-requirements.md'."
	@echo ""
endif
