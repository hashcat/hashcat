
PYTHON_CONFIG_FLAGS_LINUX := `python3-config --includes`

# Experimental support for for Windows:
# $ mkdir /opt/cpython-mingw
# $ cd /opt/cpython-mingw
# $ wget https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-python-3.12.10-1-any.pkg.tar.zst
# $ tar --zstd -xf mingw-w64-x86_64-python-3.12.10-1-any.pkg.tar.zst
PYTHON_CONFIG_FLAGS_WIN   := -I/opt/cpython-mingw/mingw64/include/python3.12

ifeq ($(BUILD_MODE),cross)
bridges/bridge_python_generic_hash_sp.so:  src/bridges/bridge_python_generic_hash_sp.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX)
bridges/bridge_python_generic_hash_sp.dll: src/bridges/bridge_python_generic_hash_sp.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_WIN)
else
ifeq ($(SHARED),1)
bridges/bridge_python_generic_hash_sp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_sp.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX) $(PYTHON_CONFIG_FLAGS_WIN)
else
bridges/bridge_python_generic_hash_sp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_sp.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX) $(PYTHON_CONFIG_FLAGS_WIN)
endif
endif

PYTHON_INCLUDE_PATH := $(shell echo $(PYTHON_CONFIG_FLAGS_LINUX) | sed -n 's/-I\([^ ]*\).*/\1/p')
PYTHON_HAS_OWN_GIL := $(shell grep -r -q 'PyInterpreterConfig_OWN_GIL' $(PYTHON_INCLUDE_PATH) && echo yes || echo no)

ifeq ($(BRIDGE_SUFFIX),so)
ifeq ($(PYTHON_HAS_OWN_GIL),no)
bridges/bridge_python_generic_hash_sp.so:
	@echo ""
	@echo "WARNING: Skipping freethreaded plugin 70200: Python 3.12+ headers not found."
	@echo "         Please read 'docs/hashcat-python-plugin-requirements.md'."
	@echo ""	
endif
endif
