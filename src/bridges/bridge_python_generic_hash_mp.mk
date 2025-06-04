
PYTHON_CONFIG_FLAGS_LINUX := `python3-config --includes`
# See BUILD_WSL.md to prepare /opt/win-python
PYTHON_CONFIG_FLAGS_WIN   := -I/opt/win-python/mingw64/include/python3.12

ifeq ($(BUILD_MODE),cross)
bridges/bridge_python_generic_hash_mp.so:  src/bridges/bridge_python_generic_hash_mp.c src/cpu_features.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX)
bridges/bridge_python_generic_hash_mp.dll: src/bridges/bridge_python_generic_hash_mp.c src/cpu_features.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_WIN)
else
ifeq ($(SHARED),1)
bridges/bridge_python_generic_hash_mp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_mp.c src/cpu_features.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX) $(PYTHON_CONFIG_FLAGS_WIN)
else
bridges/bridge_python_generic_hash_mp.$(BRIDGE_SUFFIX): src/bridges/bridge_python_generic_hash_mp.c src/cpu_features.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(PYTHON_CONFIG_FLAGS_LINUX) $(PYTHON_CONFIG_FLAGS_WIN)
endif
endif
