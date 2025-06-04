
SCRYPT_YESCRYPT := deps/yescrypt-master
SCRYPT_YESCRYPT_CFLAGS := -I$(SCRYPT_YESCRYPT)/ -DSKIP_MEMZERO -Wno-cpp -Wno-type-limits

ifeq ($(BUILD_MODE),cross)
SCRYPT_YESCRYPT_CFLAGS += -mavx2
else
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),0)
SCRYPT_YESCRYPT_CFLAGS += -mavx2
endif
else
SCRYPT_YESCRYPT_CFLAGS += -march=native
endif
endif

ifeq ($(BUILD_MODE),cross)
bridges/bridge_scrypt_yescrypt.so:  src/bridges/bridge_scrypt_yescrypt.c src/cpu_features.c $(SCRYPT_YESCRYPT)/yescrypt-opt.c $(SCRYPT_YESCRYPT)/sha256.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)  $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_YESCRYPT_CFLAGS)
bridges/bridge_scrypt_yescrypt.dll: src/bridges/bridge_scrypt_yescrypt.c src/cpu_features.c $(SCRYPT_YESCRYPT)/yescrypt-opt.c $(SCRYPT_YESCRYPT)/sha256.c obj/combined.WIN.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)    $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_YESCRYPT_CFLAGS)
else
ifeq ($(SHARED),1)
bridges/bridge_scrypt_yescrypt.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_yescrypt.c src/cpu_features.c $(SCRYPT_YESCRYPT)/yescrypt-opt.c $(SCRYPT_YESCRYPT)/sha256.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_YESCRYPT_CFLAGS)
else
bridges/bridge_scrypt_yescrypt.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_yescrypt.c src/cpu_features.c $(SCRYPT_YESCRYPT)/yescrypt-opt.c $(SCRYPT_YESCRYPT)/sha256.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_YESCRYPT_CFLAGS)
endif
endif
