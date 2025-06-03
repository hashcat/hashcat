
SCRYPT_JANE := deps/scrypt-jane-master
SCRYPT_JANE_CFLAGS := -I$(SCRYPT_JANE)/ -DSCRYPT_SHA256 -DSCRYPT_SALSA -DSCRYPT_CHOOSE_COMPILETIME -Wno-unused-function -Wno-unused-but-set-variable

ifeq ($(BUILD_MODE),cross)
SCRYPT_JANE_CFLAGS += -mavx2
else
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),0)
SCRYPT_JANE_CFLAGS += -mavx2
endif
else
SCRYPT_JANE_CFLAGS += -march=native
endif
endif

ifeq ($(BUILD_MODE),cross)
bridges/bridge_scrypt_jane.so:  src/bridges/bridge_scrypt_jane.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)  $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
bridges/bridge_scrypt_jane.dll: src/bridges/bridge_scrypt_jane.c obj/combined.WIN.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)    $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
else
ifeq ($(SHARED),1)
bridges/bridge_scrypt_jane.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_jane.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
else
bridges/bridge_scrypt_jane.$(BRIDGE_SUFFIX): src/bridges/bridge_scrypt_jane.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(SCRYPT_JANE_CFLAGS)
endif
endif
