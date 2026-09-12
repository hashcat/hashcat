
LITEX_BCRYPT_CFLAGS :=

ifeq ($(BUILD_MODE),cross)
bridges/bridge_litex_bcrypt.so:  src/bridges/bridge_litex_bcrypt.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)  $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(LITEX_BCRYPT_CFLAGS)
bridges/bridge_litex_bcrypt.dll: src/bridges/bridge_litex_bcrypt.c obj/combined.WIN.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)    $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(LITEX_BCRYPT_CFLAGS)
else
ifeq ($(SHARED),1)
bridges/bridge_litex_bcrypt.$(BRIDGE_SUFFIX): src/bridges/bridge_litex_bcrypt.c $(HASHCAT_LIBRARY)
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(LITEX_BCRYPT_CFLAGS)
else
bridges/bridge_litex_bcrypt.$(BRIDGE_SUFFIX): src/bridges/bridge_litex_bcrypt.c obj/combined.NATIVE.a
	$(CC)       $(CCFLAGS) $(CFLAGS_NATIVE)       $^ -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(LITEX_BCRYPT_CFLAGS)
endif
endif
