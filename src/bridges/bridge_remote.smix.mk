
bridges/bridge_remote.smix.so:  src/bridges/bridge_remote.smix.c obj/combined.LINUX.a 
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -lssl -lcrypto -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)

bridges/bridge_remote.smix.dll: src/bridges/bridge_remote.smix.c obj/combined.WIN.a 
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN) -L/usr/x86_64-w64-mingw32/lib64 -lcrypto.dll -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
