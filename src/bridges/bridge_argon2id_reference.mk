
ARGON2_REFERENCE := deps/phc-winner-argon2-20190702

ifeq ($(MAKECMDGOALS),binaries)
ARGON2_REFERENCE_CFLAGS := -I$(ARGON2_REFERENCE)/_hashcat/ -mavx2
else
ARGON2_REFERENCE_CFLAGS := -I$(ARGON2_REFERENCE)/_hashcat/ -march=native
endif

bridges/bridge_argon2id_reference.so:  src/bridges/bridge_argon2id_reference.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)

bridges/bridge_argon2id_reference.dll: src/bridges/bridge_argon2id_reference.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION) $(ARGON2_REFERENCE_CFLAGS)
