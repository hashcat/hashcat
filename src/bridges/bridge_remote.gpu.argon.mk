BRIDGE_SRC_bridge_remote.gpu.argon = src/bridges/bridge_remote.gpu.argon.c
BRIDGE_CFLAGS_bridge_remote.gpu.argon_NATIVE := -lssl -lcrypto
BRIDGE_CFLAGS_bridge_remote.gpu.argon_LINUX := -lssl -lcrypto
BRIDGE_CFLAGS_bridge_remote.gpu.argon_WIN := -L/usr/x86_64-w64-mingw32/lib64 -lcrypto.dll