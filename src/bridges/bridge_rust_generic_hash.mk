RUST_BUILD_MODE ?= release

RUST_CARGO      ?= cargo
RUST_RUSTUP     ?= rustup

RUST_SCAN_DIR   := Rust/bridges
RUST_SUBS_DIR   := bridges/subs
RUST_MODE_FLAG  := $(if $(filter $(RUST_BUILD_MODE),release),--release,)

CARGO_PRESENT   := false
RUSTUP_PRESENT  := false

CARGO_VERSION   := $(word 2, $(shell $(RUST_CARGO) version 2>/dev/null))
ifneq ($(filter 1.%,$(CARGO_VERSION)),)
CARGO_PRESENT   := true
endif

RUSTUP_VERSION  := $(word 2, $(shell $(RUST_RUSTUP) --version 2>/dev/null))
ifneq ($(filter 1.%,$(RUSTUP_VERSION)),)
RUSTUP_PRESENT  := true
endif

COMMON_PREREQS  := src/bridges/bridge_rust_generic_hash.c src/cpu_features.c
RUST_CRATES     := $(notdir $(patsubst %/Cargo.toml,%,$(subst \,/,$(wildcard $(RUST_SCAN_DIR)/*/Cargo.toml))))
PLUGINS_LINUX   := $(addprefix $(RUST_SUBS_DIR)/,$(addsuffix .so,$(RUST_CRATES)))
PLUGINS_WIN     := $(addprefix $(RUST_SUBS_DIR)/,$(addsuffix .dll,$(RUST_CRATES)))
PLUGINS_DEFAULT := $(PLUGINS_LINUX)

ifeq ($(BRIDGE_SUFFIX),dll)
PLUGINS_DEFAULT := $(PLUGINS_WIN)
endif

RED             := $(shell tput setaf 1)
RESET           := $(shell tput sgr 0)

ifeq ($(CARGO_PRESENT),true)

ifeq ($(shell uname),Darwin)
RUST_LIB_EXT    := dylib
else
RUST_LIB_EXT    := so
endif

RUSTFLAGS_SO    :=
RUSTFLAGS_DLL   := -C link-arg=-fuse-ld=lld

ifeq ($(UNAME),Linux)
ifeq ($(USE_MOLD),1)
RUSTFLAGS_SO    += -C link-arg=-fuse-ld=mold
endif
endif

ifeq ($(ENABLE_LTO),1)
RUSTFLAGS_SO    += -C lto -C embed-bitcode=y
RUSTFLAGS_DLL   += -C lto -C embed-bitcode=y
endif

ifeq ($(BUILD_MODE),native)
RUSTFLAGS_SO    += -C target-cpu=native
RUSTFLAGS_DLL   += -C target-cpu=native
endif

$(RUST_SUBS_DIR)/%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^
	cp Rust/bridges/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
$(RUST_SUBS_DIR)/%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^ --target x86_64-pc-windows-gnu
	cp Rust/bridges/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
else
$(RUST_SUBS_DIR)/%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping regular plugin 74000: rustup not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
endif

else

$(RUST_SUBS_DIR)/%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping regular plugin 74000: rustup not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
$(RUST_SUBS_DIR)/%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping regular plugin 74000: rustup not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""

endif

ifeq ($(BUILD_MODE),cross)
bridges/bridge_rust_generic_hash.so: $(COMMON_PREREQS) obj/combined.LINUX.a $(PLUGINS_LINUX)
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $(filter-out $(RUST_SUBS_DIR)/%,$^) -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
bridges/bridge_rust_generic_hash.dll: $(COMMON_PREREQS) obj/combined.WIN.a $(PLUGINS_WIN)
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $(filter-out $(RUST_SUBS_DIR)/%,$^) -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
else
ifeq ($(SHARED),1)
bridges/bridge_rust_generic_hash.$(BRIDGE_SUFFIX): $(COMMON_PREREQS) $(HASHCAT_LIBRARY) $(PLUGINS_DEFAULT)
	$(CC) $(CCFLAGS) $(CFLAGS_NATIVE)             $(filter-out $(RUST_SUBS_DIR)/%,$^) -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
else
bridges/bridge_rust_generic_hash.$(BRIDGE_SUFFIX): $(COMMON_PREREQS) obj/combined.NATIVE.a $(PLUGINS_DEFAULT)
	$(CC) $(CCFLAGS) $(CFLAGS_NATIVE)             $(filter-out $(RUST_SUBS_DIR)/%,$^) -o $@ $(LFLAGS_NATIVE)      -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
endif
endif
