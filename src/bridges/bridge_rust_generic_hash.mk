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

RUST_CRATES     := $(notdir $(patsubst %/Cargo.toml,%,$(subst \,/,$(wildcard $(RUST_SCAN_DIR)/*/Cargo.toml))))
PLUGINS_LINUX   := $(addprefix $(RUST_SUBS_DIR)/,$(addsuffix .so,$(RUST_CRATES)))
PLUGINS_WIN     := $(addprefix $(RUST_SUBS_DIR)/,$(addsuffix .dll,$(RUST_CRATES)))
PLUGINS_NATIVE  := $(addprefix $(RUST_SUBS_DIR)/,$(addsuffix .$(PLUGIN_SUFFIX_NATIVE),$(RUST_CRATES)))

BRIDGE_SRC_bridge_rust_generic_hash         := src/bridges/bridge_rust_generic_hash.c src/cpu_features.c

# the crates are built beside the bridge and are not inputs to its compiler, so they are named as
# prerequisites and nothing else

BRIDGE_DEPS_bridge_rust_generic_hash_NATIVE := $(PLUGINS_NATIVE)
BRIDGE_DEPS_bridge_rust_generic_hash_LINUX  := $(PLUGINS_LINUX)
BRIDGE_DEPS_bridge_rust_generic_hash_WIN    := $(PLUGINS_WIN)

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

ifeq ($(ENABLE_LTO),1)
RUSTFLAGS_SO    += -C lto -C embed-bitcode=y
RUSTFLAGS_DLL   += -C lto -C embed-bitcode=y
endif

# target-cpu=native describes the machine running the build, so it goes to whichever of the two file
# names belongs to that machine and not to the one built for a release

ifeq ($(MAINTAINER_MODE),0)
ifeq ($(PLUGIN_PLATFORM_so),NATIVE)
RUSTFLAGS_SO    += -C target-cpu=native
endif

ifeq ($(PLUGIN_PLATFORM_dll),NATIVE)
RUSTFLAGS_DLL   += -C target-cpu=native
endif
endif

# MAKEFLAGS is cleared for cargo. make advertises its jobserver in MAKEFLAGS to every recipe, but it
# only hands the file descriptors behind it to a recipe it believes is a recursive make. cargo reads
# the advertisement, tries to connect, finds nothing there and says so on every build: "failed to
# connect to jobserver from environment variable". Nothing is lost by clearing it, cargo then picks
# its own parallelism, and the alternative of marking the recipe as recursive would also make it run
# during a dry run.
$(RUST_SUBS_DIR)/%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	MAKEFLAGS= RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --target-dir Rust/bridges/$*/target --manifest-path $^
	cp Rust/bridges/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
$(RUST_SUBS_DIR)/%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	MAKEFLAGS= RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --target-dir Rust/bridges/$*/target --manifest-path $^ --target x86_64-pc-windows-gnu
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
