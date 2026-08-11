RUST_BUILD_MODE ?= release

RUST_CARGO      ?= cargo
RUST_RUSTUP     ?= rustup

RUST_SCAN_DIR   := Rust/feeds
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

# A Rust feed reads FEEDS_INTERFACE_VERSION_CURRENT from the environment, which is cargo's equivalent
# of the -D a C feed gets on its compile line. It must come from here and not from the feed's own
# source, or a rebuild would re-declare compatibility the source has not earned.

# Cargo decides whether a crate needs rebuilding, not make. It tracks the sources, build.rs,
# Cargo.lock and every dependency, and make can see none of that through the manifest alone. These
# rules named only Cargo.toml, so editing a .rs file rebuilt nothing and the stale .so from the
# previous build was what shipped. The recipe runs every time now and cargo makes the decision.
#
# The copy is skipped when the library is unchanged, so a build that did nothing does not hand a
# fresh timestamp to anything downstream.

.PHONY: FORCE
FORCE:

feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml FORCE
	FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $<
	@cmp -s Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@ || cp Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml FORCE
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $< --target x86_64-pc-windows-gnu
	@cmp -s Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@ || cp Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
else
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: rustup not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
endif
else
feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: cargo not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	@echo ""
	@echo "$(RED)WARNING$(RESET): Skipping genereric attack-mode 8 plugin: cargo not found."
	@echo "         To use it, you must install Rust."
	@echo "         Otherwise, you can safely ignore this warning."
	@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
	@echo ""
endif

FEEDS_RUST_SRC := $(wildcard $(RUST_SCAN_DIR)/*/Cargo.toml)

ifeq ($(BUILD_MODE),cross)
feeds_linux: $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.so,  $(FEEDS_RUST_SRC))
feeds_win:   $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.dll, $(FEEDS_RUST_SRC))
else
feeds: $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml, feeds/rust_%.$(FEEDS_SUFFIX), $(FEEDS_RUST_SRC))
endif

