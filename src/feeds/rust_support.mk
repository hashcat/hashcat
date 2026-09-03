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

# MAKEFLAGS is cleared for cargo. make advertises its jobserver in MAKEFLAGS to every recipe, but it
# only hands the file descriptors behind it to a recipe it believes is a recursive make. cargo reads
# the advertisement, tries to connect, finds nothing there and says so on every build: "failed to
# connect to jobserver from environment variable". Nothing is lost by clearing it, cargo then picks
# its own parallelism, and the alternative of marking the recipe as recursive would also make it run
# during a dry run.

feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml FORCE
	MAKEFLAGS= FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $<
	@cmp -s Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@ 2>/dev/null || cp Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml FORCE
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	MAKEFLAGS= FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $< --target x86_64-pc-windows-gnu
	@cmp -s Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@ 2>/dev/null || cp Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
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

# a Rust feed is a feed, so it hangs off the same phony as the C ones, once for every platform whose
# plugins this run is building

$(foreach P,$(PLUGIN_PLATFORMS),$(eval feeds$(PHONY_SUFFIX_$(P)): \
  $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml,feeds/rust_%.$(PLUGIN_SUFFIX_$(P)),$(FEEDS_RUST_SRC))))

