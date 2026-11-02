RUST_BUILD_MODE ?= release

RUST_SCAN_DIR   := Rust/feeds
RUST_MODE_FLAG  := $(if $(filter $(RUST_BUILD_MODE),release),--release,)

ifeq ($(RUST_SKIP_REASON),)

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
# names belongs to that machine and not to the one built for a release. MCPU names a different
# machine, and then the crates have to be told the same thing the C side was told, or they are the
# one part of the artifact still built for the machine that compiled it.

ifeq ($(MAINTAINER_MODE),0)
RUST_TARGET_CPU := $(if $(MCPU),$(MCPU),native)

ifeq ($(PLUGIN_PLATFORM_so),NATIVE)
RUSTFLAGS_SO    += -C target-cpu=$(RUST_TARGET_CPU)
endif

ifeq ($(PLUGIN_PLATFORM_dll),NATIVE)
RUSTFLAGS_DLL   += -C target-cpu=$(RUST_TARGET_CPU)
endif
endif

# A Rust feed reads FEEDS_INTERFACE_VERSION_CURRENT from the environment, which is cargo's equivalent
# of the -D a C feed gets on its compile line. It must come from here and not from the feed's own
# source, or a rebuild would re-declare compatibility the source has not earned.

# MAKEFLAGS is cleared for cargo. make advertises its jobserver in MAKEFLAGS to every recipe, but it
# only hands the file descriptors behind it to a recipe it believes is a recursive make. cargo reads
# the advertisement, tries to connect, finds nothing there and says so on every build: "failed to
# connect to jobserver from environment variable". Nothing is lost by clearing it, cargo then picks
# its own parallelism, and the alternative of marking the recipe as recursive would also make it run
# during a dry run.

feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	MAKEFLAGS= FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --target-dir Rust/feeds/$*/target --manifest-path $<
	cp Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	MAKEFLAGS= FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --target-dir Rust/feeds/$*/target --manifest-path $< --target x86_64-pc-windows-gnu
	cp Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
else
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(call RUST_SKIP_WARNING,generic attack-mode 8 plugin,rustup not found)
endif
else
feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(call RUST_SKIP_WARNING,generic attack-mode 8 plugin,$(RUST_SKIP_REASON))
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(call RUST_SKIP_WARNING,generic attack-mode 8 plugin,$(RUST_SKIP_REASON))
endif

FEEDS_RUST_SRC := $(wildcard $(RUST_SCAN_DIR)/*/Cargo.toml)

# A Rust feed depends on its own sources, and on obj/arrangement for the same reason the C feeds do.
# These rules carry no recipe and only add prerequisites to the pattern rules above, which name
# Cargo.toml alone.

$(foreach D,$(patsubst %/Cargo.toml,%,$(FEEDS_RUST_SRC)),$(eval feeds/rust_$(notdir $(D)).so feeds/rust_$(notdir $(D)).dll: $(call RUST_CRATE_SRC,$(D)) obj/arrangement))

# a Rust feed is a feed, so it hangs off the same phony as the C ones, once for every platform whose
# plugins this run is building

$(foreach P,$(PLUGIN_PLATFORMS),$(eval feeds$(PHONY_SUFFIX_$(P)): \
  $(patsubst $(RUST_SCAN_DIR)/%/Cargo.toml,feeds/rust_%.$(PLUGIN_SUFFIX_$(P)),$(FEEDS_RUST_SRC))))

