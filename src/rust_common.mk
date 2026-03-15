# Shared Rust build configuration.
# Included before bridge/feed .mk files so that CARGO_PRESENT and other
# variables are available everywhere, and hashcat-sys is pre-built exactly
# once to avoid parallel bindings.rs generation races.

RUST_BUILD_MODE ?= release

RUST_CARGO      ?= cargo
RUST_RUSTUP     ?= rustup

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

RED             ?= $(shell tput setaf 1)
RESET           ?= $(shell tput sgr 0)

# Pre-build hashcat-sys to generate bindings.rs exactly once
HASHCAT_SYS_DIR   := Rust/hashcat-sys
HASHCAT_SYS_STAMP := $(HASHCAT_SYS_DIR)/.build-stamp

ifeq ($(CARGO_PRESENT),true)
$(HASHCAT_SYS_STAMP): $(HASHCAT_SYS_DIR)/build.rs $(HASHCAT_SYS_DIR)/src/hashcat_types.h
	$(RM) -f $(HASHCAT_SYS_DIR)/src/bindings.rs
	RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $(HASHCAT_SYS_DIR)/Cargo.toml
	@touch $@
else
$(HASHCAT_SYS_STAMP):
	@touch $@
endif
