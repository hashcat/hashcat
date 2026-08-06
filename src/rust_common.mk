# Shared Rust build configuration, included before the bridge and feed .mk files that use it.

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
