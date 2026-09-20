# Finding the Rust toolchain, once, for everything that needs it.
#
# The bridge and the feed both build a crate with cargo and cross-compile it with rustup, and each
# worked out for itself whether those were installed. That was the same detection written twice, and
# the two copies had already drifted: the bridge named rustup in the message it printed when cargo
# was the thing that was missing.
#
# A version is asked for as well as a presence. Below the floor cargo refuses the manifest before it
# compiles anything, and the message it gives is about a manifest rather than about a toolchain, so
# the reason is stated here instead.
#
# The floor is what the crates need and nothing more. They are written in edition 2024, which cargo
# understands from 1.85, and 1.84 and everything below it fails to parse Cargo.toml at all. This is
# above what Ubuntu 24.04 carries, so rustup rather than the distribution is how it is met.

RUST_MIN_VERSION ?= 1.85

RUST_CARGO       ?= cargo
RUST_RUSTUP      ?= rustup

CARGO_VERSION    := $(word 2, $(shell $(RUST_CARGO) version 2>/dev/null))
RUSTUP_VERSION   := $(word 2, $(shell $(RUST_RUSTUP) --version 2>/dev/null))

CARGO_PRESENT    := false
RUSTUP_PRESENT   := false
CARGO_RECENT     := false

ifneq ($(filter 1.%,$(CARGO_VERSION)),)
CARGO_PRESENT    := true
endif

ifneq ($(filter 1.%,$(RUSTUP_VERSION)),)
RUSTUP_PRESENT   := true
endif

# sort -V -C answers whether its input is already in version order, so the floor first and the
# installed version second is true exactly when the installed one is new enough. It is asked only
# when a version was read, because an empty second line sorts fine and would answer true.

ifeq ($(CARGO_PRESENT),true)
CARGO_RECENT     := $(shell printf '%s\n%s\n' '$(RUST_MIN_VERSION)' '$(CARGO_VERSION)' | sort -V -C && echo true || echo false)
endif

# One reason, so every target that has to be skipped says the same thing and says the right thing.

RUST_SKIP_REASON :=

ifeq ($(CARGO_PRESENT),false)
RUST_SKIP_REASON := cargo not found
else ifeq ($(CARGO_RECENT),false)
RUST_SKIP_REASON := cargo $(CARGO_VERSION) is older than $(RUST_MIN_VERSION)
endif

RUST_RED         := $(shell tput setaf 1 2>/dev/null)
RUST_RESET       := $(shell tput sgr 0 2>/dev/null)

# $(call RUST_SKIP_WARNING,what was skipped,why)

define RUST_SKIP_WARNING
@echo ""
@echo "$(RUST_RED)WARNING$(RUST_RESET): Skipping $(1): $(2)."
@echo "         To use it, you must install Rust $(RUST_MIN_VERSION) or newer."
@echo "         Otherwise, you can safely ignore this warning."
@echo "         For more information, see 'docs/hashcat-rust-plugin-requirements.md'."
@echo ""
endef
