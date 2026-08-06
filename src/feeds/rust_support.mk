RUST_SCAN_DIR   := Rust/feeds

ifeq ($(CARGO_PRESENT),true)

# A Rust feed reads FEEDS_INTERFACE_VERSION_CURRENT from the environment, which is cargo's equivalent
# of the -D a C feed gets on its compile line. It must come from here and not from the feed's own
# source, or a rebuild would re-declare compatibility the source has not earned.

feeds/rust_%.so: $(RUST_SCAN_DIR)/%/Cargo.toml
	FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_SO)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^
	cp Rust/feeds/$*/target/$(RUST_BUILD_MODE)/lib$*.$(RUST_LIB_EXT) $@
ifeq ($(RUSTUP_PRESENT),true)
feeds/rust_%.dll: $(RUST_SCAN_DIR)/%/Cargo.toml
	$(RUST_RUSTUP) --quiet target add x86_64-pc-windows-gnu
	FEEDS_INTERFACE_VERSION_CURRENT="$(FEEDS_INTERFACE_VERSION)" RUSTFLAGS="$(RUSTFLAGS_DLL)" $(RUST_CARGO) build --quiet $(RUST_MODE_FLAG) --manifest-path $^ --target x86_64-pc-windows-gnu
	cp Rust/feeds/$*/target/x86_64-pc-windows-gnu/$(RUST_BUILD_MODE)/$*.dll $@
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

