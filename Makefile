.PHONY: cev test build release install ship clean version fmt lint

BINARY = supplyify
INSTALL_DIR = $(HOME)/bin/automator-tools

ship: cev test install
	@echo "$(BINARY) shipped"

cev: fmt lint

fmt:
	cargo fmt --check

lint:
	cargo clippy -- -D warnings

test:
	cargo test

build:
	cargo build

release:
	cargo build --release

install: release
	@mkdir -p $(INSTALL_DIR)
	cp target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	chmod +x $(INSTALL_DIR)/$(BINARY)
	@echo "$(BINARY) installed to $(INSTALL_DIR)/$(BINARY)"

clean:
	cargo clean

version:
	@grep '^version' Cargo.toml | head -1 | cut -d'"' -f2
