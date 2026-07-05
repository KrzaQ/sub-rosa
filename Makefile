# sub rosa — committed targets (reproducible on any clone).
# Machine-specific targets (push remotes, deploy) live in Makefile.local,
# which is gitignored. See Makefile.local.example.

.PHONY: build test fmt lint install clean help

help:            ## list available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build:           ## release build (target/release/rosa)
	cargo build --release

test:            ## run tests
	cargo test

fmt:             ## format Rust sources
	cargo fmt --all

lint:            ## clippy with warnings as errors
	cargo clippy --all-targets -- -D warnings

install:         ## install the rosa binary via cargo
	cargo install --path .

clean:           ## remove build artifacts
	cargo clean

# Local, machine-specific targets (push remotes, ...).
# The leading '-' means "include if present, don't error if missing".
-include Makefile.local
