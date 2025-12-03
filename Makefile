.PHONY: build fmt test ctx ctx-full

build:
	cargo build --manifest-path gateway/Cargo.toml

fmt:
	cargo fmt --all

test:
	cargo test --manifest-path gateway/Cargo.toml
	@if command -v pytest >/dev/null 2>&1; then \
	  echo "[test] pytest"; \
	  pytest; \
	else \
	  echo "[test] (skipped pytest: pytest not installed)"; \
	fi

ctx:
	@bash scripts/ctx.sh

ctx-full:
	@DEPTH=3 LINES=800 bash scripts/ctx.sh
