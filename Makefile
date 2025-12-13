.PHONY: test ctx ctx-full determinism-local determinism-remote

test:
	@if command -v pytest >/dev/null 2>&1; then \
	  echo "[test] pytest"; \
	  PYTHONPATH=. pytest; \
	else \
	  echo "[test] (skipped pytest: pytest not installed)"; \
	fi

determinism-local:
	@if command -v pytest >/dev/null 2>&1; then \
	  echo "[determinism-local] pytest tests/determinism/test_bundle_determinism.py"; \
	  PYTHONPATH=. pytest tests/determinism/test_bundle_determinism.py -q; \
	else \
	  echo "[determinism-local] (skipped pytest: pytest not installed)"; \
	fi

determinism-remote:
	@if command -v pytest >/dev/null 2>&1; then \
	  echo "[determinism-remote] pytest tests/determinism/test_bundle_determinism.py"; \
	  PYTHONPATH=. pytest tests/determinism/test_bundle_determinism.py -q; \
	else \
	  echo "[determinism-remote] (skipped pytest: pytest not installed)"; \
	fi

ctx:
	@bash scripts/ctx.sh

ctx-full:
	@DEPTH=3 LINES=800 bash scripts/ctx.sh
