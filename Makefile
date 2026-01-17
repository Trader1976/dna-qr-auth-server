# -----------------------------
# DNA QR Auth Server & Audit TUI
# -----------------------------

AUDIT_LOG ?= audit/signature_audit.jsonl

.PHONY: help audit server server-build server-clean

help:
	@echo ""
	@echo "Targets:"
	@echo "  make audit              Run audit TUI (default log)"
	@echo "  make audit AUDIT_LOG=path/to/log.jsonl"
	@echo "  make server             Start QR auth server (Docker)"
	@echo "  make server-build       Rebuild server image (no cache)"
	@echo "  make server-clean       Stop + remove containers"
	@echo ""

# ---- Audit TUI ----

audit:
	@. .venv/bin/activate && python3 audit_tui.py $(AUDIT_LOG)

# ---- Server ----

server:
	docker compose up

server-build:
	docker compose build --no-cache

server-clean:
	docker compose down --remove-orphans
