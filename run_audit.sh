#!/bin/bash
source .venv/bin/activate
exec python3 audit_tui.py "$@"
