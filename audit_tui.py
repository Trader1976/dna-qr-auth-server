#!/usr/bin/env python3
"""
DNA QR Auth Audit TUI (Textual)

Loads a JSONL audit log and (by default) follows new lines.

Keys:
  q        Quit
  p        Pause/Resume follow updates
  c        Clear table
  /        Focus filter input (substring)
  Esc      Leave filter input, focus table
  Enter    Apply filter (when in filter input) OR show details for highlighted row (when table focused)
  ↑↓       Move selection in table (details update live)
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, List

from textual import events
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Input, Static


# -----------------------------
# Utilities
# -----------------------------

def safe_get(d: Dict[str, Any], key: str, default: str = "") -> str:
    v = d.get(key, default)
    if v is None:
        return default
    return str(v)


def short(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: max(0, n - 1)] + "…"


def ts_to_hhmmss(ts: Optional[int]) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%H:%M:%S")
    except Exception:
        return ""


def fmt_origin(origin: str) -> str:
    origin = origin.strip()
    if origin.startswith("http://"):
        return origin[7:]
    if origin.startswith("https://"):
        return origin[8:]
    return origin


def classify_event(e: Dict[str, Any]) -> str:
    reason = safe_get(e, "reason")
    result = safe_get(e, "result")
    return reason or result or "event"


# -----------------------------
# JSONL reader
# -----------------------------

class JsonlReader:
    """Reads JSONL records from a file, with optional rotation handling."""

    def __init__(self, path: str, start_at_end: bool = False):
        self.path = path
        self.start_at_end = start_at_end
        self._fp = None
        self._ino = None
        self._pin_details = False

    def open(self) -> None:
        self._fp = open(self.path, "r", encoding="utf-8", errors="replace")
        st = os.fstat(self._fp.fileno())
        self._ino = st.st_ino
        self._fp.seek(0, os.SEEK_END if self.start_at_end else os.SEEK_SET)

    def close(self) -> None:
        if self._fp:
            try:
                self._fp.close()
            finally:
                self._fp = None
                self._ino = None

    def _reopen_if_rotated(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if self._ino is None:
            return
        if st.st_ino != self._ino:
            self.close()
            self.open()

    def read_one(self) -> Optional[Dict[str, Any]]:
        if not self._fp:
            self.open()

        self._reopen_if_rotated()

        line = self._fp.readline()
        if not line:
            return None

        line = line.strip()
        if not line:
            return None

        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return obj
        except Exception:
            return {"_parse_error": True, "raw": line}

        return None


# -----------------------------
# UI Widgets
# -----------------------------

@dataclass
class ChainState:
    last_hash: Optional[str] = None
    last_ts_iso: Optional[str] = None
    ok: bool = True
    breaks: int = 0


class StatsBar(Static):
    issued = reactive(0)
    approved = reactive(0)
    denied = reactive(0)
    expired = reactive(0)
    other = reactive(0)

    paused = reactive(False)
    filter_text = reactive("")
    chain_ok = reactive(True)
    chain_breaks = reactive(0)
    events_total = reactive(0)
    last_time = reactive("")

    def render(self) -> str:
        parts = []
        parts.append(f"[b]Events[/b]: {self.events_total}")
        parts.append(f"[b]issued[/b]: {self.issued}")
        parts.append(f"[b]approved[/b]: {self.approved}")
        parts.append(f"[b]denied[/b]: {self.denied}")
        parts.append(f"[b]expired[/b]: {self.expired}")
        parts.append(f"[b]other[/b]: {self.other}")
        parts.append(f"[b]last[/b]: {self.last_time or '-'}")

        chain = "OK" if self.chain_ok else "BROKEN"
        chain_style = "green" if self.chain_ok else "red"
        parts.append(f"[b]chain[/b]: [{chain_style}]{chain}[/{chain_style}] ({self.chain_breaks})")

        if self.paused:
            parts.append("[yellow][b]PAUSED[/b][/yellow]")

        if self.filter_text:
            parts.append(f"[b]filter[/b]: “{short(self.filter_text, 40)}”")

        return "  |  ".join(parts)


class DetailsPane(Static):
    def show_event(self, e: Optional[Dict[str, Any]]) -> None:
        if not e:
            self.update("↑↓ select • Space inspect • / filter • p pause")
            return

        def color_result(r: str) -> str:
            r = r.lower()
            if r == "approved":
                return "[bold green]approved[/bold green]"
            if r == "issued":
                return "[bold cyan]issued[/bold cyan]"
            if r in ("denied", "rejected"):
                return "[bold red]denied[/bold red]"
            return f"[bold]{r}[/bold]"

        lines: list[str] = []

        # --- Header / outcome ---
        if "result" in e:
            lines.append(f"[b]Result[/b]: {color_result(str(e['result']))}")

        if "reason" in e:
            lines.append(f"[b]Reason[/b]: [yellow]{e['reason']}[/yellow]")

        lines.append("")

        # --- Time ---
        if "ts_iso" in e:
            lines.append(f"[b]Time[/b]: [cyan]{e['ts_iso']}[/cyan]")
        elif "ts" in e:
            lines.append(f"[b]Time[/b]: [cyan]{e['ts']}[/cyan]")

        # --- Origin / session ---
        if "origin" in e:
            lines.append(f"[b]Origin[/b]: [yellow]{e['origin']}[/yellow]")
        if "session_id" in e:
            lines.append(f"[b]Session[/b]: [#00ff66]{e['session_id']}[/#00ff66]")
        if "nonce" in e:
            lines.append(f"[b]Nonce[/b]: [#00ff66]{e['nonce']}[/#00ff66]")

        lines.append("")

        # --- Identity / crypto ---
        if "claimed_fp" in e:
            lines.append(f"[b]Claimed FP[/b]: [#00ff66]{e['claimed_fp']}[/#00ff66]")
        if "pubkey_fp" in e:
            lines.append(f"[b]Pubkey FP[/b]: [#00ff66]{e['pubkey_fp']}[/#00ff66]")
        if "alg" in e:
            lines.append(f"[b]Algorithm[/b]: [cyan]{e['alg']}[/cyan]")

        lines.append("")

        # --- Network ---
        if "request_ip" in e:
            lines.append(f"[b]IP[/b]: [yellow]{e['request_ip']}[/yellow]")
        if "user_agent" in e:
            lines.append(f"[b]User-Agent[/b]: [dim]{e['user_agent']}[/dim]")

        lines.append("")

        # --- Hash chain ---
        if "hash" in e:
            lines.append(f"[b]Hash[/b]: [dim]{e['hash']}[/dim]")
        if "prev_hash" in e:
            lines.append(f"[b]Prev Hash[/b]: [dim]{e['prev_hash']}[/dim]")

        # --- Anything else (fallback) ---
        known = {
            "result","reason","ts","ts_iso","origin","session_id","nonce",
            "claimed_fp","pubkey_fp","alg","request_ip","user_agent",
            "hash","prev_hash"
        }
        extras = sorted(k for k in e.keys() if k not in known)
        if extras:
            lines.append("")
            lines.append("[b]Other[/b]:")
            for k in extras:
                lines.append(f"  {k}: [dim]{e[k]}[/dim]")

        self.update("\n".join(lines))


# -----------------------------
# Main App
# -----------------------------

class AuditTui(App):
    # CPUNK-ish green accents (approx) for borders / highlight
    CSS = """
    Screen { layout: vertical; }

    /* CPUNK green accent */
    $cpunk_green: #00ff66;

    #top { height: 3; }
    #body { height: 1fr; }
    #left { width: 1fr; }
    #right { width: 1fr; }
    #filter_row { height: 3; }
    DataTable { height: 1fr; }

    #details {
        height: 1fr;
        padding: 1;
        border: round $cpunk_green;
    }

    #stats { padding: 0 1; }

    #filter {
        width: 1fr;
        border: round $cpunk_green;
    }

    Input:focus {
        border: round $cpunk_green;
    }

    DataTable:focus {
        border: round $cpunk_green;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_pause", "Pause"),
        ("c", "clear", "Clear"),
        ("u", "unpin", "Unpin"),
        ("f", "focus_filter", "Filter"),
        ("space", "show_details", "Details"),
    ]


    def action_unpin(self) -> None:
        self._pin_details = False
        # jump back to latest row when unpinning
        self._select_latest()
    paused: bool = reactive(False)

    def __init__(self, log_path: str, follow: bool = True, refresh_hz: float = 10.0, max_rows: int = 500):
        super().__init__()
        self.log_path = log_path
        self.follow = follow
        self.refresh_hz = refresh_hz
        self.max_rows = max_rows
        self._pin_details = False
        # start_at_end=False so admins see history on startup
        self.reader = JsonlReader(log_path, start_at_end=False)
        self.chain = ChainState()

        # row_key -> event
        self._row_to_event: Dict[int, Dict[str, Any]] = {}
        self._next_row_key = 1

        # keep insertion order for filter rebuilds
        self._events: List[Dict[str, Any]] = []

        # visible row keys in table order (used to map cursor index -> event)
        self._visible_keys: List[int] = []

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="top"):
            yield StatsBar(id="stats")

        with Horizontal(id="filter_row"):
            yield Static("Filter:", classes="label")
            yield Input(placeholder="substring match (origin, session_id, fp, reason, result…)", id="filter")

        with Horizontal(id="body"):
            with Vertical(id="left"):
                table = DataTable(id="table")
                table.show_cursor = True
                table.cursor_type = "row"
                table.add_columns("Time", "Result", "Reason", "Origin", "Session", "FP", "IP", "Chain")
                yield table

            with Vertical(id="right"):
                yield DetailsPane("↑↓ select • Space inspect • / filter • p pause", id="details")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        self.reader.open()

        # Load whole file once
        while True:
            e = self.reader.read_one()
            if e is None:
                break
            self._events.append(e)
            self._ingest_event(e, auto_select=False)

        # If we have rows, select the newest and focus the table so Space works immediately
        if table.row_count > 0:
            table.cursor_coordinate = (table.row_count - 1, 0)


        # Select newest row
        self._select_latest()

        # Default: follow ON
        if self.follow:
            self.set_interval(1.0 / self.refresh_hz, self._tick_follow)

        if self._visible_keys:
            key = self._visible_keys[-1]
            self.query_one(DetailsPane).show_event(self._row_to_event.get(key))

    
        table.focus()  # <-- key line: no mouse needed

    # --- Actions

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        self.query_one(StatsBar).paused = self.paused

    def action_clear(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        table.add_columns("Time", "Result", "Reason", "Origin", "Session", "FP", "IP", "Chain")

        self._row_to_event.clear()
        self._events.clear()
        self._visible_keys.clear()
        self._next_row_key = 1
        self.chain = ChainState()

        stats = self.query_one(StatsBar)
        stats.issued = stats.approved = stats.denied = stats.expired = stats.other = 0
        stats.events_total = 0
        stats.last_time = ""
        stats.chain_ok = True
        stats.chain_breaks = 0

        self.query_one(DetailsPane).show_event(None)

    def action_focus_filter(self) -> None:
        self.query_one(Input).focus()

    def action_show_details(self) -> None:
        """Show details for the currently highlighted row (works across Textual versions)."""
        self._pin_details = True
        table = self.query_one(DataTable)
        details = self.query_one(DetailsPane)
        self._pin_details = True

        row_index = None
        if hasattr(table, "cursor_row"):
            row_index = table.cursor_row
        elif hasattr(table, "cursor_coordinate"):
            row_index = table.cursor_coordinate[0]

        if row_index is None:
            return

        if 0 <= row_index < len(self._visible_keys):
            key = self._visible_keys[row_index]
            details.show_event(self._row_to_event.get(key))

    # --- Events / UI callbacks

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one(StatsBar).filter_text = event.value.strip()
        self._rebuild_table()
        # after rebuild, focus table for navigation
        self.query_one(DataTable).focus()

    def on_key(self, event: events.Key) -> None:
        # Esc: leave filter input
        if event.key == "escape":
            self.query_one(DataTable).focus()
            return

        # If table is focused, force Enter/Return/Space to show details
        if event.key in "space":
            table = self.query_one(DataTable)
            if table.has_focus:
                self.action_show_details()
                event.stop()  # prevent DataTable from swallowing it
                return


    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Some Textual versions only emit this on mouse click; still useful when it happens.
        e = self._row_to_event.get(event.row_key)
        self.query_one(DetailsPane).show_event(e)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        # Optional: live-update details while moving with arrows (htop-like).
        e = self._row_to_event.get(event.row_key)
        self.query_one(DetailsPane).show_event(e)

    # --- Core logic

    def _match_filter(self, e: Dict[str, Any], filt: str) -> bool:
        if not filt:
            return True
        blob = " ".join([
            safe_get(e, "origin"),
            safe_get(e, "session_id"),
            safe_get(e, "nonce"),
            safe_get(e, "result"),
            safe_get(e, "reason"),
            safe_get(e, "claimed_fp"),
            safe_get(e, "pubkey_fp"),
            safe_get(e, "request_ip"),
            safe_get(e, "user_agent"),
            safe_get(e, "rp_id_hash"),
        ]).lower()
        return filt.lower() in blob

    def _update_stats(self, e: Dict[str, Any]) -> None:
        stats = self.query_one(StatsBar)
        res = safe_get(e, "result").lower()
        stats.events_total += 1
        stats.last_time = safe_get(e, "ts_iso") or ts_to_hhmmss(e.get("ts")) or stats.last_time

        if res == "issued":
            stats.issued += 1
        elif res == "approved":
            stats.approved += 1
        elif res == "denied":
            stats.denied += 1
        elif res == "expired":
            stats.expired += 1
        else:
            stats.other += 1

    def _check_chain(self, e: Dict[str, Any]) -> bool:
        h = safe_get(e, "hash")
        prev = safe_get(e, "prev_hash")
        ok = True

        if self.chain.last_hash and prev:
            if prev != self.chain.last_hash:
                ok = False
                self.chain.ok = False
                self.chain.breaks += 1

        if h:
            self.chain.last_hash = h
        self.chain.last_ts_iso = safe_get(e, "ts_iso") or self.chain.last_ts_iso
        return ok

    def _ingest_event(self, e: Dict[str, Any], auto_select: bool = True) -> None:
        self._update_stats(e)
        chain_ok = self._check_chain(e)
        self._add_row(e, chain_ok, auto_select=auto_select)

        stats = self.query_one(StatsBar)
        stats.chain_ok = self.chain.ok
        stats.chain_breaks = self.chain.breaks

    def _add_row(self, e: Dict[str, Any], chain_ok: bool, auto_select: bool = True) -> None:
        table = self.query_one(DataTable)
        stats = self.query_one(StatsBar)
        filt = stats.filter_text

        if not self._match_filter(e, filt):
            return

        t = safe_get(e, "ts_iso") or ts_to_hhmmss(e.get("ts"))
        result = safe_get(e, "result")
        reason = safe_get(e, "reason") or classify_event(e)
        origin = fmt_origin(safe_get(e, "origin"))
        sid = short(safe_get(e, "session_id"), 18)
        fp = safe_get(e, "claimed_fp") or safe_get(e, "pubkey_fp") or ""
        fp = short(fp, 18)
        ip = short(safe_get(e, "request_ip"), 16)
        chain_mark = "OK" if chain_ok else "BROKE"

        row_key = self._next_row_key
        self._next_row_key += 1

        self._row_to_event[row_key] = e
        self._visible_keys.append(row_key)

        table.add_row(
            short(t, 8),
            short(result, 10),
            short(reason, 18),
            short(origin, 30),
            sid,
            fp,
            ip,
            chain_mark,
            key=row_key,
        )


        # Trim visible table list to max_rows (and keep _visible_keys in sync)
        while table.row_count > self.max_rows and self._visible_keys:
            # DataTable APIs differ; easiest is to clear/rebuild if it grows too big.
            # But for steady follow, we can rebuild occasionally. Here: do a simple rebuild.
            break

        if table.row_count > self.max_rows:
            self._rebuild_table(keep_tail=True)
            return

        if auto_select and not self._pin_details:
            table.cursor_coordinate = (table.row_count - 1, 0)
            self.query_one(DetailsPane).show_event(e)

    def _select_latest(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count <= 0:
            return
        table.cursor_coordinate = (table.row_count - 1, 0)

        # update details for the highlighted row
        if self._visible_keys:
            key = self._visible_keys[-1]
            self.query_one(DetailsPane).show_event(self._row_to_event.get(key))

    def _rebuild_table(self, keep_tail: bool = False) -> None:
        """Rebuild table from self._events, applying filter. keep_tail keeps only last max_rows matches."""
        table = self.query_one(DataTable)
        filt = self.query_one(StatsBar).filter_text

        table.clear()
        table.add_columns("Time", "Result", "Reason", "Origin", "Session", "FP", "IP", "Chain")

        self._row_to_event.clear()
        self._visible_keys.clear()
        self._next_row_key = 1

        # Decide which events to render
        src = self._events
        if keep_tail and self.max_rows > 0:
            # keep only last max_rows events that match filter
            matched = [e for e in src if self._match_filter(e, filt)]
            src = matched[-self.max_rows :]

        # Recompute chain display in view order
        temp_chain = ChainState()

        def check_chain_local(ev: Dict[str, Any]) -> bool:
            h = safe_get(ev, "hash")
            prev = safe_get(ev, "prev_hash")
            ok = True
            if temp_chain.last_hash and prev:
                if prev != temp_chain.last_hash:
                    ok = False
            if h:
                temp_chain.last_hash = h
            return ok

        for e in src:
            if not self._match_filter(e, filt):
                continue
            chain_ok = check_chain_local(e)

            # Add row without auto-select spam
            self._update_stats_no_increment(e)  # no-op placeholder (see below)
            self._add_row(e, chain_ok, auto_select=False)

        # If we used the hacky _update_stats_no_increment, ensure details updates anyway
        self._select_latest()
        if table.row_count == 0:
            self.query_one(DetailsPane).show_event(None)

    def _update_stats_no_increment(self, e: Dict[str, Any]) -> None:
        # Rebuild should not change counters; intentionally empty.
        return

    def _tick_follow(self) -> None:
        stats = self.query_one(StatsBar)
        stats.paused = self.paused
        stats.chain_ok = self.chain.ok
        stats.chain_breaks = self.chain.breaks

        if self.paused:
            return

        N = 500
        for _ in range(N):
            e = self.reader.read_one()
            if e is None:
                break
            self._events.append(e)
            self._ingest_event(e, auto_select=True)

        # Keep table bounded in busy environments
        if self.query_one(DataTable).row_count > self.max_rows:
            self._rebuild_table(keep_tail=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="DNA QR Auth Audit Log TUI (Textual)")
    ap.add_argument("logfile", help="Path to JSONL audit log file")
    ap.add_argument("--no-follow", action="store_true", help="Load once and do NOT follow new lines")
    ap.add_argument("--hz", type=float, default=10.0, help="Follow refresh rate (default: 10)")
    ap.add_argument("--max-rows", type=int, default=500, help="Max visible rows (default: 500)")
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        raise SystemExit(f"Log file not found: {args.logfile}")

    AuditTui(
        args.logfile,
        follow=not args.no_follow,
        refresh_hz=args.hz,
        max_rows=args.max_rows,
    ).run()


if __name__ == "__main__":
    main()
