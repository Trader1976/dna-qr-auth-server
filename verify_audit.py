#!/usr/bin/env python3
"""
verify_audit.py — Verify tamper-evident audit logs (JSONL) with optional hash-chaining.

Supports:
- JSONL audit logs where each line is a JSON object.
- Optional hash chaining fields: "prev_hash" and "hash"
- Optional state file containing last hash (e.g., signature_audit.state)
- Validation of serialized bytes objects emitted by audit.py (_json_default):
    {"_type":"bytes","len":N,"sha3_256":"...","b64":"..."}

Exit codes:
- 0: OK
- 1: Verification failed
- 2: Log format not supported / missing required fields (in strict mode)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


ZERO64 = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    lines: int
    chained_lines: int
    bytes_objects_checked: int
    last_hash: Optional[str]
    message: str


def _sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _canonical_json(obj: Any) -> str:
    # Canonical representation used for hashing: stable ordering, unicode preserved.
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _is_hex64(s: Any) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def _iter_jsonl(path: Path) -> Iterable[Tuple[int, Dict[str, Any], str]]:
    """
    Yields: (line_number starting at 1, parsed_object, raw_line_stripped)
    """
    with path.open("r", encoding="utf-8") as f:
        for idx, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise ValueError(f"{path}:{idx}: invalid JSON: {e}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{idx}: JSON root must be object/dict")
            yield idx, obj, line


def _verify_bytes_objects(obj: Any, *, strict: bool) -> int:
    """
    Recursively verify any {"_type":"bytes", ...} objects:
      - len matches decoded b64 length
      - sha3_256 matches decoded b64
    Returns count of verified bytes objects.
    """
    count = 0

    def walk(x: Any) -> None:
        nonlocal count
        if isinstance(x, dict):
            # Detect the special bytes wrapper
            if x.get("_type") == "bytes":
                # Minimal requirements
                if "len" not in x or "sha3_256" not in x:
                    if strict:
                        raise ValueError("bytes object missing required fields (len/sha3_256)")
                    return
                b64 = x.get("b64")
                if b64 is None:
                    if strict:
                        raise ValueError("bytes object missing b64 (strict mode)")
                    return

                try:
                    data = base64.b64decode(b64, validate=True)
                except Exception as e:
                    raise ValueError(f"invalid base64 in bytes object: {e}") from e

                if int(x["len"]) != len(data):
                    raise ValueError(f"bytes object len mismatch: expected {x['len']} got {len(data)}")

                h = _sha3_256_hex(data)
                if str(x["sha3_256"]) != h:
                    raise ValueError(f"bytes object sha3_256 mismatch: expected {x['sha3_256']} got {h}")

                count += 1
                return

            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return count


def _compute_event_hash(event: Dict[str, Any]) -> str:
    """
    Compute hash in the recommended scheme:
      hash = sha3_256( canonical_json(event_without_hash) )
    """
    tmp = dict(event)
    tmp.pop("hash", None)
    payload = _canonical_json(tmp).encode("utf-8")
    return _sha3_256_hex(payload)


def verify_audit(
    jsonl_path: Path,
    state_path: Optional[Path] = None,
    *,
    strict_chain: bool = False,
    strict_bytes: bool = False,
) -> VerifyResult:
    """
    Verifies:
    - JSONL parsing
    - Optional bytes wrapper integrity
    - Optional hash chaining integrity if fields exist
    - Optional state file match
    """
    if not jsonl_path.exists():
        return VerifyResult(False, 0, 0, 0, None, f"Log not found: {jsonl_path}")

    lines = 0
    chained_lines = 0
    bytes_checked = 0

    prev_hash_actual: Optional[str] = None
    last_hash: Optional[str] = None

    for lineno, event, _raw in _iter_jsonl(jsonl_path):
        lines += 1

        # Validate bytes wrapper objects (if any)
        bytes_checked += _verify_bytes_objects(event, strict=strict_bytes)

        # Chain verification only if fields are present
        has_chain_fields = ("hash" in event) or ("prev_hash" in event)

        if not has_chain_fields:
            if strict_chain:
                return VerifyResult(
                    False, lines, chained_lines, bytes_checked, last_hash,
                    f"{jsonl_path}:{lineno}: missing chain fields (hash/prev_hash) in strict mode"
                )
            # no chaining in this log; continue
            continue

        # If using chaining, we require both.
        if "hash" not in event or "prev_hash" not in event:
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"{jsonl_path}:{lineno}: chain requires both 'prev_hash' and 'hash'"
            )

        prev_hash_claimed = event["prev_hash"]
        hash_claimed = event["hash"]

        if not _is_hex64(prev_hash_claimed):
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"{jsonl_path}:{lineno}: prev_hash is not 64-hex"
            )
        if not _is_hex64(hash_claimed):
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"{jsonl_path}:{lineno}: hash is not 64-hex"
            )

        # Check linkage
        expected_prev = prev_hash_actual if prev_hash_actual is not None else ZERO64
        if prev_hash_claimed != expected_prev:
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"{jsonl_path}:{lineno}: prev_hash mismatch: expected {expected_prev} got {prev_hash_claimed}"
            )

        # Recompute current hash
        recomputed = _compute_event_hash(event)
        if hash_claimed != recomputed:
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"{jsonl_path}:{lineno}: hash mismatch: expected {recomputed} got {hash_claimed}"
            )

        chained_lines += 1
        prev_hash_actual = hash_claimed
        last_hash = hash_claimed

    # If state file is provided, ensure it matches last hash (when chaining exists)
    if state_path is not None:
        if not state_path.exists():
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"State file not found: {state_path}"
            )

        state_val = state_path.read_text(encoding="utf-8").strip()
        if state_val and not _is_hex64(state_val):
            return VerifyResult(
                False, lines, chained_lines, bytes_checked, last_hash,
                f"State file value is not 64-hex: {state_path}"
            )

        # If the log has chaining, last_hash must exist and match state
        if chained_lines > 0:
            if last_hash is None:
                return VerifyResult(
                    False, lines, chained_lines, bytes_checked, last_hash,
                    "State file provided but no last hash computed"
                )
            if state_val != last_hash:
                return VerifyResult(
                    False, lines, chained_lines, bytes_checked, last_hash,
                    f"State mismatch: state={state_val} log_last={last_hash}"
                )
        else:
            # No chaining found in log
            if strict_chain:
                return VerifyResult(
                    False, lines, chained_lines, bytes_checked, last_hash,
                    "State file provided but log contains no chaining fields"
                )

    return VerifyResult(
        True, lines, chained_lines, bytes_checked, last_hash,
        "OK"
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Verify DNA QR auth audit log integrity (JSONL) with optional hash chaining."
    )
    p.add_argument(
        "log",
        type=Path,
        help="Path to audit JSONL file (e.g. audit/signature_audit.jsonl)",
    )
    p.add_argument(
        "--state",
        type=Path,
        default=None,
        help="Optional state file containing last hash (e.g. audit/signature_audit.state)",
    )
    p.add_argument(
        "--strict-chain",
        action="store_true",
        help="Fail if log entries do not contain hash chaining fields.",
    )
    p.add_argument(
        "--strict-bytes",
        action="store_true",
        help="Fail if bytes-wrapper objects are missing b64/len/sha3_256 or invalid.",
    )
    args = p.parse_args()

    try:
        res = verify_audit(
            args.log,
            state_path=args.state,
            strict_chain=args.strict_chain,
            strict_bytes=args.strict_bytes,
        )
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    if res.ok:
        print("OK")
        print(f"lines={res.lines}")
        print(f"chained_lines={res.chained_lines}")
        print(f"bytes_objects_checked={res.bytes_objects_checked}")
        if res.last_hash:
            print(f"last_hash={res.last_hash}")
        return 0

    print("FAIL", file=sys.stderr)
    print(res.message, file=sys.stderr)
    print(f"lines={res.lines}", file=sys.stderr)
    print(f"chained_lines={res.chained_lines}", file=sys.stderr)
    print(f"bytes_objects_checked={res.bytes_objects_checked}", file=sys.stderr)
    if res.last_hash:
        print(f"last_hash={res.last_hash}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
