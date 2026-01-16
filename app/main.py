# app/main.py
#
# -----------------------------------------------------------------------------
# Architectural notes (high level)
# -----------------------------------------------------------------------------
# This file is intentionally "thin" orchestration glue:
#   - It wires HTTP endpoints to the domain primitives implemented elsewhere.
#   - It MUST NOT implement crypto itself (crypto lives in identity.py + v4_tokens.py).
#   - It SHOULD keep state minimal (v3 uses store; v4 is stateless except a tiny
#     in-memory polling cache for demo/single-node UX).
#
# Key modules / responsibilities:
#   - config.py      : environment-driven settings (ORIGIN/RP_ID/RP_NAME/AUTH_MODE)
#   - storage.py     : v3 session state machine + persistence + nonce tracking
#   - qr.py          : pure QR rendering (no security)
#   - identity.py    : ML-DSA-87 verification + optional allowlist policy
#   - v4_tokens.py   : Ed25519 token mint/verify for v4 stateless tokens (st/at)
#   - audit.py       : append-only audit log (security telemetry, forensics)
#
# Two protocol "lanes":
#   - v3 (stateful): server creates session, browser polls /api/v1/session/{id}
#                    phone POSTs to /api/v1/session/{id}/complete.
#   - v4 (stateless): server mints signed session token (st), phone POSTs to
#                    /api/v4/verify, server returns approval token (at).
#                    Browser polling uses /api/v4/status?sid=... (demo cache only).
#
# IMPORTANT: v4 "stateless verification" does not require DB. The only reason we
# keep V4_APPROVALS is to make a browser redirect UX easy in a single-node demo.
# In a true CDN / multi-node deployment, replace the polling cache with Redis or
# have the browser submit the returned "at" token directly to the relying party.
#
# WARNING (DEPLOYMENT):
# - V4_APPROVALS is an in-memory dict: it is NOT shared across Uvicorn workers
#   or across nodes. If you run multiple workers/nodes, /api/v4/status polling
#   will randomly miss approvals. Use Redis/shared cache or remove polling.
# -----------------------------------------------------------------------------


from pathlib import Path
import base64
import hashlib
import time
import secrets

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from urllib.parse import quote

from .config import settings
from .storage import store, SessionStatus
from .qr import make_auth_qr_svg_bytes
from .identity import verify_mldsa87_signature, is_fingerprint_allowed
from .audit import append_event, build_common

from .v4_tokens import (
    load_ed25519_private_key_from_b64,
    sign_token_v4,
    verify_token_v4,
)

# -----------------------------------------------------------------------------
# Crypto roots (v4)
# -----------------------------------------------------------------------------
# Architectural rule: the server Ed25519 key is an infrastructure secret used
# only for signing/verifying server-issued tokens (st/at). It is NOT the user's
# identity key and must never be confused with it.
ED25519_SK = load_ed25519_private_key_from_b64(settings.SERVER_ED25519_SK_B64)
ED25519_PK = ED25519_SK.public_key()

# -----------------------------------------------------------------------------
# v4 UX helper cache (NOT part of stateless verification!)
# -----------------------------------------------------------------------------
# This is a small, best-effort cache to support "browser polling → redirect"
# without a database. It is safe to lose entries (worst case: browser doesn't
# auto-redirect and user refreshes).
#
# True stateless/CDN: replace with Redis (shared) or remove browser polling and
# have the browser submit "at" to the RP directly.
V4_APPROVALS: dict[str, dict] = {}

# -----------------------------------------------------------------------------
# Feature gates (deploy-time protocol selection)
# -----------------------------------------------------------------------------
# Architectural goal: allow operators to toggle protocol versions without code
# changes (Docker env var AUTH_MODE).
#
# - AUTH_MODE=v3  : expose only v3 endpoints and stateful landing
# - AUTH_MODE=v4  : expose only v4 endpoints and stateless landing
# - AUTH_MODE=auto: expose both; landing prefers v4
def _v4_enabled() -> bool:
    return settings.AUTH_MODE in ("auto", "v4")


def _v3_enabled() -> bool:
    return settings.AUTH_MODE in ("auto", "v3")


def _require_v4():
    # 404 (not 403) on purpose: hides disabled surface area from scanners and
    # makes it clear "this route does not exist in this deployment".
    if not _v4_enabled():
        raise HTTPException(404, "v4 disabled")


def _require_v3():
    if not _v3_enabled():
        raise HTTPException(404, "v3 disabled")


# -----------------------------------------------------------------------------
# Time + cache helpers
# -----------------------------------------------------------------------------
def _now_epoch() -> int:
    # Keep time source centralized for easier testing/mocking.
    return int(time.time())


def _prune_v4_approvals(now: int | None = None) -> int:
    """Best-effort pruning to prevent unbounded growth (demo UX only)."""
    now = now or _now_epoch()
    dead = [k for k, v in V4_APPROVALS.items() if now > int(v.get("expires_at", 0))]
    for k in dead:
        V4_APPROVALS.pop(k, None)
    return len(dead)


# -----------------------------------------------------------------------------
# Canonicalization helpers
# -----------------------------------------------------------------------------
def _assert_safe_token_str(value: str, field: str):
    # Canonical JSON is built by string formatting; disallow characters that could
    # alter JSON structure if later fields become user-controlled.
    if any(c in value for c in ['"', "\\", "\n", "\r", "\t"]):
        raise HTTPException(400, f"invalid characters in {field}")


def _canonical_v4_phone_auth(sp: dict) -> bytes:
    """
    Canonical bytes for the PHONE-SIGNED payload in v4.

    Canonicalization contract:
      - UTF-8 bytes
      - no whitespace
      - fixed key order
      - integer timestamps (issued_at/expires_at)
    """
    # required fields & types
    try:
        exp = int(sp["expires_at"])
        iat = int(sp["issued_at"])
    except Exception:
        raise HTTPException(400, "issued_at/expires_at must be int")

    sid = str(sp["sid"])
    origin = str(sp["origin"])
    nonce = str(sp["nonce"])
    rp_id_hash = str(sp["rp_id_hash"]).strip()
    st_hash = str(sp["st_hash"]).strip()

    # optional but recommended
    session_id = str(sp.get("session_id", sid))

    # Guardrails: keep canonical JSON safe even if fields expand in future
    _assert_safe_token_str(nonce, "nonce")
    _assert_safe_token_str(origin, "origin")
    _assert_safe_token_str(rp_id_hash, "rp_id_hash")
    _assert_safe_token_str(st_hash, "st_hash")
    _assert_safe_token_str(sid, "sid")
    _assert_safe_token_str(session_id, "session_id")

    canonical = (
        f'{{"expires_at":{exp},"issued_at":{iat},"nonce":"{nonce}",'
        f'"origin":"{origin}","rp_id_hash":"{rp_id_hash}",'
        f'"session_id":"{session_id}","sid":"{sid}","st_hash":"{st_hash}"}}'
    )
    return canonical.encode("utf-8")


# -----------------------------------------------------------------------------
# FastAPI application
# -----------------------------------------------------------------------------
app = FastAPI(
    title="DNA QR Auth Server",
    version="0.1.0",
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Static assets (CSS / JS)
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
MIN_PROTOCOL_V = 3


def _b64decode_loose(s: str) -> bytes:
    """
    Decode Base64 with optional missing padding.
    Standard Base64 (NOT urlsafe).
    """
    s = str(s).strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def _fingerprint_from_pubkey(pubkey: bytes) -> str:
    """Compute DNA identity fingerprint from a public key."""
    return hashlib.sha3_512(pubkey).hexdigest()


def _sha256_b64(s: str) -> str:
    """
    WebAuthn-like helper: rp_id_hash = base64( SHA-256(rp_id) ).
    Standard Base64 (NOT urlsafe) to match phone.
    """
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


# -----------------------------------------------------------------------------
# Web UI
# -----------------------------------------------------------------------------
@app.get("/api/v4/qr.svg")
def v4_qr_svg(st: str):
    _require_v4()

    origin_hint = quote(settings.ORIGIN.rstrip("/"), safe="")
    app_hint = quote(settings.RP_NAME or "CPUNK", safe="")

    st_enc = quote(st, safe="")
    qr_uri = f"dna://auth?v=4&st={st_enc}&origin={origin_hint}&app={app_hint}"

    svg_bytes = make_auth_qr_svg_bytes(qr_uri)
    return Response(content=svg_bytes, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    mode = settings.AUTH_MODE  # "auto" | "v3" | "v4"

    if mode in ("v4", "auto"):
        return templates.TemplateResponse(
            "landing_v4.html",
            {
                "request": request,
                "auth_mode": mode,
                "rp_name": settings.RP_NAME,
                "origin": settings.ORIGIN,
            },
        )

    # v3 landing: server creates session immediately and stores it (stateful)
    sess = store.create_session(
        origin=settings.ORIGIN,
        ttl_seconds=settings.SESSION_TTL_SECONDS,
        rp_id=settings.RP_ID,
        rp_name=settings.RP_NAME,
        scopes=settings.SCOPES,
    )

    # Debug-only
    print("QR_URI:", sess.qr_uri, flush=True)

    return templates.TemplateResponse(
        "landing.html",
        {
            "request": request,
            "auth_mode": mode,
            "origin": settings.ORIGIN,
            "session_id": sess.session_id,
            "expires_at": sess.expires_at,
        },
    )


# -----------------------------------------------------------------------------
# v3 QR endpoints (stateful)
# -----------------------------------------------------------------------------
@app.get("/api/v1/session/{session_id}/qr.svg")
def session_qr_svg(session_id: str):
    _require_v3()

    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    svg_bytes = make_auth_qr_svg_bytes(sess.qr_uri)
    return Response(content=svg_bytes, media_type="image/svg+xml")


@app.get("/api/v1/session/{session_id}/challenge")
def get_challenge(session_id: str):
    _require_v3()

    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    return {
        "v": MIN_PROTOCOL_V,
        "session_id": sess.session_id,
        "challenge": sess.challenge,
        "rp_id": settings.RP_ID,
        "rp_name": settings.RP_NAME,
        "scopes": settings.SCOPES,
        "issued_at": sess.issued_at,
        "expires_at": sess.expires_at,
    }


# -----------------------------------------------------------------------------
# v3 completion (stateful verify + session approval)
# -----------------------------------------------------------------------------
@app.post("/api/v1/session/{session_id}/complete")
def complete(session_id: str, request: Request, body: dict = Body(...)):
    _require_v3()
    """
    v3: Completes a QR authentication session (stateful).
    """
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    if sess.status != SessionStatus.PENDING:
        raise HTTPException(409, "session not pending")

    if body.get("type") != "dna.auth.response":
        raise HTTPException(400, "invalid type")

    try:
        payload_v = int(body.get("v", 0))
    except Exception:
        raise HTTPException(400, "invalid version")

    if payload_v < MIN_PROTOCOL_V:
        raise HTTPException(
            status_code=426,
            detail={
                "error": "upgrade_required",
                "min_v": MIN_PROTOCOL_V,
                "message": f"Client protocol too old. Minimum supported v is {MIN_PROTOCOL_V}.",
            },
        )
    if payload_v != MIN_PROTOCOL_V:
        raise HTTPException(400, "invalid version")

    for k in ("session_id", "fingerprint", "signature", "signed_payload", "pubkey_b64"):
        if k not in body:
            raise HTTPException(400, f"missing field: {k}")

    if body["session_id"] != session_id:
        raise HTTPException(400, "session_id mismatch")

    signed_payload = body["signed_payload"]
    if not isinstance(signed_payload, dict):
        raise HTTPException(400, "signed_payload must be object")

    required = ["origin", "session_id", "nonce", "issued_at", "expires_at", "rp_id", "rp_id_hash"]
    for k in required:
        if k not in signed_payload:
            raise HTTPException(400, f"missing signed_payload field: {k}")

    if signed_payload["session_id"] != session_id:
        raise HTTPException(400, "signed_payload.session_id mismatch")

    if str(signed_payload["origin"]).rstrip("/") != sess.origin.rstrip("/"):
        raise HTTPException(400, "origin mismatch")

    try:
        iat = int(signed_payload["issued_at"])
        exp = int(signed_payload["expires_at"])
    except Exception:
        raise HTTPException(400, "issued_at/expires_at must be int")

    if exp <= iat:
        raise HTTPException(400, "expires_at must be > issued_at")
    if exp - iat > 600:
        raise HTTPException(400, "expires window too large")

    nonce = str(signed_payload["nonce"])
    origin = str(signed_payload["origin"])
    client_ip = (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")

    if store.seen_nonce(sess.session_id, nonce):
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=str(body.get("fingerprint", "")).lower().strip() or None,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                ),
                "result": "denied",
                "reason": "replay_nonce",
                "v": payload_v,
            }
        )
        raise HTTPException(409, "replay nonce")

    try:
        signature = _b64decode_loose(body["signature"])
        pubkey = _b64decode_loose(body["pubkey_b64"])
    except Exception:
        raise HTTPException(400, "invalid base64 encoding")

    claimed_fp = str(body["fingerprint"]).lower().strip()
    computed_fp = _fingerprint_from_pubkey(pubkey)

    rp_id = str(signed_payload["rp_id"]).lower().strip()
    expected_rp = str(sess.rp_id).lower().strip()

    if rp_id != expected_rp:
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                    signature_bytes=signature,
                ),
                "result": "denied",
                "reason": "rp_id_mismatch",
                "rp_id": rp_id,
                "expected_rp_id": expected_rp,
                "v": payload_v,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "not_authorized",
                "reason": "rp_id_mismatch",
                "message": "RP binding failed (rp_id mismatch).",
            },
        )

    rp_id_hash = str(signed_payload["rp_id_hash"]).strip()
    expected_hash = _sha256_b64(rp_id)

    if rp_id_hash != expected_hash:
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                    signature_bytes=signature,
                ),
                "result": "denied",
                "reason": "rp_id_hash_mismatch",
                "rp_id": rp_id,
                "rp_id_hash": rp_id_hash,
                "expected_rp_id_hash": expected_hash,
                "v": payload_v,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "not_authorized",
                "reason": "rp_id_hash_mismatch",
                "message": "RP cryptographic binding failed (rp_id_hash mismatch).",
            },
        )

    if not is_fingerprint_allowed(computed_fp):
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                    signature_bytes=signature,
                ),
                "result": "denied",
                "reason": "identity_not_allowed",
                "v": payload_v,
                "rp_id": rp_id,
                "rp_id_hash": rp_id_hash,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "not_authorized",
                "reason": "identity_not_allowed",
                "message": "This DNA identity is not authorized for this service.",
            },
        )

    canonical = (
        f'{{"expires_at":{exp},"issued_at":{iat},"nonce":"{nonce}",'
        f'"origin":"{origin}","rp_id":"{rp_id}","rp_id_hash":"{rp_id_hash}",'
        f'"session_id":"{session_id}"}}'
    )
    canonical_bytes = canonical.encode("utf-8")

    if claimed_fp != computed_fp:
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    canonical_bytes=canonical_bytes,
                    signature_bytes=signature,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                ),
                "result": "denied",
                "reason": "fingerprint_pubkey_mismatch",
                "v": payload_v,
                "rp_id": rp_id,
                "rp_id_hash": rp_id_hash,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "not_authorized",
                "reason": "fingerprint_pubkey_mismatch",
                "message": "Identity mismatch (fingerprint does not match public key).",
            },
        )

    try:
        ok = verify_mldsa87_signature(pubkey, canonical_bytes, signature)
    except Exception as e:
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    canonical_bytes=canonical_bytes,
                    signature_bytes=signature,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                ),
                "result": "error",
                "reason": "verifier_exception",
                "detail": str(e)[:200],
                "v": payload_v,
                "rp_id": rp_id,
                "rp_id_hash": rp_id_hash,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(500, f"verifier error: {e!s}")

    if not ok:
        append_event(
            {
                **build_common(
                    session_id=session_id,
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    canonical_bytes=canonical_bytes,
                    signature_bytes=signature,
                    origin=origin,
                    nonce=nonce,
                    request_ip=client_ip,
                    user_agent=user_agent,
                ),
                "result": "denied",
                "reason": "invalid_signature",
                "v": payload_v,
                "rp_id": rp_id,
                "rp_id_hash": rp_id_hash,
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "not_authorized",
                "reason": "invalid_signature",
                "message": "Signature verification failed.",
            },
        )

    store.save_response(
        sess.session_id,
        {
            "v": payload_v,
            "type": body["type"],
            "session_id": session_id,
            "fingerprint": claimed_fp,
            "signature_b64": body["signature"],
            "pubkey_b64": body["pubkey_b64"],
            "signed_payload": signed_payload,
            "server_canonical": canonical,
            "verified": True,
        },
    )

    append_event(
        {
            **build_common(
                session_id=session_id,
                claimed_fp=claimed_fp,
                pubkey_fp=computed_fp,
                canonical_bytes=canonical_bytes,
                signature_bytes=signature,
                origin=origin,
                nonce=nonce,
                request_ip=client_ip,
                user_agent=user_agent,
            ),
            "result": "approved",
            "reason": "signature_valid",
            "alg": "ML-DSA-87",
            "v": payload_v,
            "rp_id": rp_id,
            "rp_id_hash": rp_id_hash,
        }
    )

    store.set_status(sess.session_id, SessionStatus.APPROVED)
    return {"ok": True}


# -----------------------------------------------------------------------------
# v3 browser polling (stateful)
# -----------------------------------------------------------------------------
@app.get("/api/v1/session/{session_id}")
def session_status(session_id: str):
    _require_v3()

    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    if sess.is_expired and sess.status == SessionStatus.PENDING:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)

    return sess.public_view()


# -----------------------------------------------------------------------------
# Shared success page (both modes)
# -----------------------------------------------------------------------------
@app.get("/success", response_class=HTMLResponse)
def success(request: Request):
    return templates.TemplateResponse("success.html", {"request": request})


# -----------------------------------------------------------------------------
# v4 Stateless / CDN-scale mode
# -----------------------------------------------------------------------------
MIN_PROTOCOL_V4 = 4


@app.post("/api/v4/session")
def v4_create_session():
    _require_v4()
    _prune_v4_approvals()

    iat = _now_epoch()
    exp = iat + int(settings.SESSION_TTL_SECONDS)

    sid = secrets.token_urlsafe(18)
    nonce = secrets.token_urlsafe(18)

    st_payload = {
        "v": 4,
        "typ": "st",
        "sid": sid,
        "origin": settings.ORIGIN.rstrip("/"),
        "rp_id_hash": _sha256_b64(settings.RP_ID.lower().strip()),
        "nonce": nonce,
        "issued_at": iat,
        "expires_at": exp,
    }

    st = sign_token_v4(ED25519_SK, st_payload)

    qr_uri = (
        f"dna://auth?v=4&st={quote(st, safe='')}"
        f"&origin={quote(settings.ORIGIN.rstrip('/'), safe='')}"
        f"&app={quote(settings.RP_NAME or 'CPUNK', safe='')}"
    )

    append_event(
        {
            **build_common(session_id=sid, origin=st_payload["origin"], nonce=nonce),
            "result": "issued",
            "reason": "v4_st_issued",
            "v": 4,
            "rp_id_hash": st_payload["rp_id_hash"],
        }
    )

    return {"v": 4, "sid": sid, "expires_at": exp, "st": st, "qr_uri": qr_uri}


@app.post("/api/v4/verify")
def v4_verify(request: Request, body: dict = Body(...)):
    _require_v4()
    _prune_v4_approvals()

    def _fail(status: int, msg: str, **extra):
        detail = {"error": "bad_request" if status == 400 else "not_authorized", "message": msg}
        if extra:
            detail.update(extra)
        raise HTTPException(status_code=status, detail=detail)

    try:
        # Envelope
        if body.get("type") != "dna.auth.response":
            _fail(400, "invalid type")

        try:
            payload_v = int(body.get("v", 0))
        except Exception:
            _fail(400, "invalid version")

        if payload_v != MIN_PROTOCOL_V4:
            _fail(400, "invalid version", expected=MIN_PROTOCOL_V4, got=payload_v)

        for k in ("st", "fingerprint", "signature", "signed_payload", "pubkey_b64"):
            if k not in body:
                _fail(400, f"missing field: {k}")

        st = str(body["st"]).strip()
        signed_payload = body["signed_payload"]
        if not isinstance(signed_payload, dict):
            _fail(400, "signed_payload must be object")

        # Verify st (server signature)
        try:
            st_obj = verify_token_v4(ED25519_PK, st)
        except Exception as e:
            _fail(400, "invalid st", detail=str(e)[:120])

        if st_obj.get("v") != 4 or st_obj.get("typ") != "st":
            _fail(400, "invalid st claims", claims={"v": st_obj.get("v"), "typ": st_obj.get("typ")})

        # TTL / time window
        now = _now_epoch()
        try:
            st_exp = int(st_obj["expires_at"])
            st_iat = int(st_obj["issued_at"])
        except Exception:
            _fail(400, "invalid st timestamps")

        if now > st_exp:
            raise HTTPException(status_code=410, detail={"error": "expired", "message": "st expired"})
        if st_exp <= st_iat:
            _fail(400, "invalid st time window")

        # st_hash binding
        st_hash = base64.b64encode(hashlib.sha256(st.encode("utf-8")).digest()).decode("ascii")
        got_st_hash = str(signed_payload.get("st_hash", "")).strip()
        if got_st_hash != st_hash:
            _fail(400, "st_hash mismatch", expected=st_hash, got=got_st_hash)

        # Claim mirroring (be strict on ints for timestamps)
        def _req_str(k: str) -> str:
            v = signed_payload.get(k)
            if v is None:
                _fail(400, f"missing signed_payload field: {k}")
            return str(v)

        def _req_int(k: str) -> int:
            v = signed_payload.get(k)
            if v is None:
                _fail(400, f"missing signed_payload field: {k}")
            try:
                return int(v)
            except Exception:
                _fail(400, f"signed_payload.{k} must be int")

        if _req_str("sid") != str(st_obj.get("sid")):
            _fail(400, "claim mismatch: sid", expected=st_obj.get("sid"), got=signed_payload.get("sid"))
        if _req_str("origin") != str(st_obj.get("origin")):
            _fail(400, "claim mismatch: origin", expected=st_obj.get("origin"), got=signed_payload.get("origin"))
        if _req_str("rp_id_hash") != str(st_obj.get("rp_id_hash")):
            _fail(400, "claim mismatch: rp_id_hash", expected=st_obj.get("rp_id_hash"), got=signed_payload.get("rp_id_hash"))
        if _req_str("nonce") != str(st_obj.get("nonce")):
            _fail(400, "claim mismatch: nonce", expected=st_obj.get("nonce"), got=signed_payload.get("nonce"))
        if _req_int("issued_at") != int(st_obj.get("issued_at")):
            _fail(400, "claim mismatch: issued_at", expected=st_obj.get("issued_at"), got=signed_payload.get("issued_at"))
        if _req_int("expires_at") != int(st_obj.get("expires_at")):
            _fail(400, "claim mismatch: expires_at", expected=st_obj.get("expires_at"), got=signed_payload.get("expires_at"))

        # Origin binding to deployment configuration
        if str(st_obj["origin"]).rstrip("/") != settings.ORIGIN.rstrip("/"):
            _fail(
                400,
                "origin mismatch",
                expected=settings.ORIGIN.rstrip("/"),
                got=str(st_obj["origin"]).rstrip("/"),
            )

        # RP binding via rp_id_hash (deployment config)
        expected_rp_hash = _sha256_b64(settings.RP_ID.lower().strip())
        if str(st_obj["rp_id_hash"]).strip() != expected_rp_hash:
            _fail(
                403,
                "rp_id_hash mismatch",
                expected=expected_rp_hash,
                got=str(st_obj["rp_id_hash"]).strip(),
            )

        # Decode inputs
        try:
            signature = _b64decode_loose(body["signature"])
            pubkey = _b64decode_loose(body["pubkey_b64"])
        except Exception:
            _fail(400, "invalid base64 encoding")

        # Identity binding
        claimed_fp = str(body["fingerprint"]).lower().strip()
        computed_fp = _fingerprint_from_pubkey(pubkey)

        if claimed_fp != computed_fp:
            append_event(
                {
                    **build_common(
                        session_id=st_obj["sid"],
                        claimed_fp=claimed_fp,
                        pubkey_fp=computed_fp,
                        origin=st_obj["origin"],
                        nonce=st_obj["nonce"],
                        request_ip=(request.client.host if request.client else None),
                        user_agent=request.headers.get("user-agent"),
                        signature_bytes=signature,
                    ),
                    "result": "denied",
                    "reason": "fingerprint_pubkey_mismatch",
                    "v": 4,
                }
            )
            _fail(403, "fingerprint_pubkey_mismatch")

        # Policy: allowlist
        if not is_fingerprint_allowed(computed_fp):
            append_event(
                {
                    **build_common(
                        session_id=st_obj["sid"],
                        claimed_fp=claimed_fp,
                        pubkey_fp=computed_fp,
                        origin=st_obj["origin"],
                        nonce=st_obj["nonce"],
                        request_ip=(request.client.host if request.client else None),
                        user_agent=request.headers.get("user-agent"),
                        signature_bytes=signature,
                    ),
                    "result": "denied",
                    "reason": "identity_not_allowed",
                    "v": 4,
                }
            )
            _fail(403, "identity_not_allowed")

        # Canonical bytes (protocol)
        canonical_bytes = _canonical_v4_phone_auth(signed_payload)

        # PQ verify (native)
        try:
            ok = verify_mldsa87_signature(pubkey, canonical_bytes, signature)
        except Exception as e:
            append_event(
                {
                    **build_common(
                        session_id=st_obj["sid"],
                        claimed_fp=claimed_fp,
                        pubkey_fp=computed_fp,
                        canonical_bytes=canonical_bytes,
                        signature_bytes=signature,
                        origin=st_obj["origin"],
                        nonce=st_obj["nonce"],
                        request_ip=(request.client.host if request.client else None),
                        user_agent=request.headers.get("user-agent"),
                    ),
                    "result": "error",
                    "reason": "verifier_exception",
                    "detail": str(e)[:200],
                    "v": 4,
                }
            )
            raise HTTPException(status_code=500, detail={"error": "verifier_error", "message": str(e)[:200]})

        if not ok:
            append_event(
                {
                    **build_common(
                        session_id=st_obj["sid"],
                        claimed_fp=claimed_fp,
                        pubkey_fp=computed_fp,
                        canonical_bytes=canonical_bytes,
                        signature_bytes=signature,
                        origin=st_obj["origin"],
                        nonce=st_obj["nonce"],
                        request_ip=(request.client.host if request.client else None),
                        user_agent=request.headers.get("user-agent"),
                    ),
                    "result": "denied",
                    "reason": "invalid_signature",
                    "v": 4,
                }
            )
            _fail(403, "invalid_signature")

        # Issue approval token (at)
        at_payload = {
            "v": 4,
            "typ": "at",
            "sid": st_obj["sid"],
            "st_hash": st_hash,
            "rp_id_hash": st_obj["rp_id_hash"],
            "fingerprint": claimed_fp,
            "issued_at": now,
            "expires_at": now + 60,
        }
        at = sign_token_v4(ED25519_SK, at_payload)

        append_event(
            {
                **build_common(
                    session_id=st_obj["sid"],
                    claimed_fp=claimed_fp,
                    pubkey_fp=computed_fp,
                    canonical_bytes=canonical_bytes,
                    signature_bytes=signature,
                    origin=st_obj["origin"],
                    nonce=st_obj["nonce"],
                    request_ip=(request.client.host if request.client else None),
                    user_agent=request.headers.get("user-agent"),
                ),
                "result": "approved",
                "reason": "v4_signature_valid",
                "alg": "ML-DSA-87",
                "v": 4,
                "rp_id_hash": st_obj["rp_id_hash"],
            }
        )

        # Demo browser redirect cache (NOT stateless across workers/nodes)
        sid1 = str(st_obj.get("sid", "")).strip()
        sid2 = str(signed_payload.get("sid", "")).strip()
        sid3 = str(body.get("session_id", "")).strip()

        # Keep multi-key writes while debugging; tighten later (fail-fast).
        store_keys = {k for k in (sid1, sid2, sid3) if k}
        entry = {"at": at, "fingerprint": claimed_fp, "expires_at": _now_epoch() + 120}

        for k in store_keys:
            V4_APPROVALS[k] = entry

        print("V4_APPROVED stored keys:", sorted(store_keys), flush=True)
        return {"ok": True, "v": 4, "at": at}

    except HTTPException as e:
        try:
            print("V4_VERIFY_FAIL:", e.detail, flush=True)
        except Exception:
            pass
        raise


@app.post("/api/v4/validate")
def v4_validate(body: dict = Body(...)):
    _require_v4()

    at = str(body.get("at", "")).strip()
    if not at:
        raise HTTPException(400, "missing at")

    try:
        obj = verify_token_v4(ED25519_PK, at)
    except Exception:
        raise HTTPException(400, "invalid at")

    if obj.get("v") != 4 or obj.get("typ") != "at":
        raise HTTPException(400, "invalid at claims")

    now = _now_epoch()
    if now > int(obj.get("expires_at", 0)):
        raise HTTPException(410, "at expired")

    return obj


@app.get("/api/v4/status")
def v4_status(sid: str):
    _require_v4()
    _prune_v4_approvals()

    obj = V4_APPROVALS.get(sid)
    if not obj:
        return {"ok": True, "approved": False}

    if _now_epoch() > int(obj.get("expires_at", 0)):
        V4_APPROVALS.pop(sid, None)
        return {"ok": True, "approved": False, "expired": True}

    return {
        "ok": True,
        "approved": True,
        "at": obj["at"],
        "fingerprint": obj.get("fingerprint"),
    }
