from pathlib import Path
import base64
import hashlib

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from .config import settings
from .storage import store, SessionStatus
from .qr import make_auth_qr_svg_bytes
from .identity import verify_mldsa87_signature
from .audit import append_event, build_common


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
def _b64decode_loose(s: str) -> bytes:
    """
    Decode Base64 with optional missing padding.

    DNA-Messenger uses Dart's base64Encode(), which produces standard Base64.
    Some implementations omit '=' padding, so we normalize before decoding.

    Rejects non-Base64 characters (validate=True).
    """
    s = str(s).strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def _fingerprint_from_pubkey(pubkey: bytes) -> str:
    """
    Compute DNA identity fingerprint from a public key.

    Fingerprint format:
      SHA3-512(pubkey) → hex string (128 hex characters)

    This is the authoritative identity identifier across DNA-Messenger.
    """
    return hashlib.sha3_512(pubkey).hexdigest()


# -----------------------------------------------------------------------------
# Web UI
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """
    Landing page.

    Creates a new authentication session and embeds the session metadata
    into the HTML page so the browser can poll for approval.
    """
    sess = store.create_session(
        origin=settings.ORIGIN,
        ttl_seconds=settings.SESSION_TTL_SECONDS,
    )

    return templates.TemplateResponse(
        "landing.html",
        {
            "request": request,
            "origin": settings.ORIGIN,
            "session_id": sess.session_id,
            "expires_at": sess.expires_at,
        },
    )


# -----------------------------------------------------------------------------
# QR code
# -----------------------------------------------------------------------------
@app.get("/api/v1/session/{session_id}/qr.svg")
def session_qr_svg(session_id: str):
    """
    Returns the QR code SVG for a given session.

    The QR code encodes a *challenge descriptor*, not a secret.
    """
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    svg_bytes = make_auth_qr_svg_bytes(sess.qr_uri)
    return Response(content=svg_bytes, media_type="image/svg+xml")


# -----------------------------------------------------------------------------
# Optional challenge endpoint (future / debugging)
# -----------------------------------------------------------------------------
@app.get("/api/v1/session/{session_id}/challenge")
def get_challenge(session_id: str):
    """
    Returns a minimal challenge object.

    Not strictly required for the QR flow, but useful for debugging
    or future extensions.
    """
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    return {
        "v": 1,
        "session_id": sess.session_id,
        "challenge": sess.challenge,
        "rp_id": settings.RP_ID,
        "rp_name": settings.RP_NAME,
        "scopes": settings.SCOPES,
        "issued_at": sess.issued_at,
        "expires_at": sess.expires_at,
    }


# -----------------------------------------------------------------------------
# QR authentication completion (CRITICAL PATH)
# -----------------------------------------------------------------------------
@app.post("/api/v1/session/{session_id}/complete")
def complete(session_id: str, request: Request, body: dict = Body(...)):
    """
    Completes a QR authentication session.

    This endpoint:
      - Validates session state
      - Reconstructs the canonical message
      - Verifies fingerprint ↔ public key binding
      - Verifies ML-DSA-87 signature using native PQClean code
      - Approves or denies the session
    """
    # -------------------------------------------------------------------------
    # Session validation
    # -------------------------------------------------------------------------
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    if sess.status != SessionStatus.PENDING:
        raise HTTPException(409, "session not pending")

    # -------------------------------------------------------------------------
    # Envelope validation
    # -------------------------------------------------------------------------
    if body.get("type") != "dna.auth.response":
        raise HTTPException(400, "invalid type")

    if int(body.get("v", 0)) != 1:
        raise HTTPException(400, "invalid version")

    # Client must explicitly send public key now
    for k in ("session_id", "fingerprint", "signature", "signed_payload", "pubkey_b64"):
        if k not in body:
            raise HTTPException(400, f"missing field: {k}")

    if body["session_id"] != session_id:
        raise HTTPException(400, "session_id mismatch")

    signed_payload = body["signed_payload"]
    if not isinstance(signed_payload, dict):
        raise HTTPException(400, "signed_payload must be object")

    for k in ("origin", "session_id", "nonce", "issued_at", "expires_at"):
        if k not in signed_payload:
            raise HTTPException(400, f"missing signed_payload field: {k}")

    if signed_payload["session_id"] != session_id:
        raise HTTPException(400, "signed_payload.session_id mismatch")

    # Origin must match what the server issued
    if str(signed_payload["origin"]).rstrip("/") != sess.origin.rstrip("/"):
        raise HTTPException(400, "origin mismatch")

    # -------------------------------------------------------------------------
    # Time & replay protection
    # -------------------------------------------------------------------------
    try:
        iat = int(signed_payload["issued_at"])
        exp = int(signed_payload["expires_at"])
    except Exception:
        raise HTTPException(400, "issued_at/expires_at must be int")

    if exp <= iat:
        raise HTTPException(400, "expires_at must be > issued_at")

    # Prevent long-lived signatures
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
            }
        )
        raise HTTPException(409, "replay nonce")

    # -------------------------------------------------------------------------
    # Canonical message reconstruction
    #
    # MUST match the phone byte-for-byte.
    # Any difference here breaks signature verification.
    # -------------------------------------------------------------------------
    canonical = (
        f'{{"expires_at":{exp},"issued_at":{iat},"nonce":"{nonce}",'
        f'"origin":"{origin}","session_id":"{session_id}"}}'
    )
    canonical_bytes = canonical.encode("utf-8")

    # -------------------------------------------------------------------------
    # Decode signature and public key
    # -------------------------------------------------------------------------
    try:
        signature = _b64decode_loose(body["signature"])
        pubkey = _b64decode_loose(body["pubkey_b64"])
    except Exception:
        raise HTTPException(400, "invalid base64 encoding")

    # -------------------------------------------------------------------------
    # Fingerprint ↔ public key binding (authoritative)
    # -------------------------------------------------------------------------
    claimed_fp = str(body["fingerprint"]).lower().strip()
    computed_fp = _fingerprint_from_pubkey(pubkey)

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
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(403, "fingerprint/pubkey mismatch")

    # -------------------------------------------------------------------------
    # Cryptographic verification (native PQClean, ML-DSA-87)
    # -------------------------------------------------------------------------
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
            }
        )
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(403, "invalid signature")

    # -------------------------------------------------------------------------
    # Success → approve session
    # -------------------------------------------------------------------------
    store.save_response(
        sess.session_id,
        {
            "v": 1,
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
        }
    )

    store.set_status(sess.session_id, SessionStatus.APPROVED)
    return {"ok": True}


# -----------------------------------------------------------------------------
# Browser polling endpoint
# -----------------------------------------------------------------------------
@app.get("/api/v1/session/{session_id}")
def session_status(session_id: str):
    """
    Returns public session status.

    The browser polls this endpoint to detect approval.
    """
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    # Auto-expire pending sessions
    if sess.is_expired and sess.status == SessionStatus.PENDING:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)

    return sess.public_view()


# -----------------------------------------------------------------------------
# Success page
# -----------------------------------------------------------------------------
@app.get("/success", response_class=HTMLResponse)
def success(request: Request):
    """
    Final landing page after successful authentication.
    """
    return templates.TemplateResponse("success.html", {"request": request})
