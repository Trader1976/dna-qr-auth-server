from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi import Body
from .identity import verify_mldsa87_signature

import json
from collections import OrderedDict
import base64
import hashlib
from .storage import store, SessionStatus
from .identity import resolve_pubkey_from_fingerprint

from .config import settings
from .storage import store, SessionStatus
from .qr import make_auth_qr_svg_bytes, make_auth_qr_svg


app = FastAPI(title="DNA QR Auth Server", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def b64decode_strict(s: str) -> bytes:
    # standard base64 with optional padding
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        # allow missing padding (some libs omit it)
        pad = '=' * (-len(s) % 4)
        return base64.b64decode(s + pad)


def _b64decode_loose(s: str) -> bytes:
    """
    Base64 decode that accepts missing padding and rejects non-base64 chars.
    DNA-Messenger uses standard base64 (base64Encode in Dart).
    """
    s = str(s).strip()
    # add padding if missing
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise ValueError("invalid base64")

def _fingerprint_from_pubkey(pubkey: bytes) -> str:
    # DNA fingerprints in your app are 128 hex chars -> sha3_512 hex
    return hashlib.sha3_512(pubkey).hexdigest()


def fp_from_pubkey(pubkey: bytes) -> str:
    # DNA fingerprint appears to be SHA3-512 hex (128 chars)
    # This matches your earlier fingerprints being 128 hex chars.
    return hashlib.sha3_512(pubkey).hexdigest()

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    sess = store.create_session(origin=settings.ORIGIN, ttl_seconds=settings.SESSION_TTL_SECONDS)
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "origin": settings.ORIGIN,
        "session_id": sess.session_id,
        "expires_at": sess.expires_at,
    })


import json

@app.get("/api/v1/session/{session_id}/qr.svg")
def session_qr_svg(session_id: str):
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    svg_bytes = make_auth_qr_svg_bytes(sess.qr_uri)
    return Response(content=svg_bytes, media_type="image/svg+xml")


@app.get("/api/v1/session/{session_id}/challenge")
def get_challenge(session_id: str):
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    # Minimal fields for phone to sign
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


def canonical_signing_string(
    session_id: str,
    challenge: str,
    decision: str,
    fingerprint: str,
    display_name: str,
    iat: int,
    exp: int,
    nonce: str,
    scopes: list[str],
) -> bytes:
    if "\n" in display_name:
        raise ValueError("display_name contains newline")
    scopes_csv = ",".join(sorted(scopes))
    s = (
        "DNA-AUTH-V1\n"
        f"session_id={session_id}\n"
        f"challenge={challenge}\n"
        f"decision={decision}\n"
        f"fingerprint={fingerprint}\n"
        f"display_name={display_name}\n"
        f"iat={iat}\n"
        f"exp={exp}\n"
        f"nonce={nonce}\n"
        f"scopes={scopes_csv}\n"
    )
    return s.encode("utf-8")


from fastapi import Body

from fastapi import Body, HTTPException
import base64
import oqs

from .storage import store, SessionStatus
from .identity import resolve_pubkey_from_fingerprint


def verify_dilithium5(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature("Dilithium5") as verifier:
        return verifier.verify(message, signature, pubkey)



@app.post("/api/v1/session/{session_id}/complete")
def complete(session_id: str, body: dict = Body(...)):
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")
    if sess.status != SessionStatus.PENDING:
        raise HTTPException(409, "session not pending")

    # Envelope
    if body.get("type") != "dna.auth.response":
        raise HTTPException(400, "invalid type")
    if int(body.get("v", 0)) != 1:
        raise HTTPException(400, "invalid version")

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

    if str(signed_payload["origin"]).rstrip("/") != sess.origin.rstrip("/"):
        raise HTTPException(400, "origin mismatch")

    # Time checks
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
    if store.seen_nonce(sess.session_id, nonce):
        raise HTTPException(409, "replay nonce")

    # Canonical JSON EXACTLY like the app
    origin = str(signed_payload["origin"])
    canonical = (
        f'{{"expires_at":{exp},"issued_at":{iat},"nonce":"{nonce}",'
        f'"origin":"{origin}","session_id":"{session_id}"}}'
    )
    canonical_bytes = canonical.encode("utf-8")

    # Decode base64
    try:
        signature = _b64decode_loose(body["signature"])
        pubkey = _b64decode_loose(body["pubkey_b64"])
    except Exception:
        raise HTTPException(400, "invalid base64 encoding")

    # Fingerprint must match pubkey (authoritative check)
    claimed_fp = str(body["fingerprint"]).lower().strip()
    computed_fp = _fingerprint_from_pubkey(pubkey)
    if claimed_fp != computed_fp:
        store.set_status(sess.session_id, SessionStatus.DENIED)
        print("QR_AUTH DEBUG fingerprint/pubkey mismatch",
              "claimed_fp=", claimed_fp[:16],
              "computed_fp=", computed_fp[:16],
              "pubkey_len=", len(pubkey),
              "sig_len=", len(signature))
        raise HTTPException(403, "fingerprint/pubkey mismatch")

    # ---- VERIFY USING NATIVE LIB (the only correct method) ----
    try:
        ok = verify_mldsa87_signature(pubkey, canonical_bytes, signature)
    except Exception as e:
        store.set_status(sess.session_id, SessionStatus.DENIED)
        print("QR_AUTH DEBUG verifier exception:", repr(e))
        raise HTTPException(500, "verifier error")

    if not ok:
        store.set_status(sess.session_id, SessionStatus.DENIED)
        print("QR_AUTH DEBUG verify_failed canonical=", canonical,
              "pubkey_len=", len(pubkey),
              "sig_len=", len(signature),
              "msg_len=", len(canonical_bytes))
        raise HTTPException(403, "invalid signature")

    # Success
    store.save_response(sess.session_id, {
        "v": 1,
        "type": body["type"],
        "session_id": session_id,
        "fingerprint": claimed_fp,
        "signature_b64": body["signature"],
        "pubkey_b64": body["pubkey_b64"],
        "signed_payload": signed_payload,
        "server_canonical": canonical,
        "verified": True,
    })
    store.set_status(sess.session_id, SessionStatus.APPROVED)
    return {"ok": True}



@app.get("/api/v1/session/{session_id}")
def session_status(session_id: str):
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    # auto-expire pending sessions
    if sess.is_expired and sess.status == SessionStatus.PENDING:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)

    return sess.public_view()

@app.get("/success", response_class=HTMLResponse)
def success(request: Request):
    return templates.TemplateResponse("success.html", {
        "request": request,
    })
