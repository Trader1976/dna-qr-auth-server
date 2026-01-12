from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from .config import settings
from .storage import store, SessionStatus
from .qr import make_auth_qr_svg
from .models import AuthCallback

app = FastAPI(title="DNA QR Auth Server", version="0.1.0")

templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    sess = store.create_session(origin=settings.ORIGIN, ttl_seconds=settings.SESSION_TTL_SECONDS,
                                callback_url=settings.CALLBACK_URL)
    qr_svg = make_auth_qr_svg(sess.qr_payload_json)
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "origin": settings.ORIGIN,
        "session_id": sess.session_id,
        "expires_at": sess.expires_at,
        "qr_svg": qr_svg,
    })


@app.get("/api/session/{session_id}")
def get_session(session_id: str):
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    return sess.public_view()


@app.post("/api/callback")
def callback(body: AuthCallback):
    # 1) locate session
    sess = store.get(body.session_id)
    if not sess:
        raise HTTPException(404, "session not found")

    # 2) expiry check
    if sess.is_expired:
        store.set_status(sess.session_id, SessionStatus.EXPIRED)
        raise HTTPException(410, "session expired")

    # 3) match signed_payload against what we issued (hard requirement)
    if not store.matches_issued_payload(sess.session_id, body.signed_payload):
        store.set_status(sess.session_id, SessionStatus.DENIED)
        raise HTTPException(400, "signed_payload mismatch")

    # 4) TODO: verify Dilithium signature
    #    - resolve fingerprint -> pubkey (via your DHT / nodus / cpunk service)
    #    - verify signature over CANONICAL JSON bytes (your RFC8785 ordering)
    # For now we accept and store response:
    store.save_response(sess.session_id, body.model_dump())
    store.set_status(sess.session_id, SessionStatus.APPROVED)

    return {"ok": True}
