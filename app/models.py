from pydantic import BaseModel, Field
from typing import Dict, Any

class AuthCallback(BaseModel):
    type: str
    v: int
    session_id: str
    fingerprint: str
    signature: str
    signed_payload: Dict[str, Any]
