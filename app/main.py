"""FastAPI wrapper. OpenAI-compatible-ish endpoint so clients are easy to point here."""
from fastapi import FastAPI, Request, Header
from pydantic import BaseModel

from app.pipeline import process

app = FastAPI(title="Secure AI Gateway", version="1.0")

# Demo API-key -> (user_id, tier) map. Replace with a real store.
API_KEYS = {
    "demo-free-key": ("user_free", "free"),
    "demo-premium-key": ("user_premium", "premium"),
}


class ChatBody(BaseModel):
    prompt: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat")
def chat(body: ChatBody, request: Request, x_api_key: str = Header(default="")):
    # --- Auth: resolve user + tier from API key ---
    if x_api_key not in API_KEYS:
        return {"decision": "blocked", "violation_type": "auth",
                "response": "Invalid or missing API key."}
    user_id, tier = API_KEYS[x_api_key]
    client_ip = request.client.host if request.client else "0.0.0.0"

    result = process(user_id, body.prompt, tier, client_ip)
    return {
        "request_id": result.request_id,
        "decision": result.decision,
        "violation_type": result.violation_type,
        "stage": result.stage,
        "latency_ms": result.latency_ms,
        "response": result.response,
    }
