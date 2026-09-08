import uvicorn
import uuid
import logging
import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.orchestration.chain import SimplePrivacyChain
from src.engine.anonymizer import PrivacyEngine
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AXION-SERVICE")

app = FastAPI(
    title="AXION | Privacy Middleware",
    description="Service-oriented de-identification layer for secure AI interaction.",
    version="3.0.0"
)

# CORS configuration for React integration.
# Origins restricted via env var (comma-separated). Defaults to local dev only.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
_allowed = [o.strip() for o in os.getenv("AXION_ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Session-ID"],
)

try:
    logger.info("Initializing AXION Secure Node...")
    privacy_engine = PrivacyEngine()
    secure_chain = SimplePrivacyChain(engine=privacy_engine)
    logger.info("AXION Node Online.")
except Exception as e:
    logger.error(f"Boot Error: {e}")
    raise

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    masked_text: str
    metrics: dict
    entities: list

@app.post("/chat", response_model=ChatResponse)
async def secure_chat(request: ChatRequest, provider: str = "google", x_session_id: str = Header(None)):
    """
    Primary endpoint for secure LLM interaction.
    Input is scrubbed locally, sent to cloud, and re-hydrated before response.
    """
    try:
        # Use existing session ID or fallback to a temporary one.
        sid = x_session_id or str(uuid.uuid4())
        
        # Process the secure interaction loop in a threadpool to avoid blocking
        final_res, masked, metrics, entities = await asyncio.to_thread(
            secure_chain.run, request.message, provider=provider, session_id=sid
        )
        
        return ChatResponse(
            response=final_res,
            masked_text=masked,
            metrics=metrics,
            entities=entities
        )
    except Exception as e:
        logger.error(f"Request Trace: {sid} | Failure: {str(e)}")
        raise HTTPException(status_code=500, detail="Secure link failure. Check logs.")

@app.get("/health")
async def status():
    return {"status": "ok", "engine": "ettin-68m"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
