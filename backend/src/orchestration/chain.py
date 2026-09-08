import os
import threading
from datetime import datetime, timedelta
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnableLambda

load_dotenv()

class SimplePrivacyChain:
    """
    AXION Secure Chain
    Orchestrates the de-identification, LLM request, and re-hydration loop.
    Uses LCEL for modularity and session isolation for security.
    """
    
    def __init__(self, engine):
        self.engine = engine
        
        # Local session store to keep mappings isolated in RAM.
        # Format: { session_id: { mapping, metrics, entities, expiry } }
        self.sessions = {}
        self.session_lock = threading.Lock()

    def _get_llm(self, provider):
        """Toggle between cloud providers (Gemini or OpenAI)."""
        if provider == "openai":
            return ChatOpenAI(model="gpt-4o-mini")
        else:
            return ChatGoogleGenerativeAI(model="gemini-flash-latest")

    def _llm_step(self, provider):
        """Passes the cleaned prompt to the cloud LLM."""
        key = "OPENAI_API_KEY" if provider == "openai" else "GOOGLE_API_KEY"
        if not os.getenv(key):
            # No credentials configured: skip the network call instead of failing.
            # The de-identification pipeline has already run at this point, so the
            # audit panel still shows what would have been transmitted.
            notice = (f"No {key} configured, so nothing was sent to a model. "
                      "The de-identification pipeline still ran: open the audit "
                      "panel to see the redacted prompt and the entities found.")
            return RunnableLambda(lambda x: {"res": notice, "sid": x["sid"]})

        llm = self._get_llm(provider)

        def call(prompt):
            try:
                return llm.invoke(prompt)
            except Exception as exc:
                # Redaction already happened. Letting a provider outage or a
                # rate limit bubble up would hide the audit trail behind a 500.
                return (f"The model call failed ({type(exc).__name__}). Nothing "
                        "was leaked: the redacted prompt is in the audit panel.")

        return RunnableLambda(lambda x: {
            "res": call(x["prompt"]),
            "sid": x["sid"]
        })

    def _mask_step(self, data):
        """Phase 1: Local scrubbing of the user's prompt."""
        prompt, sid = data["input"], data["sid"]
        anon_text, mapping, metrics, entities = self.engine.anonymize(prompt)
        
        # Save sensitive mapping to the private session store.
        with self.session_lock:
            self.sessions[sid] = {
                "map": mapping,
                "met": metrics,
                "ent": entities,
                "masked_view": anon_text,
                "exp": datetime.now() + timedelta(hours=1)
            }
            self._cleanup_sessions()
        
        return {
            "prompt": f"You are a helpful assistant. Keep any tokens like <NAME_0> exactly as they are. Answer the following request: {anon_text}",
            "sid": sid
        }

    def _restore_step(self, data):
        """Phase 2: Local restoration of PII into the LLM's answer."""
        res, sid = data["res"], data["sid"]
        with self.session_lock:
            session = self.sessions.get(sid, {})
            mapping = session.get("map", {})
        return self.engine.deanonymize(res, mapping)

    def _cleanup_sessions(self):
        """Security: Purge old secrets from local RAM."""
        now = datetime.now()
        expired = [sid for sid, s in self.sessions.items() if s["exp"] < now]
        for sid in expired:
            del self.sessions[sid]

    def run(self, user_input, provider="google", session_id="default"):
        """Execution entry point. Returns restored text and audit metadata."""
        # The core LCEL pipeline initialized per-request to avoid state pollution
        chain = (
            RunnableLambda(self._mask_step) |
            self._llm_step(provider) |
            RunnableLambda(self._restore_step)
        )
        
        final_text = chain.invoke({"input": user_input, "sid": session_id})
        with self.session_lock:
            s = self.sessions.get(session_id, {})
        
        return final_text, s.get("masked_view", ""), s.get("met"), s.get("ent")
