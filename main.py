from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from .auth import token_endpoint, jwks, introspect, authorize_endpoint
from .rbac import require_scope, require_role
from .schemas import TokenResponse
import uvicorn

app = FastAPI(title="DeafAuth (bootstrap)", version="0.1.0")

# Simple CORS for pinksync frontend during dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes implemented in modules
app.post("/oauth/token")(token_endpoint)
app.get("/.well-known/jwks.json")(jwks)
app.post("/oauth/introspect")(introspect)
app.get("/oauth/authorize")(authorize_endpoint)  # simple stub for interactive flows

# Example protected route showing RBAC usage
@app.post("/v1/agent/{agent_id}/invoke")
async def invoke_agent(agent_id: str, token=Depends(require_scope("agent:invoke:{agent_id}"))):
    # token is the decoded token claims dict returned by the dependency
    return {"ok": True, "agent_id": agent_id, "caller": token.get("sub")}

@app.get("/admin/metrics")
async def admin_metrics(_=Depends(require_role("agent_admin"))):
    return {"uptime_s": 1234, "registered_clients": 2}

@app.get("/")
async def root():
    return {"service": "DeafAuth (bootstrap)", "version": "0.1.0"}

if __name__ == "__main__":
    uvicorn.run("deafauth.main:app", host="0.0.0.0", port=8000, reload=True)
