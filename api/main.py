"""
AgentGate API

FastAPI application for agent authentication and identity management.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import agents, keys, tokens, verify, audit
from api.middleware.auth import APIKeyMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print("AgentGate API starting...")

    # Initialize database connection if configured
    supabase_url = os.environ.get("SUPABASE_URL")
    if supabase_url:
        from supabase import create_client

        supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        app.state.db = create_client(supabase_url, supabase_key)
        print("Connected to Supabase")
    else:
        app.state.db = None
        print("Running without database (in-memory mode)")

    yield

    # Shutdown
    print("AgentGate API shutting down...")


app = FastAPI(
    title="AgentGate",
    description="Agent Authentication Service - Identity and auth for AI agents",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(keys.router, prefix="/api/v1/keys", tags=["keys"])
app.include_router(tokens.router, prefix="/api/v1/tokens", tags=["tokens"])
app.include_router(verify.router, prefix="/api/v1/verify", tags=["verify"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "AgentGate",
        "version": "0.1.0",
        "description": "Agent Authentication Service",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=True,
    )
