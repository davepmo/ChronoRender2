# server.py
# -----------------------------------------------------------------------------
# Chrono Validator/Executor (FastAPI)
#
# - Auth:
#     * Reads secret from ENV: AUTH_KEY (preferred) or API_KEY (fallback).
#     * Accepts credentials via:
#         - HTTP header:   Authorization: Bearer <SECRET>
#         - JSON body key: {"auth_key": "<SECRET>"}  (legacy; still supported)
# - Endpoints:
#     * POST /validate  -> static checks only (no execution)
#     * POST /execute   -> re-validates, then runs in a temp file with timeout
#     * GET  /health    -> simple health probe
# - Notes:
#     * keep allowlist.json alongside this file (mounted or baked into image)
#     * set AUTH_KEY or API_KEY in Render (Environment → Environment Variables)
#     * increase timeouts carefully if you truly need longer runs
# -----------------------------------------------------------------------------

import os
import sys
import json
import time
import tempfile
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

from allowlist_enforcer import validate_code  # your existing validator

# ----- Configuration ----------------------------------------------------------

# Prefer AUTH_KEY; fallback to API_KEY for backward compatibility.
SECRET = os.getenv("AUTH_KEY") or os.getenv("API_KEY") or ""

# Allowlist path (relative to working dir)
ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "allowlist.json")

# Hard limits to avoid abuse / accidental huge posts
MAX_CODE_BYTES = int(os.getenv("MAX_CODE_BYTES", "200000"))  # ~200 KB
EXEC_TIMEOUT_S = float(os.getenv("EXEC_TIMEOUT_S", "15"))    # seconds

# ----- FastAPI app ------------------------------------------------------------

app = FastAPI(title="Chrono Validator/Executor", version="1.0.0")


# ----- Models ----------------------------------------------------------------

class CodeReq(BaseModel):
    code: str
    # Legacy/optional: body credential
    auth_key: Optional[str] = None


# ----- Auth helpers -----------------------------------------------------------

def _extract_bearer(authorization: Optional[str]) -> str:
    """Return token value from 'Authorization: Bearer <token>' or ''."""
    if not authorization:
        return ""
    parts = authorization.split(None, 1)  # ["Bearer", "<token>"]
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _require_auth(authorization: Optional[str], body_key: Optional[str]) -> None:
    """Enforce that provided credential matches SECRET."""
    if not SECRET:
        # If no secret is configured, deny all for safety.
        raise HTTPException(status_code=500, detail="server not configured (missing AUTH_KEY/API_KEY)")
    provided = _extract_bearer(authorization) or (body_key or "")
    if provided != SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")


def _check_size(s: str) -> None:
    """Limit incoming code size."""
    if len(s.encode("utf-8", errors="ignore")) > MAX_CODE_BYTES:
        raise HTTPException(status_code=413, detail=f"code too large (> {MAX_CODE_BYTES} bytes)")


# ----- Endpoints --------------------------------------------------------------

@app.get("/health")
def health():
    """Simple liveness endpoint."""
    return {"ok": True, "ts": time.time()}


@app.post("/validate")
def validate(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    """Static validation against allowlist only. No execution."""
    _require_auth(authorization, req.auth_key)
    _check_size(req.code)

    try:
        errors = validate_code(req.code, ALLOWLIST_PATH)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"allowlist not found: {ALLOWLIST_PATH}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

    return {"ok": not bool(errors), "errors": errors}


@app.post("/execute")
def execute(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    """Re-validate, then run the code under a timeout; return stdout/stderr."""
    _require_auth(authorization, req.auth_key)
    _check_size(req.code)

    # Defensive re-validation
    try:
        errors = validate_code(req.code, ALLOWLIST_PATH)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"allowlist not found: {ALLOWLIST_PATH}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

    if errors:
        # Surface validation errors with 422 so callers can branch on it
        raise HTTPException(status_code=422, detail={"errors": errors})

    # Execute in a temp file with a hard timeout
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "main.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(req.code)

        try:
            proc = subprocess.run(
                [sys.executable, "-u", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=EXEC_TIMEOUT_S,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail=f"execution timeout ({EXEC_TIMEOUT_S:.0f}s)")

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
