# server.py
# ---------------------------------------------------------------------------
# Chrono 9.0.1 Gate: Rewrite + Validate + Execute microservice
#
# - Auth: "Authorization: Bearer <AUTH_KEY>" header (preferred), or JSON auth_key.
# - Endpoints:
#     GET  /            -> { ok: true, name: "...", ts: <unix> }    (root for default health probes)
#     GET  /health      -> { ok: true, ts: <unix> }                  (explicit health)
#     GET  /healthz     -> { ok: true }                              (alt path for some platforms)
#     GET  /version     -> { ok: true, version: "...", allowlist_loaded: bool }
#     POST /rewrite     -> { ok, errors, rewritten, replacements }
#     POST /validate    -> { ok, errors }
#     POST /execute     -> { ok, returncode, stdout, stderr }  (re-validates first)
#
# Notes:
# - Only enforces class/attr rules defined in allowlist.json (legacy imports are ignored).
# - Legacy → current renames happen in /rewrite (conservative text-level).
# - This file does NOT import pychrono. Validation is static (AST-based).
# - Make sure your Render start command uses: gunicorn -k uvicorn.workers.UvicornWorker server:app
#
# Environment:
#   AUTH_KEY         : required secret for bearer auth
#   ALLOWLIST_PATH   : optional; default "allowlist.json"
#   EXEC_TIMEOUT_SEC : optional; default "15"
# ---------------------------------------------------------------------------

import os
import time
import tempfile
import subprocess
import sys
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

from allowlist_enforcer import validate_code  # signature: validate_code(code: str, allowlist_path: str)

APP_VERSION = "v3.0"
AUTH_KEY = os.environ.get("AUTH_KEY", "")
ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "allowlist.json")
EXEC_TIMEOUT = float(os.environ.get("EXEC_TIMEOUT_SEC", "15"))

app = FastAPI(title="Chrono 9.0.1 Code Gate")

# -------------------- Legacy→Current map (extend as needed) --------------------
LEGACY_TO_CURRENT = {
    # Examples (adjust to your actual mapping choices):
    "ChLinkEngine": "ChLinkMotorRotationTorque",
    "ChLinkEngineRotation": "ChLinkMotorRotationSpeed",
}

# -------------------- Models --------------------
class CodeReq(BaseModel):
    code: str
    auth_key: Optional[str] = None  # fallback if no Authorization header

class RewriteReq(BaseModel):
    code: str

# -------------------- Auth helpers --------------------
def _extract_bearer(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

def _check_auth(authorization: Optional[str], body_key: Optional[str]):
    token = _extract_bearer(authorization) or (body_key or "")
    if not AUTH_KEY:
        # fail closed if not configured
        raise HTTPException(status_code=500, detail="Server misconfig: AUTH_KEY not set")
    if token != AUTH_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")

# -------------------- Utils --------------------
def _rewrite_legacy_symbols(source: str) -> (str, Dict[str, str]):
    """Conservative text-level replace for exact 'chrono.<Name>' occurrences."""
    replaced: Dict[str, str] = {}
    out = source
    for old, new in LEGACY_TO_CURRENT.items():
        needle = f"chrono.{old}"
        if needle in out:
            out = out.replace(needle, f"chrono.{new}")
            replaced[old] = new
    return out, replaced

# -------------------- Health & meta --------------------
@app.get("/")
def root():
    # Root path helps when Render’s health check is left at default "/"
    return {"ok": True, "name": "chrono-gate", "ts": time.time()}

@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/version")
def version():
    return {"ok": True, "version": APP_VERSION, "allowlist_loaded": os.path.exists(ALLOWLIST_PATH)}

# -------------------- Core endpoints --------------------
@app.post("/rewrite")
def rewrite(req: RewriteReq, authorization: Optional[str] = Header(default=None)):
    _check_auth(authorization, None)
    try:
        rewritten, replacements = _rewrite_legacy_symbols(req.code)
        return {"ok": True, "errors": {}, "rewritten": rewritten, "replacements": replacements}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rewrite error: {type(e).__name__}: {e}")

@app.post("/validate")
def validate(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    _check_auth(authorization, req.auth_key)
    try:
        errors = validate_code(req.code, ALLOWLIST_PATH)  # no extra kwargs
        return {"ok": not bool(errors), "errors": errors}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

@app.post("/execute")
def execute(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    _check_auth(authorization, req.auth_key)
    try:
        errors = validate_code(req.code, ALLOWLIST_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")
    if errors:
        raise HTTPException(status_code=422, detail={"errors": errors})

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "main.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(req.code)
        try:
            proc = subprocess.run(
                [sys.executable, "-u", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=EXEC_TIMEOUT,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail=f"execution timeout ({EXEC_TIMEOUT:.0f}s)")

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
