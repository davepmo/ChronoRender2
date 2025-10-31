# server.py
# ---------------------------------------------------------------------------
# Chrono 9.0.1 Gate: Rewrite + Validate + Execute microservice
#
# - Auth: "Authorization: Bearer <AUTH_KEY>" header (preferred), or JSON auth_key.
# - Endpoints:
#     GET  /health            -> { ok: true, ts: <unix> }
#     GET  /version           -> { ok: true, version: "v3.0", allowlist_loaded: bool }
#     POST /rewrite           -> { ok, errors, rewritten, replacements }
#     POST /validate          -> { ok, errors }
#     POST /execute           -> { ok, returncode, stdout, stderr }  (re-validates first)
#
# - Only enforces class/attr rules defined in allowlist.json.
# - Ignores import policing (per user request) — we do NOT block non-pychrono imports here.
# - Legacy → current renames happen in /rewrite only (server-local map). You can extend it.
# - Keep the validator’s public API small: validate_code(code, allowlist_path)
#
# Environment:
#   AUTH_KEY         : required secret for bearer auth
#   ALLOWLIST_PATH   : optional; default "allowlist.json"
#   EXEC_TIMEOUT_SEC : optional; default "15"
#
# ---------------------------------------------------------------------------

import os
import time
import json
import tempfile
import subprocess
import sys
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel

from allowlist_enforcer import validate_code  # EXPECTS signature: (code: str, allowlist_path: str)
# If your allowlist_enforcer also exports rewrite helpers, you can import them here.

APP_VERSION = "v3.0"

AUTH_KEY = os.environ.get("AUTH_KEY", "")
ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "allowlist.json")
EXEC_TIMEOUT = float(os.environ.get("EXEC_TIMEOUT_SEC", "15"))

app = FastAPI(title="Chrono 9.0.1 Code Gate")

# --- Legacy→Current name map (extend as needed) ---------------------
LEGACY_TO_CURRENT = {
    # Example legacy symbol → current symbol mappings
    # NOTE: These are just *examples*. Replace with your actual decisions.
    "ChLinkEngine": "ChLinkMotorRotationTorque",   # pre-9.x -> 9.x family example
    "ChLinkEngineRotation": "ChLinkMotorRotationSpeed",
    # Add more here…
}

# -------------------- Models --------------------

class CodeReq(BaseModel):
    code: str
    # Optional JSON body fallback for auth if no Authorization header is present
    auth_key: Optional[str] = None

class RewriteReq(BaseModel):
    code: str
    # If you later want flags, add them here (e.g., apply_legacy_map: bool = True)

# -------------------- Auth helper --------------------

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
        # If you forgot to set AUTH_KEY in the environment, fail closed.
        raise HTTPException(status_code=500, detail="Server misconfig: AUTH_KEY not set")
    if token != AUTH_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")

# -------------------- Utilities --------------------

def _rewrite_legacy_symbols(source: str) -> (str, Dict[str, str]):
    """
    Extremely conservative text-level rewrite:
    - Only replaces exact 'chrono.<Name>' occurrences using LEGACY_TO_CURRENT.
    - Does not touch strings, comments, or aliases like 'import pychrono as ch'.
      (If you need alias support, add a small parser or regex with import alias extraction.)
    """
    replaced: Dict[str, str] = {}
    out = source
    for old, new in LEGACY_TO_CURRENT.items():
        needle = f"chrono.{old}"
        if needle in out:
            out = out.replace(needle, f"chrono.{new}")
            replaced[old] = new
    return out, replaced

# -------------------- Routes --------------------

@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}

@app.get("/version")
def version():
    exists = os.path.exists(ALLOWLIST_PATH)
    return {"ok": True, "version": APP_VERSION, "allowlist_loaded": bool(exists)}

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
        # IMPORTANT: keep the validator API small & stable
        errors = validate_code(req.code, ALLOWLIST_PATH)
        return {"ok": not bool(errors), "errors": errors}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

@app.post("/execute")
def execute(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    _check_auth(authorization, req.auth_key)

    # Always validate first
    try:
        errors = validate_code(req.code, ALLOWLIST_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

    if errors:
        # Fail-fast on policy violations
        raise HTTPException(status_code=422, detail={"errors": errors})

    # Run in a temp dir with a timeout. This does NOT guarantee total sandboxing!
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
