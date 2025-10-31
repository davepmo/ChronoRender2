# server.py
# -----------------------------------------------------------------------------
# Chrono 9.0.1 Code Gate (FastAPI)
#
# Purpose
#   - Enforce generation of pure PyChrono 9.0.1 scripts:
#       * Optionally REWRITE known legacy (v7/v8) names -> current 9.0.1 names
#       * VALIDATE that resulting code uses only classes/attrs from allowlist.json
#       * IGNORE non-pychrono imports entirely (per your new requirement)
#
# Security & Auth
#   - Reads secret from ENV: AUTH_KEY (preferred) or API_KEY (fallback)
#   - Accepts credentials via:
#       * HTTP header: Authorization: Bearer <SECRET>   (recommended)
#       * JSON body key: {"auth_key": "<SECRET>"}       (legacy; still accepted)
#
# Endpoints
#   GET  /health                      -> liveness
#   POST /validate                    -> rewrite (optional) + validate only
#   POST /rewrite                     -> rewrite only (no validation/execution)
#   POST /execute                     -> rewrite + validate + run with timeout
#
# Environment Variables (Render)
#   AUTH_KEY or API_KEY               -> required
#   ALLOWLIST_PATH                    -> default "allowlist.json"
#   MAX_CODE_BYTES                    -> default "200000" (~200KB)
#   EXEC_TIMEOUT_S                    -> default "15" (seconds)
#
# Files expected alongside server:
#   - allowlist.json                  -> produced by your harvester; contains:
#                                        { "modules": {...}, "overloads": {...}, "enums": [...] }
#   - allowlist_enforcer.py           -> must expose:
#                                        * validate_code(code, allowlist_path, ignore_imports=True)
#                                          -> returns set/list of error strings (empty if OK)
#                                        * rewrite_code(code)  [optional]
#                                          -> returns (rewritten_code, replacements_list)
#                                        If rewrite_code is not present, rewrite steps are skipped.
# -----------------------------------------------------------------------------

import os
import sys
import time
import json
import tempfile
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# Import your validator/remapper. We soft-detect rewrite_code for portability.
from allowlist_enforcer import validate_code  # required
try:
    from allowlist_enforcer import rewrite_code  # optional, legacy->current remap
    HAVE_REWRITE = True
except Exception:
    HAVE_REWRITE = False

# ----- Configuration ----------------------------------------------------------

SECRET = os.getenv("AUTH_KEY") or os.getenv("API_KEY") or ""
ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "allowlist.json")
MAX_CODE_BYTES = int(os.getenv("MAX_CODE_BYTES", "200000"))
EXEC_TIMEOUT_S = float(os.getenv("EXEC_TIMEOUT_S", "15"))

app = FastAPI(title="Chrono 9.0.1 Code Gate", version="2.0.0")


# ----- Models ----------------------------------------------------------------

class CodeReq(BaseModel):
    code: str
    # legacy/optional inline credential
    auth_key: Optional[str] = None
    # request-level toggles (can be omitted; sensible defaults provided)
    apply_legacy_map: Optional[bool] = True     # attempt legacy->current rewrite
    ignore_non_pychrono_imports: Optional[bool] = True  # ignore non-pychrono imports during validation


class ValidateResp(BaseModel):
    ok: bool
    errors: list[str] = []
    rewritten: Optional[str] = None
    replacements: Optional[list[str]] = None


class ExecResp(BaseModel):
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    rewritten: Optional[str] = None
    replacements: Optional[list[str]] = None


# ----- Helpers ---------------------------------------------------------------

def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _require_auth(authorization: Optional[str], body_key: Optional[str]) -> None:
    if not SECRET:
        raise HTTPException(status_code=500, detail="server not configured (missing AUTH_KEY/API_KEY)")
    provided = _extract_bearer(authorization) or (body_key or "")
    if provided != SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")


def _check_size(s: str) -> None:
    if len(s.encode("utf-8", errors="ignore")) > MAX_CODE_BYTES:
        raise HTTPException(status_code=413, detail=f"code too large (> {MAX_CODE_BYTES} bytes)")


def _maybe_rewrite(code: str, enable: bool) -> tuple[str, list[str]]:
    """Apply legacy->current remap if available & enabled; else no-op."""
    if enable and HAVE_REWRITE:
        try:
            new_code, replacements = rewrite_code(code)
            return new_code, (replacements or [])
        except Exception as e:
            # Fail closed: surface an internal error if remapper explodes
            raise HTTPException(status_code=500, detail=f"rewrite error: {type(e).__name__}: {e}")
    return code, []


# ----- Routes ----------------------------------------------------------------

@app.get("/health")
def health():
    return {"ok": True, "ts": time.time()}


@app.post("/rewrite", response_model=ValidateResp)
def rewrite(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    """Return ONLY the rewritten code (no validation or execution)."""
    _require_auth(authorization, req.auth_key)
    _check_size(req.code)

    new_code, replacements = _maybe_rewrite(req.code, enable=req.apply_legacy_map)
    return ValidateResp(ok=True, errors=[], rewritten=new_code, replacements=replacements)


@app.post("/validate", response_model=ValidateResp)
def validate(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    """Rewrite (optional) + validate against allowlist.json; no execution."""
    _require_auth(authorization, req.auth_key)
    _check_size(req.code)

    # 1) rewrite legacy -> current (if enabled & available)
    new_code, replacements = _maybe_rewrite(req.code, enable=req.apply_legacy_map)

    # 2) validate strictly against allowlist; ignore non-pychrono imports if requested
    try:
        errors = validate_code(
            new_code,
            ALLOWLIST_PATH,
            ignore_imports=req.ignore_non_pychrono_imports  # <— your enforcer should honor this
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"allowlist not found: {ALLOWLIST_PATH}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

    return ValidateResp(ok=not bool(errors), errors=sorted(errors), rewritten=new_code, replacements=replacements)


@app.post("/execute", response_model=ExecResp)
def execute(req: CodeReq, authorization: Optional[str] = Header(default=None)):
    """Rewrite + validate + run under a timeout; returns stdout/stderr."""
    _require_auth(authorization, req.auth_key)
    _check_size(req.code)

    # 1) rewrite
    new_code, replacements = _maybe_rewrite(req.code, enable=req.apply_legacy_map)

    # 2) re-validate (defensive)
    try:
        errors = validate_code(
            new_code,
            ALLOWLIST_PATH,
            ignore_imports=req.ignore_non_pychrono_imports
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"allowlist not found: {ALLOWLIST_PATH}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"validator error: {type(e).__name__}: {e}")

    if errors:
        # Surface validation errors with 422 to let the caller branch
        raise HTTPException(status_code=422, detail={"errors": sorted(errors)})

    # 3) execute
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "main.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_code)

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

    return ExecResp(
        ok=(proc.returncode == 0),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        rewritten=new_code,
        replacements=replacements,
    )
