# server.py
#Minimal server (FastAPI) with double-check and timeout
import os, json, tempfile, subprocess, sys, textwrap, time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from allowlist_enforcer import validate_code

AUTH_KEY = os.environ.get("AUTH_KEY", "")  # set on Render

app = FastAPI(title="Chrono Validator/Executor")

class CodeReq(BaseModel):
    code: str
    auth_key: str

@app.post("/validate")
def validate(req: CodeReq):
    if req.auth_key != AUTH_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    errs = validate_code(req.code, "allowlist.json")
    return {"ok": not bool(errs), "errors": errs}

@app.post("/execute")
def execute(req: CodeReq):
    if req.auth_key != AUTH_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    # Re-validate defensively
    errs = validate_code(req.code, "allowlist.json")
    if errs:
        raise HTTPException(status_code=422, detail={"errors": errs})
    # Run in a temp file with timeout and no internet (Render free dyno has no egress by default)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "main.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(req.code)
        try:
            # Use same Python on Render; if you need conda env, point to it here.
            proc = subprocess.run(
                [sys.executable, "-u", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=False, text=True
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail="execution timeout (15s)")
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr
    }

@app.get("/health")
def health():
    return {"ok": True}
