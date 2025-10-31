# allowlist_enforcer.py
# -----------------------------------------------------------------------------
# Chrono 9.0.1 allowlist validator (AST-based)
#
# What’s new in this version:
# - Allows `import pychrono as chrono` (top-level import).
# - Resolves top-level `pychrono.<ClassName>` to the correct submodule by
#   looking up the class name across the allowed submodules in allowlist.json.
#   Example: pychrono.ChBodyEasyCylinder -> pychrono.core.ChBodyEasyCylinder.
# - Keeps strict enforcement of:
#     * Only pychrono modules (plus SAFE_EXTRA_IMPORTS) may be imported.
#     * Only whitelisted classes/constructors may be used.
#     * Only methods that exist on those classes (via reflection) may be called.
# - Produces clear, actionable error messages.
#
# Inputs:
#   - allowlist.json with shape:
#       {
#         "modules": {
#           "pychrono.core": [...class names...],
#           "pychrono.vehicle": [...],
#           "pychrono.irrlicht": [...],
#           "pychrono.fea": [...]
#         },
#         "enums": [...],
#         "class_methods": {},   # (optional, unused here)
#         "overloads": {}        # (optional, for ctor arity/type checks elsewhere)
#       }
#
# Usage (CLI):
#   python allowlist_enforcer.py your_script.py [allowlist.json]
#
# Typical server usage:
#   from allowlist_enforcer import validate_code
#   errs = validate_code(code_str, "allowlist.json")
#   if errs: reject with 4xx; else proceed.
# -----------------------------------------------------------------------------

import ast
import json
import importlib
from typing import Dict, List, Optional, Tuple, Set

# You may add tiny stdlib helpers you want to allow (math, time, etc.)
SAFE_EXTRA_IMPORTS = {"math"}

def load_allowlist(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("modules", {})
    data.setdefault("enums", [])
    data.setdefault("class_methods", {})
    data.setdefault("overloads", {})
    return data

def _attr_fqn(attr: ast.Attribute) -> Optional[str]:
    """Turn an Attribute tree (e.g., pychrono.core.ChBodyEasyCylinder) into 'pychrono.core.ChBodyEasyCylinder'."""
    parts: List[str] = []
    cur = attr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None

def _call_target(func: ast.AST) -> Optional[Tuple[str, str]]:
    """Return ('module.like.path', 'NameOrFunction') for a Call node target if attribute-based."""
    if isinstance(func, ast.Attribute):
        fqn = _attr_fqn(func)
        if fqn and "." in fqn:
            mod, name = fqn.rsplit(".", 1)
            return mod, name
    return None

class AllowlistValidator(ast.NodeVisitor):
    def __init__(self, allow: dict):
        self.errors: List[str] = []
        self.allow = allow
        # Map of module -> set(classnames)
        self.allowed_modules: Dict[str, Set[str]] = {m: set(v) for m, v in allow["modules"].items()}
        # Track variable name -> fully-qualified class name (e.g. pychrono.core.ChBodyEasyCylinder)
        self.var_types: Dict[str, str] = {}
        # Keep imported modules for light reflection
        self._imports: Dict[str, object] = {}
        self._method_cache: Dict[str, Set[str]] = {}

        # Pre-import submodules listed in allowlist (best-effort).
        for m in self.allowed_modules:
            try:
                self._imports[m] = importlib.import_module(m)
            except Exception:
                self._imports[m] = None

        # Try top-level pychrono too (to support `import pychrono as chrono`)
        try:
            self._imports["pychrono"] = importlib.import_module("pychrono")
        except Exception:
            self._imports["pychrono"] = None

    # -------------------------
    # Utilities & error helper
    # -------------------------
    def _report(self, msg: str):
        self.errors.append(msg)

    def _resolve_top_level_class(self, cls_name: str) -> Optional[str]:
        """If user wrote pychrono.<ClassName>, figure out which submodule owns that class.
        Returns the submodule path (e.g., 'pychrono.core') or None if not found/ambiguous."""
        owners = [m for m, names in self.allowed_modules.items() if cls_name in names]
        if len(owners) == 1:
            return owners[0]
        # If ambiguous or not found, return None to force a clean error downstream.
        return None

    def _is_allowed_module_name(self, name: str) -> bool:
        """Accept a submodule exactly listed in allowlist, or the top-level 'pychrono' namespace as import-only."""
        if name == "pychrono":
            return True
        return any(name == m or name.startswith(m + ".") for m in self.allowed_modules)

    # -------------
    # Import rules
    # -------------
    def visit_ImportFrom(self, node: ast.ImportFrom):
        # Keep imports consistent: forbid 'from X import Y' style.
        self._report(f"Disallowed import style: 'from {node.module} import ...'. Use plain 'import ...' only.")

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            if name in SAFE_EXTRA_IMPORTS:
                continue
            if not name.startswith("pychrono"):
                self._report(
                    f"Import not allowed: '{name}'. Only 'pychrono' (top-level) and allowed pychrono submodules (plus {SAFE_EXTRA_IMPORTS}) are permitted."
                )
                continue
            if not self._is_allowed_module_name(name):
                self._report(
                    f"Import not allowed: '{name}'. Not present in allowlist modules (allowed: top-level 'pychrono' and submodules in allowlist.json)."
                )
                continue
            # Record import attempt (best-effort)
            try:
                self._imports[name] = importlib.import_module(name)
            except Exception:
                self._imports[name] = None

    # -----------------------------------
    # Assignments: track constructed type
    # -----------------------------------
    def visit_Assign(self, node: ast.Assign):
        # If user is constructing e.g. x = pychrono.ChBodyEasyCylinder(...)
        if isinstance(node.value, ast.Call):
            target_info = _call_target(node.value.func)
            if target_info:
                mod, cls = target_info
                fq_mod = mod

                # If top-level pychrono, resolve to owning submodule by classname.
                if mod == "pychrono":
                    owner = self._resolve_top_level_class(cls)
                    if owner is None:
                        self._report(
                            f"Constructor not allowed or ambiguous: {mod}.{cls}. "
                            f"Could not resolve to a unique submodule in allowlist."
                        )
                    else:
                        fq_mod = owner

                # Enforce constructor validity
                if fq_mod in self.allowed_modules and cls in self.allowed_modules[fq_mod]:
                    fqcn = f"{fq_mod}.{cls}"
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.var_types[t.id] = fqcn
                elif mod.startswith("pychrono"):
                    self._report(f"Constructor not allowed: {mod}.{cls} (not in allowlist).")
        self.generic_visit(node)

    # ----------------------------
    # Calls: static & instance use
    # ----------------------------
    def visit_Call(self, node: ast.Call):
        # Direct qualified calls (e.g., pychrono.ChSystem(...), pychrono.core.ChSystem(...))
        target = _call_target(node.func)
        if target:
            mod, name = target
            check_mod = mod

            if mod == "pychrono":
                owner = self._resolve_top_level_class(name)
                if owner:
                    check_mod = owner

            if check_mod in self.allowed_modules and name not in self.allowed_modules[check_mod]:
                self._report(f"Call to '{mod}.{name}' is not a whitelisted constructor/class.")
        # Instance method calls: x.SetMass(...)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            var = node.func.value.id
            meth = node.func.attr
            fqcn = self.var_types.get(var)
            if fqcn:
                if not self._method_exists(fqcn, meth):
                    self._report(f"Method '{meth}' not found on {fqcn}.")
        self.generic_visit(node)

    # ----------------------------
    # Attribute access on classes
    # ----------------------------
    def visit_Attribute(self, node: ast.Attribute):
        fqn = _attr_fqn(node)
        if fqn and fqn.startswith("pychrono") and "." in fqn:
            mod, name = fqn.rsplit(".", 1)

            # If user referenced pychrono.<ClassName>, resolve to actual submodule.
            check_mod = mod
            if mod == "pychrono":
                owner = self._resolve_top_level_class(name)
                if owner:
                    check_mod = owner

            # If it *looks* like a class (PascalCase), enforce class allowlist.
            if name and name[0].isupper():
                if check_mod in self.allowed_modules:
                    if name not in self.allowed_modules[check_mod]:
                        self._report(f"Access to '{fqn}' is not allowed (class not in allowlist).")
                else:
                    # top-level class that we cannot resolve
                    if mod == "pychrono":
                        self._report(
                            f"Access to '{fqn}' is not allowed; could not resolve '{name}' to an allowed submodule."
                        )
        self.generic_visit(node)

    # ----------------------
    # Reflection for methods
    # ----------------------
    def _method_exists(self, fqcn: str, meth: str) -> bool:
        """Light reflection: loads class and caches its dir(). If reflection fails, be lenient."""
        if fqcn in self._method_cache:
            return meth in self._method_cache[fqcn]
        try:
            mod, cls = fqcn.rsplit(".", 1)
            m = self._imports.get(mod)
            if not m:
                return True  # Cannot reflect here; don't hard-fail on environments without Chrono.
            cobj = getattr(m, cls)
            self._method_cache[fqcn] = {n for n in dir(cobj) if not n.startswith("_")}
            return meth in self._method_cache[fqcn]
        except Exception:
            return True  # Be lenient if reflection fails (runtime guard can still catch)
        # Note: overload/arg-type checks happen in a separate runtime step.

def validate_code(code: str, allowlist_path: str = "allowlist.json") -> List[str]:
    """Validate source code against allowlist.json rules. Returns a list of error strings (empty == OK)."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"SyntaxError: {e}"]

    allow = load_allowlist(allowlist_path)
    v = AllowlistValidator(allow)
    v.visit(tree)
    return v.errors

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python allowlist_enforcer.py <file.py> [allowlist.json]")
        sys.exit(2)
    src = open(sys.argv[1], "r", encoding="utf-8").read()
    errs = validate_code(src, sys.argv[2] if len(sys.argv) > 2 else "allowlist.json")
    import json as _json
    print(_json.dumps({"ok": not bool(errs), "errors": errs}, indent=2))
    sys.exit(0 if not errs else 2)
