# allowlist_enforcer.py  This is the AST gate
import ast, json, importlib
from typing import Dict, List, Optional, Tuple, Set

SAFE_EXTRA_IMPORTS = {"math"}  # keep or empty set()

def load_allowlist(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("modules", {})
    data.setdefault("enums", [])
    data.setdefault("class_methods", {})
    data.setdefault("overloads", {})
    return data

def _attr_fqn(attr: ast.Attribute) -> Optional[str]:
    parts = []
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
        self.allowed_modules: Dict[str, Set[str]] = {m: set(v) for m, v in allow["modules"].items()}
        self.var_types: Dict[str, str] = {}
        self._imports: Dict[str, object] = {}
        self._method_cache: Dict[str, Set[str]] = {}
        for m in self.allowed_modules:
            try:
                self._imports[m] = importlib.import_module(m)
            except Exception:
                self._imports[m] = None

    def _report(self, msg: str): self.errors.append(msg)

    # --- imports ---
    def visit_ImportFrom(self, node: ast.ImportFrom):
        self._report(f"Disallowed import style: 'from {node.module} import ...'. Use 'import pychrono.*' only.")

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            if name in SAFE_EXTRA_IMPORTS:
                continue
            if not name.startswith("pychrono"):
                self._report(f"Import not allowed: '{name}'. Only pychrono modules (and {SAFE_EXTRA_IMPORTS}) are permitted.")
                continue
            if not any(name == m or name.startswith(m + ".") for m in self.allowed_modules):
                self._report(f"Import not allowed: '{name}'. Not present in allowlist modules.")

    # --- assignments: constructor tracking ---
    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Call):
            ctor = _call_target(node.value.func)
            if ctor:
                mod, cls = ctor
                if mod in self.allowed_modules and cls in self.allowed_modules[mod]:
                    fqcn = f"{mod}.{cls}"
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.var_types[t.id] = fqcn
                elif mod.startswith("pychrono"):
                    self._report(f"Constructor not allowed: {mod}.{cls} (not in allowlist).")
        self.generic_visit(node)

    # --- calls: direct calls & instance methods ---
    def visit_Call(self, node: ast.Call):
        target = _call_target(node.func)
        if target:
            mod, name = target
            if mod in self.allowed_modules and name not in self.allowed_modules[mod]:
                self._report(f"Call to '{mod}.{name}' is not a whitelisted constructor/class.")
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            var = node.func.value.id
            meth = node.func.attr
            fqcn = self.var_types.get(var)
            if fqcn:
                if not self._method_exists(fqcn, meth):
                    self._report(f"Method '{meth}' not found on {fqcn}.")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        fqn = _attr_fqn(node)
        if fqn and fqn.startswith("pychrono") and "." in fqn:
            mod, name = fqn.rsplit(".", 1)
            if mod in self.allowed_modules and name and name[0].isupper():
                if name not in self.allowed_modules[mod]:
                    self._report(f"Access to '{fqn}' is not allowed (class not in allowlist).")
        self.generic_visit(node)

    # --- reflection ---
    def _method_exists(self, fqcn: str, meth: str) -> bool:
        if fqcn in self._method_cache:
            return meth in self._method_cache[fqcn]
        try:
            mod, cls = fqcn.rsplit(".", 1)
            m = self._imports.get(mod)
            if not m: return True  # if we cannot reflect here, be lenient
            cobj = getattr(m, cls)
            self._method_cache[fqcn] = {n for n in dir(cobj) if not n.startswith("_")}
            return meth in self._method_cache[fqcn]
        except Exception:
            return True  # lenient if reflection fails

def validate_code(code: str, allowlist_path: str = "allowlist.json"):
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"SyntaxError: {e}"]
    allow = load_allowlist(allowlist_path)
    v = AllowlistValidator(allow)
    v.visit(tree)
    return v.errors

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("usage: python allowlist_enforcer.py <file.py> [allowlist.json]")
        sys.exit(2)
    code = open(sys.argv[1], "r", encoding="utf-8").read()
    errs = validate_code(code, sys.argv[2] if len(sys.argv) > 2 else "allowlist.json")
    print(json.dumps({"ok": not bool(errs), "errors": errs}, indent=2))
    sys.exit(0 if not errs else 2)
