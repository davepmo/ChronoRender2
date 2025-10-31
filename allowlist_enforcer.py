# allowlist_enforcer.py
# -----------------------------------------------------------------------------
# PyChrono 9.0.1 Code Gate: validate & (optionally) auto-rewrite user scripts
#
# What it enforces:
#   - Only classes explicitly listed in allowlist.json under pychrono.* modules
#     may be constructed (e.g., chrono.ChBodyEasyCylinder(...)).
#   - If overloads exist in allowlist.json, constructor arg-count must match one
#     of the allowed windows (len(args)-defaults ... len(args)).
#   - Non-PyChrono imports/usages are ignored (per user request).
#   - Legacy -> current rename map is applied before validation.
#   - A small attribute denylist blocks removed/legacy methods with suggestions
#     (e.g., AddTypicalCamera, SetYoungModulus on NSC).
#
# What it DOES NOT do:
#   - It does not attempt deep type-flow to know the runtime class behind a var.
#     Attribute checks are name-based and conservative by design.
#
# Inputs:
#   - allowlist.json: {
#       "enums": [...],
#       "modules": {"pychrono.core":[...], "pychrono.vehicle":[...], ...},
#       "overloads": { "pychrono.core.ClassName":[{"args":[...],"defaults":N}, ...] }
#     }
#   - optional legacy_map.json: {
#       "classes": { "OldName":"NewName", "ChLinkSpringDamper":"ChLinkTSDA", ... },
#       "attributes": { "AddTypicalCamera":"AddCamera" }
#     }
#
# Exposed API:
#   validate_code(source:str, allowlist_path:str) -> List[str]  # errors only
#   rewrite_and_validate(source:str, allowlist_path:str, legacy_map_path:str|None)
#       -> (rewritten_source:str, errors:List[str], applied_renames:List[str])
#
# -----------------------------------------------------------------------------

from __future__ import annotations
import ast, json, os, re
from typing import Dict, List, Tuple, Optional, Set

# -----------------------------
# Small built-in legacy helpers
# -----------------------------
# Extend these or supply legacy_map.json next to allowlist.json.
_BUILTIN_CLASS_RENAMES = {
    # Example legacy → current:
    # "ChLinkSpringDamper": "ChLinkTSDA",
    # Add your known aliases here:
}
_BUILTIN_ATTR_RENAMES = {
    # Example: Irrlicht API changes
    # "AddTypicalCamera": "AddCamera",
}

# Attribute names known to be invalid/removed in 9.0.1 or misleading in NSC:
# (name-only check; provide human-action suggestion)
_DENY_ATTR_WITH_HINT = {
    "AddTypicalCamera": "Removed in 9.x. Use vis.AddCamera(pos, target) on ChVisualSystemIrrlicht.",
    "SetYoungModulus": "Not available on ChContactMaterialNSC. Use ChContactMaterialSMC.SetYoungModulus(...) or remove for NSC.",
}

# -----------------------------
# Helpers for reading allowlist
# -----------------------------

class Allowlist:
    def __init__(self, data: Dict):
        self.data = data
        self.modules: Dict[str, Set[str]] = {
            m: set(v) for m, v in (data.get("modules") or {}).items()
        }
        self.overloads: Dict[str, List[Dict]] = data.get("overloads") or {}

    def is_allowed_class(self, fqname: str) -> bool:
        # fqname like "pychrono.core.ChBodyEasyCylinder"
        mod, _, cls = fqname.rpartition(".")
        allowed = cls and mod in self.modules and cls in self.modules[mod]
        return bool(allowed)

    def ctor_windows(self, fqname: str) -> List[Tuple[int, int]]:
        """Return list of (min_args, max_args) windows for ctor arg-count checks."""
        ols = self.overloads.get(fqname, [])
        wins: List[Tuple[int, int]] = []
        for o in ols:
            args = o.get("args", [])
            defaults = int(o.get("defaults", 0))
            n = len(args)
            min_n = n - defaults
            max_n = n
            if min_n < 0:
                min_n = 0
            wins.append((min_n, max_n))
        return wins


def load_allowlist(path: str) -> Allowlist:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Allowlist(data)


def load_legacy_map(path: Optional[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    classes = dict(_BUILTIN_CLASS_RENAMES)
    attrs = dict(_BUILTIN_ATTR_RENAMES)
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                m = json.load(f)
            classes.update(m.get("classes", {}))
            attrs.update(m.get("attributes", {}))
        except Exception:
            pass
    return classes, attrs

# -----------------------------
# AST inspection utilities
# -----------------------------

def _is_pychrono_alias(node: ast.AST, aliases: Dict[str, str]) -> bool:
    """Return True if node is a Name that is an alias to a pychrono.* import."""
    return isinstance(node, ast.Name) and node.id in aliases

def _attr_chain(root: ast.AST) -> List[str]:
    """
    Turn a.Attribute.Attribute into ["a", "Attribute", "Attribute"].
    If not resolvable, return [].
    """
    out: List[str] = []
    cur = root
    while isinstance(cur, ast.Attribute):
        out.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        out.append(cur.id)
        out.reverse()
        return out
    return []

def _guess_module_from_alias(alias_target: str, alias_map: Dict[str, str]) -> Optional[str]:
    """
    Given the first identifier in a chain, see which pychrono module it belongs to.
    alias_map: {'chrono':'pychrono.core', 'veh':'pychrono.vehicle', ...}
    """
    return alias_map.get(alias_target)

def _fqname_from_chain(chain: List[str], alias_map: Dict[str, str]) -> Optional[str]:
    """
    Convert something like ["chrono","ChBodyEasyCylinder"] to "pychrono.core.ChBodyEasyCylinder",
    or ["veh","M113"] -> "pychrono.vehicle.M113".
    """
    if not chain:
        return None
    base = chain[0]
    mod = _guess_module_from_alias(base, alias_map)
    if not mod:
        return None
    if len(chain) == 1:
        return mod
    return mod + "." + ".".join(chain[1:])

# -----------------------------
# Rewriter (legacy → current)
# -----------------------------

class LegacyRewriter(ast.NodeTransformer):
    def __init__(self, class_renames: Dict[str, str], attr_renames: Dict[str, str]):
        self.class_renames = class_renames
        self.attr_renames = attr_renames
        self.applied: List[str] = []

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        self.generic_visit(node)
        # Rename attribute names if needed
        if node.attr in self.attr_renames:
            new = self.attr_renames[node.attr]
            if new != node.attr:
                self.applied.append(f"attribute: {node.attr} -> {new}")
                node.attr = new
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        # Safe to rename bare identifiers (e.g., class names in direct use)
        if node.id in self.class_renames:
            new = self.class_renames[node.id]
            if new != node.id:
                self.applied.append(f"class: {node.id} -> {new}")
                node.id = new
        return node

# -----------------------------
# Validator (constructors + deny attrs)
# -----------------------------

class PyChronoValidator(ast.NodeVisitor):
    def __init__(self, allow: Allowlist, alias_map: Dict[str, str]):
        self.allow = allow
        self.alias_map = alias_map
        self.errors: List[str] = []

    def visit_Call(self, node: ast.Call):
        # (1) Attribute denylist by name (no deep type info; conservative)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in _DENY_ATTR_WITH_HINT:
                self.errors.append(
                    f"Use of removed/denied attribute '{node.func.attr}'. Hint: {_DENY_ATTR_WITH_HINT[node.func.attr]}"
                )

        # (2) Constructor checks only for pychrono.* classes in allowlist
        # Attempt to recover a fully-qualified name from alias + attribute chain
        chain = _attr_chain(node.func) if isinstance(node.func, ast.Attribute) else []
        if chain:
            fq = _fqname_from_chain(chain, self.alias_map)

            # If it looks like a class ctor (module + ClassName), validate
            if fq and fq.count(".") >= 2:
                if not self.allow.is_allowed_class(fq):
                    self.errors.append(f"Constructor not allowed: '{fq}'. Not in allowlist.")
                else:
                    # If overloads exist, validate arg-count window
                    wins = self.allow.ctor_windows(fq)
                    if wins:
                        argc = len(node.args) + sum(1 for k in node.keywords if k.arg is not None)
                        ok = any(lo <= argc <= hi for (lo, hi) in wins)
                        if not ok:
                            self.errors.append(
                                f"Constructor mismatch for {fq} with {argc} args. "
                                f"Allowed arg windows: {wins}"
                            )

        self.generic_visit(node)

# -----------------------------
# Public API
# -----------------------------

def _collect_aliases(tree: ast.AST) -> Dict[str, str]:
    """
    Map local aliases to exact pychrono modules:
      import pychrono as chrono             -> {'chrono': 'pychrono.core'}  (default core)
      import pychrono.core as chrono        -> {'chrono': 'pychrono.core'}
      import pychrono.vehicle as veh        -> {'veh': 'pychrono.vehicle'}
      from pychrono import vehicle as veh   -> {'veh': 'pychrono.vehicle'}
    """
    alias_map: Dict[str, str] = {}

    class _A(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import):
            for n in node.names:
                if n.name == "pychrono":
                    # Default alias points to core in end-user scripts
                    asname = n.asname or "pychrono"
                    alias_map[asname] = "pychrono.core"
        def visit_ImportFrom(self, node: ast.ImportFrom):
            if node.module == "pychrono":
                for n in node.names:
                    if n.name in ("core", "vehicle", "irrlicht", "fea"):
                        asname = n.asname or n.name
                        alias_map[asname] = f"pychrono.{n.name}"
            elif node.module in ("pychrono.core", "pychrono.vehicle", "pychrono.irrlicht", "pychrono.fea"):
                # from pychrono.core import something as X
                asname = None
                for n in node.names:
                    asname = n.asname or n.name
                    # These become local names; we still map to the parent module
                    parent = node.module
                    alias_map[asname] = parent

    _A().visit(tree)
    # Common community alias
    if "chrono" not in alias_map:
        # Many examples use 'import pychrono as chrono'
        # Make a soft assumption that 'chrono' means core when used.
        alias_map["chrono"] = "pychrono.core"
    return alias_map


def rewrite_and_validate(
    source: str,
    allowlist_path: str,
    legacy_map_path: Optional[str] = None
) -> Tuple[str, List[str], List[str]]:
    """
    (1) Apply legacy renames (classes + attributes).
    (2) Validate ctor usage and denylisted attributes.
    Returns: (rewritten_source, errors, applied_renames)
    """
    allow = load_allowlist(allowlist_path)
    cls_ren, attr_ren = load_legacy_map(legacy_map_path)

    # Parse
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return source, [f"SyntaxError: {e.msg} at line {e.lineno}"], []

    # Rewriting pass
    rewriter = LegacyRewriter(cls_ren, attr_ren)
    new_tree = rewriter.visit(tree)
    ast.fix_missing_locations(new_tree)
    rewritten = source
    if rewriter.applied:
        try:
            import astor  # optional; nicer roundtrip if present
            rewritten = astor.to_source(new_tree)
        except Exception:
            # Fallback: use built-in unparse (Py3.9+)
            try:
                rewritten = ast.unparse(new_tree)  # type: ignore[attr-defined]
            except Exception:
                # Last resort: do name-based text replacements (best-effort)
                rewritten = source
                for old, new in cls_ren.items():
                    rewritten = re.sub(rf"\b{re.escape(old)}\b", new, rewritten)
                for old, new in attr_ren.items():
                    rewritten = re.sub(rf"\.{re.escape(old)}\b", f".{new}", rewritten)

    # Validation pass
    try:
        tree2 = ast.parse(rewritten)
    except SyntaxError as e:
        return rewritten, [f"SyntaxError after rewrite: {e.msg} at line {e.lineno}"], rewriter.applied

    alias_map = _collect_aliases(tree2)
    validator = PyChronoValidator(allow, alias_map)
    validator.visit(tree2)

    return rewritten, validator.errors, rewriter.applied


def validate_code(source: str, allowlist_path: str) -> List[str]:
    """For servers that only want errors (no rewrite)."""
    _rew, errs, _applied = rewrite_and_validate(source, allowlist_path, None)
    return errs
