"""ValGap core engine — AST-based validation gap detection for Pydantic models."""
import ast
import json
from dataclasses import dataclass, field as dc_field
from typing import List, Optional, Any

PAYLOADS = {
    "xss": ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
    "sqli": ["' OR 1=1 --", "'; DROP TABLE users;--"],
    "ssti": ["{{7*7}}", "${7*7}"],
    "path_trav": ["../../etc/passwd", "..\\..\\windows\\system32"],
    "unicode": ["\u202eabc", "\x00", "\ufeff"],
    "overflow": ["A" * 10000],
    "numbers": [0, -1, 2**31, -(2**31), 1e308],
}
SEMANTIC_KEYS = {
    "email": ["email", "mail"], "url": ["url", "uri", "link", "href"],
    "path": ["path", "file", "dir"], "phone": ["phone", "tel", "mobile"],
    "html": ["html", "markup"], "sql": ["query", "sql", "where_clause"],
}
SEMANTIC_PAYLOADS = {
    "email": "sqli", "url": "ssti", "path": "path_trav",
    "html": "xss", "sql": "sqli", "phone": "overflow",
}


@dataclass
class FieldInfo:
    name: str
    type_str: str
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    gt: Optional[float] = None
    ge: Optional[float] = None
    lt: Optional[float] = None
    le: Optional[float] = None
    semantic: Optional[str] = None


@dataclass
class Gap:
    model: str
    field: str
    gap_type: str
    severity: str
    description: str
    samples: List[Any] = dc_field(default_factory=list)


def _type_str(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return f"{_type_str(node.value)}[{_type_str(node.slice)}]"
    return "unknown"


def _semantic(name: str) -> Optional[str]:
    low = name.lower()
    for sem, keys in SEMANTIC_KEYS.items():
        if any(k in low for k in keys):
            return sem
    return None


def _extract_fields(cls: ast.ClassDef) -> List[FieldInfo]:
    fields = []
    for node in cls.body:
        if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
            continue
        fi = FieldInfo(name=node.target.id, type_str=_type_str(node.annotation))
        fi.semantic = _semantic(fi.name)
        if node.value and isinstance(node.value, ast.Call):
            fn = getattr(node.value.func, "id", getattr(node.value.func, "attr", ""))
            if fn == "Field":
                for kw in node.value.keywords:
                    v = getattr(kw.value, "value", None)
                    attr_map = {"max_length": "max_length", "regex": "pattern",
                                "pattern": "pattern", "gt": "gt", "ge": "ge",
                                "lt": "lt", "le": "le"}
                    if kw.arg in attr_map and v is not None:
                        setattr(fi, attr_map[kw.arg], v)
        fields.append(fi)
    return fields


def _find_gaps(model: str, fields: List[FieldInfo]) -> List[Gap]:
    gaps = []
    for f in fields:
        base = f.type_str.replace("Optional[", "").rstrip("]")
        is_str = base == "str"
        is_num = base in ("int", "float")
        if is_str and f.max_length is None:
            gaps.append(Gap(model, f.name, "no_max_length", "high",
                f"String '{f.name}' has no max_length — DoS via huge input possible",
                PAYLOADS["overflow"] + PAYLOADS["xss"]))
        if f.semantic and not f.pattern:
            pk = SEMANTIC_PAYLOADS.get(f.semantic, "unicode")
            gaps.append(Gap(model, f.name, "no_semantic_validation", "high",
                f"'{f.name}' looks like {f.semantic} but lacks pattern validation",
                PAYLOADS.get(pk, PAYLOADS["unicode"])))
        if is_num and all(x is None for x in [f.gt, f.ge, f.lt, f.le]):
            gaps.append(Gap(model, f.name, "no_range_check", "medium",
                f"Numeric '{f.name}' has no range — allows overflow/special values",
                PAYLOADS["numbers"]))
        if is_str:
            gaps.append(Gap(model, f.name, "no_unicode_filter", "medium",
                f"String '{f.name}' allows Unicode control chars (null, RTL, BOM)",
                PAYLOADS["unicode"]))
    return gaps


def analyze_source(source: str, filename: str = "<input>") -> List[Gap]:
    tree = ast.parse(source, filename)
    gaps = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = [getattr(b, "id", getattr(b, "attr", "")) for b in node.bases]
            if "BaseModel" in bases:
                gaps.extend(_find_gaps(node.name, _extract_fields(node)))
    return gaps


def to_sarif(gaps: List[Gap], uri: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ValGap", "version": "0.1.0"}},
            "results": [{"ruleId": g.gap_type,
                "level": "error" if g.severity == "high" else "warning",
                "message": {"text": g.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": {"model": g.model, "field": g.field,
                    "samples": [str(s)[:80] for s in g.samples[:5]]},
            } for g in gaps]}],
    }
