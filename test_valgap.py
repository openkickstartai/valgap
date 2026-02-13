"""Tests for ValGap validation gap analyzer."""
from valgap_analyzer import analyze_source, to_sarif

VULNERABLE = '''
from pydantic import BaseModel, Field
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: str
    age: int
    bio: str = Field(max_length=500)
    website_url: Optional[str] = None
'''

SAFE = '''
from pydantic import BaseModel, Field

class SafeInput(BaseModel):
    name: str = Field(max_length=100, pattern=r"^[a-zA-Z ]+$")
    age: int = Field(ge=0, le=150)
'''


def test_detects_missing_max_length():
    gaps = analyze_source(VULNERABLE)
    flagged = {g.field for g in gaps if g.gap_type == "no_max_length"}
    assert "username" in flagged
    assert "email" in flagged
    assert "website_url" in flagged
    assert "bio" not in flagged  # bio has max_length=500


def test_detects_missing_semantic_validation():
    gaps = analyze_source(VULNERABLE)
    flagged = {g.field for g in gaps if g.gap_type == "no_semantic_validation"}
    assert "email" in flagged, "email field needs pattern validation"
    assert "website_url" in flagged, "URL field needs pattern validation"
    assert "username" not in flagged, "username has no known semantic type"


def test_detects_missing_range_check():
    gaps = analyze_source(VULNERABLE)
    range_gaps = [g for g in gaps if g.gap_type == "no_range_check"]
    assert any(g.field == "age" for g in range_gaps)
    assert not any(g.field == "username" for g in range_gaps)


def test_safe_model_no_high_severity():
    gaps = analyze_source(SAFE)
    high = [g for g in gaps if g.severity == "high"]
    assert len(high) == 0, f"Expected 0 high-severity gaps, got {len(high)}"


def test_adversarial_samples_present():
    gaps = analyze_source(VULNERABLE)
    assert len(gaps) > 0
    for g in gaps:
        assert len(g.samples) > 0, f"{g.gap_type} on {g.field} must have samples"


def test_sarif_output_valid():
    gaps = analyze_source(VULNERABLE)
    sarif = to_sarif(gaps, "models.py")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "ValGap"
    assert len(sarif["runs"][0]["results"]) == len(gaps)
    for r in sarif["runs"][0]["results"]:
        assert r["level"] in ("error", "warning")
        assert "ruleId" in r


def test_no_models_yields_no_gaps():
    source = "x = 42\ndef greet(name): return f'hi {name}'\n"
    assert analyze_source(source) == []


def test_unicode_filter_covers_all_strings():
    gaps = analyze_source(VULNERABLE)
    unicode_flagged = {g.field for g in gaps if g.gap_type == "no_unicode_filter"}
    assert unicode_flagged == {"username", "email", "bio", "website_url"}
