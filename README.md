# 🔍 ValGap — Validation Gap Detector

ValGap statically analyzes your Pydantic models to find missing, incomplete, or bypassable
input validation — then generates adversarial samples that exploit each gap.

## Why?

Every `str` field without `max_length` is a DoS vector. Every `email` field without a
pattern is an injection surface. ValGap finds these gaps before attackers do.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a file
python main.py app/models.py

# Scan a directory, only high severity
python main.py src/ --min-severity high

# Output SARIF for GitHub Code Scanning
python main.py app/ --format sarif > results.sarif

# Output JSON
python main.py models.py --format json
```

## Example Output

```
🔍 Found 4 validation gap(s):

  🔴 models.py → UserCreate.email
     [no_semantic_validation] 'email' looks like email but lacks pattern validation
     Samples: "' OR 1=1 --", "'; DROP TABLE users;--"

  🔴 models.py → UserCreate.username
     [no_max_length] String 'username' has no max_length — DoS via huge input possible
     Samples: 'AAAAAAA...(10000 chars)', '<script>alert(1)</script>'
```

## What It Detects

| Gap Type | Severity | Description |
|---|---|---|
| `no_max_length` | 🔴 High | String field without length limit |
| `no_semantic_validation` | 🔴 High | Email/URL/path field without pattern |
| `no_range_check` | 🟡 Medium | Numeric field without bounds |
| `no_unicode_filter` | 🟡 Medium | String accepting control characters |

## Run Tests

```bash
pytest test_valgap.py -v
```

## CI Integration

Add to `.github/workflows/ci.yml` — see included config.
ValGap exits with code 1 when gaps are found, failing the pipeline.

## License

MIT
