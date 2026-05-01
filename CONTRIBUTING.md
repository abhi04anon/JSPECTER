# Contributing to JSPECTER

Thank you for helping make JSPECTER more accurate and more useful for the bug bounty community.

## Reporting False Positives

If JSPECTER flags something incorrectly, please open a [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml). False positives are taken seriously — every detection rule should have near-zero FP rate.

## Adding CVE Detection Rules

### Endpoint pattern (cve_engine.py → ENDPOINT_CVE_MAP)

```python
{
    "pattern": "/your-endpoint",   # substring matched against endpoint path
    "cve": "CVE-YYYY-NNNNN",
    "issue": "Short Issue Name",
    "severity": "HIGH",            # CRITICAL | HIGH | MEDIUM | LOW
    "cvss": 7.5,                   # numeric CVSS score
    "description": "One sentence explaining the vulnerability.",
    "hint": (
        "Step 1: ...\n"
        "Step 2: ..."
    ),
    "param": "",                   # triggering param name if applicable
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-..."],
},
```

**Before submitting:** test the pattern against at least 3 targets that do NOT have the vulnerability and confirm zero false positives.

### Parameter pattern (cve_engine.py → PARAM_CVE_MAP)

Same structure, but `"params"` is a list of parameter names that trigger the rule.

Keep parameter lists **narrow** — do not add `"data"`, `"body"`, `"content"` unless you have confirmed these are specifically associated with the vulnerability class.

### Secret signature (secrets_engine.py → SECRET_SIGNATURES)

```python
SecretSignature(
    name="Service Name API Key",
    pattern=re.compile(r'service-prefix-[A-Za-z0-9]{32}'),
    severity="HIGH",
    description="ServiceName API key allows full account access.",
),
```

The regex must be specific enough to match real keys without matching test/placeholder values. Include at least one real example key format in a comment.

## React2Shell Scanner

The React2Shell scanner (`react2shell.py`) uses a weighted evidence model. Any change to detection signals must preserve the zero-false-positive guarantee:

- **CONFIRMED** signals (weight 3): Only add if the pattern appears **exclusively** in `react-server-dom-*` compiled bundles and cannot appear in any other library or user code.
- **STRONG** signals (weight 2): Highly specific — must not appear in plain Next.js apps without RSC server functions.
- **SUPPORTING** signals (weight 1): OK to be less specific, but **cannot trigger a finding alone**.

The `_compute_verdict()` function requires `rsc_runtime_confirmed=True` before setting `vulnerable=True`. Do not change this requirement.

## Code Style

- Format with `black --line-length 100`
- Type hints on all public functions
- Module-level docstrings explaining purpose
- Comments explaining **why**, not just **what**

## Testing

```bash
pip install ".[dev]"
pytest tests/ -v --asyncio-mode=auto
```

## Disclosure Policy

Do not include real targets, credentials, or exploit payloads in PRs, issues, or commits.

For responsible disclosure of a vulnerability in JSPECTER itself, email the maintainers directly rather than opening a public issue.
