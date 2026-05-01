"""
JSPECTER Secrets Discovery Engine
Detects API keys, tokens, credentials, and sensitive data in JS.
Inspired by truffleHog's approach: regex signatures + entropy analysis.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .utils import Icon, RED, YELLOW, CYAN, DIM, RESET, GREEN, ORANGE, logger, shannon_entropy, truncate

# ─── Secret Signature Definitions ────────────────────────────────────────────

@dataclass
class SecretSignature:
    name: str
    pattern: re.Pattern
    severity: str = "HIGH"
    description: str = ""
    example: str = ""


# Comprehensive secret patterns
SECRET_SIGNATURES: List[SecretSignature] = [
    # Cloud Providers
    SecretSignature(
        name="AWS Access Key ID",
        pattern=re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])', re.I),
        severity="CRITICAL",
        description="Amazon Web Services Access Key ID detected.",
        example="AKIAIOSFODNN7EXAMPLE",
    ),
    SecretSignature(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r'(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|aws_secret)["\s]*[:=]["\s]*([A-Za-z0-9/+=]{40})',
            re.I
        ),
        severity="CRITICAL",
        description="AWS Secret Access Key found in JavaScript.",
    ),
    SecretSignature(
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        severity="HIGH",
        description="Google Cloud/Maps/Firebase API key detected.",
    ),
    SecretSignature(
        name="Google OAuth Client Secret",
        pattern=re.compile(r'GOCSPX-[0-9A-Za-z\-_]{28}'),
        severity="HIGH",
        description="Google OAuth 2.0 client secret.",
    ),
    SecretSignature(
        name="Firebase API Key",
        pattern=re.compile(r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z\-_]{35})"'),
        severity="HIGH",
        description="Firebase project API key exposed in JS config.",
    ),
    SecretSignature(
        name="Firebase Database URL",
        pattern=re.compile(r'"databaseURL"\s*:\s*"(https://[^"]+\.firebaseio\.com)"'),
        severity="MEDIUM",
        description="Firebase realtime database URL exposed.",
    ),
    # Payment Processors
    SecretSignature(
        name="Stripe Secret Key",
        pattern=re.compile(r'sk_(?:live|test)_[0-9a-zA-Z]{24,}'),
        severity="CRITICAL",
        description="Stripe secret key can be used to charge customers.",
    ),
    SecretSignature(
        name="Stripe Publishable Key",
        pattern=re.compile(r'pk_(?:live|test)_[0-9a-zA-Z]{24,}'),
        severity="MEDIUM",
        description="Stripe publishable key exposed (lower risk but confirms Stripe usage).",
    ),
    SecretSignature(
        name="PayPal / Braintree Token",
        pattern=re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
        severity="CRITICAL",
        description="Braintree production access token.",
    ),
    SecretSignature(
        name="Square Access Token",
        pattern=re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
        severity="HIGH",
        description="Square payment access token.",
    ),
    # Auth & Identity
    SecretSignature(
        name="JSON Web Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        severity="HIGH",
        description="JWT token exposed in JavaScript source.",
    ),
    SecretSignature(
        name="Bearer Token",
        pattern=re.compile(r'[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*)'),
        severity="HIGH",
        description="HTTP Bearer token hardcoded in source.",
    ),
    SecretSignature(
        name="Basic Auth Header",
        pattern=re.compile(r'[Bb]asic\s+([A-Za-z0-9+/]{20,}={0,2})'),
        severity="HIGH",
        description="HTTP Basic auth credentials (Base64 encoded).",
    ),
    SecretSignature(
        name="GitHub Personal Access Token",
        pattern=re.compile(r'ghp_[0-9A-Za-z]{36}'),
        severity="CRITICAL",
        description="GitHub Personal Access Token — may expose code repositories.",
    ),
    SecretSignature(
        name="GitHub OAuth Token",
        pattern=re.compile(r'gho_[0-9A-Za-z]{36}'),
        severity="HIGH",
        description="GitHub OAuth token.",
    ),
    SecretSignature(
        name="GitLab Personal Token",
        pattern=re.compile(r'glpat-[0-9A-Za-z\-_]{20}'),
        severity="HIGH",
        description="GitLab personal access token.",
    ),
    SecretSignature(
        name="Slack Token",
        pattern=re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
        severity="HIGH",
        description="Slack API or bot token.",
    ),
    SecretSignature(
        name="Slack Webhook",
        pattern=re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+'),
        severity="MEDIUM",
        description="Slack incoming webhook URL — can post messages to workspace.",
    ),
    # Communication
    SecretSignature(
        name="Twilio Account SID",
        pattern=re.compile(r'AC[0-9a-fA-F]{32}'),
        severity="HIGH",
        description="Twilio Account SID.",
    ),
    SecretSignature(
        name="Twilio Auth Token",
        pattern=re.compile(r'(?:twilio[_\-.]?(?:auth[_\-.]?)?token)["\s]*[:=]["\s]*([0-9a-f]{32})', re.I),
        severity="CRITICAL",
        description="Twilio auth token — full account access.",
    ),
    SecretSignature(
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[A-Za-z0-9\-._]{22}\.[A-Za-z0-9\-._]{43}'),
        severity="HIGH",
        description="SendGrid email delivery API key.",
    ),
    SecretSignature(
        name="Mailchimp API Key",
        pattern=re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
        severity="HIGH",
        description="Mailchimp API key with datacenter suffix.",
    ),
    # Infrastructure
    SecretSignature(
        name="Heroku API Key",
        pattern=re.compile(
            r'(?:heroku[_\s]+(?:api[_\s]+)?(?:key|token)|HEROKU_API_KEY)'
            r'[^a-zA-Z0-9]{0,20}'
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            re.I
        ),
        severity="HIGH",
        description="Heroku API key found in context of heroku variable name.",
    ),
    SecretSignature(
        name="DigitalOcean Token",
        pattern=re.compile(r'(?:do_|digitalocean[_.](?:pat|token))["\s]*[:=]["\s]*([A-Za-z0-9]{64})', re.I),
        severity="HIGH",
        description="DigitalOcean personal access token.",
    ),
    SecretSignature(
        name="Azure Storage Key",
        pattern=re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})'),
        severity="CRITICAL",
        description="Azure Storage Account connection string.",
    ),
    # Generic / High-Entropy
    SecretSignature(
        name="Generic Secret Variable",
        pattern=re.compile(
            r'(?:secret|password|passwd|pwd|api_key|apikey|api_secret|auth_token|'
            r'access_token|private_key|client_secret|encryption_key)["\s]*[:=]["\s]*'
            r'(["\']?)([A-Za-z0-9/+=]{16,})\1',
            re.I,
        ),
        severity="MEDIUM",
        description="Generic secret or credential variable assignment.",
    ),
    SecretSignature(
        name="Private Key Block",
        pattern=re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        severity="CRITICAL",
        description="PEM private key block found in JavaScript.",
    ),
    SecretSignature(
        name="Mapbox Token",
        pattern=re.compile(r'pk\.eyJ1Ijoiey[0-9A-Za-z\-._]+'),
        severity="MEDIUM",
        description="Mapbox public access token.",
    ),
    SecretSignature(
        name="Shopify Token",
        pattern=re.compile(r'shpat_[0-9a-fA-F]{32}'),
        severity="HIGH",
        description="Shopify Admin API access token.",
    ),
    SecretSignature(
        name="NPM Auth Token",
        pattern=re.compile(r'//registry\.npmjs\.org/:_authToken\s*=\s*([A-Za-z0-9\-_]+)'),
        severity="HIGH",
        description="NPM registry auth token found.",
    ),
    SecretSignature(
        name="Telegram Bot Token",
        pattern=re.compile(r'\d{8,10}:[A-Za-z0-9_\-]{35}'),
        severity="HIGH",
        description="Telegram bot API token.",
    ),
    SecretSignature(
        name="Discord Bot Token",
        pattern=re.compile(r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}'),
        severity="HIGH",
        description="Discord bot token.",
    ),
]

# ─── Entropy Thresholds ───────────────────────────────────────────────────────
# Strings above these thresholds near sensitive keywords are flagged
ENTROPY_THRESHOLD_BASE64: float = 4.5
ENTROPY_THRESHOLD_HEX:    float = 3.5
HIGH_ENTROPY_MIN_LEN:     int = 20
HIGH_ENTROPY_MAX_LEN:     int = 100

_RE_ENTROPY_CONTEXT = re.compile(
    r'(?:key|token|secret|password|credential|auth)["\s]*[:=]["\s]*'
    r'["\']([A-Za-z0-9+/=_\-]{' + str(HIGH_ENTROPY_MIN_LEN) + r',' + str(HIGH_ENTROPY_MAX_LEN) + r'})["\']',
    re.I,
)

_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS    = set("ABCDEFabcdef0123456789")


@dataclass
class SecretFinding:
    """A discovered secret or credential."""
    secret_type: str
    matched_value: str
    source_js: str
    severity: str
    description: str
    line_context: str = ""
    entropy: float = 0.0
    detection_method: str = "regex"

    def redacted_value(self, chars: int = 6) -> str:
        """Return partially redacted value for safe display."""
        v = self.matched_value.strip("\"'`")
        if len(v) <= chars * 2:
            return "*" * len(v)
        return v[:chars] + "*" * (len(v) - chars * 2) + v[-chars:]


# ─── Secrets Engine ───────────────────────────────────────────────────────────

class SecretsEngine:
    """
    Advanced secret and credential detection engine.
    Combines regex signatures with entropy analysis.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def _extract_line_context(self, content: str, pos: int, window: int = 60) -> str:
        """Extract surrounding code context for a match position."""
        start = max(0, pos - window)
        end   = min(len(content), pos + window)
        line = content[start:end].replace("\n", " ").strip()
        return truncate(line, 120)

    def _scan_signatures(self, content: str, source: str) -> List[SecretFinding]:
        """Run all regex signatures against content."""
        findings: List[SecretFinding] = []
        seen: set = set()

        for sig in SECRET_SIGNATURES:
            for match in sig.pattern.finditer(content):
                # Get the most meaningful group
                value = ""
                for i in range(len(match.groups()), 0, -1):
                    grp = match.group(i)
                    if grp and len(grp) >= 8:
                        value = grp
                        break
                if not value:
                    value = match.group(0)

                # Deduplicate
                key = f"{sig.name}:{value[:20]}"
                if key in seen:
                    continue
                seen.add(key)

                context = self._extract_line_context(content, match.start())
                ent = shannon_entropy(value)

                findings.append(SecretFinding(
                    secret_type=sig.name,
                    matched_value=value,
                    source_js=source,
                    severity=sig.severity,
                    description=sig.description,
                    line_context=context,
                    entropy=ent,
                    detection_method="regex",
                ))

        return findings

    def _scan_entropy(self, content: str, source: str) -> List[SecretFinding]:
        """
        Find high-entropy strings near sensitive variable names.
        Inspired by truffleHog's entropy approach.
        """
        findings: List[SecretFinding] = []
        seen: set = set()

        for match in _RE_ENTROPY_CONTEXT.finditer(content):
            candidate = match.group(1)
            if not candidate:
                continue

            # Determine character set and threshold
            is_hex    = all(c in _HEX_CHARS for c in candidate)
            is_b64    = all(c in _BASE64_CHARS for c in candidate)
            threshold = ENTROPY_THRESHOLD_HEX if is_hex else ENTROPY_THRESHOLD_BASE64

            ent = shannon_entropy(candidate)
            if ent < threshold:
                continue

            key = f"entropy:{candidate[:16]}"
            if key in seen:
                continue
            seen.add(key)

            context = self._extract_line_context(content, match.start())
            char_type = "hex" if is_hex else "base64-like"

            findings.append(SecretFinding(
                secret_type=f"High-Entropy String ({char_type})",
                matched_value=candidate,
                source_js=source,
                severity="MEDIUM",
                description=(
                    f"High-entropy {char_type} string ({ent:.2f} bits/char) found near "
                    f"sensitive keyword. May be a hardcoded secret."
                ),
                line_context=context,
                entropy=ent,
                detection_method="entropy",
            ))

        return findings

    def scan_content(self, content: str, source: str) -> List[SecretFinding]:
        """Scan a single JS string for secrets."""
        findings = self._scan_signatures(content, source)
        findings += self._scan_entropy(content, source)
        return findings

    def scan_all(
        self,
        js_contents: Dict[str, str],
        inline_scripts: List[str],
    ) -> List[SecretFinding]:
        """
        Scan all JS files and inline scripts for secrets.

        Args:
            js_contents: dict of {url: js_source}
            inline_scripts: list of inline script strings

        Returns:
            List of SecretFinding objects
        """
        all_findings: List[SecretFinding] = []

        for url, content in js_contents.items():
            findings = self.scan_content(content, url)
            all_findings.extend(findings)
            if self.verbose and findings:
                for f in findings:
                    logger.debug(
                        f"  Secret in {truncate(url, 50)}: "
                        f"{f.secret_type} [{f.severity}]"
                    )

        for i, inline in enumerate(inline_scripts):
            source = f"<inline:{i}>"
            findings = self.scan_content(inline, source)
            all_findings.extend(findings)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        # Print summary
        if all_findings:
            print_summary = {
                "CRITICAL": sum(1 for f in all_findings if f.severity == "CRITICAL"),
                "HIGH":     sum(1 for f in all_findings if f.severity == "HIGH"),
                "MEDIUM":   sum(1 for f in all_findings if f.severity == "MEDIUM"),
            }
            icon = Icon.SECRET if all_findings else Icon.SUCCESS
            print(
                f"\n  {icon} {RED}Secrets found:{RESET} "
                f"CRITICAL={print_summary['CRITICAL']} "
                f"HIGH={print_summary['HIGH']} "
                f"MEDIUM={print_summary['MEDIUM']}"
            )
        else:
            print(f"\n  {Icon.SUCCESS} {GREEN}No secrets detected.{RESET}")

        return all_findings
