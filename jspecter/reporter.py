"""
JSPECTER Reporter Module
Generates JSON, HTML, and TXT output reports.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .cve_engine import CVEFinding
from .js_analyzer import EndpointFinding, JSAnalysisResult
from .secrets_engine import SecretFinding
from .tester import ProbeResult
from .utils import (
    Icon, BLUE, BOLD, CYAN, DIM, GREEN, MAGENTA, ORANGE, RED, RESET,
    WHITE, YELLOW, colorize_severity, safe_write, truncate, current_ts
)


# ─── Data Serializers ─────────────────────────────────────────────────────────

def _serialize_endpoint(ep: EndpointFinding) -> Dict:
    return {
        "url": ep.url,
        "source_js": ep.source_js,
        "type": ep.endpoint_type,
        "method": ep.method,
        "params": ep.params,
        "interesting": ep.interesting,
        "notes": ep.notes,
    }


def _serialize_secret(s: SecretFinding) -> Dict:
    return {
        "type": s.secret_type,
        "value_redacted": s.redacted_value(),
        "source": s.source_js,
        "severity": s.severity,
        "description": s.description,
        "entropy": round(s.entropy, 3),
        "detection_method": s.detection_method,
        "context": s.line_context,
    }


def _serialize_cve(c: CVEFinding) -> Dict:
    return {
        "cve_id": c.cve_id,
        "target_url": c.target_url,
        "endpoint_path": c.endpoint_path,
        "parameter": c.parameter,
        "issue_type": c.issue_type,
        "severity": c.severity,
        "cvss_score": c.cvss_score,
        "description": c.description,
        "hint": c.hint,
        "poc_steps": c.poc_steps,
        "source": c.source,
        "affected_library": c.affected_library,
        "affected_versions": c.affected_versions,
        "references": c.references,
    }


def _serialize_probe(p: ProbeResult) -> Dict:
    return {
        "url": p.url,
        "status_code": p.status_code,
        "content_type": p.content_type,
        "response_length": p.response_length,
        "redirect_url": p.redirect_url,
        "server": p.server_header,
        "interesting": p.interesting,
        "flags": p.flags,
        "severity": p.severity,
        "notes": p.notes,
    }


# ─── JSON Report ──────────────────────────────────────────────────────────────

def build_json_report(
    target: str,
    js_urls: List[str],
    js_analysis: JSAnalysisResult,
    secrets: List[SecretFinding],
    cves: List[CVEFinding],
    probes: List[ProbeResult],
    scan_meta: Dict,
) -> str:
    """Build full JSON report string."""
    report = {
        "meta": {
            "tool": "JSPECTER",
            "version": "1.0.0",
            "target": target,
            "timestamp": current_ts(),
            "duration_seconds": scan_meta.get("duration", 0),
            "scan_config": scan_meta.get("config", {}),
        },
        "summary": {
            "js_files_discovered": len(js_urls),
            "endpoints_extracted": len(js_analysis.endpoints),
            "interesting_endpoints": js_analysis.stats.get("interesting_endpoints", 0),
            "secrets_found": len(secrets),
            "cve_correlations": len(cves),
            "endpoints_probed": len(probes),
            "open_endpoints": sum(1 for p in probes if p.status_code == 200),
            "libraries_detected": len(js_analysis.libraries),
            "source_maps_exposed": len(js_analysis.source_maps),
            "overall_risk": scan_meta.get("overall_risk", "NONE"),
        },
        "js_files": js_urls,
        "endpoints": [_serialize_endpoint(e) for e in js_analysis.endpoints],
        "secrets": [_serialize_secret(s) for s in secrets],
        "cve_correlations": [_serialize_cve(c) for c in cves],
        "probe_results": [_serialize_probe(p) for p in probes],
        "libraries": js_analysis.libraries,
        "source_maps": js_analysis.source_maps,
        "graphql_operations": js_analysis.graphql_operations,
        "todos": js_analysis.todos[:50],  # cap at 50
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


# ─── HTML Report ──────────────────────────────────────────────────────────────

_SEVERITY_COLOR_CSS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
    "NONE":     "#888888",
}

def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLOR_CSS.get(severity.upper(), "#888888")
    return (
        f'<span style="background:{color};color:#000;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:bold">{severity}</span>'
    )


def build_html_report(
    target: str,
    js_urls: List[str],
    js_analysis: JSAnalysisResult,
    secrets: List[SecretFinding],
    cves: List[CVEFinding],
    probes: List[ProbeResult],
    scan_meta: Dict,
) -> str:
    """Build full HTML report."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall_risk = scan_meta.get("overall_risk", "NONE")
    risk_color = _SEVERITY_COLOR_CSS.get(overall_risk, "#888")

    # ── Summary cards ─────────────────────────────────────────────────────────
    def card(label: str, value: Any, color: str = "#00ffcc") -> str:
        return f"""
        <div class="card">
            <div class="card-value" style="color:{color}">{value}</div>
            <div class="card-label">{label}</div>
        </div>"""

    cards_html = "".join([
        card("JS Files",        len(js_urls),                       "#00ccff"),
        card("Endpoints",       len(js_analysis.endpoints),          "#00ffcc"),
        card("Secrets Found",   len(secrets),                        "#ff4444" if secrets else "#00ff88"),
        card("CVE Matches",     len(cves),                           "#ff8800" if cves else "#00ff88"),
        card("Open Endpoints",  sum(1 for p in probes if p.status_code == 200), "#ffcc00"),
        card("Libraries",       len(js_analysis.libraries),          "#bb88ff"),
    ])

    # ── Secrets table ─────────────────────────────────────────────────────────
    def secrets_rows() -> str:
        if not secrets:
            return '<tr><td colspan="5" class="empty">No secrets detected.</td></tr>'
        rows = []
        for s in secrets:
            rows.append(f"""
            <tr>
                <td>{_severity_badge(s.severity)}</td>
                <td><b>{s.secret_type}</b></td>
                <td><code>{s.redacted_value()}</code></td>
                <td><small>{truncate(s.source_js, 50)}</small></td>
                <td><small>{truncate(s.line_context, 80)}</small></td>
            </tr>""")
        return "".join(rows)

    # ── CVE table ─────────────────────────────────────────────────────────────
    def cve_rows() -> str:
        if not cves:
            return '<tr><td colspan="7" class="empty">No CVE correlations found.</td></tr>'
        rows = []
        for c in cves:
            cvss_str = f"{c.cvss_score:.1f}" if c.cvss_score else "N/A"
            refs_html = " ".join(
                f'<a href="{r}" target="_blank" style="color:#00ccff;font-size:10px">[ref]</a>'
                for r in c.references[:2]
            ) if c.references else ""
            rows.append(f"""
            <tr>
                <td>{_severity_badge(c.severity)}</td>
                <td style="white-space:nowrap"><b>{c.cve_id}</b><br><small style="color:#888">{cvss_str} CVSS</small></td>
                <td>{c.issue_type}</td>
                <td><a href="{c.target_url}" target="_blank" style="color:#00ccff"><code>{truncate(c.target_url, 50)}</code></a>
                    {('<br><small style="color:#888">param: ' + c.parameter + '</small>') if c.parameter else ""}</td>
                <td><small style="color:#aaa">{c.description[:130]}</small></td>
                <td><small><pre style="margin:0;white-space:pre-wrap;color:#ffcc88;font-size:10px">{truncate(c.hint, 220)}</pre></small></td>
                <td>{refs_html}</td>
            </tr>""")
        return "".join(rows)

    # ── Endpoints table ───────────────────────────────────────────────────────
    def endpoint_rows() -> str:
        interesting = [e for e in js_analysis.endpoints if e.interesting]
        if not interesting:
            return '<tr><td colspan="4" class="empty">No interesting endpoints found.</td></tr>'
        rows = []
        for e in interesting[:100]:  # cap
            rows.append(f"""
            <tr>
                <td><code>{truncate(e.url, 70)}</code></td>
                <td>{e.endpoint_type}</td>
                <td>{e.method}</td>
                <td><small>{truncate(e.source_js, 50)}</small></td>
            </tr>""")
        return "".join(rows)

    # ── Libraries list ────────────────────────────────────────────────────────
    def lib_rows() -> str:
        if not js_analysis.libraries:
            return '<li class="empty">No libraries detected.</li>'
        return "".join(
            f'<li><b>{name}</b> <span class="version">v{version}</span></li>'
            for name, version in js_analysis.libraries.items()
        )

    # ── Source maps ───────────────────────────────────────────────────────────
    def map_rows() -> str:
        if not js_analysis.source_maps:
            return '<li class="empty">No source maps found.</li>'
        return "".join(
            f'<li><code>{sm}</code></li>' for sm in js_analysis.source_maps
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JSPECTER Report – {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0d0d0d;
    color: #e0e0e0;
    font-family: 'Courier New', monospace;
    padding: 24px;
    line-height: 1.6;
  }}
  .header {{
    text-align: center;
    padding: 40px 0 30px;
    border-bottom: 1px solid #222;
    margin-bottom: 30px;
  }}
  .logo {{
    font-size: 28px;
    font-weight: bold;
    color: #00ffcc;
    letter-spacing: 6px;
    text-transform: uppercase;
  }}
  .tagline {{
    color: #666;
    font-size: 13px;
    margin-top: 6px;
    font-style: italic;
  }}
  .target {{ color: #00ccff; font-size: 14px; margin-top: 12px; }}
  .timestamp {{ color: #555; font-size: 12px; margin-top: 4px; }}
  .risk-badge {{
    display: inline-block;
    background: {risk_color};
    color: #000;
    padding: 4px 16px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 14px;
    margin-top: 12px;
  }}
  .cards {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin: 24px 0;
  }}
  .card {{
    background: #161616;
    border: 1px solid #222;
    border-radius: 8px;
    padding: 20px 24px;
    min-width: 120px;
    text-align: center;
    flex: 1;
  }}
  .card-value {{
    font-size: 32px;
    font-weight: bold;
  }}
  .card-label {{
    color: #777;
    font-size: 12px;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  h2 {{
    color: #00ffcc;
    margin: 32px 0 12px;
    font-size: 16px;
    letter-spacing: 2px;
    text-transform: uppercase;
    border-left: 3px solid #00ffcc;
    padding-left: 12px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-bottom: 24px;
  }}
  th {{
    background: #1a1a1a;
    color: #00ffcc;
    text-align: left;
    padding: 10px 12px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid #222;
  }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid #1a1a1a;
    vertical-align: top;
  }}
  tr:hover td {{ background: #161616; }}
  code {{
    background: #1a1a1a;
    padding: 2px 6px;
    border-radius: 3px;
    color: #00ccff;
    font-size: 12px;
    word-break: break-all;
  }}
  ul {{ list-style: none; padding: 0; }}
  ul li {{
    padding: 6px 0;
    border-bottom: 1px solid #1a1a1a;
    font-size: 13px;
  }}
  .version {{ color: #666; }}
  .empty {{ color: #555; font-style: italic; text-align: center; padding: 20px; }}
  .footer {{
    text-align: center;
    color: #333;
    font-size: 11px;
    margin-top: 60px;
    padding-top: 20px;
    border-top: 1px solid #1a1a1a;
  }}
  .disclaimer {{
    background: #1a1000;
    border: 1px solid #442200;
    border-radius: 6px;
    padding: 12px 16px;
    font-size: 12px;
    color: #aa6600;
    margin-bottom: 24px;
  }}
</style>
</head>
<body>
<div class="header">
  <div class="logo">⚡ JSPECTER</div>
  <div class="tagline">"Hunting what JavaScript tries to hide."</div>
  <div class="target">Target: {target}</div>
  <div class="timestamp">Generated: {ts}</div>
  <div class="risk-badge">Overall Risk: {overall_risk}</div>
</div>

<div class="disclaimer">
  ⚠️ This report is for authorized security research only. Do not use findings
  against systems you do not have explicit written permission to test.
</div>

<div class="cards">{cards_html}</div>

<h2>🔑 Secrets Discovered</h2>
<table>
  <tr><th>Severity</th><th>Type</th><th>Value (Redacted)</th><th>Source</th><th>Context</th></tr>
  {secrets_rows()}
</table>

<h2>🧠 CVE Correlations</h2>
<table>
  <tr><th>Severity</th><th>CVE ID</th><th>Issue</th><th>Endpoint</th><th>Hint</th></tr>
  {cve_rows()}
</table>

<h2>🧩 Interesting Endpoints</h2>
<table>
  <tr><th>URL</th><th>Type</th><th>Method</th><th>Source JS</th></tr>
  {endpoint_rows()}
</table>

<h2>📦 Detected Libraries</h2>
<ul>{lib_rows()}</ul>

<h2>🗺️ Exposed Source Maps</h2>
<ul>{map_rows()}</ul>

<div class="footer">
  Generated by JSPECTER v1.0.0 | For authorized ethical security research only.
</div>
</body>
</html>"""
    return html


# ─── TXT Report ───────────────────────────────────────────────────────────────

def build_txt_report(
    target: str,
    js_urls: List[str],
    js_analysis: JSAnalysisResult,
    secrets: List[SecretFinding],
    cves: List[CVEFinding],
    probes: List[ProbeResult],
    scan_meta: Dict,
) -> str:
    """Build plain text report."""
    lines = [
        "=" * 70,
        "  JSPECTER - JavaScript Recon & Vulnerability Intelligence Engine",
        "  \"Hunting what JavaScript tries to hide.\"",
        "=" * 70,
        f"  Target:    {target}",
        f"  Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Risk:      {scan_meta.get('overall_risk', 'NONE')}",
        "=" * 70,
        "",
        "SUMMARY",
        "-" * 40,
        f"  JS Files Discovered:    {len(js_urls)}",
        f"  Endpoints Extracted:    {len(js_analysis.endpoints)}",
        f"  Secrets Found:          {len(secrets)}",
        f"  CVE Correlations:       {len(cves)}",
        f"  Libraries Detected:     {len(js_analysis.libraries)}",
        f"  Source Maps Exposed:    {len(js_analysis.source_maps)}",
        "",
    ]

    if secrets:
        lines += ["SECRETS DISCOVERED", "-" * 40]
        for s in secrets:
            lines += [
                f"  [{s.severity}] {s.secret_type}",
                f"    Value:   {s.redacted_value()}",
                f"    Source:  {truncate(s.source_js, 60)}",
                f"    Context: {truncate(s.line_context, 80)}",
                "",
            ]

    if cves:
        lines += ["CVE CORRELATIONS", "-" * 40]
        for c in cves:
            lines += [
                f"  [{c.severity}] {c.cve_id}",
                f"    Issue:    {c.issue_type}",
                f"    Endpoint: {truncate(c.target_url, 60)}",
                f"    Param:    {c.parameter or 'N/A'}",
                f"    Hint:     {truncate(c.hint, 80)}",
                "",
            ]

    if js_analysis.libraries:
        lines += ["DETECTED LIBRARIES", "-" * 40]
        for name, version in js_analysis.libraries.items():
            lines.append(f"  {name}: {version}")
        lines.append("")

    if js_analysis.source_maps:
        lines += ["EXPOSED SOURCE MAPS", "-" * 40]
        for sm in js_analysis.source_maps:
            lines.append(f"  {sm}")
        lines.append("")

    interesting_eps = [e for e in js_analysis.endpoints if e.interesting]
    if interesting_eps:
        lines += ["INTERESTING ENDPOINTS", "-" * 40]
        for ep in interesting_eps[:50]:
            lines.append(f"  [{ep.method}] {ep.url}")
        lines.append("")

    lines += [
        "=" * 70,
        "  DISCLAIMER: For authorized ethical security research only.",
        "=" * 70,
    ]
    return "\n".join(lines)


# ─── CLI Print Reporter ───────────────────────────────────────────────────────

def print_cli_report(
    target: str,
    js_urls: List[str],
    js_analysis: JSAnalysisResult,
    secrets: List[SecretFinding],
    cves: List[CVEFinding],
    probes: List[ProbeResult],
    scan_meta: Dict,
) -> None:
    """Print colorized summary to stdout."""
    print(f"\n{CYAN}{'═' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  JSPECTER SCAN RESULTS  —  {target}{RESET}")
    print(f"{CYAN}{'═' * 70}{RESET}")

    overall_risk = scan_meta.get("overall_risk", "NONE")
    print(f"  Overall Risk: {colorize_severity(overall_risk)}")
    print()

    # Secrets
    if secrets:
        print(f"  {Icon.SECRET} {RED}{BOLD}SECRETS ({len(secrets)}){RESET}")
        for s in secrets[:20]:
            print(
                f"    {Icon.ARROW} [{colorize_severity(s.severity)}] "
                f"{s.secret_type}: {DIM}{s.redacted_value()}{RESET}"
            )
            print(f"      {DIM}Source: {truncate(s.source_js, 55)}{RESET}")
        if len(secrets) > 20:
            print(f"    {DIM}... and {len(secrets)-20} more. See full report.{RESET}")

    # CVEs
    if cves:
        print(f"\n  {Icon.CVE} {ORANGE}{BOLD}CVE CORRELATIONS ({len(cves)}){RESET}")
        for c in cves[:20]:
            print(
                f"\n    {Icon.WARN} {colorize_severity(c.severity)} "
                f"{BOLD}{c.cve_id}{RESET}: {c.issue_type}"
            )
            print(f"      Endpoint:  {CYAN}{truncate(c.target_url, 55)}{RESET}")
            if c.parameter:
                print(f"      Parameter: {YELLOW}{c.parameter}{RESET}")
            print(f"      Hint:      {DIM}{truncate(c.hint, 75)}{RESET}")

    # Interesting endpoints
    interesting = [e for e in js_analysis.endpoints if e.interesting]
    if interesting:
        print(f"\n  {Icon.ENDPOINT} {BLUE}INTERESTING ENDPOINTS ({len(interesting)}){RESET}")
        for ep in interesting[:20]:
            print(f"    → {CYAN}{truncate(ep.url, 65)}{RESET} [{ep.endpoint_type}]")

    # Libraries
    if js_analysis.libraries:
        print(f"\n  {Icon.INFO} {MAGENTA}LIBRARIES DETECTED:{RESET}")
        for name, version in list(js_analysis.libraries.items())[:10]:
            print(f"    • {name} {DIM}v{version}{RESET}")

    # Source maps
    if js_analysis.source_maps:
        print(f"\n  {Icon.WARN} {YELLOW}EXPOSED SOURCE MAPS:{RESET}")
        for sm in js_analysis.source_maps:
            print(f"    → {sm}")

    print(f"\n{CYAN}{'─' * 70}{RESET}")
    print(
        f"  JS Files: {len(js_urls)} | "
        f"Endpoints: {len(js_analysis.endpoints)} | "
        f"Secrets: {len(secrets)} | "
        f"CVEs: {len(cves)}"
    )
    print(f"{CYAN}{'─' * 70}{RESET}\n")


