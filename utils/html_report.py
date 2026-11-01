"""Self-contained interactive HTML report."""

from __future__ import annotations

import html
import json
from typing import Any

from utils.text import NOTICE, format_duration


def render_html(report: dict[str, Any]) -> str:
    """Render a standalone HTML report. All dynamic values are escaped."""
    target = report.get("target") or {}
    host = str(target.get("host") or target.get("raw") or "target")
    summary = report.get("summary") or {}
    modules = report.get("modules") or {}
    raw_json = html.escape(json.dumps(report, indent=2, ensure_ascii=False))

    highest = summary.get("highest_severity") or "none"
    outcome = _outcome(summary)
    parts = [
        _document_start(host),
        _header(report, host, outcome),
        "<main>",
        _metrics(summary, highest),
        _module_strip(modules),
        _subdomains_section(modules.get("subdomains")),
        _ports_section(modules.get("ports")),
        _headers_section(modules.get("headers")),
        _errors_section(modules),
        f"<details class='raw'><summary>Raw JSON</summary><pre>{raw_json}</pre></details>",
        "</main>",
        f"<footer><p>{html.escape(NOTICE)}</p><p>{html.escape(str(report.get('tool', 'recon-cli')))} "
        f"{html.escape(str(report.get('version', '')))}</p></footer>",
        _script(),
        "</body></html>",
    ]
    return "\n".join(parts)


def _document_start(host: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon report — {html.escape(host)}</title>
<style>
:root {{
  --bg: #0c1218;
  --card: #141c26;
  --card-2: #1b2633;
  --line: #2a3a4d;
  --text: #e7eef6;
  --muted: #8ea0b5;
  --accent: #3dd6ff;
  --green: #3dd68c;
  --yellow: #f0c14d;
  --red: #ff6b6b;
  --cyan: #7fd1ff;
  --shadow: 0 12px 40px rgba(0, 0, 0, .28);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: radial-gradient(1200px 500px at 10% -10%, #173044 0%, transparent 55%), var(--bg);
  color: var(--text);
  font: 15px/1.5 "Segoe UI", "Helvetica Neue", sans-serif;
}}
header, main, footer {{ width: min(1120px, calc(100% - 32px)); margin: 0 auto; }}
header {{ padding: 36px 0 8px; }}
.eyebrow {{ color: var(--accent); letter-spacing: .14em; text-transform: uppercase; font-size: 12px; margin: 0; }}
h1 {{ margin: 6px 0 8px; font-size: 34px; line-height: 1.15; }}
.sub {{ color: var(--muted); margin: 0; }}
.outcome {{
  display: inline-block; margin-top: 14px; padding: 4px 10px; border-radius: 999px;
  border: 1px solid var(--line); background: var(--card); font-size: 13px;
}}
.metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0; }}
.card, .panel {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); }}
.card {{ padding: 16px 18px; }}
.card span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }}
.card strong {{ display: block; margin-top: 6px; font-size: 28px; }}
.strip {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }}
.pill {{ border: 1px solid var(--line); background: var(--card-2); border-radius: 999px; padding: 6px 10px; color: var(--muted); font-size: 13px; }}
.panel {{ padding: 18px; margin: 0 0 16px; }}
.panel h2 {{ margin: 0 0 4px; font-size: 20px; }}
.toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 12px 0; }}
input[type="search"] {{
  background: var(--bg); color: var(--text); border: 1px solid var(--line); border-radius: 8px;
  padding: 8px 10px; min-width: min(280px, 100%);
}}
button {{
  background: var(--card-2); color: var(--text); border: 1px solid var(--line); border-radius: 8px;
  padding: 7px 10px; cursor: pointer;
}}
button.active {{ border-color: var(--accent); color: var(--accent); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; cursor: pointer; user-select: none; }}
tr[hidden] {{ display: none; }}
.badge {{ display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 12px; border: 1px solid var(--line); }}
.badge.high, .badge.critical, .badge.missing {{ color: var(--red); }}
.badge.medium, .badge.weak {{ color: var(--yellow); }}
.badge.low, .badge.open {{ color: var(--cyan); }}
.badge.info, .badge.present, .badge.success {{ color: var(--green); }}
.badge.not_applicable {{ color: var(--muted); }}
.badge.skipped {{ color: var(--yellow); }}
.badge.error {{ color: var(--red); }}
.badge.partial {{ color: var(--yellow); }}
.empty {{ color: var(--muted); margin: 8px 0 0; }}
.meta {{ color: var(--muted); font-size: 13px; }}
details.raw {{ margin: 8px 0 28px; }}
pre {{ overflow: auto; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px; max-height: 420px; }}
footer {{ color: var(--muted); font-size: 13px; padding-bottom: 40px; }}
.bar {{ height: 8px; background: var(--card-2); border-radius: 99px; overflow: hidden; margin-top: 8px; }}
.bar span {{ display: block; height: 100%; background: linear-gradient(90deg, var(--accent), var(--green)); }}
@media (max-width: 800px) {{
  .metrics {{ grid-template-columns: 1fr 1fr; }}
  h1 {{ font-size: 28px; }}
}}
@media print {{
  body {{ background: white; color: black; }}
  .card, .panel, pre {{ box-shadow: none; background: white; }}
  .toolbar, footer button {{ display: none; }}
  a {{ color: black; }}
}}
</style>
</head>
<body>"""


def _outcome(summary: dict[str, Any]) -> str:
    if not summary.get("ok"):
        return "Needs review"
    if int(summary.get("header_issues") or 0) > 0:
        return "Findings"
    return "Complete"


def _header(report: dict[str, Any], host: str, outcome: str) -> str:
    started = str(report.get("started_at", ""))
    duration = format_duration(float(report.get("duration_ms") or 0))
    target = report.get("target") or {}
    url = str(target.get("url") or "")
    return f"""<header>
  <p class="eyebrow">{html.escape(str(report.get("tool", "recon-cli")))} {html.escape(str(report.get("version", "")))}</p>
  <h1>{html.escape(host)}</h1>
  <p class="sub">Started {html.escape(started)} · Duration {html.escape(duration)} · {html.escape(url)}</p>
  <div class="outcome">{html.escape(outcome)}</div>
</header>"""


def _metrics(summary: dict[str, Any], highest: object) -> str:
    cards = [
        ("Subdomains", summary.get("subdomains", 0)),
        ("Open ports", summary.get("open_ports", 0)),
        ("Header issues", summary.get("header_issues", 0)),
        ("Highest severity", highest),
    ]
    body = "\n".join(
        f"<article class='card'><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></article>"
        for label, value in cards
    )
    return f"<section class='metrics'>{body}</section>"


def _module_strip(modules: dict[str, Any]) -> str:
    if not modules:
        return "<div class='strip'><span class='pill'>No modules were run</span></div>"
    pills = []
    for name, result in modules.items():
        status = str(result.get("status", "unknown"))
        label = str(result.get("label") or name)
        duration = format_duration(float(result.get("duration_ms") or 0))
        pills.append(
            f"<span class='pill'>{html.escape(label)} · "
            f"<span class='badge {html.escape(status)}'>{html.escape(status)}</span> · "
            f"{html.escape(duration)}</span>"
        )
    return "<div class='strip'>" + "".join(pills) + "</div>"


def _subdomains_section(result: dict[str, Any] | None) -> str:
    if result is None:
        return _not_run("Subdomains", "subdomains")
    names = [str(item) for item in result.get("findings") or []]
    meta = result.get("meta") or {}
    if result.get("status") == "skipped":
        reason = html.escape(str(meta.get("reason") or "This module was skipped."))
        body = f"<p class='empty'>{reason}</p>"
        return f"""<section class="panel" id="subdomains" data-kind="search">
  <h2>Subdomains</h2>
  <p class="meta">Skipped.</p>
  {body}
</section>"""
    if not names:
        body = "<p class='empty'>No subdomains were returned.</p>"
    else:
        rows = "\n".join(
            f'<tr data-search="{html.escape(name)}"><td>{index}</td><td>{html.escape(name)}</td></tr>'
            for index, name in enumerate(names, start=1)
        )
        body = f"""<div class="toolbar"><input type="search" placeholder="Filter subdomains" aria-label="Filter subdomains"></div>
<table>
  <thead><tr><th data-type="number">#</th><th>Subdomain</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""
    source = html.escape(str(meta.get("source") or "crt.sh"))
    return f"""<section class="panel" id="subdomains" data-kind="search">
  <h2>Subdomains</h2>
  <p class="meta">{len(names)} name(s) from {source}.</p>
  {body}
</section>"""


def _ports_section(result: dict[str, Any] | None) -> str:
    if result is None:
        return _not_run("Open ports", "ports")
    findings = result.get("findings") or []
    meta = result.get("meta") or {}
    scanned = meta.get("ports_scanned", 0)
    address = html.escape(str(meta.get("scanned_address") or ""))
    if not findings:
        body = "<p class='empty'>No open ports were found.</p>"
    else:
        rows = []
        for entry in findings:
            port = int(entry.get("port", 0))
            service = str(entry.get("service", "unknown"))
            state = str(entry.get("state", "open"))
            protocol = str(entry.get("protocol", "tcp"))
            search = html.escape(f"{port} {protocol} {state} {service}")
            rows.append(
                f'<tr data-search="{search}">'
                f'<td data-value="{port}">{port}</td>'
                f"<td>{html.escape(protocol)}</td>"
                f"<td><span class=\"badge open\">{html.escape(state)}</span></td>"
                f"<td>{html.escape(service)}</td></tr>"
            )
        body = f"""<div class="toolbar"><input type="search" placeholder="Filter ports" aria-label="Filter ports"></div>
<table>
  <thead><tr><th data-type="number">Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>"""
    return f"""<section class="panel" id="ports" data-kind="search">
  <h2>Open ports</h2>
  <p class="meta">{len(findings)} open / {html.escape(str(scanned))} scanned · {address} · TCP connect</p>
  {body}
</section>"""


def _headers_section(result: dict[str, Any] | None) -> str:
    if result is None:
        return _not_run("HTTP security headers", "headers")
    findings = [item for item in (result.get("findings") or []) if isinstance(item, dict)]
    meta = result.get("meta") or {}
    applicable = [
        item for item in findings
        if item.get("category") == "security_header" and item.get("status") != "not_applicable"
    ]
    present = sum(1 for item in applicable if item.get("status") == "present")
    total = len(applicable) or 1
    percent = round(present / total * 100)
    rows = []
    for finding in findings:
        status = str(finding.get("status", ""))
        severity = str(finding.get("severity", "info"))
        issue = status in {"missing", "weak"} and severity in {"low", "medium", "high", "critical"}
        name = str(finding.get("name", ""))
        value = finding.get("value") or "—"
        detail = str(finding.get("detail") or "")
        recommendation = str(finding.get("recommendation") or "")
        search = html.escape(" ".join((name, status, severity, str(value), detail)))
        rows.append(
            f'<tr data-search="{search}" data-severity="{html.escape(severity)}" '
            f'data-issue="{"true" if issue else "false"}">'
            f"<td>{html.escape(name)}</td>"
            f'<td><span class="badge {html.escape(status)}">{html.escape(status.replace("_", " "))}</span></td>'
            f'<td><span class="badge {html.escape(severity)}">{html.escape(severity)}</span></td>'
            f"<td>{html.escape(str(value))}<div class=\"meta\">{html.escape(detail)}</div></td>"
            f"<td>{html.escape(recommendation)}</td></tr>"
        )
    final_url = html.escape(str(meta.get("final_url") or meta.get("requested_url") or ""))
    code = html.escape(str(meta.get("status_code", "—")))
    body = "<p class='empty'>No header results.</p>"
    if rows:
        body = f"""<div class="bar" aria-hidden="true"><span style="width:{percent}%"></span></div>
<p class="meta">{present} of {len(applicable)} applicable security headers look healthy.</p>
<div class="toolbar">
  <input type="search" placeholder="Filter headers" aria-label="Filter headers">
  <button type="button" class="active" data-severity-filter="all">All</button>
  <button type="button" data-severity-filter="issues">Issues</button>
  <button type="button" data-severity-filter="high">High</button>
  <button type="button" data-severity-filter="medium">Medium</button>
  <button type="button" data-severity-filter="low">Low</button>
  <button type="button" data-severity-filter="info">Info</button>
</div>
<table>
  <thead><tr><th>Header</th><th>Status</th><th>Severity</th><th>Observed</th><th>Recommendation</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>"""
    return f"""<section class="panel" id="headers" data-kind="headers">
  <h2>HTTP security headers</h2>
  <p class="meta">HTTP {code} · {final_url}</p>
  {body}
</section>"""


def _errors_section(modules: dict[str, Any]) -> str:
    items: list[str] = []
    for result in modules.values():
        for error in result.get("errors") or []:
            label = str(result.get("label") or result.get("name") or "module")
            items.append(f"<li><strong>{html.escape(label)}.</strong> {html.escape(str(error))}</li>")
    if not items:
        return ""
    return "<section class='panel' id='errors'><h2>Module errors</h2><ul>" + "".join(items) + "</ul></section>"


def _not_run(title: str, anchor: str) -> str:
    return (
        f"<section class='panel' id='{html.escape(anchor)}'><h2>{html.escape(title)}</h2>"
        "<p class='empty'>This module was not selected.</p></section>"
    )


def _script() -> str:
    return """<script>
document.querySelectorAll("section.panel").forEach((section) => {
  const input = section.querySelector("input[type='search']");
  const buttons = [...section.querySelectorAll("[data-severity-filter]")];
  let severity = "all";

  function apply() {
    const query = (input && input.value || "").trim().toLowerCase();
    section.querySelectorAll("tbody tr").forEach((row) => {
      const text = (row.dataset.search || row.textContent || "").toLowerCase();
      const rowSeverity = row.dataset.severity || "";
      const issue = row.dataset.issue === "true";
      const severityOk = severity === "all"
        || (severity === "issues" && issue)
        || rowSeverity === severity;
      row.hidden = !(severityOk && (!query || text.includes(query)));
    });
  }

  if (input) input.addEventListener("input", apply);
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      severity = button.dataset.severityFilter || "all";
      buttons.forEach((item) => item.classList.toggle("active", item === button));
      apply();
    });
  });

  section.querySelectorAll("th").forEach((header) => {
    header.addEventListener("click", () => {
      const table = header.closest("table");
      const body = table && table.tBodies[0];
      if (!body) return;
      const index = [...header.parentElement.children].indexOf(header);
      const ascending = header.dataset.dir !== "asc";
      header.dataset.dir = ascending ? "asc" : "desc";
      const numeric = header.dataset.type === "number";
      const rows = [...body.rows];
      rows.sort((left, right) => {
        const a = left.cells[index].dataset.value || left.cells[index].textContent.trim();
        const b = right.cells[index].dataset.value || right.cells[index].textContent.trim();
        let compared;
        if (numeric) compared = Number(a) - Number(b);
        else compared = a.localeCompare(b);
        return ascending ? compared : -compared;
      });
      rows.forEach((row) => body.appendChild(row));
    });
  });
});
</script>"""
