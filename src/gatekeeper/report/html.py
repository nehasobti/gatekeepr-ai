"""HTML standalone report generator with interactive filtering."""

from __future__ import annotations

import html
from pathlib import Path

from gatekeeper.models import AuditResult, Verdict


def generate_html_content(result: AuditResult) -> str:
    """Generate self-contained HTML report with filters and modern styling."""
    verdict_badge = {
        Verdict.PASS: ('<span class="badge badge-pass">PASS</span>', "#10b981"),
        Verdict.FAIL: ('<span class="badge badge-fail">FAIL</span>', "#ef4444"),
        Verdict.SKIPPED: ('<span class="badge badge-skip">SKIPPED</span>', "#f59e0b"),
        Verdict.ERROR: ('<span class="badge badge-error">ERROR</span>', "#dc2626"),
    }.get(result.verdict, ("<span>UNKNOWN</span>", "#6b7280"))

    findings_cards: list[str] = []
    for f in result.findings:
        sev_class = f"sev-{f.severity.value}"
        loc = f"{f.file}:{f.start_line}"
        if f.end_line > f.start_line:
            loc += f"-{f.end_line}"

        card = f"""
        <div class="finding-card {sev_class}" data-severity="{f.severity.value}" data-category="{f.category.value}">
            <div class="finding-header">
                <span class="badge badge-{f.severity.value}">{f.severity.value.upper()}</span>
                <span class="finding-loc">{html.escape(loc)}</span>
                <span class="finding-cat">{html.escape(f.category.value)}</span>
                <span class="finding-source">via {html.escape(", ".join(f.source))}</span>
            </div>
            <h3 class="finding-title">{html.escape(f.title)}</h3>
            <p class="finding-expl">{html.escape(f.explanation)}</p>
            <div class="finding-fix">
                <strong>Suggested Fix:</strong>
                <pre><code>{html.escape(f.suggested_fix)}</code></pre>
            </div>
        </div>
        """
        findings_cards.append(card)

    meta = result.metadata
    skipped_items = "".join(f"<li><code>{html.escape(s)}</code></li>" for s in meta.skipped_files)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gatekeeper AI Audit Report - {result.verdict.value}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --pass: #10b981;
            --fail: #ef4444;
            --critical: #dc2626;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #06b6d4;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ font-size: 1.75rem; font-weight: 700; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.875rem;
            text-transform: uppercase;
        }}
        .badge-pass {{ background: var(--pass); color: #fff; }}
        .badge-fail {{ background: var(--fail); color: #fff; }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-info {{ background: var(--info); color: #fff; }}
        .badge-skip {{ background: var(--medium); color: #000; }}
        .badge-error {{ background: var(--critical); color: #fff; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .stat-value {{ font-size: 1.75rem; font-weight: 700; margin-bottom: 0.25rem; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}

        .filter-bar {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            align-items: center;
        }}
        select, input {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
        }}

        .finding-card {{
            background: var(--surface);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--border);
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        .sev-critical {{ border-left-color: var(--critical); }}
        .sev-high {{ border-left-color: var(--high); }}
        .sev-medium {{ border-left-color: var(--medium); }}
        .sev-low {{ border-left-color: var(--low); }}
        .sev-info {{ border-left-color: var(--info); }}

        .finding-header {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
        }}
        .finding-loc {{ font-family: monospace; color: var(--text-muted); }}
        .finding-cat {{ background: var(--surface-hover); padding: 0.15rem 0.5rem; border-radius: 4px; }}
        .finding-source {{ color: var(--text-muted); margin-left: auto; }}
        .finding-title {{ font-size: 1.15rem; margin-bottom: 0.5rem; }}
        .finding-expl {{ color: #cbd5e1; margin-bottom: 0.75rem; }}
        .finding-fix {{
            background: rgba(0,0,0,0.25);
            padding: 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--border);
        }}
        pre {{ overflow-x: auto; font-family: monospace; font-size: 0.9rem; margin-top: 0.25rem; }}

        footer {{
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Gatekeeper AI Quality Gate</h1>
                <p style="color: var(--text-muted)">Automated code review & security audit</p>
            </div>
            <div>
                {verdict_badge[0]}
            </div>
        </header>

        <section class="stats-grid">
            <div class="stat-card"><div class="stat-value" style="color:var(--critical)">{result.summary.critical}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-value" style="color:var(--high)">{result.summary.high}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-value" style="color:var(--medium)">{result.summary.medium}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card"><div class="stat-value" style="color:var(--low)">{result.summary.low}</div><div class="stat-label">Low</div></div>
            <div class="stat-card"><div class="stat-value" style="color:var(--info)">{result.summary.info}</div><div class="stat-label">Info</div></div>
            <div class="stat-card"><div class="stat-value">{result.summary.total}</div><div class="stat-label">Total</div></div>
        </section>

        <div class="filter-bar">
            <label for="sevFilter">Filter Severity:</label>
            <select id="sevFilter" onchange="filterFindings()">
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
            </select>
        </div>

        <section id="findingsList">
            {"".join(findings_cards) if findings_cards else '<p style="color:var(--pass)">No issues detected.</p>'}
        </section>

        {"<details style='margin-top:1.5rem'><summary>Skipped Files (" + str(len(meta.skipped_files)) + ")</summary><ul>" + skipped_items + "</ul></details>" if meta.skipped_files else ""}

        <footer>
            Model: <code>{html.escape(meta.model)}</code> |
            Prompt v<code>{html.escape(meta.prompt_version)}</code> |
            Duration: {meta.duration_seconds:.2f}s |
            Tokens (In: {meta.input_tokens}, Out: {meta.output_tokens}, Cached: {meta.cached_tokens}) |
            Estimated Cost: ${meta.estimated_cost_usd:.4f}
        </footer>
    </div>

    <script>
        function filterFindings() {{
            const filter = document.getElementById('sevFilter').value;
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (filter === 'all' || card.getAttribute('data-severity') === filter) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""


def generate_html_report(result: AuditResult, output_path: str | Path) -> Path:
    """Write HTML report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_html_content(result)
    path.write_text(content, encoding="utf-8")
    return path
