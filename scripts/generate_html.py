#!/usr/bin/env python3
import argparse
import csv
import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SEVS = ['Critical', 'High', 'Medium', 'Low', 'Warning', 'Note', 'Error', 'N/A']

def rows(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def e(value):
    return html.escape(str(value or ''))

def sev(row):
    security_severity = (row.get('Security Severity') or '').strip()
    if security_severity and security_severity.lower() != 'n/a':
        return security_severity.title()
    return (row.get('Severity') or 'N/A').title()

def main():
    parser = argparse.ArgumentParser(description='Generate CodeQL C/C++ security HTML dashboard.')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--title', default='CodeQL C/C++ Security Portal')
    parser.add_argument('--classification', default='Confidential - Security')
    parser.add_argument('--report-pdf', default='codeql-cpp-alerts.pdf')
    parser.add_argument('--report-csv', default='codeql-cpp-alerts.csv')
    parser.add_argument('--history', action='append', nargs=2, default=[], metavar=('LABEL', 'LINK'))
    args = parser.parse_args()

    report_rows = rows(args.input)
    severity_counts = Counter(sev(row) for row in report_rows)
    status_counts = Counter((row.get('Status', 'Unknown') or 'Unknown') for row in report_rows)
    max_severity_count = max([severity_counts[name] for name in SEVS] + [1])

    bars = ''.join(
        f'<div class="bar"><b>{e(name)}</b><span><i style="width:{max(4, int(severity_counts[name] / max_severity_count * 100))}%"></i></span><b>{severity_counts[name]}</b></div>'
        for name in SEVS if severity_counts[name]
    )

    chips = ''.join(
        f'<span class="chip">{e(status)} <b>{count}</b></span>'
        for status, count in sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))
    )

    history = ''.join(
        f'<li><a href="{e(link)}">{e(label)}</a> <a class="history-download" href="{e(link)}" download>Download PDF</a></li>'
        for label, link in args.history
    ) or '<li>No history.</li>'

    finding_rows = []
    for row in report_rows:
        severity = sev(row)
        finding_rows.append(
            f'<tr>'
            f'<td>{e(row.get("Alert ID"))}</td>'
            f'<td><code>{e(row.get("Rule ID"))}</code></td>'
            f'<td class="{e(severity).lower()}">{e(severity)}</td>'
            f'<td>{e(row.get("File"))}:{e(row.get("Start Line"))}</td>'
            f'<td>{e(row.get("Status"))}</td>'
            f'<td>{e(row.get("Assignee / Owner"))}</td>'
            f'<td>{e(row.get("Dismissed By"))}</td>'
            f'<td>{e(row.get("Dismissal Reason"))}</td>'
            f'<td>{e(row.get("Triage Comment"))}</td>'
            f'<td><a href="{e(row.get("Alert URL"))}" target="_blank" rel="noopener noreferrer">Alert</a></td>'
            f'</tr>'
        )
    finding_table_rows = ''.join(finding_rows) or '<tr><td colspan="10">No findings.</td></tr>'

    pdf_filename = Path(args.report_pdf).name
    csv_filename = Path(args.report_csv).name

    document = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{e(args.title)}</title>
<style>
:root{{--bg:#f5f7fa;--card:#fff;--ink:#101828;--muted:#667085;--line:#d0d5dd;--header:#101828;--accent:#475467}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px "Segoe UI",Arial,sans-serif}}
header{{background:var(--header);color:#fff;padding:28px 5vw}}
header h1{{margin:0 0 7px;font-size:28px}}
header p{{color:#d0d5dd}}
main{{max-width:1550px;margin:25px auto;padding:0 24px}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}}
.card,.panel{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px}}
.metric{{font-size:30px;font-weight:750}}
.muted{{color:var(--muted);font-size:12px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}}
.bar{{display:grid;grid-template-columns:90px 1fr 35px;gap:10px;align-items:center;margin:11px 0}}
.bar span{{height:14px;background:#eaecf0;border-radius:10px;overflow:hidden}}
.bar i{{display:block;height:100%;background:var(--accent)}}
.chip{{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:8px 12px;margin:4px;background:#f9fafb}}
.btn{{display:inline-block;padding:11px 16px;margin:18px 8px 18px 0;border-radius:8px;background:#101828;color:#fff;text-decoration:none;font-weight:650;cursor:pointer}}
.btn:hover{{opacity:.9}}
.alt{{background:#fff;color:#101828;border:1px solid var(--line)}}
.download-status{{display:inline-block;margin-left:4px;color:var(--muted);font-size:12px}}
.history-download{{margin-left:10px;font-size:12px}}
.table{{overflow:auto}}
table{{border-collapse:collapse;width:100%;min-width:1450px;background:#fff}}
th,td{{border-bottom:1px solid var(--line);padding:9px 8px;text-align:left;vertical-align:top;font-size:12px}}
th{{background:#f2f4f7;position:sticky;top:0}}
.critical{{color:#b42318;font-weight:700}}.high{{color:#d92d20;font-weight:700}}.medium{{color:#b54708;font-weight:700}}.low{{color:#027a48;font-weight:700}}
footer{{max-width:1550px;margin:25px auto;padding:0 24px 40px;color:var(--muted);font-size:12px}}
@media(max-width:900px){{.cards{{grid-template-columns:repeat(2,1fr)}}.grid{{grid-template-columns:1fr}}}}
@media(max-width:600px){{.cards{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header><h1>{e(args.title)}</h1><p>{e(args.classification)} · {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</p></header>
<main>
<section aria-label="Report downloads">
<a class="btn" href="{e(args.report_pdf)}" download="{e(pdf_filename)}">Download PDF</a>
<a class="btn alt" href="{e(args.report_csv)}" download="{e(csv_filename)}" onclick="downloadFile(event, this.href, '{e(csv_filename)}')">Download CSV</a>
<span id="download-status" class="download-status"></span>
</section>
<section class="cards">
<div class="card"><div class="metric">{len(report_rows)}</div><div class="muted">Total findings</div></div>
<div class="card"><div class="metric">{severity_counts['Critical']}</div><div class="muted">Critical</div></div>
<div class="card"><div class="metric">{severity_counts['High']}</div><div class="muted">High</div></div>
<div class="card"><div class="metric">{severity_counts['Medium']}</div><div class="muted">Medium</div></div>
<div class="card"><div class="metric">{severity_counts['Low']}</div><div class="muted">Low</div></div>
</section>
<div class="grid">
<section class="panel"><h2>Severity distribution</h2>{bars or '<p>No findings.</p>'}</section>
<section class="panel"><h2>Triage status</h2>{chips or '<p>No findings.</p>'}</section>
</div>
<section class="panel" style="margin-top:18px"><h2>Historical reports</h2><ul>{history}</ul></section>
<section class="panel" style="margin-top:18px"><h2>Finding details</h2><div class="table"><table><thead><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>Location</th><th>Status</th><th>Assignee / Owner</th><th>Dismissed By</th><th>Reason</th><th>Triage Comment</th><th>GitHub</th></tr></thead><tbody>{finding_table_rows}</tbody></table></div></section>
</main>
<footer>Generated from GitHub Code Scanning / CodeQL REST API. Treat as confidential security information.</footer>
<script>
async function downloadFile(event, url, filename) {{
    event.preventDefault();
    const status = document.getElementById('download-status');
    try {{
        status.textContent = 'Preparing CSV download...';
        const response = await fetch(url, {{method:'GET', credentials:'same-origin', cache:'no-store'}});
        if (!response.ok) throw new Error('HTTP ' + response.status + ' ' + response.statusText);
        const blob = await response.blob();
        if (!blob.size) throw new Error('The downloaded CSV file is empty.');
        const blobUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => window.URL.revokeObjectURL(blobUrl), 1000);
        status.textContent = 'CSV download started.';
        window.setTimeout(() => status.textContent = '', 3000);
    }} catch (error) {{
        console.error('CSV download failed:', error);
        status.textContent = 'Download failed. Opening CSV in a new tab...';
        window.open(url, '_blank', 'noopener,noreferrer');
    }}
}}
</script>
</body>
</html>
'''

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding='utf-8')

if __name__ == '__main__':
    main()