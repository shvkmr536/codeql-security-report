# CodeQL C/C++ Security Report Portal

GitHub Actions + GitHub Pages portal for C/C++ CodeQL findings.

## Features
- CodeQL REST API export
- C/C++ `cpp/*` filtering
- Open and closed/fixed/dismissed findings
- Severity dashboard
- Triage status
- Assignee / Owner, dismissed-by, dismissal reason and triage comment
- File/line and commit SHA
- PDF and CSV downloads
- Historical reports by date
- Weekly scheduled refresh

## Setup
1. Create a private repository if the reports are confidential.
2. Replace `YOUR_ORGANIZATION` in `.github/workflows/publish-report.yml`.
3. Create an Actions secret `CODEQL_REPORT_TOKEN` with minimum Code Scanning read access.
4. Enable GitHub Pages using GitHub Actions.
5. Run the workflow manually once.

## Local test
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export GITHUB_TOKEN='...'
python scripts/codeql_alerts.py --org YOUR_ORGANIZATION --rule-prefix cpp/ --output codeql-cpp-alerts.csv
python scripts/generate_pdf.py --input codeql-cpp-alerts.csv --output codeql-cpp-alerts.pdf
python scripts/generate_html.py --input codeql-cpp-alerts.csv --output site/index.html
```

## API behavior
The exporter intentionally omits the `state` filter, so the report includes open and closed/fixed/dismissed alerts. It filters to CodeQL and the `cpp/` rule namespace, which excludes workflow/YAML findings from the C/C++ report.

Triage metadata comes from the Code Scanning alert API. Alert assignees are read from the API when returned; otherwise `Unassigned` is reported. The script does not infer ownership from CODEOWNERS.

## Security
These reports contain source paths, findings, triage comments and ownership data. Keep the repository and Pages site within your organization's approved access boundary. Do not hard-code tokens. Protect the default branch and the `github-pages` environment.
