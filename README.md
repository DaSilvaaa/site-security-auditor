# Site Auditor — web security audit with a PDF report

Analyzes a website in seconds and generates a **client-ready PDF report**: grade (A–F), issues by severity and **how to fix each one**.

**Problem it solves:** small businesses rarely know whether their site has HTTPS configured properly, expiring certificates or insecure cookies. This report is deliverable and can be sold as a service.

## What it checks
| Area | Checks |
|---|---|
| TLS | Valid and trusted certificate, validity (warning < 30 days), protocol version, weak cipher |
| Headers | HSTS, CSP (and unsafe directives), clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, exposed software versions |
| Cookies | `Secure`, `HttpOnly`, `SameSite` |
| Network | HTTP → HTTPS redirect |

Example: [`examples/relatorio-exemplo.pdf`](examples/relatorio-exemplo.pdf).

## Usage
```bash
pip install -r requirements.txt
cd src
python -m siteaudit https://example.com --yes -o report.pdf
```
`--yes` confirms that you are authorized to audit the site. The exit code is 0 for A/B and 1 for worse (useful in CI).

## Architecture
`checks.py` (pure rules, no network) · `fetch.py` (the only module with I/O) · `report.py` (PDF with ReportLab) · `cli.py`. The rules are tested without network access.

```bash
python -m pytest tests
```

## Limitations
It only analyzes the home page, without following redirects or crawling the site; it does not detect application vulnerabilities (XSS, SQLi) and is not a substitute for a penetration test. Only audit your own sites or sites you are authorized to audit.
