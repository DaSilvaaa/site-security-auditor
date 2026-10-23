import argparse
import sys

from . import checks, fetch
from .report import build_pdf


def audit(url: str) -> tuple[str, list[checks.Finding]]:
    host, port = fetch.parse_target(url)
    status, headers, cookies = fetch.fetch_https(host, port)
    findings = checks.analyze_tls(fetch.fetch_tls(host, port))
    findings += checks.analyze_headers(headers)
    findings += checks.analyze_cookies(cookies)
    findings += checks.analyze_redirect(*fetch.fetch_http_redirect(host))
    return host, findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Auditoria de headers, cookies e TLS com relatório PDF")
    ap.add_argument("url", help="ex.: https://exemplo.com")
    ap.add_argument("-o", "--output", default="relatorio.pdf")
    ap.add_argument("--yes", action="store_true", help="confirmo que tenho autorização para auditar este site")
    a = ap.parse_args(argv)
    if not a.yes:
        print("Só audite sites que são seus ou para os quais tem autorização. Repita com --yes para confirmar.")
        return 2
    try:
        host, findings = audit(a.url)
    except (ValueError, OSError) as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 2
    build_pdf(a.output, host, findings)
    points, grade = checks.score(findings)
    print(f"{host}: classificação {grade} ({points}/100) — relatório em {a.output}")
    return 0 if grade in ("A", "B") else 1
