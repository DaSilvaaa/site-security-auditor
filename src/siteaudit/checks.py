"""Regras de auditoria (funções puras, sem rede): recebem dados e devolvem Findings."""
from dataclasses import dataclass
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    passed: bool
    detail: str
    fix: str = ""


def _f(id_, title, sev, ok, detail_ok, detail_bad, fix) -> Finding:
    return Finding(id_, title, sev, ok, detail_ok if ok else detail_bad, "" if ok else fix)


def _h(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def analyze_headers(headers: dict[str, str], is_https: bool = True) -> list[Finding]:
    h = _h(headers)
    out: list[Finding] = []

    def check(id_, title, sev, ok, detail_ok, detail_bad, fix):
        out.append(Finding(id_, title, sev, ok, detail_ok if ok else detail_bad, "" if ok else fix))

    hsts = h.get("strict-transport-security", "")
    max_age = 0
    for part in hsts.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    if is_https:
        check("HDR-HSTS", "Strict-Transport-Security (HSTS)", "high", max_age >= 15552000,
              f"HSTS ativo (max-age={max_age}).",
              "HSTS ausente ou com max-age demasiado curto (< 180 dias).",
              "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains")

    csp = h.get("content-security-policy", "")
    csp_weak = "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp.split()
    check("HDR-CSP", "Content-Security-Policy", "high", bool(csp) and not csp_weak,
          "CSP presente e sem diretivas inseguras.",
          "CSP ausente." if not csp else "CSP presente mas permite 'unsafe-inline', 'unsafe-eval' ou '*'.",
          "Definir uma CSP restritiva, por exemplo: default-src 'self'; object-src 'none'")

    xfo_ok = "x-frame-options" in h or "frame-ancestors" in csp
    check("HDR-FRAME", "Proteção contra clickjacking", "medium", xfo_ok,
          "X-Frame-Options ou frame-ancestors definido.",
          "Sem X-Frame-Options nem frame-ancestors: o site pode ser embebido em iframes maliciosos.",
          "Adicionar X-Frame-Options: DENY (ou CSP frame-ancestors 'none')")

    check("HDR-XCTO", "X-Content-Type-Options", "medium", h.get("x-content-type-options", "").lower() == "nosniff",
          "nosniff ativo.", "Header ausente ou inválido.", "Adicionar: X-Content-Type-Options: nosniff")

    check("HDR-REFERRER", "Referrer-Policy", "low", "referrer-policy" in h,
          f"Definido: {h.get('referrer-policy')}.", "Header ausente: URLs completos podem vazar para terceiros.",
          "Adicionar: Referrer-Policy: strict-origin-when-cross-origin")

    check("HDR-PERMS", "Permissions-Policy", "low", "permissions-policy" in h,
          "Definido.", "Header ausente: funcionalidades do browser (câmara, microfone, localização) não restritas.",
          "Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=()")

    leaks = {k: h[k] for k in ("server", "x-powered-by", "x-aspnet-version") if k in h and any(c.isdigit() for c in h[k])}
    check("HDR-LEAK", "Divulgação de versões", "low", not leaks,
          "Sem versões de software expostas.",
          "Versões expostas: " + ", ".join(f"{k}: {v}" for k, v in leaks.items()),
          "Remover ou ocultar os headers Server / X-Powered-By.")
    return out


def analyze_cookies(set_cookie_headers: list[str], is_https: bool = True) -> list[Finding]:
    if not set_cookie_headers:
        return [Finding("CKE-NONE", "Cookies", "info", True, "O site não define cookies na página inicial.")]
    out = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().lower() for a in raw.split(";")[1:]}
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite=") for a in attrs):
            missing.append("SameSite")
        out.append(Finding(
            f"CKE-{name}", f"Cookie '{name}'", "medium", not missing,
            "Flags de segurança corretas." if not missing else "Faltam flags: " + ", ".join(missing) + ".",
            "" if not missing else f"Definir {', '.join(missing)} no cookie '{name}'.",
        ))
    return out


def analyze_redirect(http_status: int | None, location: str | None) -> list[Finding]:
    if http_status is None:
        return [Finding("NET-HTTP", "Redirecionamento HTTP→HTTPS", "info", True, "Porta 80 não acessível.")]
    ok = http_status in (301, 302, 307, 308) and (location or "").lower().startswith("https://")
    return [_f("NET-HTTP", "Redirecionamento HTTP→HTTPS", "high", ok,
                    "HTTP redireciona para HTTPS.", "O site responde em HTTP sem redirecionar para HTTPS.",
                    "Configurar redirecionamento permanente (301) de HTTP para HTTPS.")]


def analyze_tls(info: dict, now: datetime | None = None) -> list[Finding]:
    """info: protocol, cipher, not_after (datetime UTC), hostname, san (list[str]), verify_error (str|None)."""
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    err = info.get("verify_error")
    out.append(_f("TLS-CHAIN", "Certificado válido e confiável", "critical", not err,
                       f"Cadeia validada (emissor: {info.get('issuer', 'n/d')}).",
                       f"Certificado não confiável: {err}",
                       "Instalar um certificado válido emitido por uma CA reconhecida (ex.: Let's Encrypt)."))
    if info.get("not_after"):
        days = (info["not_after"] - now).days
        sev = "critical" if days < 0 else "high" if days < 14 else "medium"
        out.append(_f("TLS-EXPIRY", "Validade do certificado", sev, days >= 30,
                           f"Expira em {days} dias.",
                           "Certificado expirado." if days < 0 else f"Expira em apenas {days} dias.",
                           "Renovar o certificado e automatizar a renovação (ex.: certbot)."))
    proto = info.get("protocol", "")
    out.append(_f("TLS-PROTO", "Versão do protocolo TLS", "high", proto in ("TLSv1.2", "TLSv1.3"),
                       f"Negociado {proto}.", f"Negociado {proto or 'protocolo desconhecido'}, considerado obsoleto.",
                       "Desativar TLS 1.0/1.1 e SSLv3; permitir apenas TLS 1.2 e 1.3."))
    cipher = info.get("cipher", "")
    weak = any(x in cipher.upper() for x in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5"))
    out.append(_f("TLS-CIPHER", "Cifra negociada", "high", not weak,
                       f"Cifra: {cipher}.", f"Cifra fraca: {cipher}.",
                       "Restringir as cifras a suites AEAD (AES-GCM, ChaCha20-Poly1305)."))
    return out


def score(findings: list[Finding]) -> tuple[int, str]:
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings if not f.passed)
    points = max(0, 100 - penalty)
    grade = "A" if points >= 90 else "B" if points >= 75 else "C" if points >= 60 else "D" if points >= 40 else "F"
    return points, grade
