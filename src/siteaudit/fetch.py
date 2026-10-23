"""Recolha de dados de rede (a única parte com I/O)."""
import http.client
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

TIMEOUT = 10
USER_AGENT = "siteaudit/1.0 (auditoria de seguranca autorizada)"


def parse_target(url: str) -> tuple[str, int]:
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise ValueError("Indique um URL https:// válido.")
    return p.hostname, p.port or 443


def fetch_https(host: str, port: int) -> tuple[int, dict[str, str], list[str]]:
    """GET / sem seguir redirects. Devolve (status, headers, lista de Set-Cookie)."""
    conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ssl.create_default_context())
    try:
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        return resp.status, headers, cookies
    finally:
        conn.close()


def fetch_http_redirect(host: str) -> tuple[int | None, str | None]:
    conn = http.client.HTTPConnection(host, 80, timeout=TIMEOUT)
    try:
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location")
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        conn.close()


def fetch_tls(host: str, port: int) -> dict:
    info: dict = {"hostname": host, "verify_error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock, ctx.wrap_socket(
            sock, server_hostname=host
        ) as tls:
            cert = tls.getpeercert()
            info["protocol"] = tls.version()
            info["cipher"] = tls.cipher()[0]
            info["not_after"] = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            info["issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "n/d")
            info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return info
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = e.verify_message or str(e)
    except ssl.SSLError as e:
        info["verify_error"] = str(e)
    # Falhou a validação: voltar a ligar sem validar só para recolher protocolo/cifra/validade.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock, ctx.wrap_socket(
        sock, server_hostname=host
    ) as tls:
        info["protocol"] = tls.version()
        info["cipher"] = tls.cipher()[0]
    return info
