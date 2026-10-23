# Site Auditor — auditoria de segurança web com relatório PDF

Analisa um site em segundos e gera um **relatório PDF para o cliente**: classificação (A–F), problemas por gravidade e **como corrigir cada um**.

**Problema que resolve:** pequenas empresas raramente sabem se o site tem HTTPS bem configurado, certificados a expirar ou cookies inseguros. Este relatório é entregável e vendável como serviço.

## O que verifica
| Área | Verificações |
|---|---|
| TLS | Certificado válido e confiável, validade (aviso < 30 dias), versão do protocolo, cifra fraca |
| Headers | HSTS, CSP (e diretivas inseguras), clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, versões de software expostas |
| Cookies | `Secure`, `HttpOnly`, `SameSite` |
| Rede | Redirecionamento HTTP → HTTPS |

Exemplo: [`examples/relatorio-exemplo.pdf`](examples/relatorio-exemplo.pdf).

## Utilização
```bash
pip install -r requirements.txt
cd src
python -m siteaudit https://exemplo.com --yes -o relatorio.pdf
```
`--yes` confirma que tem autorização para auditar o site. O código de saída é 0 para A/B e 1 para pior (útil em CI).

## Arquitetura
`checks.py` (regras puras, sem rede) · `fetch.py` (único módulo com I/O) · `report.py` (PDF com ReportLab) · `cli.py`. As regras são testadas sem rede.

```bash
python -m pytest tests
```

## Limitações
Analisa só a página inicial, sem seguir redirects nem rastrear o site; não deteta vulnerabilidades da aplicação (XSS, SQLi) e não substitui um teste de intrusão. Só audite sites seus ou com autorização.
