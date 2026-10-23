"""Geração do relatório PDF para o cliente."""
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .checks import Finding, score

SEV_COLOR = {
    "critical": colors.HexColor("#b91c1c"), "high": colors.HexColor("#dc2626"),
    "medium": colors.HexColor("#d97706"), "low": colors.HexColor("#ca8a04"), "info": colors.HexColor("#6b7280"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_PT = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Info"}


def build_pdf(path: str, target: str, findings: list[Finding], when: datetime | None = None) -> None:
    when = when or datetime.now()
    points, grade = score(findings)
    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    story = [
        Paragraph("Relatório de Auditoria de Segurança Web", styles["Title"]),
        Paragraph(f"<b>Alvo:</b> {escape(target)} &nbsp;&nbsp; <b>Data:</b> {when:%Y-%m-%d %H:%M}", body),
        Spacer(1, 0.5 * cm),
    ]
    failed = [f for f in findings if not f.passed]
    counts = {s: sum(1 for f in failed if f.severity == s) for s in SEV_ORDER}
    summary = Table(
        [["Classificação", "Pontuação", "Problemas", "Verificações OK"],
         [grade, f"{points}/100", str(len(failed)), str(len(findings) - len(failed))]],
        colWidths=[4 * cm] * 4,
    )
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 1), (-1, 1), 16), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("TOPPADDING", (0, 1), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
    ]))
    story += [summary, Spacer(1, 0.3 * cm)]
    story.append(Paragraph(
        "Problemas por gravidade: " + ", ".join(f"{SEV_PT[s]}: {counts[s]}" for s in SEV_ORDER if s != "info"), body))
    story += [Spacer(1, 0.5 * cm), Paragraph("Problemas encontrados e como corrigir", styles["Heading2"])]

    if not failed:
        story.append(Paragraph("Não foram encontrados problemas nas verificações realizadas.", body))
    for f in sorted(failed, key=lambda x: SEV_ORDER.index(x.severity)):
        c = SEV_COLOR[f.severity].hexval()[2:]
        story.append(Paragraph(
            f'<font color="#{c}"><b>[{SEV_PT[f.severity]}]</b></font> <b>{escape(f.title)}</b>', body))
        story.append(Paragraph(escape(f.detail), body))
        story.append(Paragraph(f"<i>Como corrigir:</i> {escape(f.fix)}", body))
        story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Verificações aprovadas", styles["Heading2"]))
    for f in findings:
        if f.passed:
            story.append(Paragraph(f"OK — {escape(f.title)} — {escape(f.detail)}", body))
    story += [Spacer(1, 0.6 * cm), Paragraph(
        "<i>Esta auditoria é automatizada e não substitui um teste de intrusão. Cobre configuração de headers HTTP, "
        "cookies e TLS observáveis externamente na página inicial.</i>", body)]
    SimpleDocTemplate(path, pagesize=A4, title=f"Auditoria {target}", author="siteaudit").build(story)
