import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from backend.models import Application, Dependency, Vulnerability, Scan


class PDFReportGenerator:
    """Generates enterprise PDF security assessment reports."""

    def generate(self, application_id, scan_id, output_dir):
        app = Application.query.get(application_id)
        if not app:
            raise ValueError(f"Application {application_id} not found")

        scan = Scan.query.get(scan_id) if scan_id else None
        deps = Dependency.query.filter_by(application_id=application_id).all()
        vuln_count = sum(d.vulnerabilities.count() for d in deps)

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"SBOM_Report_{app.name.replace(' ', '_')}_{timestamp}.pdf"
        filepath = os.path.join(output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=letter, topMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor("#1a3a5c"))
        heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#2c5f8a"))
        normal = styles["Normal"]

        elements = []
        elements.append(Paragraph("Software Supply Chain Risk Assessment", title_style))
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(f"<b>Application:</b> {app.name}", normal))
        elements.append(Paragraph(f"<b>Owner:</b> {app.owner}", normal))
        elements.append(Paragraph(f"<b>Business Criticality:</b> {app.business_criticality}", normal))
        elements.append(Paragraph(f"<b>Risk Score:</b> {app.risk_score} ({app.risk_level.upper()})", normal))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Executive Summary", heading_style))
        summary_data = [
            ["Metric", "Value"],
            ["Total Dependencies", str(len(deps))],
            ["Total Vulnerabilities", str(vuln_count)],
            ["Risk Level", app.risk_level.upper()],
            ["Risk Score", f"{app.risk_score}"],
        ]
        if scan:
            summary_data.append(["Scan Date", scan.created_at.strftime("%Y-%m-%d")])

        summary_table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Top Risk Dependencies", heading_style))
        top_deps = sorted(deps, key=lambda d: d.risk_contribution, reverse=True)[:15]
        dep_data = [["Package", "Version", "Risk Score", "License", "Outdated"]]
        for d in top_deps:
            dep_data.append([
                d.name[:30],
                d.version or "N/A",
                f"{d.risk_contribution}",
                d.license_name or "Unknown",
                "Yes" if d.is_outdated else "No",
            ])

        dep_table = Table(dep_data, colWidths=[2 * inch, 1 * inch, 1 * inch, 1.2 * inch, 0.8 * inch])
        dep_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ]))
        elements.append(dep_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Vulnerability Summary", heading_style))
        all_vulns = []
        for d in deps:
            for v in d.vulnerabilities:
                all_vulns.append(v)
        top_vulns = sorted(all_vulns, key=lambda v: v.cvss_score, reverse=True)[:10]

        if top_vulns:
            vuln_data = [["CVE ID", "Severity", "CVSS", "Package", "Patch"]]
            for v in top_vulns:
                vuln_data.append([
                    v.cve_id,
                    v.severity.upper(),
                    f"{v.cvss_score}",
                    v.dependency.name[:25],
                    "Yes" if v.patch_available else "No",
                ])
            vuln_table = Table(vuln_data, colWidths=[1.3 * inch, 0.8 * inch, 0.7 * inch, 2 * inch, 0.7 * inch])
            vuln_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
            ]))
            elements.append(vuln_table)
        else:
            elements.append(Paragraph("No vulnerabilities detected.", normal))

        doc.build(elements)
        return filename, filepath
