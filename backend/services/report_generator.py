import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import tempfile

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
        # Cover page
        elements.append(Paragraph("Software Supply Chain Risk Assessment", title_style))
        elements.append(Spacer(1, 0.6 * inch))
        elements.append(Paragraph(f"Application: <b>{app.name}</b>", styles['Heading3']))
        elements.append(Paragraph(f"Owner: {app.owner}", normal))
        elements.append(Paragraph(f"Business Criticality: {app.business_criticality}", normal))
        elements.append(Paragraph(f"Risk Score: {app.risk_score} ({app.risk_level.upper()})", normal))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal))
        elements.append(Spacer(1, 0.4 * inch))
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
        elements.append(Spacer(1, 0.2 * inch))

        # Generate small charts (risk distribution by severity, top CVEs)
        try:
            # risk by severity pie
            severities = {'critical':0,'high':0,'medium':0,'low':0}
            for d in deps:
                for v in d.vulnerabilities:
                    sev = (v.severity or 'low').lower()
                    if sev in severities:
                        severities[sev] += 1
            fig1, ax1 = plt.subplots(figsize=(3,3))
            labels = [k.capitalize() for k in severities.keys()]
            vals = list(severities.values())
            colors_list = ['#212529','#dc3545','#ffc107','#00d4aa']
            ax1.pie(vals, labels=labels, colors=colors_list, autopct=lambda p: '{:.0f}'.format(p*sum(vals)/100) if sum(vals)>0 else '')
            ax1.set_title('Vulnerabilities by Severity')
            tmp1 = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            fig1.savefig(tmp1.name, bbox_inches='tight')
            plt.close(fig1)
            elements.append(Image(tmp1.name, width=3*inch, height=3*inch))
        except Exception:
            pass

        elements.append(Spacer(1, 0.2 * inch))

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
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph("Vulnerability Summary", heading_style))

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

        elements.append(Spacer(1, 0.3 * inch))

        # License conflicts
        try:
            from backend.models import LicenseRecord
            conflicts = LicenseRecord.query.filter_by(compatibility='conflict').count()
        except Exception:
            conflicts = 0
        elements.append(Paragraph('License Conflicts', heading_style))
        elements.append(Paragraph(f'Total conflicts detected: {conflicts}', normal))
        elements.append(Spacer(1, 0.2 * inch))

        # Maintenance score (simple heuristic: percent of outdated deps)
        outdated = sum(1 for d in deps if d.is_outdated)
        maintenance_score = 100 - (outdated / len(deps) * 100) if deps else 100
        elements.append(Paragraph('Maintenance Score', heading_style))
        elements.append(Paragraph(f'Score: {int(maintenance_score)} / 100', normal))
        elements.append(Spacer(1, 0.2 * inch))

        # Recommendations (simple autogenerated bullets)
        elements.append(Paragraph('Recommendations', heading_style))
        recs = []
        if top_vulns:
            recs.append('Prioritize fixing the top CVEs listed in this report, starting with highest CVSS scores.')
        if conflicts:
            recs.append('Resolve license conflicts to avoid compliance risks.')
        if outdated:
            recs.append('Update outdated libraries to supported versions to reduce maintenance risk.')
        if not recs:
            recs.append('No immediate recommendations; continue regular scanning and monitoring.')
        for r in recs:
            elements.append(Paragraph('- ' + r, normal))

        # Add a page break before any detailed tables
        elements.append(PageBreak())

        doc.build(elements)
        return filename, filepath
