import os
from datetime import datetime
from typing import List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from app.db.models import Scan, FindingModel
from app.core.config import settings

def generate_pdf_report(scan: Scan, findings: List[FindingModel]) -> str:
    """
    Generates a professional executive security assessment report in PDF format.
    Returns absolute filepath of generated PDF.
    """
    filename = f"scan_report_{scan.id}.pdf"
    filepath = os.path.join(settings.REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#1E293B')
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#64748B')
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#0F172A'),
        backColor=colors.HexColor('#F1F5F9'),
        borderColor=colors.HexColor('#CBD5E1'),
        borderWidth=0.5,
        borderPadding=4
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("Web Application Security Assessment Report", title_style))
    story.append(Spacer(1, 4))
    formatted_date = scan.start_time.strftime("%B %d, %Y - %H:%M:%S UTC") if scan.start_time else "N/A"
    story.append(Paragraph(f"Target Host: <b>{scan.target_url}</b> | Scan Date: {formatted_date}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3B82F6'), spaceAfter=15))

    # 2. Executive Summary Badge & Score
    score = scan.security_score
    if score >= 80:
        score_color = colors.HexColor('#10B981')  # Green
        score_color_hex = '#10B981'
        status_text = "GOOD SECURITY POSTURE"
    elif score >= 50:
        score_color = colors.HexColor('#F59E0B')  # Yellow
        score_color_hex = '#F59E0B'
        status_text = "MODERATE RISK EXPOSURE"
    else:
        score_color = colors.HexColor('#EF4444')  # Red
        score_color_hex = '#EF4444'
        status_text = "HIGH RISK / CRITICAL VULNERABILITIES"

    summary_data = [
        [
            Paragraph("<b>Overall Security Score</b>", body_style),
            Paragraph(f"<font size=18 color='{score_color_hex}'><b>{score:.1f} / 100</b></font><br/><font size=8 color='#64748B'>{status_text}</font>", body_style),
            Paragraph(f"<b>Total Findings:</b> {scan.total_findings}<br/><b>Total Crawled Pages:</b> {scan.total_urls_crawled}<br/><b>Duration:</b> {scan.duration_seconds:.1f}s", body_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[2.2*inch, 2.5*inch, 2.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BORDER', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # 3. Severity Breakdown Table
    story.append(Paragraph("Vulnerability Severity Breakdown", h2_style))
    sev_data = [
        ["Severity Level", "Count", "Risk Level Description"],
        ["CRITICAL", str(scan.critical_count), "Direct compromise, credentials leak, or full source disclosure"],
        ["HIGH", str(scan.high_count), "Insecure transport, weak cookie auth flags, CORS misconfigurations"],
        ["MEDIUM", str(scan.medium_count), "Missing CSP/HSTS security headers, sensitive comments"],
        ["LOW", str(scan.low_count), "Server header version leakage, missing Referrer-Policy"],
        ["INFO", str(scan.info_count), "Informational discoveries, public robots.txt files"]
    ]

    sev_table = Table(sev_data, colWidths=[1.5*inch, 1.0*inch, 4.7*inch])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#DC2626')),
        ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#EA580C')),
        ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#D97706')),
        ('TEXTCOLOR', (0, 4), (0, 4), colors.HexColor('#2563EB')),
        ('TEXTCOLOR', (0, 5), (0, 5), colors.HexColor('#64748B')),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 20))

    # 4. Detailed Findings Section
    story.append(Paragraph("Detailed Security Findings", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=10))

    if not findings:
        story.append(Paragraph("<i>No security vulnerabilities detected during this scan.</i>", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev_colors = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EA580C",
                "MEDIUM": "#D97706",
                "LOW": "#2563EB",
                "INFO": "#64748B"
            }
            c_code = sev_colors.get(f.severity.upper(), "#64748B")

            card_content = [
                [
                    Paragraph(f"<b>#{idx}. {f.title}</b>", ParagraphStyle('FTitle', parent=body_style, fontSize=11, fontName='Helvetica-Bold', textColor=colors.HexColor('#0F172A'))),
                    Paragraph(f"<font color='{c_code}'><b>[{f.severity.upper()}]</b></font>", ParagraphStyle('FSev', parent=body_style, alignment=2))
                ],
                [
                    Paragraph(f"<b>Affected URL:</b> {f.url}<br/><b>Category:</b> {f.category} | <b>CWE:</b> {f.cwe_id or 'N/A'}", body_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Description:</b> {f.description}", body_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Evidence:</b><br/>{f.evidence or 'N/A'}", code_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Remediation Guide:</b> {f.remediation}", body_style),
                    ""
                ]
            ]

            card_table = Table(card_content, colWidths=[5.5*inch, 1.7*inch])
            card_table.setStyle(TableStyle([
                ('SPAN', (0, 1), (1, 1)),
                ('SPAN', (0, 2), (1, 2)),
                ('SPAN', (0, 3), (1, 3)),
                ('SPAN', (0, 4), (1, 4)),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FAFAFA')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
                ('LINEBELOW', (0, 0), (1, 0), 1, colors.HexColor('#E2E8F0')),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))

            story.append(KeepTogether([card_table, Spacer(1, 12)]))

    doc.build(story)
    return filepath
