from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from .executive_summary import calculate_executive_summary
from .statistics_calculator import get_hipaa_control

def get_hipaa_description(control):
    descriptions = {
        '164.308(a)(3)(i)': 'Access Control - Implement policies to limit access to PHI',
        '164.312(a)(2)(iv)': 'Encryption - Implement encryption for PHI at rest',
        '164.308(a)(7)(ii)(A)': 'Data Backup - Establish retrievable exact copies of PHI',
        '164.312(b)': 'Audit Controls - Implement hardware/software to record activity',
        '164.312(e)(1)': 'Transmission Security - Implement technical security for PHI transmission',
        '164.308(a)(4)': 'Information Access Management - Implement policies for PHI access'
    }
    return descriptions.get(control, 'HIPAA Security Rule Requirement')

def generate_pdf_report(events, stats):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75*inch, bottomMargin=0.75*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#232f3e'), alignment=TA_CENTER, spaceAfter=12, fontName='Helvetica-Bold')
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#232f3e'), spaceBefore=20, spaceAfter=10, fontName='Helvetica-Bold')
    
    # Title
    story.append(Paragraph("S3 HIPAA Compliance Assessment Report", title_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Meta info
    report_date = datetime.utcnow().strftime('%B %d, %Y')
    account_id = events[0]['awsAccountId'] if events else 'N/A'
    
    meta_data = [
        ['Report Generated:', report_date],
        ['AWS Account ID:', account_id],
        ['Assessment Period:', 'Last 30 Days'],
        ['Compliance Framework:', 'HIPAA Security Rule (45 CFR Part 164)']
    ]
    meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.white)
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    exec_summary = calculate_executive_summary(events, stats)
    
    verdict_style = ParagraphStyle('Verdict', parent=styles['Normal'], fontSize=11, fontName='Helvetica-Bold', spaceAfter=6)
    story.append(Paragraph(f"COMPLIANCE VERDICT: {exec_summary['pass_fail']} ({exec_summary['compliance_score']}% compliant)", verdict_style))
    story.append(Paragraph(f"RISK POSTURE: {exec_summary['risk_posture']}", verdict_style))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph(exec_summary['key_takeaway'], styles['Normal']))
    story.append(Spacer(1, 0.15*inch))
    
    # HIPAA Control Mapping
    story.append(Paragraph("HIPAA Control Mapping", heading_style))
    hipaa_data = [['HIPAA Control', 'Description', 'Violations']]
    for control, count in stats['hipaa_controls'].items():
        if control != 'N/A':
            description = get_hipaa_description(control)
            if len(description) > 60:
                description = description[:57] + '...'
            hipaa_data.append([control, description, str(count)])
    
    if len(hipaa_data) > 1:
        hipaa_table = Table(hipaa_data, colWidths=[1.5*inch, 3.5*inch, 1*inch])
        hipaa_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232f3e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')])
        ]))
        story.append(hipaa_table)
    
    doc.build(story)
    return buffer.getvalue()
