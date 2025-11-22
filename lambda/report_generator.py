import json
import boto3
import os
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT

s3 = boto3.client('s3')
bucket = os.environ['BUCKET_NAME']

def lambda_handler(event, context):
    try:
        events = fetch_compliance_events()
        stats = calculate_statistics(events)
        pdf_bytes = generate_pdf_report(events, stats)
        pdf_key = upload_pdf(pdf_bytes)
        download_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': pdf_key},
            ExpiresIn=300
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'downloadUrl': download_url})
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def fetch_compliance_events():
    response = s3.list_objects_v2(Bucket=bucket, Prefix='compliance-events/')
    events = []
    for obj in response.get('Contents', [])[:100]:
        event_obj = s3.get_object(Bucket=bucket, Key=obj['Key'])
        events.append(json.loads(event_obj['Body'].read()))
    return sorted(events, key=lambda x: x['timestamp'], reverse=True)

def calculate_statistics(events):
    unique_resources = set(e['resourceId'] for e in events)
    hipaa_controls = {}
    for event in events:
        control = get_hipaa_control(event['configRuleName'])
        hipaa_controls[control] = hipaa_controls.get(control, 0) + 1
    
    return {
        'total_violations': len(events),
        'affected_resources': len(unique_resources),
        'hipaa_controls': hipaa_controls
    }

def get_hipaa_control(rule_name):
    mapping = {
        's3-bucket-public-read-prohibited': '164.308(a)(3)(i)',
        's3-bucket-public-write-prohibited': '164.308(a)(3)(i)',
        's3-bucket-server-side-encryption-enabled': '164.312(a)(2)(iv)',
        's3-bucket-versioning-enabled': '164.308(a)(7)(ii)(A)',
        's3-bucket-block-public-acl-enabled': '164.308(a)(3)(i)',
        's3-bucket-logging-enabled': '164.312(b)',
        's3-bucket-ssl-requests-only': '164.312(e)(1)',
        's3-bucket-object-lock-enabled': '164.308(a)(7)(ii)(A)',
        's3-bucket-replication-enabled': '164.308(a)(7)(ii)(A)'
    }
    return mapping.get(rule_name, 'N/A')

def get_hipaa_description(control):
    descriptions = {
        '164.308(a)(3)(i)': 'Access Control - Implement policies to limit access to PHI',
        '164.312(a)(2)(iv)': 'Encryption - Implement encryption for PHI at rest',
        '164.308(a)(7)(ii)(A)': 'Data Backup - Establish retrievable exact copies of PHI',
        '164.312(b)': 'Audit Controls - Implement hardware/software to record activity',
        '164.312(e)(1)': 'Transmission Security - Implement technical security for PHI transmission'
    }
    return descriptions.get(control, 'HIPAA Security Rule Requirement')

def generate_pdf_report(events, stats):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75*inch, bottomMargin=0.75*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#232f3e'), alignment=TA_CENTER, spaceAfter=12)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#232f3e'), spaceBefore=20, spaceAfter=10, borderColor=colors.HexColor('#ff9900'), borderWidth=2, borderPadding=5)
    
    # Logo
    try:
        logo = Image('/var/task/logo.png', width=1.5*inch, height=0.6*inch)
        logo.hAlign = 'CENTER'
        story.append(logo)
        story.append(Spacer(1, 0.2*inch))
    except Exception as e:
        print(f"Logo not found: {e}")
        pass
    
    # Title
    story.append(Paragraph("S3 HIPAA Compliance Assessment Report", title_style))
    story.append(Paragraph("WakimWorks Security Solutions", styles['Normal']))
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
    story.append(Paragraph("This report provides a comprehensive assessment of S3 bucket compliance with HIPAA Security Rule requirements. The assessment identifies configuration gaps that may pose risks to Protected Health Information (PHI) security.", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Summary stats
    summary_data = [
        ['Total Violations', 'Affected Buckets', 'HIPAA Controls'],
        [str(stats['total_violations']), str(stats['affected_resources']), str(len([c for c in stats['hipaa_controls'].keys() if c != 'N/A']))]
    ]
    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232f3e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 20),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#d13212')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BOX', (0, 0), (-1, -1), 2, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # HIPAA Control Mapping
    story.append(Paragraph("HIPAA Control Mapping", heading_style))
    hipaa_data = [['HIPAA Control', 'Description', 'Violations']]
    for control, count in stats['hipaa_controls'].items():
        if control != 'N/A':
            hipaa_data.append([control, get_hipaa_description(control), str(count)])
    
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
    story.append(Spacer(1, 0.3*inch))
    
    # Key Findings
    story.append(Paragraph("Key Findings", heading_style))
    findings_data = [['Timestamp', 'Rule Name', 'HIPAA Control', 'Resource ID', 'Status']]
    for event in events[:30]:
        timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
        findings_data.append([
            timestamp,
            event['configRuleName'][:30],
            get_hipaa_control(event['configRuleName']),
            event['resourceId'][:25],
            event['complianceType']
        ])
    
    findings_table = Table(findings_data, colWidths=[1.2*inch, 1.8*inch, 1*inch, 1.5*inch, 1*inch])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232f3e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')])
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Recommendations
    story.append(Paragraph("Recommendations", heading_style))
    recommendations = [
        "Enable server-side encryption (AES-256 or KMS) on all buckets storing PHI",
        "Block public access on all buckets containing sensitive data",
        "Enable versioning for data recovery and audit trail purposes",
        "Implement bucket logging to maintain audit controls",
        "Enforce SSL/TLS for all data transmission"
    ]
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(Spacer(1, 0.3*inch))
    
    # Conclusion
    story.append(Paragraph("Conclusion", heading_style))
    conclusion_text = f"This assessment identified {stats['total_violations']} compliance violations across {stats['affected_resources']} S3 buckets. Immediate remediation is recommended to ensure HIPAA compliance and protect Protected Health Information (PHI)."
    story.append(Paragraph(conclusion_text, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("WakimWorks Compliance Scanner provides automated remediation capabilities to address these findings. For questions or support, contact judewakim@wakimworks.com.", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    return buffer.getvalue()

def upload_pdf(pdf_bytes):
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    pdf_key = f"reports/compliance-report-{timestamp}.pdf"
    s3.put_object(
        Bucket=bucket,
        Key=pdf_key,
        Body=pdf_bytes,
        ContentType='application/pdf',
        ServerSideEncryption='AES256'
    )
    return pdf_key
