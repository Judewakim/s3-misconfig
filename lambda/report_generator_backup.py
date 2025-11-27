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
        path = event.get('rawPath', event.get('path', ''))
        
        # Handle /current-issues endpoint (always returns latest)
        if 'current-issues' in path:
            latest_event = fetch_latest_compliance_event()
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps(latest_event)
            }
        
        # Handle /compliance-events endpoint (filtered by days)
        if 'compliance-events' in path:
            params = event.get('queryStringParameters', {})
            days = int(params.get('days', 30))
            events = fetch_compliance_events(days)
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps(events)
            }
        
        # Handle /generate-report endpoint (PDF generation)
        events = fetch_compliance_events(30)
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

def fetch_compliance_events(days=30):
    from datetime import timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    response = s3.list_objects_v2(Bucket=bucket, Prefix='compliance-events/')
    events = []
    for obj in response.get('Contents', []):
        # Filter by LastModified timestamp
        if obj['LastModified'].replace(tzinfo=None) >= cutoff_date:
            event_obj = s3.get_object(Bucket=bucket, Key=obj['Key'])
            events.append(json.loads(event_obj['Body'].read()))
    return sorted(events, key=lambda x: x['timestamp'], reverse=True)

def fetch_latest_compliance_event():
    response = s3.list_objects_v2(Bucket=bucket, Prefix='compliance-events/', MaxKeys=1)
    if not response.get('Contents'):
        return {'events': [], 'timestamp': None}
    
    # Get the most recent event
    latest_obj = sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)[0]
    event_obj = s3.get_object(Bucket=bucket, Key=latest_obj['Key'])
    event = json.loads(event_obj['Body'].read())
    
    return {
        'event': event,
        'timestamp': event['timestamp'],
        'scanTime': latest_obj['LastModified'].isoformat()
    }

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

def calculate_executive_summary(events, stats):
    # Categorize by severity
    critical_rules = ['s3-bucket-public-read-prohibited', 's3-bucket-public-write-prohibited', 's3-bucket-block-public-acl-enabled']
    high_rules = ['s3-bucket-server-side-encryption-enabled', 's3-bucket-versioning-enabled']
    medium_rules = ['s3-bucket-logging-enabled', 's3-bucket-ssl-requests-only']
    low_rules = ['s3-bucket-object-lock-enabled', 's3-bucket-replication-enabled']
    
    critical = len([e for e in events if e['configRuleName'] in critical_rules and e['complianceType'] == 'NON_COMPLIANT'])
    high = len([e for e in events if e['configRuleName'] in high_rules and e['complianceType'] == 'NON_COMPLIANT'])
    medium = len([e for e in events if e['configRuleName'] in medium_rules and e['complianceType'] == 'NON_COMPLIANT'])
    low = len([e for e in events if e['configRuleName'] in low_rules and e['complianceType'] == 'NON_COMPLIANT'])
    
    # Calculate compliance score
    total_checks = len(events)
    compliant = len([e for e in events if e['complianceType'] == 'COMPLIANT'])
    compliance_score = round((compliant / total_checks * 100)) if total_checks > 0 else 100
    
    # Determine pass/fail and risk posture
    pass_fail = 'PASS' if compliance_score >= 90 and critical == 0 else 'FAIL'
    if critical > 0:
        risk_posture = 'CRITICAL'
    elif high > 5:
        risk_posture = 'HIGH'
    elif high > 0 or medium > 5:
        risk_posture = 'MEDIUM'
    else:
        risk_posture = 'LOW'
    
    # Generate key takeaway
    if critical > 0:
        key_takeaway = f"{critical} S3 bucket{'s' if critical != 1 else ''} containing patient data {'are' if critical != 1 else 'is'} publicly accessible, creating immediate risk of HIPAA breach and potential penalties up to $1.5M annually."
    elif high > 0:
        key_takeaway = f"{high} S3 bucket{'s' if high != 1 else ''} lack{'s' if high == 1 else ''} critical security controls (encryption/versioning), exposing PHI to unauthorized access and violating HIPAA requirements."
    elif medium > 0:
        key_takeaway = f"{medium} S3 bucket{'s' if medium != 1 else ''} {'are' if medium != 1 else 'is'} missing audit controls and secure transmission policies, creating compliance gaps that require remediation within 30 days."
    else:
        key_takeaway = "Your S3 infrastructure meets HIPAA Security Rule requirements. Continue monitoring to maintain compliance posture."
    
    # Generate business impact
    if critical > 0 or high > 0:
        business_impact = f"Your organization faces potential HIPAA penalties ranging from $100,000 to $1.5 million due to {critical + high} critical and high-risk violations. Immediate remediation required to avoid OCR enforcement action and protect patient data from unauthorized access."
    elif medium > 0:
        business_impact = f"Your organization has {medium} medium-risk compliance gaps that could escalate to violations if not addressed. Remediation within 30 days recommended to maintain HIPAA compliance."
    else:
        business_impact = "Your organization maintains strong HIPAA compliance posture with no immediate regulatory exposure. Continue monitoring to sustain this status."
    
    # Generate top 3 actions
    top_actions = []
    if critical > 0:
        top_actions.append(f"Block public access on {critical} S3 bucket{'s' if critical != 1 else ''} (within 24 hours)")
    if high > 0:
        encryption_count = len([e for e in events if e['configRuleName'] == 's3-bucket-server-side-encryption-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        versioning_count = len([e for e in events if e['configRuleName'] == 's3-bucket-versioning-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        if encryption_count > 0:
            top_actions.append(f"Enable encryption on {encryption_count} unencrypted bucket{'s' if encryption_count != 1 else ''} (within 7 days)")
        if versioning_count > 0:
            top_actions.append(f"Enable versioning on {versioning_count} bucket{'s' if versioning_count != 1 else ''} (within 7 days)")
    if medium > 0 and len(top_actions) < 3:
        logging_count = len([e for e in events if e['configRuleName'] == 's3-bucket-logging-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        if logging_count > 0:
            top_actions.append(f"Enable access logging on {logging_count} bucket{'s' if logging_count != 1 else ''} (within 30 days)")
    if low > 0 and len(top_actions) < 3:
        replication_count = len([e for e in events if e['configRuleName'] == 's3-bucket-replication-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        if replication_count > 0:
            top_actions.append(f"Enable cross-region replication on {replication_count} critical data store{'s' if replication_count != 1 else ''} (within 90 days)")
    
    # Ensure we have 3 actions
    if len(top_actions) == 0:
        top_actions = [
            "Continue monitoring S3 buckets for configuration drift",
            "Review and update access policies quarterly",
            "Conduct annual HIPAA compliance audit"
        ]
    elif len(top_actions) < 3:
        top_actions.append("Review all bucket policies for least-privilege access")
    if len(top_actions) < 3:
        top_actions.append("Implement automated compliance monitoring with WakimWorks")
    
    return {
        'pass_fail': pass_fail,
        'compliance_score': compliance_score,
        'risk_posture': risk_posture,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'key_takeaway': key_takeaway,
        'business_impact': business_impact,
        'top_actions': top_actions[:3]
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
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#232f3e'), alignment=TA_CENTER, spaceAfter=12, fontName='Helvetica-Bold')
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#232f3e'), spaceBefore=20, spaceAfter=10, fontName='Helvetica-Bold')
    
    # Logo
    try:
        logo = Image('/var/task/logo.png', width=1.0*inch, height=0.6*inch)
        logo.hAlign = 'CENTER'
        story.append(logo)
        story.append(Spacer(1, 0.2*inch))
    except Exception as e:
        print(f"Logo not found: {e}")
        pass
    
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
    
    # Calculate executive summary metrics
    exec_summary = calculate_executive_summary(events, stats)
    
    # Compliance Verdict
    verdict_style = ParagraphStyle('Verdict', parent=styles['Normal'], fontSize=11, fontName='Helvetica-Bold', spaceAfter=6)
    story.append(Paragraph(f"COMPLIANCE VERDICT: {exec_summary['pass_fail']} ({exec_summary['compliance_score']}% compliant)", verdict_style))
    story.append(Paragraph(f"RISK POSTURE: {exec_summary['risk_posture']}", verdict_style))
    story.append(Spacer(1, 0.15*inch))
    
    # Key Takeaway
    story.append(Paragraph(exec_summary['key_takeaway'], styles['Normal']))
    story.append(Spacer(1, 0.15*inch))
    
    # Risk Breakdown
    story.append(Paragraph("RISK BREAKDOWN:", verdict_style))
    risk_text = f"• Critical: {exec_summary['critical']} | High: {exec_summary['high']} | Medium: {exec_summary['medium']} | Low: {exec_summary['low']}"
    story.append(Paragraph(risk_text, styles['Normal']))
    story.append(Spacer(1, 0.15*inch))
    
    # Business Impact
    story.append(Paragraph("BUSINESS IMPACT:", verdict_style))
    story.append(Paragraph(exec_summary['business_impact'], styles['Normal']))
    story.append(Spacer(1, 0.15*inch))
    
    # Top 3 Actions
    story.append(Paragraph("TOP 3 ACTIONS:", verdict_style))
    for i, action in enumerate(exec_summary['top_actions'], 1):
        story.append(Paragraph(f"{i}. {action}", styles['Normal']))
        story.append(Spacer(1, 0.08*inch))
    
    story.append(Spacer(1, 0.3*inch))
    
    # HIPAA Control Mapping
    story.append(Paragraph("HIPAA Control Mapping", heading_style))
    hipaa_data = [['HIPAA Control', 'Description', 'Violations']]
    for control, count in stats['hipaa_controls'].items():
        if control != 'N/A':
            description = get_hipaa_description(control)
            # Limit description to 60 characters
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
