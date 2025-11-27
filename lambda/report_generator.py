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
    
    # Get bucket names for violations
    critical_buckets = list(set([e['resourceId'] for e in events if e['configRuleName'] in critical_rules and e['complianceType'] == 'NON_COMPLIANT']))
    high_buckets = list(set([e['resourceId'] for e in events if e['configRuleName'] in high_rules and e['complianceType'] == 'NON_COMPLIANT']))
    
    # Generate key takeaway with bucket names
    if critical > 0:
        bucket_list = ', '.join(critical_buckets[:3])
        if len(critical_buckets) > 3:
            bucket_list += f" and {len(critical_buckets) - 3} more"
        key_takeaway = f"{critical} S3 bucket{'s' if critical != 1 else ''} ({bucket_list}) containing patient data {'are' if critical != 1 else 'is'} publicly accessible, creating immediate risk of HIPAA breach and potential penalties up to $1.5M annually."
    elif high > 0:
        bucket_list = ', '.join(high_buckets[:3])
        if len(high_buckets) > 3:
            bucket_list += f" and {len(high_buckets) - 3} more"
        key_takeaway = f"{high} S3 bucket{'s' if high != 1 else ''} ({bucket_list}) lack{'s' if high == 1 else ''} critical security controls (encryption/versioning), exposing PHI to unauthorized access and violating HIPAA requirements."
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
    
    # Generate top 3 actions with bucket names
    top_actions = []
    if critical > 0:
        bucket_names = ', '.join(critical_buckets[:2])
        if len(critical_buckets) > 2:
            bucket_names += f" and {len(critical_buckets) - 2} more"
        top_actions.append(f"Block public access on {bucket_names} (within 24 hours)")
    if high > 0:
        encryption_buckets = [e['resourceId'] for e in events if e['configRuleName'] == 's3-bucket-server-side-encryption-enabled' and e['complianceType'] == 'NON_COMPLIANT']
        versioning_buckets = [e['resourceId'] for e in events if e['configRuleName'] == 's3-bucket-versioning-enabled' and e['complianceType'] == 'NON_COMPLIANT']
        if encryption_buckets:
            bucket_names = ', '.join(encryption_buckets[:2])
            if len(encryption_buckets) > 2:
                bucket_names += f" and {len(encryption_buckets) - 2} more"
            top_actions.append(f"Enable encryption on {bucket_names} (within 7 days)")
        if versioning_buckets and len(top_actions) < 3:
            bucket_names = ', '.join(versioning_buckets[:2])
            if len(versioning_buckets) > 2:
                bucket_names += f" and {len(versioning_buckets) - 2} more"
            top_actions.append(f"Enable versioning on {bucket_names} (within 7 days)")
    if medium > 0 and len(top_actions) < 3:
        logging_buckets = [e['resourceId'] for e in events if e['configRuleName'] == 's3-bucket-logging-enabled' and e['complianceType'] == 'NON_COMPLIANT']
        if logging_buckets:
            bucket_names = ', '.join(logging_buckets[:2])
            if len(logging_buckets) > 2:
                bucket_names += f" and {len(logging_buckets) - 2} more"
            top_actions.append(f"Enable access logging on {bucket_names} (within 30 days)")
    if low > 0 and len(top_actions) < 3:
        replication_buckets = [e['resourceId'] for e in events if e['configRuleName'] == 's3-bucket-replication-enabled' and e['complianceType'] == 'NON_COMPLIANT']
        if replication_buckets:
            bucket_names = ', '.join(replication_buckets[:2])
            if len(replication_buckets) > 2:
                bucket_names += f" and {len(replication_buckets) - 2} more"
            top_actions.append(f"Enable cross-region replication on {bucket_names} (within 90 days)")
    
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

def calculate_remediation_metrics(events):
    # Track resources that changed to compliant during assessment period
    resource_status = {}
    for event in sorted(events, key=lambda x: x['timestamp']):
        key = f"{event['resourceId']}:{event['configRuleName']}"
        if key not in resource_status:
            resource_status[key] = []
        resource_status[key].append(event['complianceType'])
    
    # Count transitions from NON_COMPLIANT to COMPLIANT
    remediated_count = sum(1 for statuses in resource_status.values() 
                          if len(statuses) > 1 and statuses[0] == 'NON_COMPLIANT' and statuses[-1] == 'COMPLIANT')
    
    return remediated_count

def get_rule_metadata(rule_name):
    metadata = {
        's3-bucket-public-read-prohibited': {
            'title': 'Block Public Read Access',
            'hipaa_control': '164.308(a)(3)(i)',
            'risk': 'Public exposure of PHI, potential $1.5M penalty',
            'effort': '2 min/bucket',
            'difficulty': 'Easy',
            'impact': '+25% compliance',
            'cli_template': 'aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
        },
        's3-bucket-public-write-prohibited': {
            'title': 'Block Public Write Access',
            'hipaa_control': '164.308(a)(3)(i)',
            'risk': 'Unauthorized data modification, potential $1.5M penalty',
            'effort': '2 min/bucket',
            'difficulty': 'Easy',
            'impact': '+25% compliance',
            'cli_template': 'aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
        },
        's3-bucket-block-public-acl-enabled': {
            'title': 'Enable Public ACL Blocking',
            'hipaa_control': '164.308(a)(3)(i)',
            'risk': 'ACL-based public exposure, potential $1.5M penalty',
            'effort': '2 min/bucket',
            'difficulty': 'Easy',
            'impact': '+20% compliance',
            'cli_template': 'aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
        }
    }
    return metadata.get(rule_name, {})

def generate_recommendations(events):
    critical_rules = ['s3-bucket-public-read-prohibited', 's3-bucket-public-write-prohibited', 's3-bucket-block-public-acl-enabled']
    
    # Group critical violations by rule
    violations_by_rule = {}
    for event in events:
        if event['complianceType'] == 'NON_COMPLIANT' and event['configRuleName'] in critical_rules:
            rule = event['configRuleName']
            if rule not in violations_by_rule:
                violations_by_rule[rule] = []
            violations_by_rule[rule].append(event['resourceId'])
    
    recommendations = []
    for rule, buckets in violations_by_rule.items():
        metadata = get_rule_metadata(rule)
        if metadata:
            recommendations.append({
                'title': metadata['title'],
                'buckets': buckets,
                'count': len(buckets),
                'hipaa_control': metadata['hipaa_control'],
                'risk': metadata['risk'],
                'effort': metadata['effort'],
                'difficulty': metadata['difficulty'],
                'impact': metadata['impact'],
                'cli_commands': [metadata['cli_template'].format(bucket=b) for b in buckets[:3]]  # Limit to 3 examples
            })
    
    return recommendations

def generate_conclusion(events, stats, exec_summary):
    non_compliant = len([e for e in events if e['complianceType'] == 'NON_COMPLIANT'])
    remediated = calculate_remediation_metrics(events)
    
    # Compliance Status
    if exec_summary['pass_fail'] == 'FAIL':
        status = f"Your S3 infrastructure has <b>FAILED</b> this HIPAA assessment with a {exec_summary['compliance_score']}% compliance rate. "
        status += f"Of {stats['affected_resources']} S3 bucket{'s' if stats['affected_resources'] != 1 else ''} analyzed, {non_compliant} violation{'s' if non_compliant != 1 else ''} require{'s' if non_compliant == 1 else ''} immediate attention."
    else:
        status = f"Your S3 infrastructure has <b>PASSED</b> this HIPAA assessment with a {exec_summary['compliance_score']}% compliance rate. "
        if non_compliant > 0:
            status += f"However, {non_compliant} minor gap{'s' if non_compliant != 1 else ''} remain{'s' if non_compliant == 1 else ''} that should be addressed to achieve 100% compliance."
        else:
            status += "Your proactive security posture demonstrates strong commitment to protecting PHI."
    
    # Risk Assessment with Financial Impact
    if exec_summary['critical'] > 0:
        risk = f"Your organization is in a <b>{exec_summary['risk_posture']} RISK</b> posture. "
        risk += f"The {exec_summary['critical']} critical violation{'s' if exec_summary['critical'] != 1 else ''} directly violate{'s' if exec_summary['critical'] == 1 else ''} HIPAA Security Rule controls. "
        risk += f"Based on OCR enforcement actions, organizations with similar violations face penalties of <b>$100,000-$1.5M annually</b>, plus breach notification costs averaging <b>$1.2M</b> if PHI is compromised. "
        risk += f"Estimated remediation effort: <b>8-16 hours</b> of engineering time."
    elif exec_summary['high'] > 0:
        risk = f"Your organization is in a <b>{exec_summary['risk_posture']} RISK</b> posture. "
        risk += f"The {exec_summary['high']} high-severity violation{'s' if exec_summary['high'] != 1 else ''} expose{'s' if exec_summary['high'] == 1 else ''} PHI to unauthorized access. "
        risk += f"Potential penalties range from <b>$10,000-$250,000</b> per violation. "
        risk += f"Estimated remediation effort: <b>4-8 hours</b>."
    elif exec_summary['medium'] > 0:
        risk = f"Your organization is in a <b>{exec_summary['risk_posture']} RISK</b> posture. "
        risk += f"The {exec_summary['medium']} medium-severity gap{'s' if exec_summary['medium'] != 1 else ''} should be addressed within 30 days. "
        risk += f"Estimated remediation effort: <b>2-4 hours</b>."
    else:
        risk = f"Your organization maintains a <b>{exec_summary['risk_posture']} RISK</b> posture with no immediate regulatory exposure."
    
    # Remediation Timeline
    if exec_summary['critical'] > 0:
        timeline = f"<b>IMMEDIATE ACTION REQUIRED:</b> Critical violations must be resolved within <b>24 hours</b>. High-severity issues within <b>7 days</b>. Full compliance achievable within <b>14 days</b>."
    elif exec_summary['high'] > 0:
        timeline = f"<b>ACTION REQUIRED:</b> High-severity violations should be resolved within <b>7 days</b>. Full compliance achievable within <b>30 days</b>."
    elif exec_summary['medium'] > 0:
        timeline = f"<b>RECOMMENDED ACTION:</b> Address medium-severity gaps within <b>30 days</b> to maintain compliance posture."
    else:
        timeline = f"<b>MAINTENANCE MODE:</b> Schedule quarterly compliance scans to detect configuration drift."
    
    # Progress Tracking
    if remediated > 0:
        progress = f"During this assessment period, <b>{remediated} violation{'s' if remediated != 1 else ''} {'were' if remediated != 1 else 'was'} successfully remediated</b>, demonstrating your team's commitment to compliance."
    else:
        progress = None
    
    # Next Steps
    if exec_summary['pass_fail'] == 'FAIL':
        next_steps = [
            "Assign a compliance officer to oversee remediation",
            "Execute fixes using WakimWorks automated remediation tools",
            "Schedule follow-up scan in 7 days to verify compliance",
            "Enable continuous monitoring to prevent configuration drift"
        ]
    else:
        next_steps = [
            "Schedule quarterly compliance scans to maintain this posture",
            "Enable WakimWorks continuous monitoring for real-time alerts",
            "Document current configurations for audit readiness"
        ]
    
    return {
        'status': status,
        'risk': risk,
        'timeline': timeline,
        'progress': progress,
        'next_steps': next_steps
    }

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
    story.append(Paragraph(f"\nRISK POSTURE: {exec_summary['risk_posture']}", verdict_style))
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
    
    # Key Findings - Only show critical and high severity NON_COMPLIANT
    story.append(Paragraph("Key Findings", heading_style))
    critical_rules = ['s3-bucket-public-read-prohibited', 's3-bucket-public-write-prohibited', 's3-bucket-block-public-acl-enabled']
    high_rules = ['s3-bucket-server-side-encryption-enabled', 's3-bucket-versioning-enabled']
    
    findings_data = [['Timestamp', 'Rule Name', 'HIPAA Control', 'Resource ID', 'Status']]
    for event in events[:30]:
        if event['complianceType'] == 'NON_COMPLIANT' and (event['configRuleName'] in critical_rules or event['configRuleName'] in high_rules):
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
    story.append(Paragraph("Remediation Recommendations", heading_style))
    recommendations = generate_recommendations(events)
    
    if recommendations:
        # Code style for CLI commands
        code_style = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, 
                                    textColor=colors.HexColor('#2e2e2e'), backColor=colors.HexColor('#f5f5f5'),
                                    leftIndent=10, rightIndent=10, spaceBefore=4, spaceAfter=4)
        
        for idx, rec in enumerate(recommendations, 1):
            # Recommendation header
            story.append(Paragraph(f"<b>CRITICAL PRIORITY #{idx}: {rec['title']}</b>", verdict_style))
            story.append(Spacer(1, 0.08*inch))
            
            # Metadata table
            meta_data = [
                ['Affected Resources:', f"{rec['count']} bucket{'s' if rec['count'] != 1 else ''}"],
                ['HIPAA Control:', rec['hipaa_control']],
                ['Risk:', rec['risk']],
                ['Effort:', f"{rec['effort']} | Difficulty: {rec['difficulty']} | Impact: {rec['impact']}"],
            ]
            meta_table = Table(meta_data, colWidths=[1.5*inch, 4.5*inch])
            meta_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 0.1*inch))
            
            # CLI Commands
            story.append(Paragraph("<b>AWS CLI Commands:</b>", styles['Normal']))
            story.append(Spacer(1, 0.05*inch))
            for cmd in rec['cli_commands']:
                story.append(Paragraph(cmd, code_style))
                story.append(Spacer(1, 0.03*inch))
            
            if rec['count'] > 3:
                story.append(Paragraph(f"<i>...and {rec['count'] - 3} more bucket{'s' if rec['count'] - 3 != 1 else ''}</i>", styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
            
            story.append(Spacer(1, 0.15*inch))
        
        # GitHub link for additional resources
        story.append(Paragraph("<b>Additional Resources:</b> For Terraform configurations, automation scripts, and detailed implementation guides, visit:", styles['Normal']))
        story.append(Spacer(1, 0.05*inch))
        story.append(Paragraph('<link href="https://github.com/judewakim/s3-misconfig/tree/main/remediation" color="blue">https://github.com/judewakim/s3-misconfig/tree/main/remediation</link>', styles['Normal']))
    else:
        # No critical violations - show summary of other violations
        story.append(Paragraph("<b>No critical violations detected.</b> Your S3 infrastructure meets HIPAA Security Rule requirements for public access controls.", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Show violation summary if there are any non-critical violations
        high_count = len([e for e in events if e['configRuleName'] in ['s3-bucket-server-side-encryption-enabled', 's3-bucket-versioning-enabled'] and e['complianceType'] == 'NON_COMPLIANT'])
        medium_count = len([e for e in events if e['configRuleName'] in ['s3-bucket-logging-enabled', 's3-bucket-ssl-requests-only'] and e['complianceType'] == 'NON_COMPLIANT'])
        low_count = len([e for e in events if e['configRuleName'] in ['s3-bucket-object-lock-enabled', 's3-bucket-replication-enabled'] and e['complianceType'] == 'NON_COMPLIANT'])
        
        if high_count > 0 or medium_count > 0 or low_count > 0:
            story.append(Paragraph("<b>Other Violations Detected:</b>", verdict_style))
            if high_count > 0:
                story.append(Paragraph(f"• High Severity: {high_count} violation{'s' if high_count != 1 else ''} (encryption/versioning)", styles['Normal']))
            if medium_count > 0:
                story.append(Paragraph(f"• Medium Severity: {medium_count} violation{'s' if medium_count != 1 else ''} (logging/SSL)", styles['Normal']))
            if low_count > 0:
                story.append(Paragraph(f"• Low Severity: {low_count} violation{'s' if low_count != 1 else ''} (object lock/replication)", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("While not critical, these violations should be addressed to achieve 100% HIPAA compliance.", styles['Normal']))
        else:
            story.append(Paragraph("Continue monitoring with quarterly compliance scans to maintain this posture.", styles['Normal']))
    
    story.append(Spacer(1, 0.3*inch))
    
    # Conclusion
    story.append(Paragraph("Conclusion", heading_style))
    conclusion = generate_conclusion(events, stats, exec_summary)
    
    # Compliance Status
    story.append(Paragraph(f"<b>COMPLIANCE STATUS:</b> {conclusion['status']}", styles['Normal']))
    story.append(Spacer(1, 0.12*inch))
    
    # Risk Assessment
    story.append(Paragraph(f"<b>RISK ASSESSMENT:</b> {conclusion['risk']}", styles['Normal']))
    story.append(Spacer(1, 0.12*inch))
    
    # Remediation Timeline
    story.append(Paragraph(conclusion['timeline'], styles['Normal']))
    story.append(Spacer(1, 0.12*inch))
    
    # Progress (if any)
    if conclusion['progress']:
        story.append(Paragraph(conclusion['progress'], styles['Normal']))
        story.append(Spacer(1, 0.12*inch))
    
    # Next Steps
    story.append(Paragraph("<b>NEXT STEPS:</b>", verdict_style))
    for i, step in enumerate(conclusion['next_steps'], 1):
        story.append(Paragraph(f"{i}. {step}", styles['Normal']))
        story.append(Spacer(1, 0.06*inch))
    
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("\n\n\n\n<b>Support:</b> WakimWorks provides automated remediation capabilities and continuous monitoring. For assistance, contact <b>judewakim@wakimworks.com</b>.", styles['Normal']))
    
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
