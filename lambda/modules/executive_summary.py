from .statistics_calculator import calculate_severity_counts, calculate_compliance_score

def calculate_executive_summary(events, stats):
    severity = calculate_severity_counts(events)
    compliance_score = calculate_compliance_score(events)
    
    pass_fail = 'PASS' if compliance_score >= 90 and severity['critical'] == 0 else 'FAIL'
    risk_posture = determine_risk_posture(severity)
    key_takeaway = generate_key_takeaway(severity)
    business_impact = generate_business_impact(severity)
    top_actions = generate_top_actions(events, severity)
    
    return {
        'compliance_score': compliance_score,
        'pass_fail': pass_fail,
        'risk_posture': risk_posture,
        'severity': severity,
        'key_takeaway': key_takeaway,
        'business_impact': business_impact,
        'top_actions': top_actions
    }

def determine_risk_posture(severity):
    if severity['critical'] > 0:
        return 'CRITICAL'
    elif severity['high'] > 5:
        return 'HIGH'
    elif severity['high'] > 0 or severity['medium'] > 5:
        return 'MEDIUM'
    return 'LOW'

def generate_key_takeaway(severity):
    critical, high, medium = severity['critical'], severity['high'], severity['medium']
    
    if critical > 0:
        return f"{critical} S3 bucket{'s' if critical != 1 else ''} containing patient data {'are' if critical != 1 else 'is'} publicly accessible, creating immediate risk of HIPAA breach and potential penalties up to $1.5M annually."
    elif high > 0:
        return f"{high} S3 bucket{'s' if high != 1 else ''} lack{'s' if high == 1 else ''} critical security controls (encryption/versioning), exposing PHI to unauthorized access and violating HIPAA requirements."
    elif medium > 0:
        return f"{medium} S3 bucket{'s' if medium != 1 else ''} {'are' if medium != 1 else 'is'} missing audit controls and secure transmission policies, creating compliance gaps that require remediation within 30 days."
    return "Your S3 infrastructure meets HIPAA Security Rule requirements. Continue monitoring to maintain compliance posture."

def generate_business_impact(severity):
    critical, high, medium = severity['critical'], severity['high'], severity['medium']
    
    if critical > 0 or high > 0:
        return f"Your organization faces potential HIPAA penalties ranging from $100,000 to $1.5 million due to {critical + high} critical and high-risk violations. Immediate remediation required to avoid OCR enforcement action and protect patient data from unauthorized access."
    elif medium > 0:
        return f"Your organization has {medium} medium-risk compliance gaps that could escalate to violations if not addressed. Remediation within 30 days recommended to maintain HIPAA compliance."
    return "Your organization maintains strong HIPAA compliance posture with no immediate regulatory exposure. Continue monitoring to sustain this status."

def generate_top_actions(events, severity):
    actions = []
    critical, high = severity['critical'], severity['high']
    
    if critical > 0:
        actions.append(f"Block public access on {critical} S3 bucket{'s' if critical != 1 else ''} (within 24 hours)")
    
    if high > 0:
        encryption_count = len([e for e in events if e['configRuleName'] == 's3-bucket-server-side-encryption-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        versioning_count = len([e for e in events if e['configRuleName'] == 's3-bucket-versioning-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        
        if encryption_count > 0:
            actions.append(f"Enable encryption on {encryption_count} unencrypted bucket{'s' if encryption_count != 1 else ''} (within 7 days)")
        if versioning_count > 0 and len(actions) < 3:
            actions.append(f"Enable versioning on {versioning_count} bucket{'s' if versioning_count != 1 else ''} (within 7 days)")
    
    if len(actions) < 3:
        logging_count = len([e for e in events if e['configRuleName'] == 's3-bucket-logging-enabled' and e['complianceType'] == 'NON_COMPLIANT'])
        if logging_count > 0:
            actions.append(f"Enable access logging on {logging_count} bucket{'s' if logging_count != 1 else ''} (within 30 days)")
    
    return actions[:3]
