"""
WakimWorks HIPAA Compliance Report - Data Processing
Calculates compliance metrics and categorizes findings
"""

def calculate_risk_posture(events):
    """Determines overall risk posture based on findings"""
    if not events:
        return 'LOW'
    
    critical_rules = [
        's3-bucket-public-read-prohibited',
        's3-bucket-public-write-prohibited',
        's3-bucket-block-public-acl-enabled'
    ]
    
    non_compliant = [e for e in events if e.get('complianceType') == 'NON_COMPLIANT']
    critical_violations = [e for e in non_compliant if e.get('configRuleName') in critical_rules]
    
    if len(critical_violations) >= 3:
        return 'CRITICAL'
    elif len(critical_violations) >= 1:
        return 'HIGH'
    elif len(non_compliant) >= 10:
        return 'MEDIUM'
    else:
        return 'LOW'

def calculate_compliance_score(events):
    """Calculates compliance score as percentage"""
    if not events:
        return 100
    
    resource_rule_map = {}
    for event in events:
        key = f"{event['resourceId']}-{event['configRuleName']}"
        if key not in resource_rule_map or event['timestamp'] > resource_rule_map[key]['timestamp']:
            resource_rule_map[key] = event
    
    latest_events = list(resource_rule_map.values())
    total = len(latest_events)
    compliant = len([e for e in latest_events if e.get('complianceType') == 'COMPLIANT'])
    
    return round((compliant / total) * 100) if total > 0 else 0

def categorize_findings(events):
    """Categorizes findings by severity"""
    critical_rules = [
        's3-bucket-public-read-prohibited',
        's3-bucket-public-write-prohibited',
        's3-bucket-block-public-acl-enabled'
    ]
    
    high_rules = [
        's3-bucket-server-side-encryption-enabled',
        's3-bucket-logging-enabled'
    ]
    
    medium_rules = [
        's3-bucket-versioning-enabled',
        's3-bucket-ssl-requests-only',
        's3-bucket-object-lock-enabled'
    ]
    
    low_rules = [
        's3-bucket-replication-enabled'
    ]
    
    non_compliant = [e for e in events if e.get('complianceType') == 'NON_COMPLIANT']
    
    return {
        'critical': [e for e in non_compliant if e.get('configRuleName') in critical_rules],
        'high': [e for e in non_compliant if e.get('configRuleName') in high_rules],
        'medium': [e for e in non_compliant if e.get('configRuleName') in medium_rules],
        'low': [e for e in non_compliant if e.get('configRuleName') in low_rules]
    }

def get_pass_fail_status(compliance_score):
    """Determines pass/fail based on compliance score"""
    return 'PASS' if compliance_score >= 90 else 'FAIL'

def get_key_takeaway(risk_posture, critical_count, compliance_score):
    """Generates executive summary takeaway"""
    if risk_posture == 'CRITICAL':
        return f"Your S3 environment has {critical_count} critical public access violations exposing potential PHI to unauthorized access. Immediate remediation required to prevent HIPAA violations."
    elif risk_posture == 'HIGH':
        return f"Your S3 environment has {critical_count} critical security gaps that require immediate attention. Current compliance score of {compliance_score}% indicates significant risk to PHI security."
    elif risk_posture == 'MEDIUM':
        return f"Your S3 environment shows moderate compliance gaps with a {compliance_score}% compliance score. Several improvements needed to meet HIPAA requirements."
    else:
        return f"Your S3 environment demonstrates strong compliance with a {compliance_score}% score. Continue monitoring and address remaining gaps to maintain HIPAA compliance."

def get_business_risk_translation(risk_posture, critical_count):
    """Translates technical findings to business impact"""
    if risk_posture in ['CRITICAL', 'HIGH']:
        return {
            'regulatory_exposure': f"Potential HIPAA violation with fines up to $1.5M per incident. {critical_count} critical findings require immediate remediation.",
            'data_breach_risk': "High likelihood of unauthorized PHI access. Data breach notification may be required under HIPAA Breach Notification Rule.",
            'operational_impact': "Business continuity at risk. Potential service disruption during emergency remediation."
        }
    elif risk_posture == 'MEDIUM':
        return {
            'regulatory_exposure': "Moderate HIPAA compliance risk. Findings should be addressed within 30 days to avoid violations.",
            'data_breach_risk': "Moderate risk of PHI exposure. Implement recommended controls to reduce breach likelihood.",
            'operational_impact': "Planned remediation recommended. No immediate business disruption expected."
        }
    else:
        return {
            'regulatory_exposure': "Low HIPAA compliance risk. Continue monitoring and maintain current security posture.",
            'data_breach_risk': "Low risk of PHI exposure. Existing controls provide adequate protection.",
            'operational_impact': "Normal operations. Continue routine compliance monitoring."
        }

def get_top_recommendations(categorized_findings):
    """Generates top 3 priority recommendations"""
    recommendations = []
    
    if categorized_findings['critical']:
        recommendations.append({
            'priority': 'CRITICAL',
            'action': 'Immediately block public access on all buckets containing PHI',
            'time': '15 minutes'
        })
    
    if categorized_findings['high']:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Enable server-side encryption (AES-256 or KMS) on all PHI buckets',
            'time': '30 minutes'
        })
    
    if categorized_findings['medium']:
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Enable versioning and logging for audit trail compliance',
            'time': '1 hour'
        })
    
    return recommendations[:3]

def get_remediation_status(events):
    """Determines which findings were auto-remediated vs manual"""
    auto_remediated_rules = [
        's3-bucket-public-read-prohibited',
        's3-bucket-public-write-prohibited',
        's3-bucket-server-side-encryption-enabled',
        's3-bucket-versioning-enabled',
        's3-bucket-block-public-acl-enabled'
    ]
    
    manual_rules = [
        's3-bucket-logging-enabled',
        's3-bucket-ssl-requests-only',
        's3-bucket-object-lock-enabled',
        's3-bucket-replication-enabled'
    ]
    
    non_compliant = [e for e in events if e.get('complianceType') == 'NON_COMPLIANT']
    
    return {
        'auto_remediated': [e for e in non_compliant if e.get('configRuleName') in auto_remediated_rules],
        'manual_required': [e for e in non_compliant if e.get('configRuleName') in manual_rules]
    }
