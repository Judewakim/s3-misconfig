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

def get_rule_severity_category(rule_name):
    critical_rules = ['s3-bucket-public-read-prohibited', 's3-bucket-public-write-prohibited', 's3-bucket-block-public-acl-enabled']
    high_rules = ['s3-bucket-server-side-encryption-enabled', 's3-bucket-versioning-enabled']
    medium_rules = ['s3-bucket-logging-enabled', 's3-bucket-ssl-requests-only']
    low_rules = ['s3-bucket-object-lock-enabled', 's3-bucket-replication-enabled']
    
    if rule_name in critical_rules:
        return 'critical'
    elif rule_name in high_rules:
        return 'high'
    elif rule_name in medium_rules:
        return 'medium'
    elif rule_name in low_rules:
        return 'low'
    return 'unknown'

def get_hipaa_control(rule_name):
    mapping = {
        's3-bucket-public-read-prohibited': '164.308(a)(3)(i)',
        's3-bucket-public-write-prohibited': '164.308(a)(3)(i)',
        's3-bucket-server-side-encryption-enabled': '164.312(a)(2)(iv)',
        's3-bucket-versioning-enabled': '164.308(a)(7)(ii)(A)',
        's3-bucket-logging-enabled': '164.312(b)',
        's3-bucket-ssl-requests-only': '164.312(e)(1)',
        's3-bucket-block-public-acl-enabled': '164.308(a)(3)(i)',
        's3-bucket-object-lock-enabled': '164.308(a)(7)(ii)(A)',
        's3-bucket-replication-enabled': '164.308(a)(7)(ii)(A)'
    }
    return mapping.get(rule_name, 'N/A')

def calculate_severity_counts(events):
    critical_rules = ['s3-bucket-public-read-prohibited', 's3-bucket-public-write-prohibited', 's3-bucket-block-public-acl-enabled']
    high_rules = ['s3-bucket-server-side-encryption-enabled', 's3-bucket-versioning-enabled']
    medium_rules = ['s3-bucket-logging-enabled', 's3-bucket-ssl-requests-only']
    low_rules = ['s3-bucket-object-lock-enabled', 's3-bucket-replication-enabled']
    
    return {
        'critical': len([e for e in events if e['configRuleName'] in critical_rules and e['complianceType'] == 'NON_COMPLIANT']),
        'high': len([e for e in events if e['configRuleName'] in high_rules and e['complianceType'] == 'NON_COMPLIANT']),
        'medium': len([e for e in events if e['configRuleName'] in medium_rules and e['complianceType'] == 'NON_COMPLIANT']),
        'low': len([e for e in events if e['configRuleName'] in low_rules and e['complianceType'] == 'NON_COMPLIANT'])
    }

def calculate_compliance_score(events):
    total_checks = len(events)
    compliant = len([e for e in events if e['complianceType'] == 'COMPLIANT'])
    return round((compliant / total_checks * 100)) if total_checks > 0 else 100
