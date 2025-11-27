"""
WakimWorks HIPAA Compliance Report - Data Mappings & Glossary
Centralized data definitions for HIPAA controls, AWS services, and terminology
"""

# HIPAA Control Mappings
HIPAA_CONTROL_MAPPING = {
    's3-bucket-public-read-prohibited': {
        'control': '164.308(a)(3)(i)',
        'safeguard_type': 'Technical',
        'description': 'Workforce Clearance - Implement procedures to determine access to PHI',
        'aws_config': 'Public read access must be blocked',
        'risk_level': 'CRITICAL'
    },
    's3-bucket-public-write-prohibited': {
        'control': '164.308(a)(3)(i)',
        'safeguard_type': 'Technical',
        'description': 'Workforce Clearance - Implement procedures to determine access to PHI',
        'aws_config': 'Public write access must be blocked',
        'risk_level': 'CRITICAL'
    },
    's3-bucket-block-public-acl-enabled': {
        'control': '164.308(a)(3)(i)',
        'safeguard_type': 'Technical',
        'description': 'Workforce Clearance - Implement procedures to determine access to PHI',
        'aws_config': 'Block public ACLs setting must be enabled',
        'risk_level': 'CRITICAL'
    },
    's3-bucket-server-side-encryption-enabled': {
        'control': '164.312(a)(2)(iv)',
        'safeguard_type': 'Technical',
        'description': 'Encryption and Decryption - Implement mechanism to encrypt/decrypt PHI',
        'aws_config': 'Server-side encryption (AES-256 or KMS) must be enabled',
        'risk_level': 'HIGH'
    },
    's3-bucket-versioning-enabled': {
        'control': '164.308(a)(7)(ii)(A)',
        'safeguard_type': 'Technical',
        'description': 'Data Backup Plan - Establish procedures for exact copies of PHI',
        'aws_config': 'Versioning must be enabled for data recovery',
        'risk_level': 'HIGH'
    },
    's3-bucket-logging-enabled': {
        'control': '164.312(b)',
        'safeguard_type': 'Technical',
        'description': 'Audit Controls - Record and examine system activity',
        'aws_config': 'Server access logging must be enabled',
        'risk_level': 'MEDIUM'
    },
    's3-bucket-ssl-requests-only': {
        'control': '164.312(e)(1)',
        'safeguard_type': 'Technical',
        'description': 'Transmission Security - Implement technical security for PHI in transit',
        'aws_config': 'Bucket policy must enforce SSL/TLS for all requests',
        'risk_level': 'MEDIUM'
    },
    's3-bucket-object-lock-enabled': {
        'control': '164.308(a)(7)(ii)(A)',
        'safeguard_type': 'Technical',
        'description': 'Data Backup Plan - Establish procedures for exact copies of PHI',
        'aws_config': 'Object Lock for WORM (Write Once Read Many) compliance',
        'risk_level': 'LOW'
    },
    's3-bucket-replication-enabled': {
        'control': '164.308(a)(7)(ii)(A)',
        'safeguard_type': 'Technical',
        'description': 'Data Backup Plan - Establish procedures for exact copies of PHI',
        'aws_config': 'Cross-region replication for disaster recovery',
        'risk_level': 'LOW'
    }
}

# HIPAA Safeguard Categories
SAFEGUARD_CATEGORIES = {
    'Administrative': {
        'description': 'Administrative actions, policies, and procedures to manage security measures',
        'controls': ['164.308(a)(1)(i)', '164.308(a)(3)(i)', '164.308(a)(7)(ii)(A)']
    },
    'Physical': {
        'description': 'Physical measures, policies, and procedures to protect electronic systems',
        'controls': ['164.310(a)(1)', '164.310(d)(1)']
    },
    'Technical': {
        'description': 'Technology and related policies to protect and control access to PHI',
        'controls': ['164.312(a)(2)(iv)', '164.312(b)', '164.312(e)(1)']
    }
}

# Glossary Terms
GLOSSARY_TERMS = {
    'PHI': 'Protected Health Information - Any information about health status, provision of healthcare, or payment for healthcare that can be linked to an individual',
    'HIPAA': 'Health Insurance Portability and Accountability Act - Federal law requiring creation of national standards to protect sensitive patient health information',
    'OCR': 'Office for Civil Rights - HHS division responsible for HIPAA enforcement',
    'S3': 'Amazon Simple Storage Service - Object storage service offering scalability, data availability, security, and performance',
    'Encryption at Rest': 'Data encryption while stored on disk (AES-256 or AWS KMS)',
    'Encryption in Transit': 'Data encryption during transmission (SSL/TLS protocols)',
    'Bucket Policy': 'JSON-based access policy attached to S3 buckets controlling access permissions',
    'ACL': 'Access Control List - Legacy S3 access control mechanism (AWS recommends bucket policies instead)',
    'Versioning': 'S3 feature that keeps multiple variants of an object for recovery and audit purposes',
    'Object Lock': 'S3 feature that prevents object deletion or overwrite for a fixed time or indefinitely (WORM)',
    'Server Access Logging': 'Detailed records of requests made to an S3 bucket for audit purposes',
    'Cross-Region Replication': 'Automatic, asynchronous copying of objects across S3 buckets in different AWS regions',
    'KMS': 'AWS Key Management Service - Managed service for creating and controlling encryption keys',
    'EventBridge': 'AWS serverless event bus service for application integration and compliance monitoring',
    'AWS Config': 'AWS service that assesses, audits, and evaluates configurations of AWS resources',
    'Compliance Score': 'Percentage of compliant resources out of total evaluated resources',
    'Non-Compliant': 'Resource configuration that violates defined compliance rules',
    'Remediation': 'Process of correcting non-compliant configurations to meet compliance requirements'
}

# Governance Matrix - Default Assignments (Placeholder)
# NOTE: Requires enhancement to EventBridge data to include actual owner assignments
GOVERNANCE_MATRIX = {
    '164.308(a)(3)(i)': {
        'control_name': 'Access Control',
        'owner': '[DATA REQUIRED: Bucket owner/team from tags]',
        'reviewer': 'Security Team',
        'frequency': 'Continuous (EventBridge)',
        'last_review': '[DATA REQUIRED: Last manual review date]'
    },
    '164.312(a)(2)(iv)': {
        'control_name': 'Encryption',
        'owner': '[DATA REQUIRED: Bucket owner/team from tags]',
        'reviewer': 'Security Team',
        'frequency': 'Continuous (EventBridge)',
        'last_review': '[DATA REQUIRED: Last manual review date]'
    },
    '164.308(a)(7)(ii)(A)': {
        'control_name': 'Data Backup',
        'owner': '[DATA REQUIRED: Bucket owner/team from tags]',
        'reviewer': 'Infrastructure Team',
        'frequency': 'Continuous (EventBridge)',
        'last_review': '[DATA REQUIRED: Last manual review date]'
    },
    '164.312(b)': {
        'control_name': 'Audit Controls',
        'owner': '[DATA REQUIRED: Bucket owner/team from tags]',
        'reviewer': 'Compliance Team',
        'frequency': 'Continuous (EventBridge)',
        'last_review': '[DATA REQUIRED: Last manual review date]'
    },
    '164.312(e)(1)': {
        'control_name': 'Transmission Security',
        'owner': '[DATA REQUIRED: Bucket owner/team from tags]',
        'reviewer': 'Security Team',
        'frequency': 'Continuous (EventBridge)',
        'last_review': '[DATA REQUIRED: Last manual review date]'
    }
}

def get_hipaa_control(rule_name):
    """Get HIPAA control ID for a given AWS Config rule"""
    mapping = HIPAA_CONTROL_MAPPING.get(rule_name, {})
    return mapping.get('control', 'N/A')

def get_hipaa_description(control):
    """Get description for a HIPAA control"""
    for rule_name, mapping in HIPAA_CONTROL_MAPPING.items():
        if mapping['control'] == control:
            return mapping['description']
    return 'HIPAA Security Rule Requirement'

def get_safeguard_type(rule_name):
    """Get safeguard type (Administrative/Physical/Technical) for a rule"""
    mapping = HIPAA_CONTROL_MAPPING.get(rule_name, {})
    return mapping.get('safeguard_type', 'Technical')

def get_aws_config_requirement(rule_name):
    """Get AWS-specific configuration requirement"""
    mapping = HIPAA_CONTROL_MAPPING.get(rule_name, {})
    return mapping.get('aws_config', 'Configuration check required')

def get_risk_level(rule_name):
    """Get risk level for a rule"""
    mapping = HIPAA_CONTROL_MAPPING.get(rule_name, {})
    return mapping.get('risk_level', 'MEDIUM')
