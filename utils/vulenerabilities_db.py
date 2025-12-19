"""
Vulnerability Database
Knowledge base of known Salesforce security vulnerabilities and patterns
"""

class VulnerabilityDatabase:
    """Database of known Salesforce security vulnerabilities"""
    
    # Dangerous system permissions
    DANGEROUS_PERMISSIONS = {
        'ModifyAllData': {
            'severity': 'critical',
            'category': 'Data Access',
            'description': 'User can create, edit, and delete all records regardless of sharing settings',
            'risk': 'Complete data manipulation capability - can alter financial records, delete data, bypass all security',
            'recommendation': 'Remove immediately. Grant object-specific permissions instead.',
            'compliance_impact': 'SOC 2, GDPR, HIPAA violation risk',
            'cve_reference': None,
            'owasp_category': 'A01:2021 - Broken Access Control'
        },
        'ViewAllData': {
            'severity': 'critical',
            'category': 'Data Access',
            'description': 'User can view all records regardless of sharing settings',
            'risk': 'Complete visibility to sensitive data including PII, financial data, trade secrets',
            'recommendation': 'Remove and grant object-specific read permissions only where needed.',
            'compliance_impact': 'GDPR, HIPAA, PCI-DSS violation risk',
            'cve_reference': None,
            'owasp_category': 'A01:2021 - Broken Access Control'
        },
        'ManageUsers': {
            'severity': 'high',
            'category': 'User Management',
            'description': 'User can create, edit, and deactivate users',
            'risk': 'Can create admin accounts, lock out legitimate users, disable security controls',
            'recommendation': 'Restrict to designated HR and IT administrators only.',
            'compliance_impact': 'SOC 2 - Access control violation',
            'cve_reference': None,
            'owasp_category': 'A01:2021 - Broken Access Control'
        },
        'CustomizeApplication': {
            'severity': 'high',
            'category': 'Configuration',
            'description': 'User can modify org configuration including security settings',
            'risk': 'Can weaken security controls, modify validation rules, change workflows',
            'recommendation': 'Restrict to administrators and approved developers only.',
            'compliance_impact': 'SOC 2 - Change management violation',
            'cve_reference': None,
            'owasp_category': 'A05:2021 - Security Misconfiguration'
        },
        'AuthorApex': {
            'severity': 'high',
            'category': 'Development',
            'description': 'User can write and deploy Apex code',
            'risk': 'Can introduce backdoors, data exfiltration code, malicious logic',
            'recommendation': 'Restrict to vetted developers only. Implement code review process.',
            'compliance_impact': 'SOC 2 - Development security violation',
            'cve_reference': None,
            'owasp_category': 'A04:2021 - Insecure Design'
        },
        'ViewSetup': {
            'severity': 'medium',
            'category': 'Information Disclosure',
            'description': 'User can view setup and configuration information',
            'risk': 'Can map out security architecture for targeted attacks',
            'recommendation': 'Limit to administrators and necessary support staff.',
            'compliance_impact': 'Information disclosure',
            'cve_reference': None,
            'owasp_category': 'A01:2021 - Broken Access Control'
        },
        'ManageInternalUsers': {
            'severity': 'high',
            'category': 'User Management',
            'description': 'Can manage internal users including password resets',
            'risk': 'Account takeover, unauthorized access escalation',
            'recommendation': 'Restrict to IT security team only.',
            'compliance_impact': 'SOC 2 - Access control',
            'cve_reference': None,
            'owasp_category': 'A01:2021 - Broken Access Control'
        }
    }
    
    # Sharing model vulnerabilities
    SHARING_VULNERABILITIES = {
        'PublicReadWrite': {
            'severity': 'critical',
            'objects': ['Account', 'Contact', 'Opportunity', 'Lead', 'Case', 'Quote', 'Contract'],
            'description': 'All users can read and write all records',
            'risk': 'Data integrity compromise, unauthorized modifications, compliance violations',
            'recommendation': 'Change to Private. Use sharing rules for controlled access.',
            'compliance_impact': 'GDPR, SOC 2, PCI-DSS violations'
        },
        'PublicRead': {
            'severity': 'high',
            'objects': ['Account', 'Contact', 'Lead', 'Case', 'Opportunity'],
            'description': 'All users can view all records',
            'risk': 'Sensitive data exposure, privacy violations',
            'recommendation': 'Change to Private. Implement role hierarchy or sharing rules.',
            'compliance_impact': 'GDPR, HIPAA privacy violations'
        },
        'ControlledByParent': {
            'severity': 'medium',
            'objects': ['Contact', 'Opportunity', 'Case'],
            'description': 'Inherits sharing from parent record',
            'risk': 'Unintended access if parent sharing is too permissive',
            'recommendation': 'Verify parent object sharing is appropriate.',
            'compliance_impact': 'Potential data leakage'
        }
    }
    
    # Identity and access vulnerabilities
    IDENTITY_VULNERABILITIES = {
        'DormantAdminAccount': {
            'severity': 'high',
            'threshold_days': 90,
            'description': 'Administrator account inactive for 90+ days',
            'risk': 'Orphaned privileged accounts are prime targets for attackers',
            'recommendation': 'Deactivate or remove admin privileges immediately.',
            'compliance_impact': 'SOC 2, PCI-DSS - Access review violation'
        },
        'NoMFA': {
            'severity': 'high',
            'description': 'User does not have MFA enabled',
            'risk': 'Account vulnerable to credential theft and phishing',
            'recommendation': 'Enable MFA for all users, especially administrators.',
            'compliance_impact': 'SOC 2, PCI-DSS - Authentication requirement'
        },
        'FailedLoginAttempts': {
            'severity': 'medium',
            'threshold': 5,
            'description': 'Multiple failed login attempts detected',
            'risk': 'Possible brute force attack or credential stuffing',
            'recommendation': 'Investigate source IPs, consider account lockout policies.',
            'compliance_impact': 'Security monitoring requirement'
        },
        'UnusualLoginTime': {
            'severity': 'medium',
            'description': 'Login outside normal business hours',
            'risk': 'Compromised credentials or unauthorized access',
            'recommendation': 'Implement time-based login restrictions, investigate anomalies.',
            'compliance_impact': 'Anomaly detection'
        }
    }
    
    # Known attack patterns
    ATTACK_PATTERNS = {
        'PrivilegeEscalation': {
            'indicators': [
                'Multiple permission sets assigned to non-admin user',
                'Permission set with admin-level permissions',
                'Profile modification to add dangerous permissions'
            ],
            'severity': 'critical',
            'description': 'User gaining elevated privileges through permission accumulation',
            'mitigation': 'Regular permission audits, least privilege enforcement'
        },
        'DataExfiltration': {
            'indicators': [
                'Excessive report exports',
                'API usage spikes',
                'Large data exports',
                'Access to View All Data'
            ],
            'severity': 'critical',
            'description': 'Suspicious data access patterns indicating potential theft',
            'mitigation': 'Monitor API usage, implement data loss prevention'
        },
        'AccountTakeover': {
            'indicators': [
                'Login from new geographic location',
                'Multiple failed logins followed by success',
                'Password reset without MFA',
                'Unusual activity after login'
            ],
            'severity': 'critical',
            'description': 'Compromised user account being accessed by attacker',
            'mitigation': 'Enforce MFA, monitor login anomalies, implement IP restrictions'
        }
    }
    
    # Compliance requirements
    COMPLIANCE_MAPPINGS = {
        'SOC2': {
            'CC6.1': 'Logical and physical access controls',
            'CC6.2': 'Prior to issuing system credentials',
            'CC6.3': 'Removes access when terminated',
            'CC6.6': 'Manages system-to-system communications',
            'CC7.2': 'Monitors system components'
        },
        'GDPR': {
            'Article_5': 'Principles relating to processing',
            'Article_25': 'Data protection by design and default',
            'Article_32': 'Security of processing'
        },
        'HIPAA': {
            '164.308': 'Administrative safeguards',
            '164.312': 'Technical safeguards'
        },
        'PCI_DSS': {
            'Req_7': 'Restrict access to cardholder data',
            'Req_8': 'Identify and authenticate access',
            'Req_10': 'Track and monitor all access'
        }
    }
    
    @classmethod
    def get_permission_info(cls, permission_name: str) -> dict:
        """Get information about a specific permission"""
        return cls.DANGEROUS_PERMISSIONS.get(permission_name, {
            'severity': 'low',
            'description': f'Permission: {permission_name}',
            'recommendation': 'Review if this permission is necessary.'
        })
    
    @classmethod
    def get_sharing_vulnerability(cls, sharing_model: str) -> dict:
        """Get vulnerability info for sharing model"""
        for vuln_type, info in cls.SHARING_VULNERABILITIES.items():
            if vuln_type in sharing_model:
                return info
        return {}
    
    @classmethod
    def get_identity_vulnerability(cls, vuln_type: str) -> dict:
        """Get identity vulnerability information"""
        return cls.IDENTITY_VULNERABILITIES.get(vuln_type, {})
    
    @classmethod
    def check_compliance_impact(cls, finding: dict) -> list:
        """Check which compliance frameworks are impacted"""
        impacts = []
        
        if finding.get('severity') in ['critical', 'high']:
            impacts.extend(['SOC2', 'GDPR'])
            
        if 'data' in finding.get('category', '').lower():
            impacts.extend(['GDPR', 'HIPAA'])
            
        if 'access' in finding.get('type', '').lower():
            impacts.extend(['SOC2', 'PCI_DSS'])
        
        return list(set(impacts))
    
    @classmethod
    def get_remediation_priority(cls, severity: str, compliance_impact: list) -> int:
        """Calculate remediation priority (1=highest, 5=lowest)"""
        base_priority = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        }.get(severity, 5)
        
        # Increase priority if compliance is impacted
        if compliance_impact and base_priority > 1:
            base_priority -= 1
        
        return base_priority
    
    @classmethod
    def get_similar_vulnerabilities(cls, vulnerability_type: str) -> list:
        """Get similar vulnerabilities to watch for"""
        
        similarity_map = {
            'ModifyAllData': ['ViewAllData', 'ManageUsers'],
            'ViewAllData': ['ModifyAllData', 'ViewSetup'],
            'PublicReadWrite': ['PublicRead', 'ControlledByParent'],
            'DormantAdminAccount': ['NoMFA', 'UnusualLoginTime']
        }
        
        return similarity_map.get(vulnerability_type, [])