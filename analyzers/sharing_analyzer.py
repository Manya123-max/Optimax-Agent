
# analyzers/sharing_analyzer.py
from typing import Dict, List, Optional
from datetime import datetime

class SharingAnalyzer:
    """
    Analyzes Salesforce sharing model for security vulnerabilities
    """
    
    RISKY_OWD_SETTINGS = {
        'Public Read/Write': 'Critical',
        'Public Read/Write/Transfer': 'Critical',
        'Public Full Access': 'Critical',
        'Public Read Only': 'High'
    }
    
    def analyze_sharing_settings(self, sharing_settings: Dict) -> Dict:
        """
        Analyze organization-wide sharing settings
        
        Args:
            sharing_settings: OWD settings, sharing rules, role hierarchy
            
        Returns:
            Analysis results with findings
        """
        findings = []
        
        # Analyze OWD settings
        owd_findings = self._analyze_owd(sharing_settings.get('organization_wide_defaults', []))
        findings.extend(owd_findings)
        
        # Analyze role hierarchy
        role_findings = self._analyze_role_hierarchy(sharing_settings.get('role_hierarchy', []))
        findings.extend(role_findings)
        
        # Analyze sharing rules
        rule_findings = self._analyze_sharing_rules(sharing_settings.get('sharing_rules', []))
        findings.extend(rule_findings)
        
        return {
            'findings': findings,
            'owd_objects_analyzed': len(sharing_settings.get('organization_wide_defaults', [])),
            'roles_analyzed': len(sharing_settings.get('role_hierarchy', [])),
            'sharing_rules_analyzed': len(sharing_settings.get('sharing_rules', []))
        }
    
    def _analyze_owd(self, owd_settings: List[Dict]) -> List[Dict]:
        """
        Analyze Organization-Wide Default settings
        """
        findings = []
        
        sensitive_objects = ['Account', 'Contact', 'Opportunity', 'Contract', 'Case']
        
        for setting in owd_settings:
            obj_name = setting.get('ObjectName', 'Unknown')
            default_access = setting.get('DefaultAccess', 'Private')
            
            # Check if sensitive object has public access
            if obj_name in sensitive_objects and default_access in self.RISKY_OWD_SETTINGS:
                severity = self.RISKY_OWD_SETTINGS[default_access]
                
                findings.append({
                    'type': 'Insecure Organization-Wide Default',
                    'severity': severity,
                    'object': obj_name,
                    'current_setting': default_access,
                    'description': f"{obj_name} has {default_access} OWD setting",
                    'impact': f"All users can access {obj_name} records by default",
                    'recommendation': f"Change {obj_name} OWD to Private and use sharing rules for controlled access"
                })
        
        return findings
    
    def _analyze_role_hierarchy(self, roles: List[Dict]) -> List[Dict]:
        """
        Analyze role hierarchy for security issues
        """
        findings = []
        
        # Check for flat hierarchy (security issue)
        roles_without_parent = [r for r in roles if not r.get('ParentRoleId')]
        
        if len(roles_without_parent) > len(roles) * 0.5:
            findings.append({
                'type': 'Flat Role Hierarchy',
                'severity': 'Medium',
                'description': 'Role hierarchy is too flat',
                'impact': 'Users may have unintended access through role hierarchy',
                'recommendation': 'Design role hierarchy based on data access needs, not org chart',
                'roles_without_parent': len(roles_without_parent)
            })
        
        return findings
    
    def _analyze_sharing_rules(self, sharing_rules: List[Dict]) -> List[Dict]:
        """
        Analyze sharing rules for over-broad access
        """
        findings = []
        
        for rule in sharing_rules:
            access_level = rule.get('AccessLevel', 'Read')
            
            if access_level in ['Edit', 'All']:
                findings.append({
                    'type': 'Broad Sharing Rule',
                    'severity': 'Medium',
                    'rule_name': rule.get('DeveloperName', 'Unknown'),
                    'object': rule.get('SobjectType', 'Unknown'),
                    'access_level': access_level,
                    'description': f"Sharing rule grants {access_level} access",
                    'recommendation': 'Review necessity of Edit/All access in sharing rules'
                })
        
        return findings
    
    def check_sharing_bypass_permissions(self, user_permissions: List[str]) -> bool:
        """
        Check if user has permissions that bypass sharing rules
        """
        bypass_permissions = [
            'PermissionsViewAllData',
            'PermissionsModifyAllData'
        ]
        
        return any(perm in user_permissions for perm in bypass_permissions)