from typing import Dict, List, Optional

class PermissionAnalyzer:
    """
    Analyzes Salesforce permissions for security vulnerabilities
    """
    
    # Dangerous permissions that grant broad access
    DANGEROUS_PERMISSIONS = {
        'PermissionsModifyAllData': {
            'severity': 'Critical',
            'description': 'Modify All Data - Full read/write access to all records',
            'impact': 'User can view, edit, and delete ALL records in the org'
        },
        'PermissionsViewAllData': {
            'severity': 'Critical',
            'description': 'View All Data - Read access to all records',
            'impact': 'User can view ALL records, bypassing sharing rules'
        },
        'PermissionsManageUsers': {
            'severity': 'Critical',
            'description': 'Manage Users - Can create/modify users',
            'impact': 'Can create admin users, escalate privileges'
        },
        'PermissionsCustomizeApplication': {
            'severity': 'High',
            'description': 'Customize Application - Modify org configuration',
            'impact': 'Can change org settings, create fields, objects'
        },
        'PermissionsAuthorApex': {
            'severity': 'High',
            'description': 'Author Apex - Write and deploy code',
            'impact': 'Can deploy malicious code, bypass security'
        },
        'PermissionsExportReport': {
            'severity': 'Medium',
            'description': 'Export Reports - Export data to external files',
            'impact': 'Can export sensitive data in bulk'
        },
        'PermissionsManageRoles': {
            'severity': 'High',
            'description': 'Manage Roles - Modify role hierarchy',
            'impact': 'Can manipulate data access through role changes'
        },
        'PermissionsModifyMetadata': {
            'severity': 'High',
            'description': 'Modify Metadata - Change org configuration',
            'impact': 'Can alter security settings and configurations'
        },
        'PermissionsYourCustomCheck': {
        'severity': 'High',
        'description': 'Your custom permission',
        'impact': 'Impact description'
        }
    }
    
    def analyze_all_permissions(
        self, 
        permission_sets: List[Dict], 
        profiles: List[Dict]
    ) -> Dict:
        """
        Analyze all permission sets and profiles
        
        Returns:
            Analysis results with findings
        """
        findings = []
        
        # Analyze permission sets
        for ps in permission_sets:
            ps_findings = self.analyze_permission_set(ps)
            findings.extend(ps_findings)
        
        # Analyze profiles
        for profile in profiles:
            profile_findings = self._analyze_profile_permissions(profile)
            findings.extend(profile_findings)
        
        return {
            'findings': findings,
            'permission_sets_analyzed': len(permission_sets),
            'profiles_analyzed': len(profiles),
            'dangerous_assignments': self._count_dangerous_assignments(findings)
        }
    
    def analyze_permission_set(self, permission_set: Dict) -> List[Dict]:
        """
        Analyze a single permission set for security issues
        
        Args:
            permission_set: Permission set data from Salesforce
            
        Returns:
            List of security findings
        """
        findings = []
        ps_name = permission_set.get('Name', 'Unknown')
        ps_id = permission_set.get('Id', 'Unknown')
        assignments = permission_set.get('Assignments', [])
        
        # Check for dangerous permissions
        dangerous_perms = []
        for perm_field, perm_info in self.DANGEROUS_PERMISSIONS.items():
            if permission_set.get(perm_field) == True:
                dangerous_perms.append(perm_info)
                
                # Create finding for each dangerous permission
                findings.append({
                    'type': 'Dangerous Permission in Permission Set',
                    'severity': perm_info['severity'],
                    'permission_set': ps_name,
                    'permission_set_id': ps_id,
                    'permission': perm_info['description'],
                    'impact': perm_info['impact'],
                    'assigned_users': len(assignments),
                    'description': f"Permission Set '{ps_name}' grants {perm_info['description']} to {len(assignments)} user(s)",
                    'recommendation': f"Review necessity of this permission. Consider removing or restricting to fewer users.",
                    'affected_users': [u.get('Assignee', {}).get('Username', 'Unknown') for u in assignments]
                })
        
        # Check for permission escalation risk
        if len(dangerous_perms) >= 2:
            findings.append({
                'type': 'Permission Escalation Risk',
                'severity': 'Critical',
                'permission_set': ps_name,
                'description': f"Permission Set '{ps_name}' combines multiple dangerous permissions",
                'impact': 'High risk of privilege escalation and data breach',
                'recommendation': 'Split into separate permission sets with single responsibilities',
                'dangerous_permissions': [p['description'] for p in dangerous_perms]
            })
        
        return findings
    
    def analyze_profile(self, profile_data: Dict) -> Dict:
        """
        Analyze a specific profile for security issues
        
        Args:
            profile_data: Profile information from Salesforce
            
        Returns:
            Profile analysis with risk assessment
        """
        profile_name = profile_data.get('Name', 'Unknown')
        assigned_users = profile_data.get('AssignedUsers', [])
        
        analysis = {
            'profile_name': profile_name,
            'profile_id': profile_data.get('Id'),
            'assigned_users_count': len(assigned_users),
            'dangerous_permissions': [],
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'risk_score': 0
        }
        
        # Check for dangerous permissions
        for perm_field, perm_info in self.DANGEROUS_PERMISSIONS.items():
            if profile_data.get(perm_field) == True:
                analysis['dangerous_permissions'].append(perm_info['description'])
                
                if perm_info['severity'] == 'Critical':
                    analysis['critical_issues'].append({
                        'permission': perm_info['description'],
                        'impact': perm_info['impact'],
                        'users_affected': len(assigned_users)
                    })
                elif perm_info['severity'] == 'High':
                    analysis['warnings'].append({
                        'permission': perm_info['description'],
                        'impact': perm_info['impact']
                    })
        
        # Calculate risk score
        analysis['risk_score'] = self._calculate_profile_risk_score(analysis)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_profile_recommendations(analysis, profile_data)
        
        return analysis
    
    def _analyze_profile_permissions(self, profile: Dict) -> List[Dict]:
        """
        Internal method to analyze profile permissions
        """
        findings = []
        profile_name = profile.get('Name', 'Unknown')
        
        # Check if it's a standard profile
        is_standard = not profile.get('IsCustom', False)
        
        for perm_field, perm_info in self.DANGEROUS_PERMISSIONS.items():
            if profile.get(perm_field) == True:
                severity = perm_info['severity']
                
                # Elevate severity if standard profile is modified
                if is_standard and severity == 'High':
                    severity = 'Critical'
                
                findings.append({
                    'type': 'Dangerous Permission in Profile',
                    'severity': severity,
                    'profile': profile_name,
                    'profile_id': profile.get('Id'),
                    'permission': perm_info['description'],
                    'impact': perm_info['impact'],
                    'description': f"Profile '{profile_name}' has {perm_info['description']}",
                    'recommendation': 'Review and restrict this permission or move to Permission Set'
                })
        
        return findings
    
    def _calculate_profile_risk_score(self, analysis: Dict) -> int:
        """
        Calculate risk score for a profile (0-100)
        """
        score = 0
        
        # Critical issues add 30 points each
        score += len(analysis['critical_issues']) * 30
        
        # High risk warnings add 15 points each
        score += len(analysis['warnings']) * 15
        
        # More users = higher risk
        user_count = analysis['assigned_users_count']
        if user_count > 50:
            score += 20
        elif user_count > 20:
            score += 10
        
        return min(100, score)
    
    def _generate_profile_recommendations(self, analysis: Dict, profile_data: Dict) -> List[str]:
        """
        Generate specific recommendations for profile security
        """
        recommendations = []
        
        if analysis['critical_issues']:
            recommendations.append(
                f"🚨 URGENT: Remove {len(analysis['critical_issues'])} critical permission(s) "
                f"or migrate to Permission Sets for granular control"
            )
        
        if analysis['assigned_users_count'] > 20:
            recommendations.append(
                f"⚠️ {analysis['assigned_users_count']} users assigned to this profile. "
                "Consider splitting into multiple profiles based on job functions"
            )
        
        if len(analysis['dangerous_permissions']) >= 3:
            recommendations.append(
                "⚠️ Profile has multiple dangerous permissions. "
                "Implement least privilege principle"
            )
        
        if not recommendations:
            recommendations.append("✅ Profile follows security best practices")
        
        return recommendations
    
    def _count_dangerous_assignments(self, findings: List[Dict]) -> int:
        """
        Count total dangerous permission assignments
        """
        count = 0
        for finding in findings:
            if finding.get('type') == 'Dangerous Permission in Permission Set':
                count += finding.get('assigned_users', 0)
        return count
    
    def check_permission_escalation_risk(
        self,
        user_permissions: List[str]
    ) -> Dict:
        """
        Check if combination of permissions creates escalation risk
        
        Args:
            user_permissions: List of permission names user has
            
        Returns:
            Risk assessment
        """
        risky_combinations = [
            (['PermissionsAuthorApex', 'PermissionsModifyAllData'], 'Can deploy malicious code with full data access'),
            (['PermissionsManageUsers', 'PermissionsViewAllData'], 'Can create admin users and access all data'),
            (['PermissionsCustomizeApplication', 'PermissionsManageRoles'], 'Can manipulate security architecture')
        ]
        
        risks_found = []
        
        for combo, impact in risky_combinations:
            if all(perm in user_permissions for perm in combo):
                risks_found.append({
                    'combination': combo,
                    'impact': impact,
                    'severity': 'Critical'
                })
        
        return {
            'has_escalation_risk': len(risks_found) > 0,
            'risks': risks_found
        }