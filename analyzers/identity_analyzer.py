
# analyzers/identity_analyzer.py
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class IdentityAnalyzer:
    """
    Analyzes identity and access management for security issues
    """
    
    def analyze_users(self, users: List[Dict], login_history: List[Dict]) -> Dict:
        """
        Analyze user accounts for security issues
        
        Args:
            users: List of user records
            login_history: Login history records
            
        Returns:
            Analysis results with findings
        """
        findings = []
        
        # Analyze dormant users
        dormant_findings = self._find_dormant_users(users)
        findings.extend(dormant_findings)
        
        # Analyze admin users
        admin_findings = self._analyze_admin_users(users)
        findings.extend(admin_findings)
        
        # Analyze MFA compliance
        mfa_findings = self._analyze_mfa_compliance(users)
        findings.extend(mfa_findings)
        
        # Analyze login anomalies
        login_findings = self._analyze_login_history(login_history)
        findings.extend(login_findings)
        
        return {
            'findings': findings,
            'total_users': len(users),
            'active_users': len([u for u in users if u.get('IsActive')]),
            'admin_users': len([u for u in users if 'Admin' in u.get('Profile', {}).get('Name', '')])
        }
    
    def _find_dormant_users(self, users: List[Dict]) -> List[Dict]:
        """
        Find users who haven't logged in recently
        """
        findings = []
        threshold_days = 90
        threshold_date = datetime.now() - timedelta(days=threshold_days)
        
        for user in users:
            last_login = user.get('LastLoginDate')
            
            if not last_login:
                findings.append({
                    'type': 'Dormant User - Never Logged In',
                    'severity': 'Medium',
                    'username': user.get('Username'),
                    'user_id': user.get('Id'),
                    'profile': user.get('Profile', {}).get('Name', 'Unknown'),
                    'description': f"User {user.get('Username')} has never logged in",
                    'recommendation': 'Deactivate or review necessity of this account'
                })
            elif isinstance(last_login, str):
                try:
                    last_login_date = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                    if last_login_date < threshold_date:
                        days_inactive = (datetime.now() - last_login_date).days
                        findings.append({
                            'type': 'Dormant User - Inactive',
                            'severity': 'Medium',
                            'username': user.get('Username'),
                            'user_id': user.get('Id'),
                            'profile': user.get('Profile', {}).get('Name', 'Unknown'),
                            'days_inactive': days_inactive,
                            'last_login': last_login,
                            'description': f"User inactive for {days_inactive} days",
                            'recommendation': 'Consider deactivating inactive accounts'
                        })
                except:
                    pass
        
        return findings
    
    def _analyze_admin_users(self, users: List[Dict]) -> List[Dict]:
        """
        Analyze administrative users for security risks
        """
        findings = []
        
        admin_users = [
            u for u in users 
            if 'Admin' in u.get('Profile', {}).get('Name', '') or
               'System Administrator' in u.get('Profile', {}).get('Name', '')
        ]
        
        if len(admin_users) > 5:
            findings.append({
                'type': 'Excessive Admin Users',
                'severity': 'High',
                'admin_count': len(admin_users),
                'description': f"{len(admin_users)} users have System Administrator profile",
                'impact': 'Too many users with full org access increases security risk',
                'recommendation': 'Reduce admin users, use Permission Sets for specific needs',
                'admin_usernames': [u.get('Username') for u in admin_users]
            })
        
        return findings
    
    def _analyze_mfa_compliance(self, users: List[Dict]) -> List[Dict]:
        """
        Analyze Multi-Factor Authentication compliance
        """
        findings = []
        
        # Check for users without MFA (if field exists)
        non_mfa_users = []
        for user in users:
            # Note: MfaEnabled__c might be a custom field
            if user.get('MfaEnabled__c') == False:
                non_mfa_users.append(user.get('Username'))
        
        if non_mfa_users:
            findings.append({
                'type': 'MFA Not Enabled',
                'severity': 'High',
                'users_without_mfa': len(non_mfa_users),
                'description': f"{len(non_mfa_users)} users don't have MFA enabled",
                'impact': 'Accounts vulnerable to credential compromise',
                'recommendation': 'Enable MFA for all users, especially admins',
                'affected_users': non_mfa_users[:10]  # Show first 10
            })
        
        return findings
    
    def _analyze_login_history(self, login_history: List[Dict]) -> List[Dict]:
        """
        Analyze login history for suspicious patterns
        """
        findings = []
        
        # Count failed login attempts
        failed_logins = [l for l in login_history if l.get('Status') == 'Failed']
        
        if len(failed_logins) > 100:
            findings.append({
                'type': 'High Failed Login Attempts',
                'severity': 'High',
                'failed_count': len(failed_logins),
                'description': f"{len(failed_logins)} failed login attempts detected",
                'impact': 'Possible brute force attack or credential stuffing',
                'recommendation': 'Review failed attempts, consider IP restrictions'
            })
        
        # Check for logins from unusual locations (simplified)
        unique_ips = set(l.get('SourceIp', '') for l in login_history if l.get('SourceIp'))
        
        if len(unique_ips) > 100:
            findings.append({
                'type': 'Many Unique Login IPs',
                'severity': 'Medium',
                'unique_ip_count': len(unique_ips),
                'description': f"Logins from {len(unique_ips)} different IP addresses",
                'recommendation': 'Review for unauthorized access, implement IP restrictions'
            })
        
        return findings
    
    def check_mfa_compliance(self, users: List[Dict]) -> Dict:
        """
        Check organization-wide MFA compliance
        
        Returns:
            MFA compliance statistics
        """
        total_users = len(users)
        mfa_enabled = sum(1 for u in users if u.get('MfaEnabled__c') == True)
        
        return {
            'total_users': total_users,
            'mfa_enabled': mfa_enabled,
            'mfa_disabled': total_users - mfa_enabled,
            'compliance_percentage': (mfa_enabled / total_users * 100) if total_users > 0 else 0,
            'is_compliant': (mfa_enabled / total_users) >= 0.95 if total_users > 0 else False
        }