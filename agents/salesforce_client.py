from simple_salesforce import Salesforce
from typing import Dict, List, Optional
import requests
import json
from datetime import datetime, timedelta

class SalesforceClient:
    """
    Wrapper for Salesforce API to fetch security-relevant data
    """
    
    def __init__(self, username: str, password: str, security_token: str, domain: str = 'login'):
        """
        Initialize Salesforce client
        
        Args:
            username: Salesforce username
            password: Salesforce password
            security_token: Security token
            domain: 'login' for production, 'test' for sandbox
        """
        self.username = username
        self.password = password
        self.security_token = security_token
        self.domain = domain
        self.sf = None
        self.org_id = None
    
    def connect(self) -> bool:
        """
        Establish connection to Salesforce
        
        Returns:
            bool: True if connection successful
        """
        try:
            self.sf = Salesforce(
                username=self.username,
                password=self.password,
                security_token=self.security_token,
                domain=self.domain
            )
            self.org_id = self._get_org_id()
            return True
        except Exception as e:
            print(f"Connection failed: {str(e)}")
            return False
    
    def _get_org_id(self) -> str:
        """
        Retrieve Organization ID
        
        Returns:
            str: Organization ID
        """
        try:
            result = self.sf.query("SELECT Id, Name FROM Organization LIMIT 1")
            if result['records']:
                return result['records'][0]['Id']
        except:
            pass
        return "Unknown"
    
    def get_org_id(self) -> str:
        """Public method to get org ID"""
        return self.org_id or self._get_org_id()
    
    def fetch_users(self) -> List[Dict]:
        """
        Fetch all active users with relevant fields
        
        Returns:
            List of user records
        """
        query = """
        SELECT Id, Username, Name, Email, Profile.Name, ProfileId, 
               IsActive, LastLoginDate, UserRole.Name, UserRoleId,
               CreatedDate, LastModifiedDate, MfaEnabled__c
        FROM User
        WHERE IsActive = true
        ORDER BY LastLoginDate DESC NULLS LAST
        """
        
        try:
            result = self.sf.query_all(query)
            return result['records'] if result else []
        except Exception as e:
            print(f"Error fetching users: {str(e)}")
            return []
    
    def fetch_permission_sets(self) -> List[Dict]:
        """
        Fetch all permission sets with assignments
        
        Returns:
            List of permission set records with assignments
        """
        # Fetch permission sets
        ps_query = """
        SELECT Id, Name, Label, Description, IsCustom, 
               PermissionsModifyAllData, PermissionsViewAllData,
               PermissionsManageUsers, PermissionsCustomizeApplication,
               PermissionsAuthorApex, PermissionsExportReport
        FROM PermissionSet
        WHERE IsOwnedByProfile = false
        """
        
        try:
            ps_result = self.sf.query_all(ps_query)
            permission_sets = ps_result['records'] if ps_result else []
            
            # Fetch assignments for each permission set
            for ps in permission_sets:
                assignment_query = f"""
                SELECT Id, AssigneeId, Assignee.Username, Assignee.Name
                FROM PermissionSetAssignment
                WHERE PermissionSetId = '{ps['Id']}'
                """
                assign_result = self.sf.query_all(assignment_query)
                ps['Assignments'] = assign_result['records'] if assign_result else []
            
            return permission_sets
        except Exception as e:
            print(f"Error fetching permission sets: {str(e)}")
            return []
    
    def fetch_profiles(self) -> List[Dict]:
        """
        Fetch all profiles (metadata via REST API)
        
        Returns:
            List of profile records
        """
        query = """
        SELECT Id, Name, Description, UserLicenseId, UserLicense.Name,
               PermissionsModifyAllData, PermissionsViewAllData,
               PermissionsManageUsers, PermissionsCustomizeApplication,
               PermissionsAuthorApex, PermissionsExportReport
        FROM Profile
        ORDER BY Name
        """
        
        try:
            result = self.sf.query_all(query)
            return result['records'] if result else []
        except Exception as e:
            print(f"Error fetching profiles: {str(e)}")
            return []
    
    def fetch_profile_details(self, profile_id: str) -> Optional[Dict]:
        """
        Fetch detailed information for a specific profile
        
        Args:
            profile_id: Salesforce Profile ID
            
        Returns:
            Profile details with permissions
        """
        query = f"""
        SELECT Id, Name, Description, UserLicenseId, UserLicense.Name,
               PermissionsModifyAllData, PermissionsViewAllData,
               PermissionsManageUsers, PermissionsCustomizeApplication,
               PermissionsAuthorApex, PermissionsExportReport,
               PermissionsManageRoles, PermissionsTransferAnyLead,
               PermissionsModifyMetadata, PermissionsManageSharing
        FROM Profile
        WHERE Id = '{profile_id}'
        """
        
        try:
            result = self.sf.query(query)
            if result['records']:
                profile = result['records'][0]
                
                # Fetch users assigned to this profile
                user_query = f"""
                SELECT Id, Username, Name, Email, IsActive
                FROM User
                WHERE ProfileId = '{profile_id}' AND IsActive = true
                """
                user_result = self.sf.query_all(user_query)
                profile['AssignedUsers'] = user_result['records'] if user_result else []
                
                return profile
            return None
        except Exception as e:
            print(f"Error fetching profile details: {str(e)}")
            return None
    
    def fetch_sharing_settings(self) -> Dict:
        """
        Fetch Organization-Wide Defaults (OWD) and sharing settings
        Uses Metadata API
        
        Returns:
            Dictionary of sharing settings
        """
        try:
            # Use Tooling API to get some sharing info
            sharing_query = """
            SELECT Id, DeveloperName, SobjectType, AccessLevel
            FROM SharingRules
            LIMIT 200
            """
            
            sharing_settings = {
                'organization_wide_defaults': self._fetch_owd_settings(),
                'sharing_rules': [],
                'role_hierarchy': self._fetch_role_hierarchy()
            }
            
            return sharing_settings
        except Exception as e:
            print(f"Error fetching sharing settings: {str(e)}")
            return {'organization_wide_defaults': {}, 'sharing_rules': [], 'role_hierarchy': []}
    
    def _fetch_owd_settings(self) -> List[Dict]:
        """
        Fetch Organization-Wide Default sharing settings
        
        Returns:
            List of OWD settings per object
        """
        # Note: This requires Metadata API. For proof of concept, 
        # we'll use common standard objects
        common_objects = [
            'Account', 'Contact', 'Opportunity', 'Lead', 
            'Case', 'Contract', 'Campaign'
        ]
        
        owd_settings = []
        for obj in common_objects:
            # This is a simplified version - full implementation would use Metadata API
            owd_settings.append({
                'ObjectName': obj,
                'DefaultAccess': 'Public',  # Placeholder - would fetch from Metadata API
                'RiskLevel': 'Medium'
            })
        
        return owd_settings
    
    def _fetch_role_hierarchy(self) -> List[Dict]:
        """
        Fetch User Role hierarchy
        
        Returns:
            List of roles with hierarchy information
        """
        query = """
        SELECT Id, Name, ParentRoleId, DeveloperName
        FROM UserRole
        ORDER BY Name
        """
        
        try:
            result = self.sf.query_all(query)
            return result['records'] if result else []
        except Exception as e:
            print(f"Error fetching role hierarchy: {str(e)}")
            return []
    
    def fetch_login_history(self, days: int = 30) -> List[Dict]:
        """
        Fetch login history for anomaly detection
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of login history records
        """
        date_filter = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        query = f"""
        SELECT Id, UserId, LoginTime, Status, LoginType, 
               SourceIp, LoginUrl, Application, Browser, Platform
        FROM LoginHistory
        WHERE LoginTime >= {date_filter}
        ORDER BY LoginTime DESC
        LIMIT 10000
        """
        
        try:
            result = self.sf.query_all(query)
            return result['records'] if result else []
        except Exception as e:
            print(f"Error fetching login history: {str(e)}")
            return []
    
    def fetch_setup_audit_trail(self, days: int = 90) -> List[Dict]:
        """
        Fetch setup audit trail for configuration changes
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of audit records
        """
        date_filter = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        query = f"""
        SELECT Id, Action, Section, CreatedBy.Name, CreatedDate, Display
        FROM SetupAuditTrail
        WHERE CreatedDate >= {date_filter}
        ORDER BY CreatedDate DESC
        LIMIT 2000
        """
        
        try:
            result = self.sf.query_all(query)
            return result['records'] if result else []
        except Exception as e:
            print(f"Error fetching setup audit trail: {str(e)}")
            return []