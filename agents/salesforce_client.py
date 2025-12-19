import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

class SalesforceOAuthClient:
    """
    OAuth 2.0 wrapper for Salesforce API - Works with SSO-enabled orgs
    No security token needed!
    """
    
    def __init__(self, client_id: str, client_secret: str, username: str, password: str, is_sandbox: bool = False):
        """
        Initialize Salesforce OAuth client
        
        Args:
            client_id: Connected App Consumer Key
            client_secret: Connected App Consumer Secret
            username: Salesforce username (SSO email)
            password: Salesforce password (SSO password)
            is_sandbox: True if connecting to sandbox
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.is_sandbox = is_sandbox
        
        # OAuth endpoints
        self.auth_url = "https://test.salesforce.com" if is_sandbox else "https://login.salesforce.com"
        self.token_url = f"{self.auth_url}/services/oauth2/token"
        
        # Session data
        self.access_token = None
        self.instance_url = None
        self.org_id = None
        self.session = requests.Session()
    
    def connect(self) -> bool:
        """
        Establish OAuth connection to Salesforce
        
        Returns:
            bool: True if connection successful
        """
        try:
            # OAuth 2.0 Password Flow (Resource Owner Password Credentials)
            payload = {
                'grant_type': 'password',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'username': self.username,
                'password': self.password
            }
            
            response = requests.post(self.token_url, data=payload, timeout=30)
            
            if response.status_code == 200:
                oauth_response = response.json()
                self.access_token = oauth_response['access_token']
                self.instance_url = oauth_response['instance_url']
                
                # Set up session with auth header
                self.session.headers.update({
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                })
                
                # Get org ID
                self.org_id = self._get_org_id()
                
                print(f"✅ OAuth authentication successful")
                print(f"📍 Instance: {self.instance_url}")
                print(f"🆔 Org ID: {self.org_id}")
                
                return True
            else:
                error_data = response.json() if response.text else {}
                error_msg = error_data.get('error_description', response.text)
                print(f"❌ OAuth authentication failed: {error_msg}")
                print(f"Status code: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            print("❌ Connection timeout - check network connectivity")
            return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return False
    
    def _query(self, soql: str) -> Optional[Dict]:
        """
        Execute SOQL query
        
        Args:
            soql: SOQL query string
            
        Returns:
            Query results or None
        """
        try:
            query_url = f"{self.instance_url}/services/data/v58.0/query"
            response = self.session.get(query_url, params={'q': soql}, timeout=60)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Query failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Query error: {str(e)}")
            return None
    
    def _query_all(self, soql: str) -> List[Dict]:
        """
        Execute SOQL query and fetch all records (handles pagination)
        
        Args:
            soql: SOQL query string
            
        Returns:
            List of records
        """
        all_records = []
        result = self._query(soql)
        
        if not result:
            return []
        
        all_records.extend(result.get('records', []))
        
        # Handle pagination
        while not result.get('done', True):
            next_url = result.get('nextRecordsUrl')
            if not next_url:
                break
            
            try:
                response = self.session.get(f"{self.instance_url}{next_url}", timeout=60)
                if response.status_code == 200:
                    result = response.json()
                    all_records.extend(result.get('records', []))
                else:
                    break
            except:
                break
        
        return all_records
    
    def _get_org_id(self) -> str:
        """
        Retrieve Organization ID
        
        Returns:
            str: Organization ID
        """
        try:
            result = self._query("SELECT Id, Name FROM Organization LIMIT 1")
            if result and result.get('records'):
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
               CreatedDate, LastModifiedDate
        FROM User
        WHERE IsActive = true
        ORDER BY LastLoginDate DESC NULLS LAST
        """
        
        try:
            records = self._query_all(query)
            print(f"✓ Fetched {len(records)} users")
            return records
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
               PermissionsAuthorApex, PermissionsExportReport,
               PermissionsManageRoles, PermissionsModifyMetadata
        FROM PermissionSet
        WHERE IsOwnedByProfile = false
        """
        
        try:
            permission_sets = self._query_all(ps_query)
            
            # Fetch assignments for each permission set
            for ps in permission_sets:
                assignment_query = f"""
                SELECT Id, AssigneeId, Assignee.Username, Assignee.Name
                FROM PermissionSetAssignment
                WHERE PermissionSetId = '{ps['Id']}'
                """
                assignments = self._query_all(assignment_query)
                ps['Assignments'] = assignments
            
            print(f"✓ Fetched {len(permission_sets)} permission sets")
            return permission_sets
        except Exception as e:
            print(f"Error fetching permission sets: {str(e)}")
            return []
    
    def fetch_profiles(self) -> List[Dict]:
        """
        Fetch all profiles
        
        Returns:
            List of profile records
        """
        query = """
        SELECT Id, Name, Description, UserLicenseId, UserLicense.Name,
               PermissionsModifyAllData, PermissionsViewAllData,
               PermissionsManageUsers, PermissionsCustomizeApplication,
               PermissionsAuthorApex, PermissionsExportReport,
               PermissionsManageRoles, PermissionsModifyMetadata
        FROM Profile
        ORDER BY Name
        """
        
        try:
            records = self._query_all(query)
            print(f"✓ Fetched {len(records)} profiles")
            return records
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
            result = self._query(query)
            if result and result.get('records'):
                profile = result['records'][0]
                
                # Fetch users assigned to this profile
                user_query = f"""
                SELECT Id, Username, Name, Email, IsActive, LastLoginDate
                FROM User
                WHERE ProfileId = '{profile_id}' AND IsActive = true
                """
                users = self._query_all(user_query)
                profile['AssignedUsers'] = users
                
                print(f"✓ Fetched profile: {profile.get('Name')}")
                return profile
            return None
        except Exception as e:
            print(f"Error fetching profile details: {str(e)}")
            return None
    
    def fetch_sharing_settings(self) -> Dict:
        """
        Fetch Organization-Wide Defaults (OWD) and sharing settings
        
        Returns:
            Dictionary of sharing settings
        """
        try:
            sharing_settings = {
                'organization_wide_defaults': self._fetch_owd_settings(),
                'sharing_rules': [],
                'role_hierarchy': self._fetch_role_hierarchy()
            }
            
            print(f"✓ Fetched sharing settings")
            return sharing_settings
        except Exception as e:
            print(f"Error fetching sharing settings: {str(e)}")
            return {'organization_wide_defaults': [], 'sharing_rules': [], 'role_hierarchy': []}
    
    def _fetch_owd_settings(self) -> List[Dict]:
        """
        Fetch Organization-Wide Default sharing settings
        Note: This is simplified - full implementation requires Tooling/Metadata API
        
        Returns:
            List of OWD settings per object
        """
        # Common standard objects to check
        common_objects = [
            'Account', 'Contact', 'Opportunity', 'Lead', 
            'Case', 'Contract', 'Campaign', 'Asset'
        ]
        
        owd_settings = []
        for obj in common_objects:
            # Placeholder - would use Tooling API in production
            owd_settings.append({
                'ObjectName': obj,
                'DefaultAccess': 'Public',  # Would fetch from Metadata API
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
            return self._query_all(query)
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
            records = self._query_all(query)
            print(f"✓ Fetched {len(records)} login history records")
            return records
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
            records = self._query_all(query)
            print(f"✓ Fetched {len(records)} audit trail records")
            return records
        except Exception as e:
            print(f"Error fetching setup audit trail: {str(e)}")
            return []
    
    def test_connection(self) -> Dict[str, any]:
        """
        Test OAuth connection and return diagnostics
        
        Returns:
            Dictionary with connection test results
        """
        results = {
            'oauth_authenticated': False,
            'api_accessible': False,
            'org_info': None,
            'errors': []
        }
        
        try:
            # Test OAuth
            if self.access_token:
                results['oauth_authenticated'] = True
            else:
                results['errors'].append("No access token - OAuth failed")
                return results
            
            # Test API access
            org_result = self._query("SELECT Id, Name, OrganizationType FROM Organization LIMIT 1")
            if org_result and org_result.get('records'):
                results['api_accessible'] = True
                results['org_info'] = org_result['records'][0]
            else:
                results['errors'].append("API query failed")
            
        except Exception as e:
            results['errors'].append(f"Connection test error: {str(e)}")
        
        return results