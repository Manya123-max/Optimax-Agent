from simple_salesforce import Salesforce, SalesforceLogin
import requests
from datetime import datetime, timedelta
import json

class SalesforceClient:
    """Wrapper for Salesforce REST and Metadata API"""
    
    def __init__(self, username, password, security_token, domain='login'):
        """Initialize Salesforce connection"""
        self.username = username
        self.password = password
        self.security_token = security_token
        self.domain = domain
        
        # Establish connection
        self.sf = Salesforce(
            username=username,
            password=password,
            security_token=security_token,
            domain=domain
        )
        
        self.session_id = self.sf.session_id
        self.instance_url = self.sf.sf_instance
        
    def get_org_id(self):
        """Get Organization ID"""
        query = "SELECT Id FROM Organization LIMIT 1"
        result = self.sf.query(query)
        return result['records'][0]['Id']
    
    # ==================== Identity & Access Data ====================
    
    def fetch_users(self):
        """Fetch all active users with key security fields"""
        query = """
            SELECT Id, Name, Username, Email, Profile.Name, ProfileId,
                   IsActive, LastLoginDate, CreatedDate, UserRole.Name,
                   ReceivesAdminInfoEmails, ReceivesInfoEmails
            FROM User
            WHERE IsActive = true
        """
        result = self.sf.query_all(query)
        
        users = []
        for record in result['records']:
            # Check for dormant users (90+ days no login)
            last_login = record.get('LastLoginDate')
            is_dormant = False
            if last_login:
                last_login_date = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                is_dormant = (datetime.now(last_login_date.tzinfo) - last_login_date).days > 90
            
            users.append({
                'Id': record['Id'],
                'Name': record['Name'],
                'Username': record['Username'],
                'Email': record['Email'],
                'ProfileName': record['Profile']['Name'] if record.get('Profile') else 'Unknown',
                'ProfileId': record.get('ProfileId'),
                'IsActive': record['IsActive'],
                'LastLoginDate': last_login,
                'IsDormant': is_dormant,
                'RoleName': record['UserRole']['Name'] if record.get('UserRole') else None,
                'IsAdminEmail': record.get('ReceivesAdminInfoEmails', False)
            })
        
        return users
    
    def fetch_login_history(self, hours=24):
        """Fetch recent login history for anomaly detection"""
        time_ago = datetime.utcnow() - timedelta(hours=hours)
        time_str = time_ago.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        query = f"""
            SELECT Id, UserId, LoginTime, LoginType, SourceIp,
                   Status, Application, Browser, Platform
            FROM LoginHistory
            WHERE LoginTime >= {time_str}
            ORDER BY LoginTime DESC
        """
        result = self.sf.query_all(query)
        return result['records']
    
    # ==================== Permission & Authorization Data ====================
    
    def fetch_permission_sets(self):
        """Fetch all permission sets with assignments"""
        query = """
            SELECT Id, Name, Label, Description, IsOwnedByProfile,
                   Type, IsCustom, CreatedDate, LastModifiedDate
            FROM PermissionSet
        """
        result = self.sf.query_all(query)
        
        permission_sets = []
        for ps in result['records']:
            # Get assignments for this permission set
            assignments = self.fetch_permission_set_assignments(ps['Id'])
            
            # Get detailed permissions
            permissions = self.fetch_permission_set_details(ps['Id'])
            
            permission_sets.append({
                'Id': ps['Id'],
                'Name': ps['Name'],
                'Label': ps['Label'],
                'Description': ps.get('Description'),
                'Type': ps.get('Type'),
                'IsCustom': ps.get('IsCustom', False),
                'AssignmentCount': len(assignments),
                'Assignments': assignments,
                'Permissions': permissions
            })
        
        return permission_sets
    
    def fetch_permission_set_assignments(self, permission_set_id):
        """Fetch users assigned to a permission set"""
        query = f"""
            SELECT Id, AssigneeId, Assignee.Name, Assignee.Username
            FROM PermissionSetAssignment
            WHERE PermissionSetId = '{permission_set_id}'
            AND Assignee.IsActive = true
        """
        result = self.sf.query_all(query)
        return [
            {
                'UserId': r['AssigneeId'],
                'UserName': r['Assignee']['Name'],
                'Username': r['Assignee']['Username']
            }
            for r in result['records']
        ]
    
    def fetch_permission_set_details(self, permission_set_id):
        """Fetch detailed permissions for a permission set"""
        # System permissions
        system_perms_query = f"""
            SELECT Id, Parent.Name, PermissionsModifyAllData, PermissionsViewAllData,
                   PermissionsManageUsers, PermissionsCustomizeApplication,
                   PermissionsAuthorApex, PermissionsEditPublicReports,
                   PermissionsViewSetup, PermissionsManageInternalUsers
            FROM PermissionSet
            WHERE Id = '{permission_set_id}'
        """
        system_perms = self.sf.query(system_perms_query)['records'][0]
        
        # Object permissions
        obj_perms_query = f"""
            SELECT Id, SObjectType, PermissionsCreate, PermissionsRead,
                   PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords,
                   PermissionsModifyAllRecords
            FROM ObjectPermissions
            WHERE ParentId = '{permission_set_id}'
        """
        obj_perms = self.sf.query_all(obj_perms_query)['records']
        
        return {
            'system': {
                'ModifyAllData': system_perms.get('PermissionsModifyAllData', False),
                'ViewAllData': system_perms.get('PermissionsViewAllData', False),
                'ManageUsers': system_perms.get('PermissionsManageUsers', False),
                'CustomizeApplication': system_perms.get('PermissionsCustomizeApplication', False),
                'AuthorApex': system_perms.get('PermissionsAuthorApex', False),
                'ViewSetup': system_perms.get('PermissionsViewSetup', False)
            },
            'objects': [
                {
                    'Object': op['SObjectType'],
                    'Create': op.get('PermissionsCreate', False),
                    'Read': op.get('PermissionsRead', False),
                    'Edit': op.get('PermissionsEdit', False),
                    'Delete': op.get('PermissionsDelete', False),
                    'ViewAll': op.get('PermissionsViewAllRecords', False),
                    'ModifyAll': op.get('PermissionsModifyAllRecords', False)
                }
                for op in obj_perms
            ]
        }
    
    def fetch_profiles(self):
        """Fetch all profiles"""
        query = """
            SELECT Id, Name, Description, UserLicenseId, UserLicense.Name,
                   UserType, CreatedDate, LastModifiedDate
            FROM Profile
        """
        result = self.sf.query_all(query)
        
        profiles = []
        for profile in result['records']:
            # Get user count for this profile
            user_count_query = f"""
                SELECT COUNT()
                FROM User
                WHERE ProfileId = '{profile['Id']}' AND IsActive = true
            """
            user_count = self.sf.query(user_count_query)['totalSize']
            
            profiles.append({
                'Id': profile['Id'],
                'Name': profile['Name'],
                'Description': profile.get('Description'),
                'UserLicense': profile['UserLicense']['Name'] if profile.get('UserLicense') else None,
                'UserType': profile.get('UserType'),
                'ActiveUserCount': user_count
            })
        
        return profiles
    
    def fetch_profile_details(self, profile_id):
        """Fetch detailed profile information"""
        # Use Metadata API for complete profile details
        headers = {
            'Authorization': f'Bearer {self.session_id}',
            'Content-Type': 'application/json'
        }
        
        # Get profile metadata
        metadata_url = f"{self.instance_url}/services/data/v59.0/sobjects/Profile/{profile_id}"
        response = requests.get(metadata_url, headers=headers)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch profile: {response.text}")
        
        return response.json()
    
    def fetch_object_permissions(self, profile_id):
        """Fetch object-level permissions for a profile"""
        query = f"""
            SELECT Id, SObjectType, PermissionsCreate, PermissionsRead,
                   PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords,
                   PermissionsModifyAllRecords
            FROM ObjectPermissions
            WHERE ParentId = '{profile_id}'
        """
        result = self.sf.query_all(query)
        return result['records']
    
    def fetch_field_permissions(self, profile_id):
        """Fetch field-level permissions for a profile"""
        query = f"""
            SELECT Id, SObjectType, Field, PermissionsRead, PermissionsEdit
            FROM FieldPermissions
            WHERE ParentId = '{profile_id}'
        """
        result = self.sf.query_all(query)
        return result['records']
    
    # ==================== Sharing Model Data ====================
    
    def fetch_sharing_settings(self):
        """Fetch organization-wide defaults and sharing rules"""
        
        # Get OWD settings using REST API
        headers = {
            'Authorization': f'Bearer {self.session_id}',
            'Content-Type': 'application/json'
        }
        
        # Describe all objects to get sharing settings
        describe_url = f"{self.instance_url}/services/data/v59.0/sobjects/"
        response = requests.get(describe_url, headers=headers)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch objects: {response.text}")
        
        objects = response.json()['sobjects']
        
        sharing_settings = []
        for obj in objects:
            if obj.get('queryable') and not obj.get('customSetting'):
                # Get detailed object description
                obj_describe_url = f"{self.instance_url}/services/data/v59.0/sobjects/{obj['name']}/describe"
                obj_response = requests.get(obj_describe_url, headers=headers)
                
                if obj_response.status_code == 200:
                    obj_details = obj_response.json()
                    
                    sharing_model = obj_details.get('sharingModel', 'Unknown')
                    
                    # Flag potentially dangerous settings
                    is_public = 'Public' in sharing_model
                    is_read_write = 'ReadWrite' in sharing_model or 'ControlledByParent' in sharing_model
                    
                    sharing_settings.append({
                        'Object': obj['name'],
                        'Label': obj['label'],
                        'SharingModel': sharing_model,
                        'IsPublic': is_public,
                        'IsReadWrite': is_read_write,
                        'IsCustom': obj.get('custom', False)
                    })
        
        return sharing_settings
    
    def fetch_role_hierarchy(self):
        """Fetch role hierarchy structure"""
        query = """
            SELECT Id, Name, ParentRoleId, RollupDescription
            FROM UserRole
            ORDER BY ParentRoleId NULLS FIRST
        """
        result = self.sf.query_all(query)
        return result['records']