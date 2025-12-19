from anthropic import Anthropic
import json
from .prompts import FULL_SCAN_PROMPT, PROFILE_SCAN_PROMPT

class SalesforceSecurityAgent:
    """AI-powered Salesforce security vulnerability analyzer"""
    
    def __init__(self, api_key=None):
        """Initialize the agent with Anthropic API"""
        self.client = Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
        
    def analyze_full_org(self, data):
        """Perform comprehensive org security analysis"""
        
        # Prepare structured data for analysis
        analysis_input = self._prepare_full_scan_data(data)
        
        # Create prompt for Claude
        prompt = FULL_SCAN_PROMPT.format(
            org_id=data['org_id'],
            analysis_data=json.dumps(analysis_input, indent=2)
        )
        
        # Call Claude API
        response = self.client.messages.create(
            model=self.model,
            max_tokens=8000,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        return response.content[0].text
    
    def analyze_profile(self, data):
        """Analyze specific profile for vulnerabilities"""
        
        # Prepare profile data
        analysis_input = self._prepare_profile_data(data)
        
        # Create prompt
        prompt = PROFILE_SCAN_PROMPT.format(
            profile_id=data['profile']['Id'],
            profile_name=data['profile']['Name'],
            analysis_data=json.dumps(analysis_input, indent=2)
        )
        
        # Call Claude API
        response = self.client.messages.create(
            model=self.model,
            max_tokens=6000,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        return response.content[0].text
    
    def _prepare_full_scan_data(self, data):
        """Structure data for full org analysis"""
        
        # Analyze users for risks
        admin_users = []
        dormant_users = []
        
        for user in data['users']:
            if 'Admin' in user.get('ProfileName', ''):
                admin_users.append({
                    'Name': user['Name'],
                    'Username': user['Username'],
                    'LastLogin': user.get('LastLoginDate'),
                    'IsDormant': user.get('IsDormant', False)
                })
            
            if user.get('IsDormant'):
                dormant_users.append({
                    'Name': user['Name'],
                    'Username': user['Username'],
                    'Profile': user.get('ProfileName'),
                    'LastLogin': user.get('LastLoginDate')
                })
        
        # Analyze permission sets for dangerous permissions
        dangerous_permission_sets = []
        
        for ps in data['permission_sets']:
            perms = ps.get('Permissions', {}).get('system', {})
            
            dangerous_perms = []
            if perms.get('ModifyAllData'):
                dangerous_perms.append('Modify All Data')
            if perms.get('ViewAllData'):
                dangerous_perms.append('View All Data')
            if perms.get('ManageUsers'):
                dangerous_perms.append('Manage Users')
            if perms.get('AuthorApex'):
                dangerous_perms.append('Author Apex')
            
            if dangerous_perms:
                dangerous_permission_sets.append({
                    'Name': ps['Name'],
                    'Label': ps['Label'],
                    'DangerousPermissions': dangerous_perms,
                    'AssignedToUserCount': ps.get('AssignmentCount', 0),
                    'AssignedUsers': [a['Username'] for a in ps.get('Assignments', [])]
                })
        
        # Analyze sharing settings for public exposure
        public_objects = []
        
        for obj in data['sharing_settings']:
            if obj['IsPublic'] and obj['IsReadWrite']:
                public_objects.append({
                    'Object': obj['Object'],
                    'Label': obj['Label'],
                    'SharingModel': obj['SharingModel'],
                    'IsCustom': obj['IsCustom']
                })
        
        return {
            'summary': {
                'total_users': len(data['users']),
                'admin_users': len(admin_users),
                'dormant_users': len(dormant_users),
                'permission_sets': len(data['permission_sets']),
                'profiles': len(data['profiles']),
                'dangerous_permission_sets': len(dangerous_permission_sets),
                'public_read_write_objects': len(public_objects)
            },
            'identity_access': {
                'admin_users': admin_users[:10],  # Limit for context
                'dormant_users': dormant_users[:20]
            },
            'permissions': {
                'dangerous_permission_sets': dangerous_permission_sets
            },
            'sharing_model': {
                'public_read_write_objects': public_objects
            }
        }
    
    def _prepare_profile_data(self, data):
        """Structure data for profile analysis"""
        
        # Extract key profile information
        profile = data['profile']
        
        # Analyze object permissions
        full_crud_objects = []
        view_all_objects = []
        modify_all_objects = []
        
        for perm in data.get('object_permissions', []):
            obj_name = perm['SObjectType']
            
            if (perm.get('PermissionsCreate') and perm.get('PermissionsRead') and 
                perm.get('PermissionsEdit') and perm.get('PermissionsDelete')):
                full_crud_objects.append(obj_name)
            
            if perm.get('PermissionsViewAllRecords'):
                view_all_objects.append(obj_name)
            
            if perm.get('PermissionsModifyAllRecords'):
                modify_all_objects.append(obj_name)
        
        # Analyze field permissions
        editable_fields = []
        for field_perm in data.get('field_permissions', [])[:50]:  # Limit for context
            if field_perm.get('PermissionsEdit'):
                editable_fields.append({
                    'Object': field_perm['SObjectType'],
                    'Field': field_perm['Field']
                })
        
        return {
            'profile_info': {
                'Id': profile['Id'],
                'Name': profile['Name'],
                'Description': profile.get('Description', 'N/A')
            },
            'object_permissions': {
                'full_crud_count': len(full_crud_objects),
                'full_crud_objects': full_crud_objects[:30],  # Limit for context
                'view_all_records': view_all_objects,
                'modify_all_records': modify_all_objects
            },
            'field_permissions': {
                'editable_fields_count': len(editable_fields),
                'sample_editable_fields': editable_fields[:20]
            }
        }