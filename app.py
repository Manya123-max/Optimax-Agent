import gradio as gr
import os
from agents.salesforce_client import SalesforceClient
from agents.codegen_analyzer import CodeGenSecurityAnalyzer, HybridAnalyzer
import json

def perform_full_scan(sf_instance, sf_username, sf_password, sf_token, hf_token, use_hybrid):
    """Perform full org scan using CodeGen"""
    try:
        # Initialize Salesforce client
        sf_client = SalesforceClient(
            username=sf_username,
            password=sf_password,
            security_token=sf_token,
            domain=sf_instance
        )
        
        # Initialize CodeGen analyzer
        if use_hybrid:
            analyzer = HybridAnalyzer(
                model_name="mistralai/Mistral-7B-Instruct-v0.2",
                hf_token=hf_token
            )
            yield "🤖 Using Hybrid Analysis (Rules + AI)\n\n"
        else:
            analyzer = CodeGenSecurityAnalyzer(
                model_name="mistralai/Mistral-7B-Instruct-v0.2",
                hf_token=hf_token
            )
            yield "🤖 Using Full AI Analysis with Mistral-7B\n\n"
        
        # Fetch metadata
        yield "🔍 Connecting to Salesforce...\n"
        org_id = sf_client.get_org_id()
        yield f"✓ Connected to Org: {org_id}\n\n"
        
        yield "📊 Fetching user data...\n"
        users = sf_client.fetch_users()
        yield f"✓ Found {len(users)} users\n\n"
        
        yield "🔐 Fetching permission sets...\n"
        permission_sets = sf_client.fetch_permission_sets()
        yield f"✓ Found {len(permission_sets)} permission sets\n\n"
        
        yield "📋 Fetching profiles...\n"
        profiles = sf_client.fetch_profiles()
        yield f"✓ Found {len(profiles)} profiles\n\n"
        
        yield "🔗 Fetching sharing settings...\n"
        sharing_settings = sf_client.fetch_sharing_settings()
        yield f"✓ Retrieved sharing configuration\n\n"
        
        # Prepare analysis data
        yield "🔧 Preparing data for analysis...\n\n"
        
        # Analyze users for risks
        admin_users = [u for u in users if 'Admin' in u.get('ProfileName', '')]
        dormant_users = [u for u in users if u.get('IsDormant', False)]
        
        # Analyze permission sets
        dangerous_permission_sets = []
        for ps in permission_sets:
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
        
        # Analyze sharing settings
        public_objects = []
        for obj in sharing_settings:
            if obj['IsPublic'] and obj['IsReadWrite']:
                public_objects.append({
                    'Object': obj['Object'],
                    'Label': obj['Label'],
                    'SharingModel': obj['SharingModel'],
                    'IsCustom': obj['IsCustom']
                })
        
        analysis_data = {
            'org_id': org_id,
            'summary': {
                'total_users': len(users),
                'admin_users': len(admin_users),
                'dormant_users': len(dormant_users),
                'permission_sets': len(permission_sets),
                'profiles': len(profiles),
                'dangerous_permission_sets': len(dangerous_permission_sets),
                'public_read_write_objects': len(public_objects)
            },
            'identity_access': {
                'admin_users': admin_users[:10],
                'dormant_users': dormant_users[:20]
            },
            'permissions': {
                'dangerous_permission_sets': dangerous_permission_sets
            },
            'sharing_model': {
                'public_read_write_objects': public_objects
            }
        }
        
        # Analyze with CodeGen
        yield "🤖 Analyzing security with AI model...\n"
        yield "⏳ This may take 20-30 seconds for the model to load...\n\n"
        
        report = analyzer.analyze_full_org(analysis_data)
        
        yield "✅ Analysis Complete!\n\n"
        yield "=" * 80 + "\n"
        yield report
        
    except Exception as e:
        yield f"❌ Error: {str(e)}\n"
        yield f"Please check your credentials and try again.\n\n"
        yield f"If you see 'Model is loading', please wait 20-30 seconds and try again."

def perform_profile_scan(sf_instance, sf_username, sf_password, sf_token, 
                        profile_id, hf_token):
    """Perform profile-specific scan using CodeGen"""
    try:
        sf_client = SalesforceClient(
            username=sf_username,
            password=sf_password,
            security_token=sf_token,
            domain=sf_instance
        )
        
        analyzer = CodeGenSecurityAnalyzer(
            model_name="mistralai/Mistral-7B-Instruct-v0.2",
            hf_token=hf_token
        )
        
        yield f"🔍 Analyzing Profile: {profile_id}\n\n"
        
        yield "📋 Fetching profile metadata...\n"
        profile_data = sf_client.fetch_profile_details(profile_id)
        yield "✓ Profile data retrieved\n\n"
        
        yield "🔐 Fetching object permissions...\n"
        object_perms = sf_client.fetch_object_permissions(profile_id)
        yield f"✓ Found permissions for {len(object_perms)} objects\n\n"
        
        yield "📄 Fetching field permissions...\n"
        field_perms = sf_client.fetch_field_permissions(profile_id)
        yield f"✓ Found {len(field_perms)} field permissions\n\n"
        
        # Prepare analysis data
        full_crud_objects = []
        view_all_objects = []
        modify_all_objects = []
        
        for perm in object_perms:
            obj_name = perm['SObjectType']
            
            if (perm.get('PermissionsCreate') and perm.get('PermissionsRead') and 
                perm.get('PermissionsEdit') and perm.get('PermissionsDelete')):
                full_crud_objects.append(obj_name)
            
            if perm.get('PermissionsViewAllRecords'):
                view_all_objects.append(obj_name)
            
            if perm.get('PermissionsModifyAllRecords'):
                modify_all_objects.append(obj_name)
        
        analysis_data = {
            'profile_info': {
                'Id': profile_data['Id'],
                'Name': profile_data['Name'],
                'Description': profile_data.get('Description', 'N/A')
            },
            'object_permissions': {
                'full_crud_count': len(full_crud_objects),
                'full_crud_objects': full_crud_objects,
                'view_all_records': view_all_objects,
                'modify_all_records': modify_all_objects
            },
            'field_permissions': {
                'editable_fields_count': len([f for f in field_perms if f.get('PermissionsEdit')])
            }
        }
        
        yield "🤖 Analyzing with AI...\n"
        yield "⏳ Model loading (20-30 seconds)...\n\n"
        
        report = analyzer.analyze_profile(analysis_data)
        
        yield "✅ Analysis Complete!\n\n"
        yield "=" * 80 + "\n"
        yield report
        
    except Exception as e:
        yield f"❌ Error: {str(e)}\n"
        yield "If model is loading, please wait and try again."

# Create Gradio interface
with gr.Blocks(title="Salesforce Security Analyst (CodeGen)", theme=gr.themes.Soft()) as demo:
    gr.Markdown("""
    # 🛡️ Salesforce Security Analyzer - Open Source Edition
    ### Powered by CodeGen & Mistral AI Models (100% Free!)
    
    **No API costs** - Uses free Hugging Face Inference API
    """)
    
    with gr.Row():
        with gr.Column():
            gr.Markdown("### 🔐 Salesforce Credentials")
            sf_instance = gr.Textbox(
                label="Instance URL",
                placeholder="login.salesforce.com or test.salesforce.com",
                value="login.salesforce.com"
            )
            sf_username = gr.Textbox(label="Username", placeholder="user@example.com")
            sf_password = gr.Textbox(label="Password", type="password")
            sf_token = gr.Textbox(
                label="Security Token",
                type="password",
                info="Your Salesforce security token"
            )
            
        with gr.Column():
            gr.Markdown("### 🤖 Hugging Face Configuration")
            hf_token = gr.Textbox(
                label="Hugging Face Token (Optional)",
                type="password",
                placeholder="hf_...",
                info="Get free token from huggingface.co/settings/tokens"
            )
            gr.Markdown("""
            **Model Used:** Mistral-7B-Instruct-v0.2
            - Free to use via HF Inference API
            - No GPU needed
            - First run takes 20-30s (model loading)
            """)
    
    gr.Markdown("---")
    
    with gr.Tab("Full Organization Scan"):
        gr.Markdown("""
        **Comprehensive security audit:**
        - 🔍 Identity & Access Management
        - 🔐 Permission Sets & Profiles
        - 🔗 Sharing Model Vulnerabilities
        - 🛡️ Record-Level Security
        
        **Analysis Method:**
        - **Hybrid**: Fast rule-based detection + AI recommendations (Recommended)
        - **Full AI**: Complete AI-powered analysis (Slower but more detailed)
        """)
        
        use_hybrid = gr.Checkbox(
            label="Use Hybrid Analysis (Faster)",
            value=True,
            info="Combines rule-based detection with AI recommendations"
        )
        
        full_scan_btn = gr.Button("🚀 Start Full Scan", variant="primary", size="lg")
        full_scan_output = gr.Textbox(
            label="Scan Results",
            lines=25,
            max_lines=50,
            show_copy_button=True
        )
        
        full_scan_btn.click(
            fn=perform_full_scan,
            inputs=[sf_instance, sf_username, sf_password, sf_token, hf_token, use_hybrid],
            outputs=full_scan_output
        )
    
    with gr.Tab("Profile Scan"):
        gr.Markdown("""
        **Targeted profile analysis:**
        - 🔐 System Permissions
        - 📊 Object-Level Permissions
        - 📝 Field-Level Security
        - ✅ Compliance Checks
        """)
        
        profile_id = gr.Textbox(
            label="Profile ID",
            placeholder="00e...",
            info="Enter the 18-character Profile ID"
        )
        
        profile_scan_btn = gr.Button("🔍 Analyze Profile", variant="primary", size="lg")
        profile_scan_output = gr.Textbox(
            label="Profile Analysis",
            lines=25,
            max_lines=50,
            show_copy_button=True
        )
        
        profile_scan_btn.click(
            fn=perform_profile_scan,
            inputs=[sf_instance, sf_username, sf_password, sf_token, profile_id, hf_token],
            outputs=profile_scan_output
        )
    
    with gr.Tab("ℹ️ Setup Guide"):
        gr.Markdown("""
        ## How to Get Started
        
        ### 1. Salesforce Credentials
        ```
        Username: your@email.com
        Password: YourPassword
        Security Token: Get from Setup > My Personal Info > Reset Security Token
        ```
        
        ### 2. Hugging Face Token (Optional but Recommended)
        1. Go to https://huggingface.co/settings/tokens
        2. Create new token (Read access is enough)
        3. Copy and paste here
        
        **Why HF Token?**
        - Higher rate limits
        - Faster model loading
        - Better priority in queue
        
        ### 3. First Run
        - The model takes 20-30 seconds to load on first use
        - Subsequent runs are much faster
        - If you see "Model is loading", just wait and try again
        
        ### 4. Troubleshooting
        
        **"503 Service Unavailable"**
        - Model is loading, wait 30 seconds and retry
        
        **"Salesforce Connection Failed"**
        - Check username/password
        - Verify security token (it's appended to password in some cases)
        - Try with sandbox: test.salesforce.com
        
        **"Rate Limit Exceeded"**
        - Add Hugging Face token for higher limits
        - Or wait 60 seconds between scans
        
        ## Model Information
        
        This tool uses **Mistral-7B-Instruct-v0.2**, an open-source AI model:
        - ✅ Completely free to use
        - ✅ No API costs
        - ✅ Privacy-friendly (runs on HF infrastructure)
        - ✅ Good at code and security analysis
        
        Alternative models you can use (modify code):
        - `codellama/CodeLlama-13b-Instruct-hf` (better for code)
        - `Salesforce/codegen2-16B` (best but requires GPU)
        - `bigcode/starcoder2-15b` (code-focused)
        """)
    
    gr.Markdown("""
    ---
    ### 🔒 Security & Privacy
    - Your credentials are NEVER stored
    - Used only for the current scan session
    - No data is sent to any servers except Salesforce and HF Inference API
    - All processing is done in real-time
    
    ### 📊 Open Source
    This tool is powered by open-source models and can be self-hosted!
    """)

if __name__ == "__main__":
    demo.launch(
        share=False,  # Set to True to create public link
        server_name="0.0.0.0",  # Allow external access
        server_port=7860
    )