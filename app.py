import gradio as gr
import os
from agents.security_analyzer import SalesforceSecurityAgent
from agents.salesforce_client import SalesforceClient
import json

# Initialize the security agent
def init_agent(api_key):
    """Initialize agent with Anthropic API key"""
    os.environ['ANTHROPIC_API_KEY'] = api_key
    return SalesforceSecurityAgent()

def perform_full_scan(sf_instance, sf_username, sf_password, sf_token, anthropic_key):
    """Perform full org scan"""
    try:
        # Initialize Salesforce client
        sf_client = SalesforceClient(
            username=sf_username,
            password=sf_password,
            security_token=sf_token,
            domain=sf_instance
        )
        
        # Initialize agent
        agent = init_agent(anthropic_key)
        
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
        
        # Analyze with AI agent
        yield "🤖 Analyzing security vulnerabilities with AI...\n\n"
        
        analysis_data = {
            'org_id': org_id,
            'users': users,
            'permission_sets': permission_sets,
            'profiles': profiles,
            'sharing_settings': sharing_settings
        }
        
        report = agent.analyze_full_org(analysis_data)
        
        yield "✅ Analysis Complete!\n\n"
        yield "=" * 80 + "\n"
        yield report
        
    except Exception as e:
        yield f"❌ Error: {str(e)}\n"
        yield f"Please check your credentials and try again."

def perform_profile_scan(sf_instance, sf_username, sf_password, sf_token, 
                        profile_id, anthropic_key):
    """Perform profile-specific scan"""
    try:
        sf_client = SalesforceClient(
            username=sf_username,
            password=sf_password,
            security_token=sf_token,
            domain=sf_instance
        )
        
        agent = init_agent(anthropic_key)
        
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
        
        yield "🤖 Analyzing with AI...\n\n"
        
        analysis_data = {
            'profile': profile_data,
            'object_permissions': object_perms,
            'field_permissions': field_perms
        }
        
        report = agent.analyze_profile(analysis_data)
        
        yield "✅ Analysis Complete!\n\n"
        yield "=" * 80 + "\n"
        yield report
        
    except Exception as e:
        yield f"❌ Error: {str(e)}"

# Create Gradio interface
with gr.Blocks(title="Salesforce Security Analyst", theme=gr.themes.Soft()) as demo:
    gr.Markdown("""
    # 🛡️ Salesforce Security Vulnerability Analyzer
    ### AI-Powered Security Audit for Salesforce Organizations
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
            gr.Markdown("### 🤖 AI Configuration")
            anthropic_key = gr.Textbox(
                label="Anthropic API Key",
                type="password",
                placeholder="sk-ant-..."
            )
    
    gr.Markdown("---")
    
    with gr.Tab("Full Organization Scan"):
        gr.Markdown("""
        **Comprehensive security audit including:**
        - Identity & Access Management
        - Permission Sets & Profiles Analysis
        - Sharing Model Vulnerabilities
        - Record-Level Security Issues
        """)
        
        full_scan_btn = gr.Button("🚀 Start Full Scan", variant="primary", size="lg")
        full_scan_output = gr.Textbox(
            label="Scan Results",
            lines=20,
            max_lines=50,
            show_copy_button=True
        )
        
        full_scan_btn.click(
            fn=perform_full_scan,
            inputs=[sf_instance, sf_username, sf_password, sf_token, anthropic_key],
            outputs=full_scan_output
        )
    
    with gr.Tab("Profile Scan"):
        gr.Markdown("""
        **Targeted profile analysis including:**
        - System Permissions Audit
        - Object-Level Permissions
        - Field-Level Security
        - Compliance Checks
        """)
        
        profile_id = gr.Textbox(
            label="Profile ID",
            placeholder="00e...",
            info="Enter the 18-character Profile ID"
        )
        
        profile_scan_btn = gr.Button("🔍 Analyze Profile", variant="primary", size="lg")
        profile_scan_output = gr.Textbox(
            label="Profile Analysis",
            lines=20,
            max_lines=50,
            show_copy_button=True
        )
        
        profile_scan_btn.click(
            fn=perform_profile_scan,
            inputs=[sf_instance, sf_username, sf_password, sf_token, profile_id, anthropic_key],
            outputs=profile_scan_output
        )
    
    gr.Markdown("""
    ---
    ### 📖 How to Use
    1. Enter your Salesforce credentials and security token
    2. Provide your Anthropic API key for AI analysis
    3. Choose scan type: Full Org or Profile-specific
    4. Review the detailed security report
    
    **Note:** Your credentials are never stored and are only used for the current session.
    """)

if __name__ == "__main__":
    demo.launch()