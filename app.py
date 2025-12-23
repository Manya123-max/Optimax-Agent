import gradio as gr
import os
from dotenv import load_dotenv
from agents.salesforce_client import SalesforceOAuthClient
from agents.codegen_analyzer import HybridAnalyzer
from utils.report_generator import ReportGenerator

load_dotenv()

def analyze_salesforce_org(
    org_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    security_token: str,
    scan_type: str,
    profile_id: str = None,
    is_sandbox: bool = False
):
    """
    Main function to analyze Salesforce org for security vulnerabilities using OAuth
    """
    try:
        # Initialize Salesforce OAuth client
        sf_client = SalesforceOAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            security_token=security_token,
            is_sandbox=is_sandbox
        )
        
        # Verify connection
        status_msg = "🔐 **Authenticating with Salesforce using OAuth 2.0...**\n\n"
        
        if not sf_client.connect():
            return status_msg + "❌ **Error**: OAuth authentication failed. Please check your Connected App credentials.\n\n**Troubleshooting:**\n- Verify Client ID and Client Secret are correct\n- Ensure Connected App has been active for 10+ minutes\n- Check that user has API access enabled\n- Verify OAuth scopes include 'api' and 'refresh_token'"
        
        status_msg += "✅ **OAuth authentication successful!**\n"
        status_msg += f"📍 **Connected to**: {sf_client.instance_url}\n"
        status_msg += f"🆔 **Organization ID**: {sf_client.org_id}\n\n"
        
        # Initialize analyzer
        analyzer = HybridAnalyzer(
            model_name="Salesforce/codegen-350M-mono",
            use_rule_based=True  # Hybrid approach
        )
        
        # Perform analysis based on scan type
        if scan_type == "Full Organization Scan":
            status_msg += "🔍 **Starting Full Organization Security Scan...**\n\n"
            
            # Fetch all data
            status_msg += "📥 **Fetching organization data...**\n"
            users = sf_client.fetch_users()
            status_msg += f"  ✓ Users: {len(users)}\n"
            
            permission_sets = sf_client.fetch_permission_sets()
            status_msg += f"  ✓ Permission Sets: {len(permission_sets)}\n"
            
            profiles = sf_client.fetch_profiles()
            status_msg += f"  ✓ Profiles: {len(profiles)}\n"
            
            sharing_settings = sf_client.fetch_sharing_settings()
            status_msg += f"  ✓ Sharing Settings: Loaded\n"
            
            login_history = sf_client.fetch_login_history()
            status_msg += f"  ✓ Login History: {len(login_history)} records\n\n"
            
            # Analyze
            status_msg += "🔬 **Analyzing security posture...**\n"
            analysis_result = analyzer.analyze_full_org(
                users=users,
                permission_sets=permission_sets,
                profiles=profiles,
                sharing_settings=sharing_settings,
                login_history=login_history
            )
            
            # Generate report
            status_msg += "📊 **Generating comprehensive report...**\n\n"
            report_gen = ReportGenerator()
            final_report = report_gen.generate_full_report(analysis_result, sf_client.org_id)
            
            return status_msg + "---\n\n" + final_report
            
        elif scan_type == "Profile-Specific Scan":
            if not profile_id:
                return status_msg + "❌ **Error**: Profile ID is required for profile-specific scan.\n\n**How to find Profile ID:**\n1. Go to Setup → Profiles\n2. Click on the profile name\n3. Look at the URL: `/00e.../e` (the `00e...` part is the Profile ID)"
            
            status_msg += f"🔍 **Starting Profile Security Scan**\n"
            status_msg += f"📋 **Profile ID**: {profile_id}\n\n"
            
            # Fetch profile data
            status_msg += "📥 **Fetching profile data...**\n"
            profile_data = sf_client.fetch_profile_details(profile_id)
            
            if not profile_data:
                return status_msg + f"❌ **Error**: Profile {profile_id} not found or you don't have access.\n\n**Verify:**\n- Profile ID is correct (starts with '00e')\n- User has permission to view profiles"
            
            status_msg += f"✅ **Profile Found**: {profile_data.get('Name', 'Unknown')}\n"
            status_msg += f"👥 **Assigned Users**: {len(profile_data.get('AssignedUsers', []))}\n\n"
            
            # Analyze
            status_msg += "🔬 **Analyzing profile permissions...**\n"
            analysis_result = analyzer.analyze_profile(profile_data)
            
            # Generate report
            status_msg += "📊 **Generating profile report...**\n\n"
            report_gen = ReportGenerator()
            final_report = report_gen.generate_profile_report(analysis_result, profile_id)
            
            return status_msg + "---\n\n" + final_report
        
    except Exception as e:
        error_msg = f"❌ **Error during analysis**: {str(e)}\n\n"
        error_msg += "**Common Issues:**\n"
        error_msg += "- **OAuth Error**: Check Connected App setup (see Setup Guide)\n"
        error_msg += "- **API Access**: Ensure user has 'API Enabled' permission\n"
        error_msg += "- **Network**: Verify firewall allows Salesforce API access\n"
        error_msg += "- **Timeout**: Try again or use a smaller date range\n\n"
        error_msg += "**Debug Info:**\n"
        error_msg += f"```\n{str(e)}\n```"
        return error_msg

# Gradio Interface
with gr.Blocks(title="Salesforce Security Analyzer - OAuth", theme=gr.themes.Soft()) as demo:
    gr.Markdown("""
    # 🛡️ Salesforce Security Vulnerability Analyzer
    ### OAuth 2.0 Edition - Enterprise SSO Compatible
    
    Analyze your Salesforce organization for security vulnerabilities using AI-powered analysis with **OAuth 2.0 authentication** (works with SAML, Azure AD, Okta, Google SSO).
    
    **✨ Why OAuth?**
    - ✅ Works with SSO-enabled orgs
    - ✅ No security token needed
    - ✅ Revocable access
    - ✅ MFA compliant
    - ✅ Full audit trail
    
    **🔧 First Time Setup**: [Create Connected App Guide](https://github.com/your-repo/CONNECTED_APP_SETUP.md)
    """)
    
    with gr.Row():
        with gr.Column():
            gr.Markdown("### 🔐 OAuth 2.0 Credentials")
            
            gr.Markdown("""
            **Required**: Create a Connected App first ([Setup Guide](CONNECTED_APP_SETUP.md))
            """)
            
            client_id = gr.Textbox(
                label="Client ID (Consumer Key)",
                placeholder="3MVG9...",
                info="From your Connected App (long alphanumeric string)",
                type="password"
            )
            
            client_secret = gr.Textbox(
                label="Client Secret (Consumer Secret)",
                type="password",
                placeholder="1234567890123456",
                info="Click 'reveal' in Connected App to see this"
            )
            
            username = gr.Textbox(
                label="Salesforce Username",
                placeholder="user@company.com",
                info="Your SSO email or Salesforce username"
            )
            
            password = gr.Textbox(
                label="Salesforce Password",
                type="password",
                placeholder="Your SSO password",
                info="Your SSO password (for OAuth flow only, not stored)"
            )
            
            security_token = gr.Textbox(
                label="Salesforce Security Token",
                type="password",
                placeholder="Your security token",
                info="Find in Salesforce Settings -> Reset My Security Token"
            )

            is_sandbox = gr.Checkbox(
                label="Sandbox Environment",
                value=False,
                info="Check if connecting to a Salesforce Sandbox"
            )
            
            org_id = gr.Textbox(
                label="Organization ID (Optional)",
                placeholder="00D...",
                info="For reporting only - will auto-detect if not provided"
            )
            
            gr.Markdown("### 🎯 Scan Configuration")
            
            scan_type = gr.Radio(
                choices=["Full Organization Scan", "Profile-Specific Scan"],
                label="Scan Type",
                value="Full Organization Scan",
                info="Choose the type of security scan"
            )
            
            profile_id = gr.Textbox(
                label="Profile ID (for Profile Scan)",
                placeholder="00e...",
                visible=False,
                info="Find in Setup → Profiles → [Profile Name] → URL"
            )
            
            # Toggle profile ID visibility based on scan type
            def toggle_profile_input(scan_type):
                return gr.update(visible=(scan_type == "Profile-Specific Scan"))
            
            scan_type.change(
                fn=toggle_profile_input,
                inputs=[scan_type],
                outputs=[profile_id]
            )
            
            analyze_btn = gr.Button("🚀 Start Security Analysis", variant="primary", size="lg")
        
        with gr.Column():
            gr.Markdown("### 📊 Analysis Report")
            output = gr.Markdown(label="Security Analysis Report")
    
    # Button click handler
    analyze_btn.click(
        fn=analyze_salesforce_org,
        inputs=[org_id, client_id, client_secret, username, password, security_token, scan_type, profile_id, is_sandbox],
        outputs=[output]
    )
    
    gr.Markdown("""
    ---
    ### ⚠️ Security & Privacy:
    - **OAuth 2.0 Authentication** - Industry standard, secure
    - **No Password Storage** - Credentials used only for token exchange
    - **Read-Only Analysis** - Uses read-only API calls
    - **Revocable Access** - Tokens can be revoked anytime from Salesforce
    - **Audit Trail** - All API calls logged in Salesforce
    - **MFA Compatible** - Works with multi-factor authentication
    
    ### 📚 Detected Vulnerabilities:
    - **Critical**: Modify All Data, View All Data, Manage Users
    - **High**: Author Apex, Customize Application, Manage Roles
    - **Medium**: Export Reports, Public OWD settings
    - **Identity**: Dormant users, MFA compliance, admin proliferation
    - **Sharing**: Insecure OWD, over-broad sharing rules
    
    ### 🆘 Need Help?
    - [Connected App Setup Guide](CONNECTED_APP_SETUP.md)
    - [Troubleshooting OAuth Issues](#troubleshooting)
    - [Salesforce API Documentation](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/)
    
    ---
    
    **Powered by:** CodeGen AI • Salesforce REST API • OAuth 2.0
    """)

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)