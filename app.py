import gradio as gr
import os
from dotenv import load_dotenv
from agents.salesforce_client import SalesforceClient
from agents.codegen_analyzer import HybridAnalyzer
from utils.report_generator import ReportGenerator

load_dotenv()

def analyze_salesforce_org(
    org_id: str,
    username: str,
    password: str,
    security_token: str,
    scan_type: str,
    profile_id: str = None
):
    """
    Main function to analyze Salesforce org for security vulnerabilities
    """
    try:
        # Initialize Salesforce client
        sf_client = SalesforceClient(
            username=username,
            password=password,
            security_token=security_token,
            domain='login'  # Use 'test' for sandbox
        )
        
        # Verify connection
        if not sf_client.connect():
            return "❌ **Error**: Failed to connect to Salesforce. Please check your credentials."
        
        # Initialize analyzer
        analyzer = HybridAnalyzer(
            model_name="Salesforce/codegen-350M-mono",  # Lightweight CodeGen model
            use_rule_based=True  # Hybrid approach
        )
        
        # Perform analysis based on scan type
        if scan_type == "Full Organization Scan":
            status = "🔍 **Starting Full Organization Security Scan...**\n\n"
            
            # Fetch all data
            status += "📥 Fetching organization data...\n"
            users = sf_client.fetch_users()
            permission_sets = sf_client.fetch_permission_sets()
            profiles = sf_client.fetch_profiles()
            sharing_settings = sf_client.fetch_sharing_settings()
            login_history = sf_client.fetch_login_history()
            
            status += f"✅ Retrieved: {len(users)} users, {len(permission_sets)} permission sets, {len(profiles)} profiles\n\n"
            
            # Analyze
            status += "🔬 Analyzing security posture...\n"
            analysis_result = analyzer.analyze_full_org(
                users=users,
                permission_sets=permission_sets,
                profiles=profiles,
                sharing_settings=sharing_settings,
                login_history=login_history
            )
            
            # Generate report
            report_gen = ReportGenerator()
            final_report = report_gen.generate_full_report(analysis_result, org_id)
            
            return status + "\n\n" + final_report
            
        elif scan_type == "Profile-Specific Scan":
            if not profile_id:
                return "❌ **Error**: Profile ID is required for profile-specific scan."
            
            status = f"🔍 **Starting Profile Security Scan** (Profile ID: {profile_id})\n\n"
            
            # Fetch profile data
            status += "📥 Fetching profile data...\n"
            profile_data = sf_client.fetch_profile_details(profile_id)
            
            if not profile_data:
                return f"❌ **Error**: Profile {profile_id} not found."
            
            status += f"✅ Analyzing profile: {profile_data.get('Name', 'Unknown')}\n\n"
            
            # Analyze
            status += "🔬 Analyzing profile permissions...\n"
            analysis_result = analyzer.analyze_profile(profile_data)
            
            # Generate report
            report_gen = ReportGenerator()
            final_report = report_gen.generate_profile_report(analysis_result, profile_id)
            
            return status + "\n\n" + final_report
        
    except Exception as e:
        return f"❌ **Error during analysis**: {str(e)}\n\nPlease check your credentials and try again."

# Gradio Interface
with gr.Blocks(title="Salesforce Security Analyzer", theme=gr.themes.Soft()) as demo:
    gr.Markdown("""
    # 🛡️ Salesforce Security Vulnerability Analyzer
    
    Analyze your Salesforce organization for security vulnerabilities using AI-powered analysis.
    
    **Supported Scans:**
    - 🌐 Full Organization Scan: Comprehensive security analysis
    - 👤 Profile-Specific Scan: Deep dive into specific profile permissions
    """)
    
    with gr.Row():
        with gr.Column():
            gr.Markdown("### 🔐 Salesforce Credentials")
            
            org_id = gr.Textbox(
                label="Organization ID",
                placeholder="00D...",
                info="Your Salesforce Org ID (optional, for reporting)"
            )
            
            username = gr.Textbox(
                label="Username",
                placeholder="user@example.com",
                info="Your Salesforce username"
            )
            
            password = gr.Textbox(
                label="Password",
                type="password",
                placeholder="Your password",
                info="Your Salesforce password"
            )
            
            security_token = gr.Textbox(
                label="Security Token",
                type="password",
                placeholder="Your security token",
                info="Security token sent to your email"
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
                info="Required only for profile-specific scans"
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
        inputs=[org_id, username, password, security_token, scan_type, profile_id],
        outputs=[output]
    )
    
    gr.Markdown("""
    ---
    ### ⚠️ Security Notes:
    - Credentials are used only for analysis and are not stored
    - Uses read-only API calls
    - Powered by CodeGen AI for vulnerability detection
    
    ### 📚 Detected Vulnerabilities:
    - Misconfigured Profiles & Permission Sets
    - Dangerous Permissions (Modify All, View All Data)
    - Insecure Sharing Models (OWD misconfigurations)
    - Dormant Users & MFA Issues
    - Permission Escalation Risks
    """)

if __name__ == "__main__":
    demo.launch()