---
title: Salesforce Security Agent
emoji: 🏃
colorFrom: yellow
colorTo: red
sdk: gradio
sdk_version: 6.1.0
app_file: app.py
pinned: false
license: mit
short_description: 'Vulnerabilities Checking using agent '
---

Check out the configuration reference at https://huggingface.co/docs/hub/spaces-config-reference
# 🛡️ Salesforce Security Vulnerability Analyzer

AI-powered security analysis agent for Salesforce organizations using CodeGen and rule-based detection.

## 🎯 Features

### Comprehensive Security Analysis
- ✅ **Identity & Access Management**: User authentication, MFA compliance, dormant accounts
- ✅ **Permission Security**: Profiles, Permission Sets, dangerous permissions detection
- ✅ **Sharing Model**: OWD settings, role hierarchy, sharing rules analysis
- ✅ **Login Anomalies**: Failed login attempts, IP analysis, suspicious patterns

### Scan Types
1. **Full Organization Scan**: Complete security posture assessment
2. **Profile-Specific Scan**: Deep dive into individual profile security

### Key Vulnerabilities Detected
- 🔴 Modify All Data / View All Data permissions
- 🔴 Misconfigured profiles with admin-level access
- 🔴 Public Read/Write OWD settings on sensitive objects
- 🟠 Excessive permission set assignments
- 🟠 Dormant users with active access
- 🟡 MFA non-compliance
- 🟡 Over-broad sharing rules

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Salesforce account with API access
- Salesforce credentials (username, password, security token)

### Local Development

1. **Clone the repository**
```bash
git clone https://huggingface.co/spaces/YOUR_USERNAME/salesforce-security-analyzer
cd salesforce-security-analyzer
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Access the interface**
Navigate to `http://localhost:7860` in your browser

### Hugging Face Spaces Deployment

1. **Create a new Space** on Hugging Face
2. **Upload all files** to your Space
3. **Wait for build** to complete
4. **Access your Space** at `https://huggingface.co/spaces/YOUR_USERNAME/salesforce-security-analyzer`

## 📖 Usage Guide

### Full Organization Scan

1. Enter your Salesforce credentials:
   - Organization ID (optional)
   - Username
   - Password
   - Security Token

2. Select "Full Organization Scan"

3. Click "Start Security Analysis"

4. Review the comprehensive report covering:
   - Executive summary with risk score
   - Critical and high-risk findings
   - Identity & access issues
   - Permission vulnerabilities
   - Sharing model security
   - Prioritized action items

### Profile-Specific Scan

1. Enter your Salesforce credentials

2. Select "Profile-Specific Scan"

3. Enter the Profile ID (e.g., `00e...`)

4. Click "Start Security Analysis"

5. Review the profile-specific report with:
   - Dangerous permissions
   - Risk assessment
   - User impact analysis
   - Remediation recommendations

## 🔐 Security & Privacy

- **No Data Storage**: Credentials are used only for analysis and never stored
- **Read-Only Access**: Uses read-only Salesforce API calls
- **Encrypted Connection**: HTTPS/TLS for all API communications
- **Local Processing**: Analysis performed locally, no external data sharing

## 🏗️ Architecture

```
salesforce-security-analyzer/
├── app.py                    # Gradio interface
├── agents/
│   ├── salesforce_client.py  # Salesforce API wrapper
│   └── codegen_analyzer.py   # AI + rule-based analyzer
├── analyzers/
│   ├── permission_analyzer.py # Permission security
│   ├── sharing_analyzer.py    # Sharing model security
│   └── identity_analyzer.py   # Identity & access
└── utils/
    └── report_generator.py    # Report formatting
```

## 🤖 AI Model

Uses **Salesforce CodeGen** (350M parameters) for:
- Natural language security insights
- Pattern recognition in configurations
- Contextual recommendations

**Hybrid Approach**: Combines rule-based detection with AI-powered analysis for accuracy and explainability.

## 📊 Sample Report Output

```markdown
# Salesforce Security Analysis Report

## Executive Summary
- Total Security Findings: 47
- Critical Issues: 8 🔴
- High Risk Issues: 15 🟠
- Overall Risk Score: 73/100

🚨 CRITICAL RISK LEVEL - Immediate action required!

## Critical Findings

### 1. Dangerous Permission in Permission Set
**Description**: Permission Set 'Sales_Admin_Access' grants Modify All Data to 12 user(s)
**Impact**: Users can view, edit, and delete ALL records in the org
**Recommendation**: Review necessity of this permission...
```

## 🛠️ Customization

### Modify Dangerous Permissions List
Edit `analyzers/permission_analyzer.py`:

```python
DANGEROUS_PERMISSIONS = {
    'PermissionsCustomPermission': {
        'severity': 'High',
        'description': 'Custom dangerous permission',
        'impact': 'Your impact description'
    }
}
```

### Adjust Risk Scoring
Modify `_calculate_risk_score()` in `codegen_analyzer.py`

### Add Custom Analyzers
Create new analyzer in `analyzers/` directory and integrate in `HybridAnalyzer`

## 🔧 Troubleshooting

### Authentication Errors
- Verify username and password
- Ensure security token is current (check email)
- For sandbox, change domain to 'test' in code

### Model Loading Issues
- Ensure sufficient disk space (2GB+ for model)
- Check internet connection for first download
- Upgrade to CPU Upgrade on Hugging Face Spaces

### API Rate Limits
- Reduce query frequency
- Use smaller date ranges for LoginHistory
- Implement caching for metadata

## 📚 API Reference

### Salesforce API Endpoints Used
- `/services/data/v58.0/query` - SOQL queries
- `/services/data/v58.0/sobjects` - Object metadata
- Tooling API for metadata analysis

### Objects Queried
- `User` - User accounts
- `Profile` - Profile definitions
- `PermissionSet` - Permission set definitions
- `PermissionSetAssignment` - Assignments
- `LoginHistory` - Login records
- `UserRole` - Role hierarchy
- `SetupAuditTrail` - Configuration changes

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional security checks
- Enhanced AI prompts
- Custom field analysis
- Report export formats (PDF, CSV)
- Scheduled scanning

## 📝 License

MIT License - see LICENSE file

## 🔗 Resources

- [Salesforce Security Best Practices](https://developer.salesforce.com/docs/atlas.en-us.securityImplGuide.meta/securityImplGuide/)
- [CodeGen Model](https://huggingface.co/Salesforce/codegen-350M-mono)
- [Gradio Documentation](https://gradio.app/docs)

## ⚠️ Disclaimer

This tool is for security assessment purposes only. Always test in a sandbox environment first. Not a replacement for professional security audits.

---

**Built with ❤️ using Gradio, Transformers, and Salesforce APIs**