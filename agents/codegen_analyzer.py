"""
CodeGen-based Security Analyzer
Uses open-source models for vulnerability detection
"""

import requests
import json
from typing import Dict, List, Any
import time

class CodeGenSecurityAnalyzer:
    """Open-source model-based security analyzer"""
    
    def __init__(self, model_name="mistralai/Mistral-7B-Instruct-v0.2", hf_token=None):
        """
        Initialize with Hugging Face model
        
        Recommended models:
        - mistralai/Mistral-7B-Instruct-v0.2 (lightweight, fast)
        - codellama/CodeLlama-13b-Instruct-hf (better for code)
        - Salesforce/codegen2-16B (best but requires GPU)
        """
        self.model_name = model_name
        self.hf_token = hf_token
        self.api_url = f"https://api-inference.huggingface.co/models/{model_name}"
        
        # For local deployment
        self.local_mode = False
        self.local_pipeline = None
    
    def initialize_local_model(self):
        """Initialize model locally (requires GPU/CPU with sufficient RAM)"""
        from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
        
        print(f"Loading {self.model_name} locally...")
        
        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            device_map="auto",  # Automatically use available devices
            load_in_8bit=True,  # Use 8-bit quantization to reduce memory
        )
        
        self.local_pipeline = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=2000,
            temperature=0.1,
            do_sample=True,
        )
        
        self.local_mode = True
        print("Model loaded successfully!")
    
    def generate_response(self, prompt: str, max_tokens: int = 2000) -> str:
        """Generate response using HF Inference API or local model"""
        
        if self.local_mode:
            return self._generate_local(prompt, max_tokens)
        else:
            return self._generate_api(prompt, max_tokens)
    
    def _generate_api(self, prompt: str, max_tokens: int) -> str:
        """Use Hugging Face Inference API"""
        headers = {}
        if self.hf_token:
            headers["Authorization"] = f"Bearer {self.hf_token}"
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=60
                )
                
                if response.status_code == 503:
                    # Model is loading, wait and retry
                    wait_time = 20 * (attempt + 1)
                    print(f"Model loading, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                result = response.json()
                
                if isinstance(result, list) and len(result) > 0:
                    return result[0].get("generated_text", "")
                elif isinstance(result, dict):
                    return result.get("generated_text", "")
                
                return str(result)
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise Exception(f"API request failed after {max_retries} attempts: {e}")
                time.sleep(5)
        
        raise Exception("Failed to generate response")
    
    def _generate_local(self, prompt: str, max_tokens: int) -> str:
        """Generate using local model"""
        result = self.local_pipeline(
            prompt,
            max_new_tokens=max_tokens,
            temperature=0.1,
            do_sample=True
        )
        return result[0]["generated_text"]
    
    def analyze_full_org(self, data: Dict[str, Any]) -> str:
        """Analyze organization security"""
        
        # Structure the analysis prompt
        prompt = self._create_full_scan_prompt(data)
        
        # Generate analysis
        analysis = self.generate_response(prompt, max_tokens=3000)
        
        # Post-process and format
        formatted_report = self._format_report(analysis, data)
        
        return formatted_report
    
    def analyze_profile(self, data: Dict[str, Any]) -> str:
        """Analyze specific profile"""
        
        prompt = self._create_profile_scan_prompt(data)
        analysis = self.generate_response(prompt, max_tokens=2000)
        formatted_report = self._format_profile_report(analysis, data)
        
        return formatted_report
    
    def _create_full_scan_prompt(self, data: Dict[str, Any]) -> str:
        """Create optimized prompt for open-source models"""
        
        # Extract key statistics
        stats = data.get('summary', {})
        
        # Build concise prompt (open-source models work better with shorter context)
        prompt = f"""<s>[INST] You are a Salesforce security expert. Analyze this organization for vulnerabilities.

ORGANIZATION DATA:
- Total Users: {stats.get('total_users', 0)}
- Admin Users: {stats.get('admin_users', 0)}
- Dormant Users: {stats.get('dormant_users', 0)}
- Permission Sets: {stats.get('permission_sets', 0)}
- Dangerous Permission Sets: {stats.get('dangerous_permission_sets', 0)}
- Public Read/Write Objects: {stats.get('public_read_write_objects', 0)}

DANGEROUS PERMISSION SETS:
{json.dumps(data.get('permissions', {}).get('dangerous_permission_sets', [])[:5], indent=2)}

PUBLIC OBJECTS:
{json.dumps(data.get('sharing_model', {}).get('public_read_write_objects', [])[:5], indent=2)}

DORMANT ADMINS:
{json.dumps(data.get('identity_access', {}).get('admin_users', [])[:5], indent=2)}

Analyze these findings and provide:
1. CRITICAL ISSUES (severity: critical)
2. HIGH PRIORITY ISSUES (severity: high)
3. RECOMMENDATIONS (specific actions)

Format as clear sections with bullet points. [/INST]"""

        return prompt
    
    def _create_profile_scan_prompt(self, data: Dict[str, Any]) -> str:
        """Create profile analysis prompt"""
        
        profile_info = data.get('profile_info', {})
        obj_perms = data.get('object_permissions', {})
        
        prompt = f"""<s>[INST] Analyze this Salesforce profile for security issues.

PROFILE: {profile_info.get('Name')}
ID: {profile_info.get('Id')}

OBJECT PERMISSIONS:
- Full CRUD Objects: {obj_perms.get('full_crud_count', 0)}
- View All Records: {len(obj_perms.get('view_all_records', []))}
- Modify All Records: {len(obj_perms.get('modify_all_records', []))}

Objects with View All: {', '.join(obj_perms.get('view_all_records', [])[:10])}
Objects with Modify All: {', '.join(obj_perms.get('modify_all_records', [])[:10])}

Identify security risks and provide recommendations. [/INST]"""

        return prompt
    
    def _format_report(self, analysis: str, data: Dict[str, Any]) -> str:
        """Format the model output into a structured report"""
        
        stats = data.get('summary', {})
        
        report = f"""
# SALESFORCE SECURITY ANALYSIS REPORT
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Users Analyzed: {stats.get('total_users', 0)}
Admin Users: {stats.get('admin_users', 0)}
Dormant Accounts: {stats.get('dormant_users', 0)}
Dangerous Permission Sets: {stats.get('dangerous_permission_sets', 0)}
Public Read/Write Objects: {stats.get('public_read_write_objects', 0)}

## AI SECURITY ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{analysis}

## DETAILED FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Permission Sets with Dangerous Permissions:
"""
        
        for ps in data.get('permissions', {}).get('dangerous_permission_sets', [])[:10]:
            report += f"\n• {ps['Label']}\n"
            report += f"  - Permissions: {', '.join(ps['DangerousPermissions'])}\n"
            report += f"  - Assigned to: {ps['AssignedToUserCount']} users\n"
        
        report += "\n### Public Read/Write Objects:\n"
        for obj in data.get('sharing_model', {}).get('public_read_write_objects', [])[:10]:
            report += f"\n• {obj['Label']} ({obj['Object']})\n"
            report += f"  - Sharing Model: {obj['SharingModel']}\n"
        
        report += "\n### Dormant Administrator Accounts:\n"
        for admin in data.get('identity_access', {}).get('admin_users', [])[:10]:
            if admin.get('IsDormant'):
                report += f"\n• {admin['Name']} ({admin['Username']})\n"
                report += f"  - Last Login: {admin.get('LastLogin', 'Never')}\n"
        
        report += "\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        report += "End of Report\n"
        
        return report
    
    def _format_profile_report(self, analysis: str, data: Dict[str, Any]) -> str:
        """Format profile analysis report"""
        
        profile_info = data.get('profile_info', {})
        obj_perms = data.get('object_permissions', {})
        
        report = f"""
# PROFILE SECURITY ANALYSIS
Profile: {profile_info.get('Name')}
ID: {profile_info.get('Id')}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## AI ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{analysis}

## PERMISSION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Objects with Full CRUD: {obj_perms.get('full_crud_count', 0)}
{', '.join(obj_perms.get('full_crud_objects', [])[:20])}

### Objects with View All Records:
{', '.join(obj_perms.get('view_all_records', []))}

### Objects with Modify All Records:
{', '.join(obj_perms.get('modify_all_records', []))}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
End of Report
"""
        return report


# Lightweight alternative using rule-based analysis + CodeGen
class HybridAnalyzer(CodeGenSecurityAnalyzer):
    """Combines rule-based detection with AI analysis"""
    
    def analyze_full_org(self, data: Dict[str, Any]) -> str:
        """Hybrid approach: Rules + AI"""
        
        # Step 1: Rule-based detection (fast, accurate)
        rule_findings = self._rule_based_analysis(data)
        
        # Step 2: AI analysis for context and recommendations
        ai_context = self._get_ai_recommendations(rule_findings)
        
        # Step 3: Combine into report
        return self._create_hybrid_report(rule_findings, ai_context, data)
    
    def _rule_based_analysis(self, data: Dict[str, Any]) -> List[Dict]:
        """Fast rule-based vulnerability detection"""
        findings = []
        
        # Check dangerous permission sets
        for ps in data.get('permissions', {}).get('dangerous_permission_sets', []):
            for perm in ps['DangerousPermissions']:
                findings.append({
                    'severity': 'critical' if 'Modify' in perm or 'View' in perm else 'high',
                    'type': 'Dangerous Permission',
                    'title': f"{perm} in {ps['Label']}",
                    'detail': f"Assigned to {ps['AssignedToUserCount']} users",
                    'users': ps.get('AssignedUsers', [])
                })
        
        # Check public objects
        for obj in data.get('sharing_model', {}).get('public_read_write_objects', []):
            findings.append({
                'severity': 'critical',
                'type': 'Sharing Misconfiguration',
                'title': f"Public Read/Write on {obj['Label']}",
                'detail': f"All users can view and modify {obj['Object']} records"
            })
        
        # Check dormant admins
        dormant_admins = data.get('identity_access', {}).get('admin_users', [])
        for admin in dormant_admins:
            if admin.get('IsDormant'):
                findings.append({
                    'severity': 'high',
                    'type': 'Dormant Account',
                    'title': f"Inactive admin: {admin['Name']}",
                    'detail': f"Last login: {admin.get('LastLogin', 'Never')}"
                })
        
        return findings
    
    def _get_ai_recommendations(self, findings: List[Dict]) -> str:
        """Get AI-powered recommendations for findings"""
        
        # Create concise summary for AI
        summary = f"Found {len(findings)} security issues:\n"
        for f in findings[:10]:  # Limit to top 10
            summary += f"- [{f['severity'].upper()}] {f['title']}\n"
        
        prompt = f"""<s>[INST] As a Salesforce security expert, provide recommendations for these findings:

{summary}

Provide 3-5 prioritized remediation steps. [/INST]"""
        
        return self.generate_response(prompt, max_tokens=500)
    
    def _create_hybrid_report(self, findings: List[Dict], ai_recs: str, data: Dict) -> str:
        """Create comprehensive hybrid report"""
        
        # Group by severity
        critical = [f for f in findings if f['severity'] == 'critical']
        high = [f for f in findings if f['severity'] == 'high']
        medium = [f for f in findings if f['severity'] == 'medium']
        
        report = f"""
# SALESFORCE SECURITY REPORT (HYBRID ANALYSIS)
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## SUMMARY
Total Issues Found: {len(findings)}
├── Critical: {len(critical)}
├── High: {len(high)}
└── Medium: {len(medium)}

## CRITICAL FINDINGS ({len(critical)})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        for f in critical:
            report += f"\n🔴 {f['title']}\n"
            report += f"   Type: {f['type']}\n"
            report += f"   {f['detail']}\n"
            if f.get('users'):
                report += f"   Affected: {', '.join(f['users'][:5])}\n"
        
        report += f"\n## HIGH PRIORITY FINDINGS ({len(high)})\n"
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        for f in high[:10]:
            report += f"\n🟠 {f['title']}\n"
            report += f"   {f['detail']}\n"
        
        report += "\n## AI-POWERED RECOMMENDATIONS\n"
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        report += ai_recs
        
        report += "\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        return report