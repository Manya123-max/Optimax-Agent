from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from typing import Dict, List
from analyzers.permission_analyzer import PermissionAnalyzer
from analyzers.sharing_analyzer import SharingAnalyzer
from analyzers.identity_analyzer import IdentityAnalyzer

class CodeGenSecurityAnalyzer:
    """
    AI-powered security analyzer using CodeGen model
    """
    
    def __init__(self, model_name: str = "Salesforce/codegen-350M-mono"):
        """
        Initialize CodeGen analyzer
        
        Args:
            model_name: HuggingFace model identifier
        """
        print(f"Loading model: {model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            low_cpu_mem_usage=True
        )
        
        if torch.cuda.is_available():
            self.model = self.model.cuda()
        
        print("Model loaded successfully!")
    
    def generate_response(self, prompt: str, max_length: int = 500) -> str:
        """
        Generate AI response for security analysis
        
        Args:
            prompt: Input prompt describing the security context
            max_length: Maximum tokens to generate
            
        Returns:
            Generated analysis text
        """
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024)
        
        if torch.cuda.is_available():
            inputs = {k: v.cuda() for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_length=max_length,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response.replace(prompt, "").strip()


class HybridAnalyzer:
    """
    Hybrid analyzer combining rule-based checks with AI insights
    Recommended for production use
    """
    
    def __init__(self, model_name: str = "Salesforce/codegen-350M-mono", use_rule_based: bool = True):
        """
        Initialize hybrid analyzer
        
        Args:
            model_name: CodeGen model to use
            use_rule_based: Whether to include rule-based analysis (recommended)
        """
        self.use_rule_based = use_rule_based
        self.ai_analyzer = None
        
        # Initialize rule-based analyzers
        self.permission_analyzer = PermissionAnalyzer()
        self.sharing_analyzer = SharingAnalyzer()
        self.identity_analyzer = IdentityAnalyzer()
        
        # Initialize AI analyzer (optional for enhanced insights)
        try:
            if not use_rule_based:  # Only load AI if not using rule-based
                self.ai_analyzer = CodeGenSecurityAnalyzer(model_name)
        except Exception as e:
            print(f"Warning: Could not load AI model: {e}. Using rule-based only.")
            self.use_rule_based = True
    
    def analyze_full_org(
        self,
        users: List[Dict],
        permission_sets: List[Dict],
        profiles: List[Dict],
        sharing_settings: Dict,
        login_history: List[Dict]
    ) -> Dict:
        """
        Perform comprehensive organization security analysis
        
        Returns:
            Complete analysis report
        """
        analysis_report = {
            'summary': {},
            'critical_findings': [],
            'high_risk_findings': [],
            'medium_risk_findings': [],
            'recommendations': [],
            'metrics': {}
        }
        
        # 1. Identity & Access Management Analysis
        print("Analyzing identity & access management...")
        identity_results = self.identity_analyzer.analyze_users(users, login_history)
        analysis_report['identity_findings'] = identity_results
        
        # 2. Permission & Authorization Analysis
        print("Analyzing permissions and authorization...")
        permission_results = self.permission_analyzer.analyze_all_permissions(
            permission_sets, profiles
        )
        analysis_report['permission_findings'] = permission_results
        
        # 3. Sharing Model Analysis
        print("Analyzing sharing model...")
        sharing_results = self.sharing_analyzer.analyze_sharing_settings(sharing_settings)
        analysis_report['sharing_findings'] = sharing_results
        
        # 4. Aggregate findings by severity
        self._aggregate_findings(analysis_report)
        
        # 5. Generate AI-enhanced recommendations (if enabled)
        if self.ai_analyzer:
            ai_recommendations = self._get_ai_recommendations(analysis_report)
            analysis_report['ai_recommendations'] = ai_recommendations
        
        return analysis_report
    
    def analyze_profile(self, profile_data: Dict) -> Dict:
        """
        Analyze a specific profile for security issues
        
        Args:
            profile_data: Profile information from Salesforce
            
        Returns:
            Profile analysis report
        """
        analysis_report = {
            'profile_name': profile_data.get('Name', 'Unknown'),
            'profile_id': profile_data.get('Id', 'Unknown'),
            'assigned_users': len(profile_data.get('AssignedUsers', [])),
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'risk_score': 0
        }
        
        # Analyze profile using rule-based analyzer
        profile_results = self.permission_analyzer.analyze_profile(profile_data)
        
        # Merge results
        analysis_report.update(profile_results)
        
        # Generate AI insights if available
        if self.ai_analyzer:
            prompt = self._create_profile_prompt(profile_data, profile_results)
            ai_insight = self.ai_analyzer.generate_response(prompt, max_length=300)
            analysis_report['ai_insight'] = ai_insight
        
        return analysis_report
    
    def _aggregate_findings(self, report: Dict):
        """
        Aggregate findings from all analyzers by severity
        """
        # Collect all findings
        all_findings = []
        
        # From identity analysis
        if 'identity_findings' in report:
            all_findings.extend(report['identity_findings'].get('findings', []))
        
        # From permission analysis
        if 'permission_findings' in report:
            all_findings.extend(report['permission_findings'].get('findings', []))
        
        # From sharing analysis
        if 'sharing_findings' in report:
            all_findings.extend(report['sharing_findings'].get('findings', []))
        
        # Sort by severity
        for finding in all_findings:
            severity = finding.get('severity', 'Low').lower()
            
            if severity == 'critical':
                report['critical_findings'].append(finding)
            elif severity == 'high':
                report['high_risk_findings'].append(finding)
            elif severity == 'medium':
                report['medium_risk_findings'].append(finding)
        
        # Calculate metrics
        report['metrics'] = {
            'total_findings': len(all_findings),
            'critical_count': len(report['critical_findings']),
            'high_count': len(report['high_risk_findings']),
            'medium_count': len(report['medium_risk_findings']),
            'overall_risk_score': self._calculate_risk_score(report)
        }
    
    def _calculate_risk_score(self, report: Dict) -> int:
        """
        Calculate overall organization risk score (0-100)
        """
        critical = len(report['critical_findings']) * 25
        high = len(report['high_risk_findings']) * 10
        medium = len(report['medium_risk_findings']) * 3
        
        score = min(100, critical + high + medium)
        return score
    
    def _get_ai_recommendations(self, report: Dict) -> str:
        """
        Generate AI-powered recommendations
        """
        if not self.ai_analyzer:
            return "AI recommendations not available"
        
        # Create prompt summarizing findings
        prompt = f"""
        Salesforce Security Analysis Summary:
        - Critical Issues: {len(report['critical_findings'])}
        - High Risk Issues: {len(report['high_risk_findings'])}
        - Medium Risk Issues: {len(report['medium_risk_findings'])}
        
        Top Critical Issue: {report['critical_findings'][0]['description'] if report['critical_findings'] else 'None'}
        
        Provide 3 prioritized security recommendations:
        """
        
        return self.ai_analyzer.generate_response(prompt, max_length=400)
    
    def _create_profile_prompt(self, profile_data: Dict, analysis: Dict) -> str:
        """
        Create AI prompt for profile analysis
        """
        dangerous_perms = analysis.get('dangerous_permissions', [])
        
        prompt = f"""
        Analyze this Salesforce Profile security:
        Profile: {profile_data.get('Name')}
        Users: {len(profile_data.get('AssignedUsers', []))}
        Dangerous Permissions: {', '.join(dangerous_perms) if dangerous_perms else 'None'}
        
        Security recommendation:
        """
        
        return prompt