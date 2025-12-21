"""
Hybrid Security Analyzer: AI-Powered with Rule-Based Enhancement
AI is primary, rule-based provides precision and validation
"""

from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from typing import Dict, List
from analyzers.permission_analyzer import PermissionAnalyzer
from analyzers.sharing_analyzer import SharingAnalyzer
from analyzers.identity_analyzer import IdentityAnalyzer
import json

class CodeGenSecurityAnalyzer:
    """
    AI-powered security analyzer using CodeGen model
    Primary intelligence for contextual analysis
    """
    
    def __init__(self, model_name: str = "Salesforce/codegen-350M-mono"):
        """
        Initialize CodeGen analyzer
        
        Args:
            model_name: HuggingFace model identifier
        """
        print(f"🤖 Loading AI model: {model_name}...")
        print("📦 This may take 2-3 minutes on first run...")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        # Add padding token if not present
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            low_cpu_mem_usage=True,
            device_map="auto" if torch.cuda.is_available() else None
        )
        
        print(f"✅ AI model loaded successfully!")
        print(f"🖥️  Using: {'GPU' if torch.cuda.is_available() else 'CPU'}")
    
    def generate_response(self, prompt: str, max_length: int = 500) -> str:
        """
        Generate AI response for security analysis
        
        Args:
            prompt: Input prompt describing the security context
            max_length: Maximum tokens to generate
            
        Returns:
            Generated analysis text
        """
        try:
            inputs = self.tokenizer(
                prompt, 
                return_tensors="pt", 
                truncation=True, 
                max_length=1024,
                padding=True
            )
            
            if torch.cuda.is_available():
                inputs = {k: v.cuda() for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_length,
                    temperature=0.7,
                    top_p=0.9,
                    do_sample=True,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )
            
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Remove the prompt from response
            response = response[len(prompt):].strip()
            return response if response else "Analysis complete - see detailed findings below."
            
        except Exception as e:
            print(f"⚠️ AI generation error: {e}")
            return "AI analysis unavailable - see rule-based findings below."


class HybridAnalyzer:
    """
    Hybrid analyzer: AI-powered contextual analysis + Rule-based precision
    
    Architecture:
    1. Rule-based analyzers detect specific vulnerabilities (precision)
    2. AI provides contextual insights and recommendations (intelligence)
    3. Combined output gives both accuracy and understanding
    """
    
    def __init__(self, model_name: str = "Salesforce/codegen-350M-mono", use_rule_based: bool = True):
        """
        Initialize hybrid analyzer with AI priority
        
        Args:
            model_name: CodeGen model to use
            use_rule_based: Whether to also use rule-based checks (recommended: True)
        """
        print("🚀 Initializing Hybrid Security Analyzer...")
        print("🎯 Mode: AI-Powered with Rule-Based Enhancement")
        
        # Initialize rule-based analyzers (for precision)
        if use_rule_based:
            print("📋 Loading rule-based security checks...")
            self.permission_analyzer = PermissionAnalyzer()
            self.sharing_analyzer = SharingAnalyzer()
            self.identity_analyzer = IdentityAnalyzer()
            self.use_rule_based = True
            print("✅ Rule-based analyzers loaded")
        else:
            self.use_rule_based = False
            print("⚠️ Rule-based checks disabled (not recommended)")
        
        # Initialize AI analyzer (for intelligence)
        try:
            self.ai_analyzer = CodeGenSecurityAnalyzer(model_name)
            self.ai_available = True
            print("✅ Hybrid analyzer ready: AI + Rule-Based")
        except Exception as e:
            print(f"❌ Failed to load AI model: {e}")
            print("🔄 Falling back to rule-based only")
            self.ai_analyzer = None
            self.ai_available = False
            if not use_rule_based:
                raise RuntimeError("Both AI and rule-based disabled - cannot proceed")
    
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
        Uses both AI and rule-based approaches for maximum coverage
        
        Returns:
            Complete analysis report with AI insights and rule-based findings
        """
        print("\n" + "="*60)
        print("🔍 STARTING COMPREHENSIVE SECURITY ANALYSIS")
        print("="*60 + "\n")
        
        analysis_report = {
            'summary': {},
            'critical_findings': [],
            'high_risk_findings': [],
            'medium_risk_findings': [],
            'recommendations': [],
            'metrics': {},
            'analyzer_mode': 'Hybrid (AI + Rule-Based)' if self.ai_available else 'Rule-Based Only',
            'ai_insights': {}
        }
        
        # PHASE 1: Rule-Based Analysis (Precision Detection)
        if self.use_rule_based:
            print("📊 PHASE 1: Rule-Based Vulnerability Detection")
            print("-" * 60)
            
            # 1. Identity & Access Management Analysis
            print("  🔍 Analyzing identity & access management...")
            identity_results = self.identity_analyzer.analyze_users(users, login_history)
            analysis_report['identity_findings'] = identity_results
            print(f"     ✓ Found {len(identity_results.get('findings', []))} identity issues")
            
            # 2. Permission & Authorization Analysis
            print("  🔍 Analyzing permissions and authorization...")
            permission_results = self.permission_analyzer.analyze_all_permissions(
                permission_sets, profiles
            )
            analysis_report['permission_findings'] = permission_results
            print(f"     ✓ Found {len(permission_results.get('findings', []))} permission issues")
            
            # 3. Sharing Model Analysis
            print("  🔍 Analyzing sharing model...")
            sharing_results = self.sharing_analyzer.analyze_sharing_settings(sharing_settings)
            analysis_report['sharing_findings'] = sharing_results
            print(f"     ✓ Found {len(sharing_results.get('findings', []))} sharing issues")
            
            # Aggregate findings
            self._aggregate_findings(analysis_report)
            print(f"\n  📈 Total findings: {analysis_report['metrics']['total_findings']}")
            print(f"     🔴 Critical: {analysis_report['metrics']['critical_count']}")
            print(f"     🟠 High: {analysis_report['metrics']['high_count']}")
            print(f"     🟡 Medium: {analysis_report['metrics']['medium_count']}")
        
        # PHASE 2: AI-Powered Contextual Analysis
        if self.ai_available:
            print(f"\n🤖 PHASE 2: AI-Powered Contextual Analysis")
            print("-" * 60)
            
            try:
                # Generate AI insights for different areas
                print("  🧠 Generating AI security insights...")
                
                # Overall organization security posture
                org_context = self._create_org_context(
                    users, permission_sets, profiles, 
                    analysis_report.get('metrics', {})
                )
                
                print("  🤖 Analyzing organizational security posture...")
                overall_insight = self.ai_analyzer.generate_response(
                    org_context, max_length=400
                )
                analysis_report['ai_insights']['overall'] = overall_insight
                
                # Critical findings analysis
                if analysis_report['critical_findings']:
                    print("  🤖 Analyzing critical vulnerabilities...")
                    critical_context = self._create_critical_findings_context(
                        analysis_report['critical_findings']
                    )
                    critical_insight = self.ai_analyzer.generate_response(
                        critical_context, max_length=300
                    )
                    analysis_report['ai_insights']['critical_analysis'] = critical_insight
                
                # Recommendations generation
                print("  🤖 Generating prioritized recommendations...")
                recommendations = self._get_ai_recommendations(analysis_report)
                analysis_report['ai_recommendations'] = recommendations
                
                print("  ✅ AI analysis complete!")
                
            except Exception as e:
                print(f"  ⚠️ AI analysis failed: {e}")
                analysis_report['ai_insights']['error'] = str(e)
                analysis_report['ai_recommendations'] = "AI recommendations unavailable - see rule-based findings"
        
        print("\n" + "="*60)
        print("✅ ANALYSIS COMPLETE")
        print("="*60 + "\n")
        
        return analysis_report
    
    def analyze_profile(self, profile_data: Dict) -> Dict:
        """
        Analyze a specific profile with AI insights and rule-based precision
        
        Args:
            profile_data: Profile information from Salesforce
            
        Returns:
            Profile analysis report with AI insights
        """
        print("\n" + "="*60)
        print(f"🔍 ANALYZING PROFILE: {profile_data.get('Name', 'Unknown')}")
        print("="*60 + "\n")
        
        analysis_report = {
            'profile_name': profile_data.get('Name', 'Unknown'),
            'profile_id': profile_data.get('Id', 'Unknown'),
            'assigned_users': len(profile_data.get('AssignedUsers', [])),
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'risk_score': 0,
            'analyzer_mode': 'Hybrid (AI + Rule-Based)' if self.ai_available else 'Rule-Based Only',
            'ai_insights': {}
        }
        
        # Rule-based analysis
        if self.use_rule_based:
            print("📊 Performing rule-based profile analysis...")
            profile_results = self.permission_analyzer.analyze_profile(profile_data)
            analysis_report.update(profile_results)
            print(f"  ✓ Found {len(profile_results.get('critical_issues', []))} critical issues")
            print(f"  ✓ Risk Score: {profile_results.get('risk_score', 0)}/100")
        
        # AI-powered insights
        if self.ai_available:
            print("\n🤖 Generating AI-powered profile insights...")
            
            try:
                # Detailed profile analysis
                prompt = self._create_detailed_profile_prompt(profile_data, analysis_report)
                print("  🤖 Analyzing profile security context...")
                ai_insight = self.ai_analyzer.generate_response(prompt, max_length=400)
                analysis_report['ai_insights']['detailed_analysis'] = ai_insight
                
                # Risk assessment
                if analysis_report.get('critical_issues'):
                    risk_prompt = self._create_risk_assessment_prompt(profile_data, analysis_report)
                    print("  🤖 Performing risk assessment...")
                    risk_insight = self.ai_analyzer.generate_response(risk_prompt, max_length=300)
                    analysis_report['ai_insights']['risk_assessment'] = risk_insight
                
                # Remediation recommendations
                remediation_prompt = self._create_remediation_prompt(profile_data, analysis_report)
                print("  🤖 Generating remediation recommendations...")
                remediation = self.ai_analyzer.generate_response(remediation_prompt, max_length=300)
                analysis_report['ai_insights']['remediation'] = remediation
                
                print("  ✅ AI insights generated!")
                
            except Exception as e:
                print(f"  ⚠️ AI insight generation failed: {e}")
                analysis_report['ai_insights']['error'] = str(e)
        
        print("\n" + "="*60)
        print("✅ PROFILE ANALYSIS COMPLETE")
        print("="*60 + "\n")
        
        return analysis_report
    
    def _create_org_context(self, users, permission_sets, profiles, metrics) -> str:
        """Create context for AI organizational analysis"""
        context = f"""Salesforce Organization Security Analysis:

Organization Metrics:
- Total Users: {len(users)}
- Permission Sets: {len(permission_sets)}
- Profiles: {len(profiles)}
- Security Findings: {metrics.get('total_findings', 0)}
- Critical Issues: {metrics.get('critical_count', 0)}
- High Risk Issues: {metrics.get('high_count', 0)}
- Overall Risk Score: {metrics.get('overall_risk_score', 0)}/100

Analyze the security posture and provide key insights:"""
        return context
    
    def _create_critical_findings_context(self, critical_findings) -> str:
        """Create context for AI critical findings analysis"""
        findings_summary = []
        for finding in critical_findings[:5]:  # Top 5 critical
            findings_summary.append(f"- {finding.get('type', 'Unknown')}: {finding.get('description', 'N/A')}")
        
        context = f"""Critical Security Vulnerabilities Detected:

{chr(10).join(findings_summary)}

Analyze the severity and interdependencies of these critical issues:"""
        return context
    
    def _create_detailed_profile_prompt(self, profile_data, analysis) -> str:
        """Create detailed profile analysis prompt"""
        dangerous_perms = analysis.get('dangerous_permissions', [])
        
        prompt = f"""Salesforce Profile Security Analysis:

Profile: {profile_data.get('Name')}
Profile ID: {profile_data.get('Id')}
Assigned Users: {len(profile_data.get('AssignedUsers', []))}
Risk Score: {analysis.get('risk_score', 0)}/100

Dangerous Permissions Detected:
{chr(10).join(['- ' + p for p in dangerous_perms]) if dangerous_perms else '- None'}

Critical Issues: {len(analysis.get('critical_issues', []))}
Warnings: {len(analysis.get('warnings', []))}

Provide a comprehensive security assessment:"""
        return prompt
    
    def _create_risk_assessment_prompt(self, profile_data, analysis) -> str:
        """Create risk assessment prompt"""
        prompt = f"""Risk Assessment for Profile: {profile_data.get('Name')}

Risk Score: {analysis.get('risk_score', 0)}/100
Users Affected: {len(profile_data.get('AssignedUsers', []))}
Critical Issues: {len(analysis.get('critical_issues', []))}

Assess the business impact and likelihood of exploitation:"""
        return prompt
    
    def _create_remediation_prompt(self, profile_data, analysis) -> str:
        """Create remediation recommendations prompt"""
        prompt = f"""Remediation Plan for Profile: {profile_data.get('Name')}

Current State:
- Risk Score: {analysis.get('risk_score', 0)}/100
- Critical Issues: {len(analysis.get('critical_issues', []))}
- Users Affected: {len(profile_data.get('AssignedUsers', []))}

Provide step-by-step remediation recommendations prioritized by impact:"""
        return prompt
    
    def _aggregate_findings(self, report: Dict):
        """Aggregate findings from all analyzers by severity"""
        all_findings = []
        
        # Collect findings from all sources
        if 'identity_findings' in report:
            all_findings.extend(report['identity_findings'].get('findings', []))
        
        if 'permission_findings' in report:
            all_findings.extend(report['permission_findings'].get('findings', []))
        
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
        """Calculate overall organization risk score (0-100)"""
        critical = len(report['critical_findings']) * 25
        high = len(report['high_risk_findings']) * 10
        medium = len(report['medium_risk_findings']) * 3
        
        score = min(100, critical + high + medium)
        return score
    
    def _get_ai_recommendations(self, report: Dict) -> str:
        """Generate AI-powered prioritized recommendations"""
        if not self.ai_available:
            return None
        
        # Create comprehensive context for recommendations
        context = f"""Salesforce Security Analysis - Recommendations Needed:

Current Security Posture:
- Total Findings: {report['metrics']['total_findings']}
- Critical Issues: {report['metrics']['critical_count']}
- High Risk Issues: {report['metrics']['high_count']}
- Risk Score: {report['metrics']['overall_risk_score']}/100

Top Critical Issues:
"""
        
        # Add top 3 critical findings
        for i, finding in enumerate(report['critical_findings'][:3], 1):
            context += f"{i}. {finding.get('type', 'Unknown')}: {finding.get('description', 'N/A')}\n"
        
        context += "\nProvide 5 prioritized security recommendations with specific action items:"
        
        try:
            return self.ai_analyzer.generate_response(context, max_length=500)
        except Exception as e:
            print(f"⚠️ Failed to generate AI recommendations: {e}")
            return "AI recommendations unavailable - see prioritized findings above"