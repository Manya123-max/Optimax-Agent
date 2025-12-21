from typing import Dict, List
from datetime import datetime

class ReportGenerator:
    """
    Generates formatted security analysis reports with AI insights
    """
    
    def generate_full_report(self, analysis: Dict, org_id: str) -> str:
        """
        Generate comprehensive organization security report with AI insights
        
        Args:
            analysis: Complete analysis results
            org_id: Salesforce organization ID
            
        Returns:
            Formatted markdown report
        """
        report_lines = []
        
        # Header
        report_lines.append("# 🛡️ Salesforce Security Analysis Report")
        report_lines.append(f"**Organization ID**: {org_id}")
        report_lines.append(f"**Analysis Mode**: {analysis.get('analyzer_mode', 'Unknown')}")
        report_lines.append(f"**Report Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append("\n---\n")
        
        # AI Overall Insights (if available)
        ai_insights = analysis.get('ai_insights', {})
        if ai_insights.get('overall'):
            report_lines.append("## 🤖 AI Security Assessment")
            report_lines.append("")
            report_lines.append(ai_insights['overall'])
            report_lines.append("\n---\n")
        
        # Executive Summary
        report_lines.append("## 📊 Executive Summary")
        metrics = analysis.get('metrics', {})
        report_lines.append(f"- **Total Security Findings**: {metrics.get('total_findings', 0)}")
        report_lines.append(f"- **Critical Issues**: {metrics.get('critical_count', 0)} 🔴")
        report_lines.append(f"- **High Risk Issues**: {metrics.get('high_count', 0)} 🟠")
        report_lines.append(f"- **Medium Risk Issues**: {metrics.get('medium_count', 0)} 🟡")
        report_lines.append(f"- **Overall Risk Score**: {metrics.get('overall_risk_score', 0)}/100")
        report_lines.append("")
        
        # Risk level indicator
        risk_score = metrics.get('overall_risk_score', 0)
        if risk_score >= 70:
            report_lines.append("🚨 **CRITICAL RISK LEVEL** - Immediate action required!")
        elif risk_score >= 40:
            report_lines.append("⚠️ **HIGH RISK LEVEL** - Prioritize remediation")
        else:
            report_lines.append("✅ **MODERATE RISK LEVEL** - Continue monitoring")
        
        report_lines.append("\n---\n")
        
        # AI Critical Analysis (if available)
        if ai_insights.get('critical_analysis'):
            report_lines.append("## 🔴 AI Analysis of Critical Vulnerabilities")
            report_lines.append("")
            report_lines.append(ai_insights['critical_analysis'])
            report_lines.append("\n---\n")
        
        # Critical Findings
        if analysis.get('critical_findings'):
            report_lines.append("## 🔴 Critical Findings")
            report_lines.append("*These issues require immediate attention*\n")
            
            for idx, finding in enumerate(analysis['critical_findings'][:10], 1):
                report_lines.append(f"### {idx}. {finding.get('type', 'Security Issue')}")
                report_lines.append(f"**Description**: {finding.get('description', 'N/A')}")
                report_lines.append(f"**Impact**: {finding.get('impact', 'N/A')}")
                report_lines.append(f"**Recommendation**: {finding.get('recommendation', 'Review and remediate')}")
                
                # Add specific details
                if finding.get('affected_users'):
                    users = finding['affected_users'][:5]
                    report_lines.append(f"**Affected Users**: {', '.join(users)}")
                    if len(finding['affected_users']) > 5:
                        report_lines.append(f"   *(and {len(finding['affected_users']) - 5} more)*")
                
                report_lines.append("")
            
            if len(analysis['critical_findings']) > 10:
                remaining = len(analysis['critical_findings']) - 10
                report_lines.append(f"*... and {remaining} more critical findings*")
            
            report_lines.append("\n---\n")
        
        # High Risk Findings
        if analysis.get('high_risk_findings'):
            report_lines.append("## 🟠 High Risk Findings")
            report_lines.append("*Address these issues as soon as possible*\n")
            
            for idx, finding in enumerate(analysis['high_risk_findings'][:10], 1):
                report_lines.append(f"### {idx}. {finding.get('type', 'Security Issue')}")
                report_lines.append(f"- **Description**: {finding.get('description', 'N/A')}")
                report_lines.append(f"- **Recommendation**: {finding.get('recommendation', 'Review and remediate')}")
                report_lines.append("")
            
            if len(analysis['high_risk_findings']) > 10:
                remaining = len(analysis['high_risk_findings']) - 10
                report_lines.append(f"*... and {remaining} more high-risk findings*")
            
            report_lines.append("\n---\n")
        
        # Identity & Access Findings Summary
        identity_findings = analysis.get('identity_findings', {})
        if identity_findings.get('findings'):
            report_lines.append("## 👤 Identity & Access Management")
            report_lines.append(f"- **Total Users Analyzed**: {identity_findings.get('total_users', 0)}")
            report_lines.append(f"- **Active Users**: {identity_findings.get('active_users', 0)}")
            report_lines.append(f"- **Admin Users**: {identity_findings.get('admin_users', 0)}")
            report_lines.append("")
            
            identity_issues = [f for f in identity_findings['findings'] if f.get('severity') in ['Critical', 'High']]
            if identity_issues:
                report_lines.append("**Key Issues:**")
                for finding in identity_issues[:5]:
                    report_lines.append(f"- {finding.get('description', 'N/A')}")
            
            report_lines.append("\n---\n")
        
        # Permission Findings Summary
        permission_findings = analysis.get('permission_findings', {})
        if permission_findings:
            report_lines.append("## 🔐 Permissions & Authorization")
            report_lines.append(f"- **Permission Sets Analyzed**: {permission_findings.get('permission_sets_analyzed', 0)}")
            report_lines.append(f"- **Profiles Analyzed**: {permission_findings.get('profiles_analyzed', 0)}")
            report_lines.append(f"- **Dangerous Assignments**: {permission_findings.get('dangerous_assignments', 0)}")
            report_lines.append("\n---\n")
        
        # Sharing Model Findings Summary
        sharing_findings = analysis.get('sharing_findings', {})
        if sharing_findings:
            report_lines.append("## 🌐 Sharing Model Security")
            report_lines.append(f"- **Objects with OWD Settings**: {sharing_findings.get('owd_objects_analyzed', 0)}")
            report_lines.append(f"- **Roles Analyzed**: {sharing_findings.get('roles_analyzed', 0)}")
            report_lines.append(f"- **Sharing Rules**: {sharing_findings.get('sharing_rules_analyzed', 0)}")
            report_lines.append("\n---\n")
        
        # AI Recommendations (Priority Section)
        if analysis.get('ai_recommendations'):
            report_lines.append("## 🤖 AI-Powered Prioritized Recommendations")
            report_lines.append("*Generated by AI based on comprehensive analysis*\n")
            report_lines.append(analysis['ai_recommendations'])
            report_lines.append("\n---\n")
        
        # Rule-Based Action Items
        report_lines.append("## 📋 Prioritized Action Items")
        report_lines.append("*Rule-based remediation steps*\n")
        
        priority_actions = self._generate_priority_actions(analysis)
        for idx, action in enumerate(priority_actions, 1):
            report_lines.append(f"{idx}. **{action['title']}**")
            report_lines.append(f"   - {action['description']}")
            report_lines.append("")
        
        # Footer
        report_lines.append("\n---\n")
        report_lines.append("## 📚 Resources")
        report_lines.append("- [Salesforce Security Best Practices](https://developer.salesforce.com/docs/atlas.en-us.securityImplGuide.meta/securityImplGuide/)")
        report_lines.append("- [Security Health Check](https://help.salesforce.com/s/articleView?id=sf.security_health_check.htm)")
        report_lines.append("- [Permission Sets Best Practices](https://help.salesforce.com/s/articleView?id=sf.perm_sets_overview.htm)")
        
        report_lines.append("\n---\n")
        report_lines.append(f"*Report generated by Salesforce Security Analyzer • {analysis.get('analyzer_mode', 'Hybrid Mode')}*")
        
        return "\n".join(report_lines)
    
    def generate_profile_report(self, analysis: Dict, profile_id: str) -> str:
        """
        Generate profile-specific security report with AI insights
        
        Args:
            analysis: Profile analysis results
            profile_id: Salesforce profile ID
            
        Returns:
            Formatted markdown report
        """
        report_lines = []
        
        # Header
        report_lines.append("# 👤 Profile Security Analysis Report")
        report_lines.append(f"**Profile Name**: {analysis.get('profile_name', 'Unknown')}")
        report_lines.append(f"**Profile ID**: {profile_id}")
        report_lines.append(f"**Analysis Mode**: {analysis.get('analyzer_mode', 'Unknown')}")
        report_lines.append(f"**Report Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append("\n---\n")
        
        # AI Detailed Analysis (Priority Section)
        ai_insights = analysis.get('ai_insights', {})
        if ai_insights.get('detailed_analysis'):
            report_lines.append("## 🤖 AI Security Assessment")
            report_lines.append("")
            report_lines.append(ai_insights['detailed_analysis'])
            report_lines.append("\n---\n")
        
        # Summary
        report_lines.append("## 📊 Profile Summary")
        report_lines.append(f"- **Assigned Users**: {analysis.get('assigned_users_count', 0)}")
        report_lines.append(f"- **Risk Score**: {analysis.get('risk_score', 0)}/100")
        report_lines.append(f"- **Dangerous Permissions**: {len(analysis.get('dangerous_permissions', []))}")
        report_lines.append(f"- **Critical Issues**: {len(analysis.get('critical_issues', []))}")
        report_lines.append(f"- **Warnings**: {len(analysis.get('warnings', []))}")
        report_lines.append("")
        
        # Risk indicator
        risk_score = analysis.get('risk_score', 0)
        if risk_score >= 70:
            report_lines.append("🚨 **HIGH RISK PROFILE** - Immediate review required")
        elif risk_score >= 40:
            report_lines.append("⚠️ **MEDIUM RISK PROFILE** - Review recommended")
        else:
            report_lines.append("✅ **LOW RISK PROFILE** - No immediate concerns")
        
        report_lines.append("\n---\n")
        
        # AI Risk Assessment
        if ai_insights.get('risk_assessment'):
            report_lines.append("## 🎯 AI Risk Assessment")
            report_lines.append("")
            report_lines.append(ai_insights['risk_assessment'])
            report_lines.append("\n---\n")
        
        # Dangerous Permissions
        if analysis.get('dangerous_permissions'):
            report_lines.append("## ⚠️ Dangerous Permissions Detected")
            report_lines.append("")
            for perm in analysis['dangerous_permissions']:
                report_lines.append(f"- {perm}")
            report_lines.append("\n---\n")
        
        # Critical Issues
        if analysis.get('critical_issues'):
            report_lines.append("## 🔴 Critical Issues")
            report_lines.append("")
            for issue in analysis['critical_issues']:
                report_lines.append(f"### {issue.get('permission', 'Unknown Permission')}")
                report_lines.append(f"**Impact**: {issue.get('impact', 'N/A')}")
                report_lines.append(f"**Users Affected**: {issue.get('users_affected', 0)}")
                report_lines.append("")
            report_lines.append("\n---\n")
        
        # Warnings
        if analysis.get('warnings'):
            report_lines.append("## 🟡 Warnings")
            report_lines.append("")
            for warning in analysis['warnings']:
                report_lines.append(f"- **{warning.get('permission', 'Unknown')}**: {warning.get('impact', 'N/A')}")
            report_lines.append("\n---\n")
        
        # AI Remediation Recommendations (Priority)
        if ai_insights.get('remediation'):
            report_lines.append("## 🤖 AI Remediation Recommendations")
            report_lines.append("")
            report_lines.append(ai_insights['remediation'])
            report_lines.append("\n---\n")
        
        # Rule-Based Recommendations
        if analysis.get('recommendations'):
            report_lines.append("## 💡 Security Recommendations")
            report_lines.append("")
            for rec in analysis['recommendations']:
                report_lines.append(f"- {rec}")
            report_lines.append("\n---\n")
        
        # Next Steps
        report_lines.append("## 📋 Next Steps")
        report_lines.append("")
        report_lines.append("1. Review all dangerous permissions listed above")
        report_lines.append("2. Implement AI-recommended remediation steps")
        report_lines.append("3. Consider migrating admin-level permissions to Permission Sets")
        report_lines.append("4. Audit users assigned to this profile")
        report_lines.append("5. Implement least privilege principle")
        report_lines.append("6. Schedule regular profile reviews")
        
        report_lines.append("\n---\n")
        report_lines.append(f"*Report generated by Salesforce Security Analyzer • {analysis.get('analyzer_mode', 'Hybrid Mode')}*")
        
        return "\n".join(report_lines)
    
    def _generate_priority_actions(self, analysis: Dict) -> List[Dict]:
        """
        Generate prioritized list of remediation actions
        
        Returns:
            List of action items
        """
        actions = []
        
        # Critical findings
        if analysis.get('critical_findings'):
            actions.append({
                'title': 'Address Critical Security Findings',
                'description': f"Remediate {len(analysis['critical_findings'])} critical issues immediately"
            })
        
        # Admin users
        identity = analysis.get('identity_findings', {})
        admin_count = identity.get('admin_users', 0)
        if admin_count > 5:
            actions.append({
                'title': 'Reduce Admin User Count',
                'description': f"Review {admin_count} admin users, convert to Permission Sets where possible"
            })
        
        # Dangerous permissions
        perms = analysis.get('permission_findings', {})
        dangerous_count = perms.get('dangerous_assignments', 0)
        if dangerous_count > 10:
            actions.append({
                'title': 'Review Dangerous Permission Assignments',
                'description': f"Audit {dangerous_count} dangerous permission assignments"
            })
        
        # Dormant users
        dormant_findings = [
            f for f in identity.get('findings', []) 
            if f.get('type', '').startswith('Dormant User')
        ]
        if len(dormant_findings) > 5:
            actions.append({
                'title': 'Deactivate Dormant Users',
                'description': f"Review and deactivate {len(dormant_findings)} dormant user accounts"
            })
        
        # MFA compliance
        mfa_findings = [
            f for f in identity.get('findings', []) 
            if 'MFA' in f.get('type', '')
        ]
        if mfa_findings:
            actions.append({
                'title': 'Enforce Multi-Factor Authentication',
                'description': "Enable MFA for all users, especially administrators"
            })
        
        # Sharing model
        sharing = analysis.get('sharing_findings', {})
        owd_findings = [
            f for f in sharing.get('findings', []) 
            if f.get('type') == 'Insecure Organization-Wide Default'
        ]
        if owd_findings:
            actions.append({
                'title': 'Secure Organization-Wide Defaults',
                'description': f"Review and restrict {len(owd_findings)} public OWD settings"
            })
        
        return actions[:7]  # Return top 7 actions