"""
Report Generation Utilities
Formats security findings into human-readable reports
"""

import json
from datetime import datetime
from typing import List, Dict, Any

class ReportGenerator:
    """Generates formatted security reports"""
    
    SEVERITY_COLORS = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': 'ℹ️'
    }
    
    SEVERITY_PRIORITY = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4,
        'info': 5
    }
    
    @staticmethod
    def generate_executive_summary(findings: List[Dict], data: Dict) -> str:
        """Generate executive summary section"""
        
        severity_counts = {
            'critical': len([f for f in findings if f['severity'] == 'critical']),
            'high': len([f for f in findings if f['severity'] == 'high']),
            'medium': len([f for f in findings if f['severity'] == 'medium']),
            'low': len([f for f in findings if f['severity'] == 'low'])
        }
        
        total_issues = sum(severity_counts.values())
        
        summary = f"""
# SALESFORCE SECURITY ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Organization ID: {data.get('org_id', 'N/A')}

## EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Total Issues Found: {total_issues}**

Severity Breakdown:
├── 🔴 Critical: {severity_counts['critical']}
├── 🟠 High:     {severity_counts['high']}
├── 🟡 Medium:   {severity_counts['medium']}
└── 🔵 Low:      {severity_counts['low']}

"""
        
        # Add key metrics
        stats = data.get('summary', {})
        summary += f"""
**Organization Metrics:**
- Total Users: {stats.get('total_users', 0)}
- Admin Users: {stats.get('admin_users', 0)}
- Dormant Accounts: {stats.get('dormant_users', 0)}
- Permission Sets: {stats.get('permission_sets', 0)}
- Profiles: {stats.get('profiles', 0)}

**Security Posture:** """
        
        if severity_counts['critical'] > 0:
            summary += "⚠️ CRITICAL - Immediate action required"
        elif severity_counts['high'] > 5:
            summary += "⚠️ HIGH RISK - Urgent remediation needed"
        elif severity_counts['high'] > 0:
            summary += "⚠️ MODERATE RISK - Address high priority items"
        else:
            summary += "✅ GOOD - Minor issues to address"
        
        summary += "\n\n"
        return summary
    
    @staticmethod
    def format_findings_by_severity(findings: List[Dict]) -> str:
        """Format findings grouped by severity"""
        
        report = ""
        
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda x: ReportGenerator.SEVERITY_PRIORITY.get(x['severity'], 99)
        )
        
        # Group by severity
        grouped = {}
        for finding in sorted_findings:
            severity = finding['severity']
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        
        # Generate sections
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity not in grouped:
                continue
            
            severity_findings = grouped[severity]
            icon = ReportGenerator.SEVERITY_COLORS.get(severity, '•')
            
            report += f"\n## {severity.upper()} FINDINGS ({len(severity_findings)})\n"
            report += "━" * 80 + "\n\n"
            
            for idx, finding in enumerate(severity_findings, 1):
                report += ReportGenerator._format_single_finding(finding, icon, idx)
        
        return report
    
    @staticmethod
    def _format_single_finding(finding: Dict, icon: str, number: int) -> str:
        """Format a single finding"""
        
        output = f"{icon} **Finding #{number}: {finding['title']}**\n"
        output += f"   Category: {finding.get('type', finding.get('category', 'N/A'))}\n"
        output += f"   Description: {finding['detail']}\n"
        
        # Add affected items
        if finding.get('users'):
            users = finding['users'][:5]  # Show first 5
            output += f"   Affected Users: {', '.join(users)}"
            if len(finding['users']) > 5:
                output += f" (+{len(finding['users']) - 5} more)"
            output += "\n"
        
        if finding.get('affected_objects'):
            objects = finding['affected_objects'][:5]
            output += f"   Affected Objects: {', '.join(objects)}"
            if len(finding.get('affected_objects', [])) > 5:
                output += f" (+{len(finding['affected_objects']) - 5} more)"
            output += "\n"
        
        output += "\n"
        return output
    
    @staticmethod
    def generate_recommendations(findings: List[Dict]) -> str:
        """Generate prioritized recommendations"""
        
        report = "\n## RECOMMENDED ACTIONS\n"
        report += "━" * 80 + "\n\n"
        
        # Get critical and high findings
        priority_findings = [
            f for f in findings
            if f['severity'] in ['critical', 'high']
        ]
        
        if not priority_findings:
            report += "✅ No critical or high priority issues found.\n"
            report += "Continue monitoring and addressing medium/low priority items.\n\n"
            return report
        
        report += "**IMMEDIATE ACTIONS (Next 24-48 hours):**\n\n"
        
        critical_actions = {}
        for finding in [f for f in priority_findings if f['severity'] == 'critical']:
            action_key = finding.get('type', 'general')
            if action_key not in critical_actions:
                critical_actions[action_key] = []
            critical_actions[action_key].append(finding['title'])
        
        action_num = 1
        for action_type, items in critical_actions.items():
            report += f"{action_num}. **{action_type}**\n"
            for item in items[:3]:  # Top 3 per type
                report += f"   - {item}\n"
            action_num += 1
        
        report += "\n**SHORT-TERM ACTIONS (Next 1-2 weeks):**\n\n"
        
        high_findings = [f for f in priority_findings if f['severity'] == 'high'][:5]
        for idx, finding in enumerate(high_findings, action_num):
            report += f"{idx}. {finding['title']}\n"
        
        report += "\n"
        return report
    
    @staticmethod
    def generate_compliance_notes() -> str:
        """Generate compliance and best practices section"""
        
        return """
## COMPLIANCE & BEST PRACTICES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**SOC 2 Considerations:**
- Implement principle of least privilege
- Enable MFA for all users
- Regular access reviews (quarterly)
- Audit trail monitoring

**GDPR Requirements:**
- Minimize data access
- Implement data retention policies
- Document legitimate data access purposes
- Enable field audit trail

**Best Practices:**
- Use Permission Sets over modifying Profiles
- Implement Private OWD with sharing rules
- Regular permission audits
- Deactivate unused accounts within 30 days
- Enable Event Monitoring

**Next Steps:**
1. Address all Critical findings immediately
2. Create remediation plan for High priority items
3. Schedule monthly security reviews
4. Implement automated monitoring

"""
    
    @staticmethod
    def generate_full_report(findings: List[Dict], data: Dict, ai_recommendations: str = None) -> str:
        """Generate complete security report"""
        
        report = ReportGenerator.generate_executive_summary(findings, data)
        
        if ai_recommendations:
            report += "\n## AI-POWERED INSIGHTS\n"
            report += "━" * 80 + "\n"
            report += ai_recommendations + "\n\n"
        
        report += ReportGenerator.format_findings_by_severity(findings)
        report += ReportGenerator.generate_recommendations(findings)
        report += ReportGenerator.generate_compliance_notes()
        
        report += "━" * 80 + "\n"
        report += f"End of Report - Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return report
    
    @staticmethod
    def export_to_json(findings: List[Dict], data: Dict, filename: str = None) -> str:
        """Export findings to JSON format"""
        
        if filename is None:
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'generated_at': datetime.now().isoformat(),
            'org_id': data.get('org_id'),
            'summary': {
                'total_findings': len(findings),
                'critical': len([f for f in findings if f['severity'] == 'critical']),
                'high': len([f for f in findings if f['severity'] == 'high']),
                'medium': len([f for f in findings if f['severity'] == 'medium']),
                'low': len([f for f in findings if f['severity'] == 'low'])
            },
            'findings': findings,
            'metadata': data.get('summary', {})
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return filename
    
    @staticmethod
    def generate_summary_stats(findings: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics"""
        
        stats = {
            'total_findings': len(findings),
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'by_category': {},
            'top_issues': []
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'low')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count by category
            category = finding.get('type', finding.get('category', 'Other'))
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        # Get top issues (critical and high only)
        stats['top_issues'] = [
            finding['title'] for finding in findings
            if finding['severity'] in ['critical', 'high']
        ][:10]
        
        return stats