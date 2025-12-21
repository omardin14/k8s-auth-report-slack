"""
HTML Report Generator Module

Converts auth scan results into a beautiful HTML report.
"""

import json
import time
import re
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime


class HTMLReportGenerator:
    """Generates HTML reports from auth scan data."""
    
    @staticmethod
    def generate_auth_report(scan_data: Dict[str, Any], analysis: Dict[str, Any] = None,
                            output_path: str = None) -> str:
        """
        Generate a styled HTML report from auth scan data.
        
        Args:
            scan_data: Auth scan results
            analysis: Auth analysis results (optional)
            output_path: Optional path to save the HTML file
            
        Returns:
            HTML content as string
        """
        summary = scan_data.get('summary', {})
        users = scan_data.get('users', [])
        service_accounts = scan_data.get('service_accounts', [])
        all_entities = users + service_accounts
        
        total_users = summary.get('total_users', 0)
        total_sas = summary.get('total_service_accounts', 0)
        high_privilege = summary.get('high_privilege_users', 0)
        with_permissions = summary.get('users_with_permissions', 0)
        
        # Determine overall status
        if analysis and analysis.get('critical_risks'):
            status = "CRITICAL"
            status_color = "#ef4444"
        elif analysis and analysis.get('warnings'):
            status = "WARNING"
            status_color = "#f59e0b"
        else:
            status = "HEALTHY"
            status_color = "#10b981"
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Authorization Audit Report - {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .timestamp {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .status-banner {{
            background: {status_color};
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 1.8em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f9fafb;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card .label {{
            color: #6b7280;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .total {{ color: #3b82f6; }}
        .high {{ color: #ef4444; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #10b981; }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #1f2937;
        }}
        
        .entity {{
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .entity-header {{
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f9fafb;
            transition: background 0.2s;
        }}
        
        .entity-header:hover {{
            background: #f3f4f6;
        }}
        
        .entity-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #1f2937;
        }}
        
        .entity-status {{
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
        }}
        
        .status-high {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .status-medium {{
            background: #fef3c7;
            color: #92400e;
        }}
        
        .status-low {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .entity-body {{
            display: none;
            padding: 20px;
        }}
        
        .entity.expanded .entity-body {{
            display: block;
        }}
        
        .entity.expanded .entity-header {{
            background: #667eea;
            color: white;
        }}
        
        .entity.expanded .entity-title {{
            color: white;
        }}
        
        .detail {{
            background: #f9fafb;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        
        .detail strong {{
            color: #1f2937;
            display: block;
            margin-bottom: 5px;
        }}
        
        .detail .value {{
            color: #4b5563;
            font-family: 'Courier New', monospace;
        }}
        
        .ai-insights {{
            background: #eff6ff;
            padding: 15px;
            margin-top: 15px;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
        }}
        
        .ai-insights strong {{
            color: #1e40af;
            display: block;
            margin-bottom: 10px;
        }}
        
        .risk-factor {{
            background: #fef2f2;
            padding: 8px 12px;
            border-radius: 4px;
            margin: 5px 5px 5px 0;
            display: inline-block;
            color: #991b1b;
            font-size: 0.9em;
        }}
        
        .recommendation {{
            background: #eff6ff;
            padding: 12px;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
            margin-top: 10px;
            color: #1e40af;
        }}
        
        .btn-expand {{
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            margin: 20px 0;
        }}
        
        .btn-expand:hover {{
            background: #5568d3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Kubernetes Authorization Audit Report</h1>
            <div class="timestamp">{scan_data.get('scan_timestamp', 'Unknown')}</div>
        </div>
        
        <div class="status-banner">{status}</div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="label">Total Users</div>
                <div class="number total">{total_users}</div>
            </div>
            <div class="summary-card">
                <div class="label">Service Accounts</div>
                <div class="number total">{total_sas}</div>
            </div>
            <div class="summary-card">
                <div class="label">With Permissions</div>
                <div class="number medium">{with_permissions}</div>
            </div>
            <div class="summary-card">
                <div class="label">High Privilege</div>
                <div class="number high">{high_privilege}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📋 Users & Service Accounts</h2>
                <button class="btn-expand" onclick="toggleAll()">Expand/Collapse All</button>
                {HTMLReportGenerator._generate_entity_list(all_entities, analysis)}
            </div>
            
            {HTMLReportGenerator._generate_recommendations_section(analysis) if analysis else ''}
            
            {HTMLReportGenerator._generate_ai_analysis_section(analysis) if analysis and analysis.get('ai_analysis') else ''}
        </div>
    </div>
    
    <script>
        function toggleEntity(element) {{
            element.parentElement.classList.toggle('expanded');
        }}
        
        function toggleAll() {{
            const entities = document.querySelectorAll('.entity');
            const allExpanded = Array.from(entities).every(e => e.classList.contains('expanded'));
            entities.forEach(e => {{
                if (allExpanded) {{
                    e.classList.remove('expanded');
                }} else {{
                    e.classList.add('expanded');
                }}
            }});
        }}
    </script>
</body>
</html>"""
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(html)
            print(f"✅ HTML report saved to {output_path}")
        
        return html
    
    @staticmethod
    def _generate_entity_list(entities: list, analysis: Dict[str, Any] = None) -> str:
        """Generate HTML for entity list."""
        html_parts = []
        
        # Create a lookup for analysis data
        analysis_lookup = {}
        if analysis:
            for entity_analysis in analysis.get('user_analyses', []):
                analysis_lookup[entity_analysis.get('name')] = entity_analysis
        
        for entity in entities:
            entity_name = entity.get('name', 'Unknown')
            entity_type = entity.get('type', 'unknown')
            namespace = entity.get('namespace', 'cluster-wide')
            permissions = entity.get('permissions', {})
            risk_level = permissions.get('risk_level', 'low')
            risk_factors = permissions.get('risk_factors', [])
            roles = permissions.get('roles', [])
            cluster_roles = permissions.get('cluster_roles', [])
            
            # Get AI insights if available
            entity_analysis = analysis_lookup.get(entity_name, {})
            ai_insights = entity_analysis.get('ai_insights')
            
            status_class = f"status-{risk_level}"
            
            html_parts.append(f"""
            <div class="entity">
                <div class="entity-header" onclick="toggleEntity(this)">
                    <div>
                        <div class="entity-title">{entity_name} ({entity_type})</div>
                        <div style="font-size: 0.9em; color: #6b7280; margin-top: 5px;">{namespace}</div>
                    </div>
                    <div class="entity-status {status_class}">{risk_level.upper()}</div>
                </div>
                <div class="entity-body">
                    <div class="detail">
                        <strong>Type:</strong>
                        <div class="value">{entity_type}</div>
                    </div>
                    <div class="detail">
                        <strong>Namespace:</strong>
                        <div class="value">{namespace}</div>
                    </div>
                    <div class="detail">
                        <strong>Risk Level:</strong>
                        <div class="value">{risk_level.upper()}</div>
                    </div>
                    {f'<div class="detail"><strong>Risk Factors:</strong><div class="value">{" ".join([f\'<span class="risk-factor">{rf}</span>\' for rf in risk_factors])}</div></div>' if risk_factors else ''}
                    {f'<div class="detail"><strong>Roles:</strong><div class="value">{", ".join([r.get("name", "unknown") for r in roles])}</div></div>' if roles else ''}
                    {f'<div class="detail"><strong>Cluster Roles:</strong><div class="value">{", ".join([cr.get("name", "unknown") for cr in cluster_roles])}</div></div>' if cluster_roles else ''}
                    {f'<div class="ai-insights"><strong>💡 AI-Powered Insights:</strong><div class="value">{HTMLReportGenerator._format_ai_insights(ai_insights)}</div></div>' if ai_insights else ''}
                </div>
            </div>
            """)
        
        return "".join(html_parts)
    
    @staticmethod
    def _format_ai_insights(insights: str) -> str:
        """Format AI insights with proper line breaks."""
        if not insights:
            return ""
        
        # Replace numbered points with line breaks
        formatted = re.sub(r'(\d+\.)', r'<br><br><strong>\1</strong>', insights)
        # Replace double line breaks with single
        formatted = re.sub(r'<br><br><br><br>', r'<br><br>', formatted)
        
        return formatted
    
    @staticmethod
    def _generate_recommendations_section(analysis: Dict[str, Any] = None) -> str:
        """Generate recommendations section."""
        if not analysis or not analysis.get('recommendations'):
            return ""
        
        recommendations = analysis['recommendations']
        rec_html = '<div class="section"><h2>💡 Recommendations</h2>'
        
        for rec in recommendations:
            rec_html += f'<div class="recommendation">{rec}</div>'
        
        rec_html += '</div>'
        return rec_html
    
    @staticmethod
    def _generate_ai_analysis_section(analysis: Dict[str, Any] = None) -> str:
        """Generate AI analysis section."""
        if not analysis or not analysis.get('ai_analysis'):
            return ""
        
        ai_analysis = analysis['ai_analysis']
        risk_assessment = ai_analysis.get('risk_assessment', '')
        
        # Format the AI analysis with line breaks
        formatted_assessment = risk_assessment.replace('\n', '<br>')
        
        return f"""
        <div class="section">
            <h2>🤖 AI-Powered Risk Analysis</h2>
            <div class="ai-insights">
                <div class="value">{formatted_assessment}</div>
            </div>
        </div>
        """

