"""
Slack Formatter Module

Handles formatting of auth scan results into Slack message blocks.
"""

import json
import time
from typing import Dict, Any, List
from datetime import datetime


class SlackFormatter:
    """Formats auth scan results into Slack message blocks."""
    
    @staticmethod
    def parse_auth_summary(data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse auth scan data to extract summary information."""
        summary = data.get('summary', {})
        users = data.get('users', [])
        service_accounts = data.get('service_accounts', [])
        
        return {
            'total_users': summary.get('total_users', 0),
            'total_service_accounts': summary.get('total_service_accounts', 0),
            'users_with_permissions': summary.get('users_with_permissions', 0),
            'high_privilege_users': summary.get('high_privilege_users', 0),
            'scan_timestamp': data.get('scan_timestamp', ''),
            'users': users,
            'service_accounts': service_accounts
        }
    
    @staticmethod
    def create_auth_blocks(summary: Dict[str, Any], analysis: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Create Slack blocks for auth report."""
        # Determine overall status
        if analysis and analysis.get('critical_risks'):
            status_emoji = "🔴"
            status_text = "CRITICAL"
            status_color = "#ff0000"
        elif analysis and analysis.get('warnings'):
            status_emoji = "⚠️"
            status_text = "WARNING"
            status_color = "#ff9900"
        else:
            status_emoji = "✅"
            status_text = "HEALTHY"
            status_color = "#36a64f"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Kubernetes Authorization Audit Report",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Status:* {status_text}\n*Scan Time:* {summary.get('scan_timestamp', 'Unknown')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Users:*\n`{summary['total_users']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Service Accounts:*\n`{summary['total_service_accounts']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*With Permissions:*\n✅ `{summary['users_with_permissions']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High Privilege:*\n🔴 `{summary['high_privilege_users']}`"
                    }
                ]
            }
        ]
        
        # Add critical risks section
        if analysis and analysis.get('critical_risks'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🔴 Critical Risks:*"
                }
            })
            for risk in analysis['critical_risks'][:5]:  # Show top 5
                entity_name = risk.get('name', 'Unknown')
                entity_type = risk.get('type', 'unknown')
                risk_factors = risk.get('risk_factors', [])
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *{entity_name}* ({entity_type}): {', '.join(risk_factors[:3])}"
                    }
                })
        
        # Add warnings section
        if analysis and analysis.get('warnings'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*⚠️ Warnings:*"
                }
            })
            for warning in analysis['warnings'][:5]:  # Show top 5
                entity_name = warning.get('name', 'Unknown')
                entity_type = warning.get('type', 'unknown')
                risk_factors = warning.get('risk_factors', [])
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *{entity_name}* ({entity_type}): {', '.join(risk_factors[:2])}"
                    }
                })
        
        # Add user/SA details
        all_entities = summary.get('users', []) + summary.get('service_accounts', [])
        if all_entities:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*📋 Active Users & Service Accounts:*"
                }
            })
            
            for entity in all_entities[:10]:  # Show top 10
                entity_name = entity.get('name', 'Unknown')
                entity_type = entity.get('type', 'unknown')
                namespace = entity.get('namespace', 'cluster-wide')
                permissions = entity.get('permissions', {})
                risk_level = permissions.get('risk_level', 'low')
                
                # Choose emoji based on risk level
                if risk_level == 'high':
                    emoji = "🔴"
                elif risk_level == 'medium':
                    emoji = "⚠️"
                else:
                    emoji = "✅"
                
                roles_count = len(permissions.get('roles', [])) + len(permissions.get('cluster_roles', []))
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{entity_name}* ({entity_type}) - {namespace}\n*Risk:* {risk_level.upper()} | *Roles:* {roles_count}"
                    }
                })
        
        # Add recommendations
        if analysis and analysis.get('recommendations'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*💡 Recommendations:*"
                }
            })
            for rec in analysis['recommendations'][:5]:  # Show top 5
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": rec
                    }
                })
        
        # Add AI analysis if available
        if analysis and analysis.get('ai_analysis') and analysis['ai_analysis'].get('risk_assessment'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🤖 AI-Powered Risk Analysis:*"
                }
            })
            # Truncate AI analysis for Slack (it's long)
            ai_text = analysis['ai_analysis']['risk_assessment'][:1000] + "..." if len(analysis['ai_analysis']['risk_assessment']) > 1000 else analysis['ai_analysis']['risk_assessment']
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{ai_text}```"
                }
            })
        
        return blocks
    
    @staticmethod
    def create_test_blocks() -> List[Dict[str, Any]]:
        """Create test blocks for testing Slack integration."""
        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🧪 Test Message from Kubernetes Auth Reporter",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "This is a test message to verify Slack integration is working correctly."
                }
            }
        ]
    
    @staticmethod
    def format_json_data(data: Dict[str, Any], title: str = "Data Export") -> List[Dict[str, Any]]:
        """Format JSON data for Slack."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```json\n{json.dumps(data, indent=2)[:3000]}...\n```"
                }
            }
        ]
        return blocks

