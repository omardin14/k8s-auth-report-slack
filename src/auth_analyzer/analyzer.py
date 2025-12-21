"""
Auth Analyzer Module

Analyzes auth scan results and provides insights with OpenAI-powered risk analysis.
"""

import logging
import os
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class AuthAnalyzer:
    """Analyzes auth scan results and provides risk insights."""
    
    def __init__(self, openai_api_key: Optional[str] = None, openai_model: str = "gpt-4"):
        """
        Initialize the auth analyzer.
        
        Args:
            openai_api_key: OpenAI API key (optional, for AI-powered analysis)
            openai_model: OpenAI model to use (default: gpt-4)
        """
        self.openai_api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        self.openai_model = openai_model
        self.openai_enabled = self.openai_api_key is not None
    
    def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze auth scan results and provide insights.
        
        Args:
            scan_results: Auth scan results dictionary
            
        Returns:
            Analysis results with recommendations and AI-powered insights
        """
        logger.info("🔍 Analyzing auth scan results...")
        
        analysis = {
            'overall_status': 'unknown',
            'critical_risks': [],
            'warnings': [],
            'recommendations': [],
            'summary': scan_results.get('summary', {}),
            'user_analyses': []
        }
        
        users = scan_results.get('users', [])
        service_accounts = scan_results.get('service_accounts', [])
        all_entities = users + service_accounts
        
        # Analyze each user/SA
        for entity in all_entities:
            entity_analysis = self._analyze_entity(entity)
            analysis['user_analyses'].append(entity_analysis)
            
            # Collect critical risks
            if entity_analysis.get('risk_level') == 'high':
                analysis['critical_risks'].append({
                    'name': entity.get('name'),
                    'type': entity.get('type'),
                    'risk_factors': entity_analysis.get('risk_factors', [])
                })
            
            # Collect warnings
            if entity_analysis.get('risk_level') == 'medium':
                analysis['warnings'].append({
                    'name': entity.get('name'),
                    'type': entity.get('type'),
                    'risk_factors': entity_analysis.get('risk_factors', [])
                })
        
        # Determine overall status
        if analysis['critical_risks']:
            analysis['overall_status'] = 'CRITICAL'
        elif analysis['warnings']:
            analysis['overall_status'] = 'WARNING'
        else:
            analysis['overall_status'] = 'HEALTHY'
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        # Add AI-powered analysis if enabled
        if self.openai_enabled:
            logger.info("🤖 Generating AI-powered risk analysis...")
            ai_analysis = self._get_ai_risk_analysis(scan_results, analysis)
            analysis['ai_analysis'] = ai_analysis
            logger.info("✅ AI analysis complete")
        else:
            logger.info("ℹ️ OpenAI not enabled, skipping AI analysis")
        
        logger.info(f"✅ Analysis complete: {analysis['overall_status']}")
        
        return analysis
    
    def _analyze_entity(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single user or service account.
        
        Args:
            entity: User or service account information dictionary
            
        Returns:
            Analysis for the entity
        """
        permissions = entity.get('permissions', {})
        
        return {
            'name': entity.get('name'),
            'type': entity.get('type'),
            'namespace': entity.get('namespace'),
            'risk_level': permissions.get('risk_level', 'low'),
            'risk_factors': permissions.get('risk_factors', []),
            'roles': permissions.get('roles', []),
            'cluster_roles': permissions.get('cluster_roles', []),
            'has_permissions': permissions.get('has_permissions', False),
            'ai_insights': None  # Will be populated by AI if enabled
        }
    
    def _get_ai_risk_analysis(self, scan_results: Dict[str, Any], 
                             analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get AI-powered risk analysis for the auth scan results.
        
        Args:
            scan_results: Auth scan results
            analysis: Basic analysis results
            
        Returns:
            AI-powered analysis with risk insights and recommendations
        """
        if not self.openai_enabled:
            return None
        
        start_time = time.time()
        
        try:
            from openai import OpenAI
            
            logger.info("🤖 Requesting AI risk analysis for auth scan...")
            
            client = OpenAI(api_key=self.openai_api_key)
            
            # Prepare summary of high-risk entities
            high_risk_entities = []
            for entity_analysis in analysis.get('user_analyses', []):
                if entity_analysis.get('risk_level') == 'high':
                    entity_name = entity_analysis.get('name')
                    entity_type = entity_analysis.get('type')
                    risk_factors = entity_analysis.get('risk_factors', [])
                    roles = entity_analysis.get('cluster_roles', []) + entity_analysis.get('roles', [])
                    
                    high_risk_entities.append({
                        'name': entity_name,
                        'type': entity_type,
                        'risk_factors': risk_factors,
                        'roles': [r.get('name') for r in roles]
                    })
            
            # Build prompt for OpenAI
            prompt = f"""Analyze this Kubernetes authorization audit report and provide security insights.

Summary:
- Total users: {scan_results.get('summary', {}).get('total_users', 0)}
- Total service accounts: {scan_results.get('summary', {}).get('total_service_accounts', 0)}
- Users with permissions: {scan_results.get('summary', {}).get('users_with_permissions', 0)}
- High privilege users: {scan_results.get('summary', {}).get('high_privilege_users', 0)}

High-Risk Entities:
{self._format_entities_for_ai(high_risk_entities)}

Please provide:
1. Overall risk assessment (HIGH/MEDIUM/LOW) with brief explanation
2. Top 3-5 critical security concerns with business impact
3. Specific risks for each high-risk entity (what attackers could do)
4. Prioritized remediation recommendations with time estimates
5. Best practices for improving access control

Format the response as a structured analysis with clear sections."""
            
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are a Kubernetes security expert specializing in RBAC and access control. Provide clear, actionable security insights and risk assessments."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            elapsed_time = time.time() - start_time
            ai_response = response.choices[0].message.content
            
            # Extract token usage
            token_usage = {
                'prompt_tokens': response.usage.prompt_tokens,
                'completion_tokens': response.usage.completion_tokens,
                'total_tokens': response.usage.total_tokens
            }
            
            logger.info(f"✅ AI analysis complete in {elapsed_time:.2f}s (tokens: {token_usage['total_tokens']})")
            
            return {
                'risk_assessment': ai_response,
                'model': self.openai_model,
                'response_time_seconds': round(elapsed_time, 2),
                'token_usage': token_usage
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting AI risk analysis: {e}")
            return {
                'error': str(e),
                'note': 'AI analysis failed, but basic analysis is still available'
            }
    
    def _format_entities_for_ai(self, entities: List[Dict[str, Any]]) -> str:
        """
        Format entity information for AI prompt.
        
        Args:
            entities: List of entity dictionaries
        
        Returns:
            Formatted string
        """
        if not entities:
            return "No high-risk entities found."
        
        formatted = []
        for i, entity in enumerate(entities, 1):
            formatted.append(f"{i}. {entity['name']} ({entity['type']})")
            formatted.append(f"   Roles: {', '.join(entity['roles']) if entity['roles'] else 'None'}")
            formatted.append(f"   Risk Factors: {', '.join(entity['risk_factors']) if entity['risk_factors'] else 'None'}")
        
        return "\n".join(formatted)
    
    def _get_entity_ai_insights(self, entity: Dict[str, Any]) -> Optional[str]:
        """
        Get AI-powered insights for a specific entity.
        
        Args:
            entity: Entity information dictionary
        
        Returns:
            AI insights or None if OpenAI is not available
        """
        if not self.openai_enabled:
            return None
        
        entity_name = entity.get('name', 'unknown')
        permissions = entity.get('permissions', {})
        risk_level = permissions.get('risk_level', 'low')
        risk_factors = permissions.get('risk_factors', [])
        roles = permissions.get('cluster_roles', []) + permissions.get('roles', [])
        
        import time
        start_time = time.time()
        
        try:
            from openai import OpenAI
            
            logger.info(f"🤖 Requesting AI insights for entity: {entity_name}")
            
            client = OpenAI(api_key=self.openai_api_key)
            
            # Build prompt for OpenAI
            prompt = f"""Analyze this Kubernetes user/service account and provide security insights.

Entity: {entity_name}
Type: {entity.get('type', 'unknown')}
Namespace: {entity.get('namespace', 'cluster-wide')}
Risk Level: {risk_level.upper()}

Roles:
{chr(10).join([f"- {r.get('name', 'unknown')} ({r.get('kind', 'unknown')})" for r in roles])}

Risk Factors:
{chr(10).join([f"- {rf}" for rf in risk_factors]) if risk_factors else 'None identified'}

Provide:
1. What security risks this entity poses
2. What an attacker could do with these permissions
3. Specific recommendations to reduce risk
4. Priority level (HIGH/MEDIUM/LOW) for remediation

Keep the response concise (2-3 paragraphs)."""
            
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are a Kubernetes security expert. Provide clear, actionable security insights."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            elapsed_time = time.time() - start_time
            insights = response.choices[0].message.content
            
            logger.info(f"✅ AI insights for {entity_name} generated in {elapsed_time:.2f}s")
            
            return insights
            
        except Exception as e:
            logger.warning(f"⚠️ Error getting AI insights for {entity_name}: {e}")
            return None
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on analysis.
        
        Args:
            analysis: Analysis results dictionary
        
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if analysis.get('critical_risks'):
            recommendations.append(f"🔴 {len(analysis['critical_risks'])} high-risk user(s) found - review immediately")
            recommendations.append("• Remove unnecessary cluster-admin or admin roles")
            recommendations.append("• Implement least privilege access principles")
        
        if analysis.get('warnings'):
            recommendations.append(f"⚠️ {len(analysis['warnings'])} medium-risk user(s) found - review permissions")
            recommendations.append("• Audit wildcard permissions (*)")
            recommendations.append("• Review service account usage and remove unused accounts")
        
        summary = analysis.get('summary', {})
        if summary.get('high_privilege_users', 0) > 0:
            recommendations.append("• Regularly audit RBAC permissions")
            recommendations.append("• Use Role-Based Access Control (RBAC) best practices")
            recommendations.append("• Enable Kubernetes audit logging for compliance")
        
        if not recommendations:
            recommendations.append("✅ No critical issues found - continue regular monitoring")
        
        return recommendations
    
    def create_dummy_data(self) -> Dict[str, Any]:
        """
        Create dummy data for testing.
        
        Returns:
            Dummy scan results dictionary
        """
        return {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'cluster_info': {
                'version': 'v1.28.0',
                'platform': 'linux/amd64'
            },
            'users': [
                {
                    'name': 'admin-user',
                    'type': 'user',
                    'permissions': {
                        'has_permissions': True,
                        'risk_level': 'high',
                        'risk_factors': ['Has cluster-admin role'],
                        'cluster_roles': [{'name': 'cluster-admin', 'kind': 'ClusterRole'}]
                    }
                }
            ],
            'service_accounts': [
                {
                    'name': 'default',
                    'namespace': 'kube-system',
                    'type': 'service_account',
                    'permissions': {
                        'has_permissions': True,
                        'risk_level': 'medium',
                        'risk_factors': ['Has wildcard permissions'],
                        'roles': [{'name': 'edit', 'kind': 'Role', 'namespace': 'kube-system'}]
                    }
                }
            ],
            'summary': {
                'total_users': 1,
                'total_service_accounts': 1,
                'users_with_permissions': 2,
                'high_privilege_users': 1,
                'inactive_users': 0
            }
        }

