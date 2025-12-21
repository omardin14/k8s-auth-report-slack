"""
Auth Scanner Module

Scans Kubernetes cluster for active users and service accounts, checks their permissions,
and retrieves audit logs of their activities.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("kubernetes library not available. Install with: pip install kubernetes")

logger = logging.getLogger(__name__)


class AuthScanner:
    """Scans Kubernetes cluster for active users and service accounts."""
    
    def __init__(self, max_users: int = 10):
        """
        Initialize the auth scanner.
        
        Args:
            max_users: Maximum number of users/service accounts to scan (default: 10)
        """
        self.max_users = max_users
        self.v1 = None
        self.rbac_v1 = None
        self.auth_v1 = None
        
        if KUBERNETES_AVAILABLE:
            try:
                # Try to load in-cluster config first, then kubeconfig
                try:
                    config.load_incluster_config()
                    logger.info("Loaded in-cluster Kubernetes config")
                except:
                    config.load_kube_config()
                    logger.info("Loaded kubeconfig")
                
                self.v1 = client.CoreV1Api()
                self.rbac_v1 = client.RbacAuthorizationV1Api()
                self.auth_v1 = client.AuthorizationV1Api()
            except Exception as e:
                logger.error(f"Failed to initialize Kubernetes client: {e}")
                raise
    
    def scan_cluster_auth(self) -> Dict[str, Any]:
        """
        Scan the cluster for active users and service accounts.
        
        Returns:
            Dictionary containing scan results with users, permissions, and activities
        """
        logger.info(f"🔍 Starting Kubernetes auth scan (max {self.max_users} users/service accounts)...")
        
        if not KUBERNETES_AVAILABLE or not self.v1:
            raise RuntimeError("Kubernetes client not available")
        
        results = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'cluster_info': {},
            'users': [],
            'service_accounts': [],
            'summary': {
                'total_users': 0,
                'total_service_accounts': 0,
                'users_with_permissions': 0,
                'high_privilege_users': 0,
                'inactive_users': 0
            }
        }
        
        try:
            # Get cluster info
            try:
                version = self.v1.get_code()
                results['cluster_info'] = {
                    'version': version.git_version if hasattr(version, 'git_version') else 'unknown',
                    'platform': version.platform if hasattr(version, 'platform') else 'unknown'
                }
            except:
                results['cluster_info'] = {'version': 'unknown', 'platform': 'unknown'}
            
            # Get all service accounts
            logger.info("📋 Scanning service accounts...")
            service_accounts = self._get_active_service_accounts()
            results['service_accounts'] = service_accounts[:self.max_users]
            results['summary']['total_service_accounts'] = len(service_accounts)
            
            # Get users from various sources
            logger.info("👥 Scanning users...")
            users = self._get_active_users()
            results['users'] = users[:self.max_users]
            results['summary']['total_users'] = len(users)
            
            # Analyze permissions for each user/SA
            logger.info("🔐 Analyzing permissions...")
            for user_data in results['users'] + results['service_accounts']:
                user_data['permissions'] = self._analyze_user_permissions(user_data)
                user_data['recent_activities'] = self._get_recent_activities(user_data)
                
                if user_data['permissions'].get('has_permissions'):
                    results['summary']['users_with_permissions'] += 1
                
                if user_data['permissions'].get('risk_level') == 'high':
                    results['summary']['high_privilege_users'] += 1
            
            logger.info(f"✅ Auth scan complete: {len(results['users'])} users, {len(results['service_accounts'])} service accounts")
            
        except Exception as e:
            logger.error(f"❌ Error during auth scan: {e}")
            raise
        
        return results
    
    def _get_active_service_accounts(self) -> List[Dict[str, Any]]:
        """
        Get active service accounts from the cluster.
        
        Returns:
            List of service account information
        """
        service_accounts = []
        
        try:
            # Get all namespaces
            namespaces = self.v1.list_namespace()
            
            for ns in namespaces.items:
                namespace = ns.metadata.name
                
                try:
                    # Get service accounts in this namespace
                    sa_list = self.v1.list_namespaced_service_account(namespace)
                    
                    for sa in sa_list.items:
                        sa_name = sa.metadata.name
                        sa_namespace = sa.metadata.namespace
                        
                        # Get secrets associated with this SA
                        secrets = []
                        if sa.secrets:
                            for secret_ref in sa.secrets:
                                try:
                                    secret = self.v1.read_namespaced_secret(
                                        secret_ref.name, sa_namespace
                                    )
                                    if secret.data and 'token' in secret.data:
                                        secrets.append(secret_ref.name)
                                except:
                                    pass
                        
                        # Check if SA is actively used (has tokens or is referenced)
                        is_active = len(secrets) > 0 or self._is_service_account_referenced(sa_name, sa_namespace)
                        
                        if is_active:
                            service_accounts.append({
                                'name': sa_name,
                                'namespace': sa_namespace,
                                'type': 'service_account',
                                'created': sa.metadata.creation_timestamp.isoformat() if sa.metadata.creation_timestamp else None,
                                'secrets': secrets,
                                'labels': sa.metadata.labels or {},
                                'annotations': sa.metadata.annotations or {}
                            })
                
                except ApiException as e:
                    logger.warning(f"Error getting service accounts in {namespace}: {e}")
                    continue
        
        except ApiException as e:
            logger.error(f"Error listing namespaces: {e}")
        
        # Sort by creation time (most recent first)
        service_accounts.sort(
            key=lambda x: x['created'] or '1970-01-01',
            reverse=True
        )
        
        return service_accounts
    
    def _is_service_account_referenced(self, sa_name: str, namespace: str) -> bool:
        """
        Check if a service account is referenced by any pods or other resources.
        
        Args:
            sa_name: Service account name
            namespace: Namespace
        
        Returns:
            True if the SA is referenced
        """
        try:
            # Check pods
            pods = self.v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                if pod.spec.service_account_name == sa_name:
                    return True
        except:
            pass
        
        return False
    
    def _get_active_users(self) -> List[Dict[str, Any]]:
        """
        Get active users from the cluster.
        
        Returns:
            List of user information
        """
        users = []
        user_set = set()
        
        try:
            # Get users from RoleBindings and ClusterRoleBindings
            # This gives us users who have been granted permissions
            
            # ClusterRoleBindings
            try:
                crbs = self.rbac_v1.list_cluster_role_binding()
                for crb in crbs.items:
                    for subject in crb.subjects or []:
                        if subject.kind == 'User' and subject.name:
                            if subject.name not in user_set:
                                user_set.add(subject.name)
                                users.append({
                                    'name': subject.name,
                                    'type': 'user',
                                    'source': 'cluster_role_binding',
                                    'role': crb.role_ref.name if crb.role_ref else None
                                })
            except ApiException as e:
                logger.warning(f"Error getting ClusterRoleBindings: {e}")
            
            # RoleBindings (namespace-scoped)
            try:
                namespaces = self.v1.list_namespace()
                for ns in namespaces.items:
                    namespace = ns.metadata.name
                    try:
                        rbs = self.rbac_v1.list_namespaced_role_binding(namespace)
                        for rb in rbs.items:
                            for subject in rb.subjects or []:
                                if subject.kind == 'User' and subject.name:
                                    if subject.name not in user_set:
                                        user_set.add(subject.name)
                                        users.append({
                                            'name': subject.name,
                                            'type': 'user',
                                            'namespace': namespace,
                                            'source': 'role_binding',
                                            'role': rb.role_ref.name if rb.role_ref else None
                                        })
                    except ApiException:
                        continue
            except ApiException as e:
                logger.warning(f"Error getting RoleBindings: {e}")
            
            # Get users from service account tokens (if we can extract them)
            # This is more complex and may require additional permissions
            
        except Exception as e:
            logger.error(f"Error getting active users: {e}")
        
        # Sort by name for consistency
        users.sort(key=lambda x: x['name'])
        
        return users
    
    def _analyze_user_permissions(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze permissions for a user or service account.
        
        Args:
            user_data: User or service account data
        
        Returns:
            Dictionary containing permission analysis
        """
        permissions = {
            'has_permissions': False,
            'roles': [],
            'cluster_roles': [],
            'permissions': [],
            'risk_level': 'low',
            'risk_factors': []
        }
        
        user_name = user_data['name']
        user_type = user_data.get('type', 'user')
        namespace = user_data.get('namespace')
        
        try:
            # Get RoleBindings for this user/SA
            if namespace:
                try:
                    rbs = self.rbac_v1.list_namespaced_role_binding(namespace)
                    for rb in rbs.items:
                        for subject in rb.subjects or []:
                            if ((subject.kind == 'User' and subject.name == user_name) or
                                (subject.kind == 'ServiceAccount' and 
                                 subject.name == user_name and 
                                 subject.namespace == namespace)):
                                permissions['roles'].append({
                                    'name': rb.role_ref.name,
                                    'kind': rb.role_ref.kind,
                                    'namespace': namespace,
                                    'binding_name': rb.metadata.name
                                })
                                
                                # Get role details
                                if rb.role_ref.kind == 'Role':
                                    try:
                                        role = self.rbac_v1.read_namespaced_role(
                                            rb.role_ref.name, namespace
                                        )
                                        permissions['permissions'].extend(
                                            self._extract_role_permissions(role)
                                        )
                                    except:
                                        pass
                except ApiException:
                    pass
            
            # Get ClusterRoleBindings
            try:
                crbs = self.rbac_v1.list_cluster_role_binding()
                for crb in crbs.items:
                    for subject in crb.subjects or []:
                        if ((subject.kind == 'User' and subject.name == user_name) or
                            (subject.kind == 'ServiceAccount' and 
                             subject.name == user_name and 
                             (not namespace or subject.namespace == namespace))):
                            permissions['cluster_roles'].append({
                                'name': crb.role_ref.name,
                                'kind': crb.role_ref.kind,
                                'binding_name': crb.metadata.name
                            })
                            
                            # Get cluster role details
                            if crb.role_ref.kind == 'ClusterRole':
                                try:
                                    cluster_role = self.rbac_v1.read_cluster_role(
                                        crb.role_ref.name
                                    )
                                    permissions['permissions'].extend(
                                        self._extract_role_permissions(cluster_role)
                                    )
                                except:
                                    pass
            except ApiException:
                pass
            
            # Determine risk level
            permissions['has_permissions'] = len(permissions['roles']) > 0 or len(permissions['cluster_roles']) > 0
            
            if permissions['has_permissions']:
                risk_level = self._calculate_risk_level(permissions)
                permissions['risk_level'] = risk_level
                permissions['risk_factors'] = self._identify_risk_factors(permissions)
        
        except Exception as e:
            logger.warning(f"Error analyzing permissions for {user_name}: {e}")
        
        return permissions
    
    def _extract_role_permissions(self, role) -> List[Dict[str, Any]]:
        """
        Extract permissions from a Role or ClusterRole.
        
        Args:
            role: Role or ClusterRole object
        
        Returns:
            List of permission dictionaries
        """
        permissions = []
        
        if hasattr(role, 'rules'):
            for rule in role.rules or []:
                api_groups = rule.api_groups or ['*']
                resources = rule.resources or ['*']
                verbs = rule.verbs or ['*']
                
                for api_group in api_groups:
                    for resource in resources:
                        for verb in verbs:
                            permissions.append({
                                'api_group': api_group,
                                'resource': resource,
                                'verb': verb,
                                'resource_names': rule.resource_names or []
                            })
        
        return permissions
    
    def _calculate_risk_level(self, permissions: Dict[str, Any]) -> str:
        """
        Calculate risk level based on permissions.
        
        Args:
            permissions: Permissions dictionary
        
        Returns:
            Risk level: 'low', 'medium', or 'high'
        """
        high_risk_verbs = ['*', 'create', 'update', 'patch', 'delete', 'deletecollection']
        high_risk_resources = ['*', 'secrets', 'configmaps', 'pods', 'services', 'deployments', 'nodes']
        high_risk_cluster_roles = ['cluster-admin', 'admin', 'edit']
        
        # Check for cluster-admin
        for cr in permissions.get('cluster_roles', []):
            if cr['name'] in high_risk_cluster_roles:
                return 'high'
        
        # Check for dangerous permissions
        for perm in permissions.get('permissions', []):
            if (perm['verb'] in high_risk_verbs and 
                perm['resource'] in high_risk_resources):
                return 'high'
        
        # Check for wildcard permissions
        for perm in permissions.get('permissions', []):
            if perm['verb'] == '*' or perm['resource'] == '*':
                return 'medium'
        
        # Check for multiple roles
        if len(permissions.get('roles', [])) + len(permissions.get('cluster_roles', [])) > 3:
            return 'medium'
        
        return 'low'
    
    def _identify_risk_factors(self, permissions: Dict[str, Any]) -> List[str]:
        """
        Identify specific risk factors in permissions.
        
        Args:
            permissions: Permissions dictionary
        
        Returns:
            List of risk factor descriptions
        """
        risk_factors = []
        
        # Check for cluster-admin
        for cr in permissions.get('cluster_roles', []):
            if cr['name'] == 'cluster-admin':
                risk_factors.append('Has cluster-admin role')
        
        # Check for wildcard permissions
        for perm in permissions.get('permissions', []):
            if perm['verb'] == '*' and perm['resource'] == '*':
                risk_factors.append('Has wildcard permissions (*)')
        
        # Check for dangerous resource access
        dangerous_resources = ['secrets', 'configmaps', 'pods']
        for perm in permissions.get('permissions', []):
            if perm['resource'] in dangerous_resources and perm['verb'] in ['*', 'delete', 'create']:
                risk_factors.append(f'Can {perm["verb"]} {perm["resource"]}')
        
        return risk_factors
    
    def _get_recent_activities(self, user_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get recent activities for a user or service account.
        
        Note: This is a simplified implementation. In a real scenario, you would
        need access to Kubernetes audit logs, which requires cluster-admin permissions
        and audit logging to be enabled.
        
        Args:
            user_data: User or service account data
        
        Returns:
            List of recent activities
        """
        activities = []
        
        # In a real implementation, you would query audit logs here
        # For now, we'll return a placeholder indicating that audit logs
        # would need to be enabled and accessible
        
        activities.append({
            'note': 'Audit log access requires cluster-admin permissions and audit logging to be enabled',
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return activities
    
    def save_results(self, file_path: str) -> None:
        """
        Save scan results to a JSON file.
        
        Args:
            file_path: Path to save the results
        """
        results = self.scan_cluster_auth()
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"✅ Auth scan results saved to {file_path}")

