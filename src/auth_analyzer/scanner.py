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
except ImportError as e:
    KUBERNETES_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning(f"kubernetes library not available: {e}. Install with: pip install kubernetes")

logger = logging.getLogger(__name__)


class AuthScanner:
    """Scans Kubernetes cluster for active users and service accounts."""
    
    # System users/service accounts to ignore (expected to have high privileges)
    SYSTEM_USER_PATTERNS = [
        'system:kube-controller-manager',
        'system:kube-scheduler',
        'system:kube-proxy',
        'system:anonymous',
        'system:serviceaccount',
        'system:node',
        'system:unsecured',
    ]
    
    SYSTEM_NAMESPACES = [
        'kube-system',
        'kube-public',
        'kube-node-lease',
    ]
    
    SYSTEM_SA_PATTERNS = [
        'coredns',
        'kube-proxy',
        'storage-provisioner',
        'kube-dns',
        'kube-flannel',
        'calico',
        'weave',
    ]
    
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
        self.apps_v1 = None
        self._V1Subject = None  # Cache for V1Subject class
        
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
                self.apps_v1 = client.AppsV1Api()
                
                # Try to get V1Subject class
                try:
                    from kubernetes.client.models import V1Subject
                    self._V1Subject = V1Subject
                except ImportError:
                    try:
                        self._V1Subject = getattr(client, 'V1Subject', None)
                    except:
                        pass
            except Exception as e:
                logger.error(f"Failed to initialize Kubernetes client: {e}")
                raise
    
    def _create_subject(self, kind: str, name: str, namespace: str = None, api_group: str = None):
        """Create a subject object for RoleBinding/ClusterRoleBinding."""
        if self._V1Subject:
            kwargs = {'kind': kind, 'name': name}
            if namespace:
                kwargs['namespace'] = namespace
            if api_group is not None:
                kwargs['api_group'] = api_group
            return self._V1Subject(**kwargs)
        else:
            # Fallback to dict (kubernetes client should handle this)
            subject = {'kind': kind, 'name': name}
            if namespace:
                subject['namespace'] = namespace
            if api_group is not None:
                subject['apiGroup'] = api_group
            return subject
    
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
            # Filter out system service accounts
            service_accounts = [sa for sa in service_accounts if not self._is_system_account(sa)]
            results['service_accounts'] = service_accounts[:self.max_users]
            results['summary']['total_service_accounts'] = len(service_accounts)
            
            # Get users from various sources
            logger.info("👥 Scanning users...")
            users = self._get_active_users()
            # Filter out system users
            users = [u for u in users if not self._is_system_account(u)]
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
    
    def _is_system_account(self, entity: Dict[str, Any]) -> bool:
        """
        Check if a user or service account is a system account that should be ignored.
        
        Args:
            entity: User or service account dictionary
        
        Returns:
            True if it's a system account, False otherwise
        """
        entity_name = entity.get('name', '')
        entity_type = entity.get('type', '')
        namespace = entity.get('namespace', '')
        
        # Check if it's a system user
        if entity_type == 'user':
            for pattern in self.SYSTEM_USER_PATTERNS:
                if entity_name.startswith(pattern):
                    logger.debug(f"Filtering out system user: {entity_name}")
                    return True
        
        # Check if it's a system service account
        if entity_type == 'service_account':
            # Check name patterns first (more specific)
            for pattern in self.SYSTEM_SA_PATTERNS:
                if pattern.lower() in entity_name.lower():
                    logger.debug(f"Filtering out system service account: {entity_name} in {namespace}")
                    return True
            
            # Check if it's in kube-system namespace AND matches a known system pattern
            # This prevents filtering out custom SAs in kube-system
            if namespace == 'kube-system':
                # Only filter if it matches a known system pattern
                for pattern in self.SYSTEM_SA_PATTERNS:
                    if pattern.lower() in entity_name.lower():
                        logger.debug(f"Filtering out system service account: {entity_name} in {namespace}")
                        return True
        
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
        
        Tries to use audit logs first, falls back to Events and resource changes
        if audit logs are not available.
        
        Args:
            user_data: User or service account data
        
        Returns:
            List of recent activities
        """
        activities = []
        user_name = user_data.get('name', '')
        user_type = user_data.get('type', 'user')
        
        # Try audit logs first
        audit_activities = self._get_activities_from_audit_logs(user_data)
        if audit_activities:
            logger.debug(f"Found {len(audit_activities)} activities from audit logs for {user_name}")
            return audit_activities
        
        # Fallback to Events and resource changes
        logger.debug(f"Audit logs not available, using fallback methods for {user_name}")
        activities.extend(self._get_activities_from_events(user_data))
        activities.extend(self._get_activities_from_resources(user_data))
        
        if not activities:
            activities.append({
                'type': 'info',
                'message': 'No recent activity detected. Audit logs may not be enabled or user may be inactive.',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return activities
    
    def _get_activities_from_audit_logs(self, user_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get activities from Kubernetes audit logs.
        
        Note: This requires audit logging to be enabled and accessible.
        Audit logs are typically stored in files or sent to webhooks,
        not directly queryable via the Kubernetes API.
        
        Args:
            user_data: User or service account data
        
        Returns:
            List of activities from audit logs, or empty list if not available
        """
        activities = []
        user_name = user_data.get('name', '')
        user_type = user_data.get('type', 'user')
        
        # Check if we have access to audit logs
        # In most Kubernetes setups, audit logs are written to files or webhooks
        # We'll check common audit log locations or try to query via API
        
        # Try to access audit logs via API (if available in some setups)
        # Most clusters don't expose audit logs via API, so this will likely fail
        try:
            # Some managed Kubernetes services expose audit logs via API
            # For now, we'll check if we can access them
            # This is a placeholder - actual implementation depends on cluster setup
            
            # Common audit log file locations (if running on master node)
            audit_log_paths = [
                '/var/log/kubernetes/audit.log',
                '/var/log/audit.log',
                '/etc/kubernetes/audit/audit.log',
            ]
            
            # Check if any audit log files exist (would require hostPath mount)
            # For now, we'll return empty to trigger fallback
            # In production, you might mount audit log directory or use a webhook
            
        except Exception as e:
            logger.debug(f"Audit log access failed: {e}")
        
        return activities
    
    def _get_activities_from_events(self, user_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get activities from Kubernetes Events API.
        
        Args:
            user_data: User or service account data
        
        Returns:
            List of activities from events
        """
        activities = []
        user_name = user_data.get('name', '')
        user_type = user_data.get('type', 'user')
        namespace = user_data.get('namespace', '')
        
        try:
            # Get events from the last 24 hours
            since_time = datetime.utcnow() - timedelta(hours=24)
            
            # Query events in the user's namespace or cluster-wide
            if namespace:
                events = self.v1.list_namespaced_event(
                    namespace=namespace,
                    limit=50
                )
            else:
                # For cluster-wide users, check all namespaces
                events = self.v1.list_event_for_all_namespaces(limit=100)
            
            # Filter events that might be related to this user/SA
            # Note: Events don't directly show the user, but we can infer from involved objects
            for event in events.items:
                # Check if event is recent
                event_time = event.first_timestamp or event.event_time
                if event_time and event_time.replace(tzinfo=None) < since_time:
                    continue
                
                # For service accounts, check if event involves resources in their namespace
                if user_type == 'service_account' and namespace:
                    if event.involved_object.namespace == namespace:
                        activities.append({
                            'type': 'event',
                            'action': event.action or 'unknown',
                            'resource': f"{event.involved_object.kind}/{event.involved_object.name}",
                            'namespace': event.involved_object.namespace,
                            'reason': event.reason or 'unknown',
                            'message': event.message[:200] if event.message else '',
                            'timestamp': event_time.isoformat() if event_time else datetime.utcnow().isoformat()
                        })
                
                # For regular users, show events in namespaces where they have bindings
                elif user_type == 'user':
                    event_namespace = getattr(event.involved_object, 'namespace', None) if hasattr(event, 'involved_object') else None
                    # If user has namespace binding, show events in that namespace
                    # If cluster-wide user, show all events
                    if not namespace or (event_namespace == namespace):
                        activities.append({
                            'type': 'event',
                            'action': event.action or 'unknown',
                            'resource': f"{event.involved_object.kind}/{event.involved_object.name}" if hasattr(event, 'involved_object') else 'unknown',
                            'namespace': event_namespace or 'cluster-wide',
                            'reason': event.reason or 'unknown',
                            'message': event.message[:200] if event.message else '',
                            'timestamp': event_time.isoformat() if event_time else datetime.utcnow().isoformat()
                        })
                
                # Limit to avoid too many activities
                if len(activities) >= 10:
                    break
                    
        except ApiException as e:
            logger.debug(f"Failed to query events for {user_name}: {e}")
        except Exception as e:
            logger.debug(f"Error querying events: {e}")
        
        return activities
    
    def _get_activities_from_resources(self, user_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get activities by checking recent resource changes.
        
        Args:
            user_data: User or service account data
        
        Returns:
            List of activities inferred from resource changes
        """
        activities = []
        user_name = user_data.get('name', '')
        user_type = user_data.get('type', 'user')
        namespace = user_data.get('namespace', '')
        
        try:
            since_time = datetime.utcnow() - timedelta(hours=24)
            
            # Check recent pods created by this service account
            if user_type == 'service_account' and namespace:
                try:
                    pods = self.v1.list_namespaced_pod(
                        namespace=namespace,
                        limit=20
                    )
                    
                    for pod in pods.items:
                        # Check if pod uses this service account
                        pod_sa_name = pod.spec.service_account_name if pod.spec.service_account_name else 'default'
                        # For service accounts, compare the name directly
                        if pod_sa_name != user_name:
                            continue
                        
                        # Check creation time
                        if pod.metadata.creation_timestamp:
                            created = pod.metadata.creation_timestamp.replace(tzinfo=None)
                            if created < since_time:
                                continue
                            
                            activities.append({
                                'type': 'resource_creation',
                                'action': 'created',
                                'resource': f"pod/{pod.metadata.name}",
                                'namespace': namespace,
                                'status': pod.status.phase if pod.status else 'unknown',
                                'timestamp': created.isoformat()
                            })
                            
                            if len(activities) >= 10:
                                break
                except ApiException as e:
                    logger.debug(f"Failed to query pods for {user_name}: {e}")
            
            # For regular users, check resources in namespaces where they have permissions
            # Check resource annotations for creator information
            elif user_type == 'user' and namespace:
                try:
                    # Check pods in the namespace
                    pods = self.v1.list_namespaced_pod(
                        namespace=namespace,
                        limit=20
                    )
                    
                    for pod in pods.items:
                        if pod.metadata.creation_timestamp:
                            created = pod.metadata.creation_timestamp.replace(tzinfo=None)
                            if created < since_time:
                                continue
                            
                            # Check if pod has creator annotation (some clusters add this)
                            creator = None
                            if pod.metadata.annotations:
                                creator = pod.metadata.annotations.get('kubernetes.io/created-by')
                                # Some clusters use different annotation formats
                                if not creator:
                                    creator = pod.metadata.annotations.get('kubectl.kubernetes.io/last-applied-configuration')
                            
                            # If we can't determine creator, show as potential activity
                            # (user has permissions in this namespace, so they could have created it)
                            activities.append({
                                'type': 'resource_creation',
                                'action': 'created',
                                'resource': f"pod/{pod.metadata.name}",
                                'namespace': namespace,
                                'status': pod.status.phase if pod.status else 'unknown',
                                'creator': creator[:50] if creator else 'unknown',
                                'timestamp': created.isoformat()
                            })
                            
                            if len(activities) >= 10:
                                break
                except ApiException as e:
                    logger.debug(f"Failed to query pods for {user_name}: {e}")
            
            # Check for recent deployments, services, etc. in the namespace
            # This works for both users and service accounts
            if namespace and self.apps_v1:
                try:
                    # Check deployments
                    deployments = self.apps_v1.list_namespaced_deployment(
                        namespace=namespace,
                        limit=10
                    )
                    
                    for deployment in deployments.items:
                        if deployment.metadata.creation_timestamp:
                            created = deployment.metadata.creation_timestamp.replace(tzinfo=None)
                            if created >= since_time:
                                # For service accounts, we can't directly link deployments
                                # For users, show as potential activity in their namespace
                                activities.append({
                                    'type': 'resource_creation',
                                    'action': 'created',
                                    'resource': f"deployment/{deployment.metadata.name}",
                                    'namespace': namespace,
                                    'replicas': deployment.spec.replicas if deployment.spec else 0,
                                    'timestamp': created.isoformat()
                                })
                                
                                if len(activities) >= 10:
                                    break
                except Exception as e:
                    logger.debug(f"Failed to query deployments: {e}")
                    
        except Exception as e:
            logger.debug(f"Error querying resources for {user_name}: {e}")
        
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
    
    def create_test_users_and_activities(self) -> Dict[str, Any]:
        """
        Create test users, service accounts, and perform activities for testing.
        This creates temporary RBAC resources that can be used to test the scanner.
        
        Returns:
            Dictionary with information about created test resources
        """
        logger.info("🧪 Creating test users and service accounts...")
        
        if not KUBERNETES_AVAILABLE or not self.rbac_v1:
            raise RuntimeError("Kubernetes client not available")
        
        test_namespace = "auth-test"
        created_resources = {
            'namespace': test_namespace,
            'users': [],
            'service_accounts': [],
            'roles': [],
            'role_bindings': [],
            'cluster_roles': [],
            'cluster_role_bindings': []
        }
        
        try:
            # Create test namespace
            try:
                ns_body = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=test_namespace)
                )
                self.v1.create_namespace(ns_body)
                logger.info(f"✅ Created test namespace: {test_namespace}")
            except ApiException as e:
                if e.status == 409:  # Already exists
                    logger.info(f"Test namespace {test_namespace} already exists")
                else:
                    raise
            
            # Create test service accounts
            test_sas = [
                {'name': 'test-admin-sa', 'namespace': test_namespace},
                {'name': 'test-reader-sa', 'namespace': test_namespace},
                {'name': 'test-writer-sa', 'namespace': test_namespace},
            ]
            
            for sa_info in test_sas:
                try:
                    sa_body = client.V1ServiceAccount(
                        metadata=client.V1ObjectMeta(
                            name=sa_info['name'],
                            namespace=sa_info['namespace']
                        )
                    )
                    self.v1.create_namespaced_service_account(
                        sa_info['namespace'], sa_body
                    )
                    created_resources['service_accounts'].append(sa_info)
                    logger.info(f"✅ Created test service account: {sa_info['name']}")
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        created_resources['service_accounts'].append(sa_info)
                        logger.info(f"ℹ️  Service account {sa_info['name']} already exists")
                    else:
                        logger.warning(f"Error creating SA {sa_info['name']}: {e}")
            
            # Create test ClusterRoles
            test_cluster_roles = [
                {
                    'name': 'test-admin-role',
                    'rules': [
                        client.V1PolicyRule(
                            api_groups=['*'],
                            resources=['*'],
                            verbs=['*']
                        )
                    ]
                },
                {
                    'name': 'test-reader-role',
                    'rules': [
                        client.V1PolicyRule(
                            api_groups=[''],
                            resources=['pods', 'services'],
                            verbs=['get', 'list']
                        )
                    ]
                },
            ]
            
            for cr_info in test_cluster_roles:
                try:
                    cr_body = client.V1ClusterRole(
                        metadata=client.V1ObjectMeta(name=cr_info['name']),
                        rules=cr_info['rules']
                    )
                    self.rbac_v1.create_cluster_role(cr_body)
                    created_resources['cluster_roles'].append(cr_info['name'])
                    logger.info(f"✅ Created test ClusterRole: {cr_info['name']}")
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        created_resources['cluster_roles'].append(cr_info['name'])
                        logger.info(f"ℹ️  ClusterRole {cr_info['name']} already exists")
                    else:
                        logger.warning(f"Error creating ClusterRole {cr_info['name']}: {e}")
            
            # Create test Roles
            test_roles = [
                {
                    'name': 'test-writer-role',
                    'namespace': test_namespace,
                    'rules': [
                        client.V1PolicyRule(
                            api_groups=[''],
                            resources=['pods', 'configmaps'],
                            verbs=['create', 'update', 'patch']
                        )
                    ]
                },
            ]
            
            for role_info in test_roles:
                try:
                    role_body = client.V1Role(
                        metadata=client.V1ObjectMeta(
                            name=role_info['name'],
                            namespace=role_info['namespace']
                        ),
                        rules=role_info['rules']
                    )
                    self.rbac_v1.create_namespaced_role(
                        role_info['namespace'], role_body
                    )
                    created_resources['roles'].append(role_info['name'])
                    logger.info(f"✅ Created test Role: {role_info['name']}")
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        created_resources['roles'].append(role_info['name'])
                        logger.info(f"ℹ️  Role {role_info['name']} already exists")
                    else:
                        logger.warning(f"Error creating Role {role_info['name']}: {e}")
            
            # Create test ClusterRoleBindings for users
            test_users = [
                {'name': 'test-admin-user', 'role': 'test-admin-role'},
                {'name': 'test-reader-user', 'role': 'test-reader-role'},
            ]
            
            for user_info in test_users:
                try:
                    crb_body = client.V1ClusterRoleBinding(
                        metadata=client.V1ObjectMeta(name=f"test-binding-{user_info['name']}"),
                        role_ref=client.V1RoleRef(
                            api_group='rbac.authorization.k8s.io',
                            kind='ClusterRole',
                            name=user_info['role']
                        ),
                        subjects=[
                            self._create_subject(
                                kind='User',
                                name=user_info['name'],
                                api_group='rbac.authorization.k8s.io'
                            )
                        ]
                    )
                    self.rbac_v1.create_cluster_role_binding(crb_body)
                    created_resources['cluster_role_bindings'].append(f"test-binding-{user_info['name']}")
                    created_resources['users'].append(user_info['name'])
                    logger.info(f"✅ Created test user binding: {user_info['name']}")
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        created_resources['cluster_role_bindings'].append(f"test-binding-{user_info['name']}")
                        created_resources['users'].append(user_info['name'])
                        logger.info(f"ℹ️  User binding for {user_info['name']} already exists")
                    else:
                        logger.warning(f"Error creating binding for {user_info['name']}: {e}")
            
            # Create test RoleBindings for service accounts
            test_sa_bindings = [
                {
                    'sa_name': 'test-admin-sa',
                    'namespace': test_namespace,
                    'role': 'test-admin-role',
                    'role_kind': 'ClusterRole'
                },
                {
                    'sa_name': 'test-reader-sa',
                    'namespace': test_namespace,
                    'role': 'test-reader-role',
                    'role_kind': 'ClusterRole'
                },
                {
                    'sa_name': 'test-writer-sa',
                    'namespace': test_namespace,
                    'role': 'test-writer-role',
                    'role_kind': 'Role'
                },
            ]
            
            for binding_info in test_sa_bindings:
                try:
                    rb_body = client.V1RoleBinding(
                        metadata=client.V1ObjectMeta(
                            name=f"test-binding-{binding_info['sa_name']}",
                            namespace=binding_info['namespace']
                        ),
                        role_ref=client.V1RoleRef(
                            api_group='rbac.authorization.k8s.io',
                            kind=binding_info['role_kind'],
                            name=binding_info['role']
                        ),
                        subjects=[
                            self._create_subject(
                                kind='ServiceAccount',
                                name=binding_info['sa_name'],
                                namespace=binding_info['namespace'],
                                api_group=''
                            )
                        ]
                    )
                    self.rbac_v1.create_namespaced_role_binding(
                        binding_info['namespace'], rb_body
                    )
                    created_resources['role_bindings'].append(f"test-binding-{binding_info['sa_name']}")
                    logger.info(f"✅ Created test SA binding: {binding_info['sa_name']}")
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        created_resources['role_bindings'].append(f"test-binding-{binding_info['sa_name']}")
                        logger.info(f"ℹ️  SA binding for {binding_info['sa_name']} already exists")
                    else:
                        logger.warning(f"Error creating binding for {binding_info['sa_name']}: {e}")
            
            logger.info("✅ Test users and service accounts created!")
            logger.info(f"📋 Created resources: {len(created_resources['users'])} users, {len(created_resources['service_accounts'])} service accounts")
            
        except Exception as e:
            logger.error(f"❌ Error creating test resources: {e}")
            raise
        
        return created_resources
    
    def cleanup_test_resources(self, created_resources: Dict[str, Any]) -> None:
        """
        Clean up test resources created by create_test_users_and_activities.
        
        Args:
            created_resources: Dictionary returned from create_test_users_and_activities
        """
        logger.info("🧹 Cleaning up test resources...")
        
        if not KUBERNETES_AVAILABLE:
            return
        
        try:
            # Delete ClusterRoleBindings
            for crb_name in created_resources.get('cluster_role_bindings', []):
                try:
                    self.rbac_v1.delete_cluster_role_binding(crb_name)
                    logger.debug(f"Deleted ClusterRoleBinding: {crb_name}")
                except ApiException as e:
                    if e.status != 404:
                        logger.warning(f"Error deleting ClusterRoleBinding {crb_name}: {e}")
            
            # Delete RoleBindings
            namespace = created_resources.get('namespace')
            for rb_name in created_resources.get('role_bindings', []):
                try:
                    self.rbac_v1.delete_namespaced_role_binding(rb_name, namespace)
                    logger.debug(f"Deleted RoleBinding: {rb_name}")
                except ApiException as e:
                    if e.status != 404:
                        logger.warning(f"Error deleting RoleBinding {rb_name}: {e}")
            
            # Delete ClusterRoles
            for cr_name in created_resources.get('cluster_roles', []):
                try:
                    self.rbac_v1.delete_cluster_role(cr_name)
                    logger.debug(f"Deleted ClusterRole: {cr_name}")
                except ApiException as e:
                    if e.status != 404:
                        logger.warning(f"Error deleting ClusterRole {cr_name}: {e}")
            
            # Delete Roles
            for role_name in created_resources.get('roles', []):
                try:
                    self.rbac_v1.delete_namespaced_role(role_name, namespace)
                    logger.debug(f"Deleted Role: {role_name}")
                except ApiException as e:
                    if e.status != 404:
                        logger.warning(f"Error deleting Role {role_name}: {e}")
            
            # Delete ServiceAccounts
            for sa_info in created_resources.get('service_accounts', []):
                try:
                    self.v1.delete_namespaced_service_account(
                        sa_info['name'], sa_info['namespace']
                    )
                    logger.debug(f"Deleted ServiceAccount: {sa_info['name']}")
                except ApiException as e:
                    if e.status != 404:
                        logger.warning(f"Error deleting ServiceAccount {sa_info['name']}: {e}")
            
            # Delete namespace (this will clean up everything)
            try:
                self.v1.delete_namespace(created_resources.get('namespace'))
                logger.info(f"✅ Deleted test namespace: {created_resources.get('namespace')}")
            except ApiException as e:
                if e.status != 404:
                    logger.warning(f"Error deleting namespace: {e}")
            
            logger.info("✅ Test resources cleaned up!")
            
        except Exception as e:
            logger.error(f"❌ Error cleaning up test resources: {e}")

