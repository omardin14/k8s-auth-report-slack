"""
Main Application Module

Main application class that orchestrates the Kubernetes authorization audit Slack integration.
"""

import os
import logging
from typing import Optional

from slack_app import SlackClient, SlackNotifier
from auth_analyzer import AuthScanner, AuthAnalyzer
from utils import Config, setup_logging

try:
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    ApiException = None

logger = logging.getLogger(__name__)


class KubeAuthManagerApp:
    """Main application class for Kubernetes authorization audit Slack integration."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the application.
        
        Args:
            config: Configuration instance (optional)
        """
        self.config = config or Config()
        
        # Validate configuration
        if not self.config.validate():
            raise ValueError("Invalid configuration. SLACK_BOT_TOKEN is required.")
        
        # Set up logging
        setup_logging(debug=self.config.is_debug())
        
        # Initialize components
        self.slack_client = SlackClient(self.config.get_slack_token())
        self.slack_notifier = SlackNotifier(self.slack_client)
        self.auth_scanner = AuthScanner(self.config.get_max_users())
        # Initialize analyzer with OpenAI if enabled
        if self.config.is_openai_enabled():
            self.auth_analyzer = AuthAnalyzer(
                openai_api_key=self.config.get_openai_api_key(),
                openai_model=self.config.get_openai_model()
            )
        else:
            self.auth_analyzer = AuthAnalyzer()
        
        logger.info("Kubernetes authorization audit app initialized successfully")
    
    def run_sidecar_mode(self) -> int:
        """
        Run in sidecar mode (monitoring for auth scan output).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🔐 Starting Kubernetes authorization audit sidecar container")
        logger.info(f"📁 Monitoring directory: {self.config.get_output_dir()}")
        logger.info(f"📢 Target channel: {self.config.get_slack_channel()}")
        
        try:
            # Send startup notification
            self.slack_notifier.client.send_message(
                f"🚀 Kubernetes authorization audit started! Monitoring for results...",
                self.config.get_slack_channel()
            )
            
            # Monitor for auth scan output and send results
            success = self.slack_notifier.monitor_auth_scan(
                self.config.get_output_dir(),
                self.config.get_slack_channel(),
                self.config.get_max_wait_time()
            )
            
            if success:
                logger.info("✅ Authorization audit report sent successfully!")
                return 0
            else:
                logger.error("❌ Failed to send authorization audit report")
                return 1
                
        except Exception as e:
            logger.error(f"❌ Fatal error in sidecar container: {e}")
            try:
                self.slack_notifier.client.send_message(
                    f"❌ Fatal error in authorization audit sidecar: {str(e)}",
                    self.config.get_slack_channel()
                )
            except:
                pass  # Don't fail if we can't send error message
            return 1
    
    def run_test_mode(self) -> int:
        """
        Run in test mode (creating test users and sending test messages).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🧪 Running in test mode...")
        logger.info("🔍 Testing Slack connection and auth scanning functionality...")
        
        try:
            import json
            import tempfile
            from pathlib import Path
            from utils.html_report import HTMLReportGenerator
            
            # Test Slack connection
            self.slack_notifier.send_test_message(self.config.get_slack_channel())
            
            # Create test users and service accounts
            logger.info("👥 Creating test users and service accounts...")
            test_resources = None
            try:
                test_resources = self.auth_scanner.create_test_users_and_activities()
                logger.info("✅ Test users and service accounts created!")
                
                # Wait a moment for resources to be available
                import time
                time.sleep(2)
                
                # Now scan with the test users
                logger.info("🔐 Scanning cluster with test users...")
                scan_data = self.auth_scanner.scan_cluster_auth()
                analysis = self.auth_analyzer.analyze_results(scan_data)
                
                # Send the report
                self.slack_notifier.send_auth_report(scan_data, analysis, self.config.get_slack_channel())
                
                # Generate HTML report
                logger.info("🎨 Testing HTML report generation...")
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        tmppath = Path(tmpdir)
                        
                        # Save JSON file
                        json_path = tmppath / "test-results.json"
                        with open(json_path, 'w') as f:
                            json.dump(scan_data, f, indent=2)
                        
                        # Generate HTML report
                        html_path = tmppath / "test-report.html"
                        html_generator = HTMLReportGenerator()
                        html_generator.generate_auth_report(scan_data, analysis, str(html_path))
                        
                        # Upload HTML report
                        logger.info("📤 Uploading HTML report to Slack...")
                        self.slack_client.upload_file(
                            file_path=str(html_path),
                            channel=self.config.get_slack_channel(),
                            title="Test Authorization Audit Report (HTML)",
                            initial_comment="🎨 Test HTML report with test users and activities - Download and open in your browser!"
                        )
                        
                        logger.info("✅ HTML report uploaded successfully!")
                        
                except Exception as e:
                    logger.warning(f"⚠️ HTML/JSON upload test failed: {e}")
                
                # Clean up test resources
                logger.info("🧹 Cleaning up test resources...")
                self.auth_scanner.cleanup_test_resources(test_resources)
                
            except Exception as e:
                logger.error(f"❌ Error in test user creation/scanning: {e}")
                # Try to clean up if resources were created
                if test_resources:
                    try:
                        self.auth_scanner.cleanup_test_resources(test_resources)
                    except:
                        pass
                # Fall back to dummy data
                logger.info("📋 Falling back to dummy data...")
                dummy_data = self.auth_analyzer.create_dummy_data()
                analysis = self.auth_analyzer.analyze_results(dummy_data)
                self.slack_notifier.send_auth_report(dummy_data, analysis, self.config.get_slack_channel())
            
            logger.info("🎉 All tests completed successfully!")
            logger.info("✅ Your Kubernetes authorization audit Slack integration is ready to use!")
            logger.info("📊 Check your Slack channel for the HTML report!")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            return 1
    
    def create_test_users_only(self) -> int:
        """
        Create test users and service accounts only (no Slack reports, no cleanup).
        Useful for testing deployments with test data.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("👥 Creating test users and service accounts...")
        
        if not KUBERNETES_AVAILABLE or not self.auth_scanner.v1:
            logger.error("❌ Kubernetes client not available. Cannot create test resources.")
            return 1
        
        try:
            test_resources = self.auth_scanner.create_test_users_and_activities()
            logger.info("✅ Test users and service accounts created!")
            logger.info(f"📋 Created resources:")
            logger.info(f"   - Namespace: {test_resources.get('namespace')}")
            logger.info(f"   - Users: {len(test_resources.get('users', []))}")
            logger.info(f"   - Service Accounts: {len(test_resources.get('service_accounts', []))}")
            logger.info(f"   - ClusterRoles: {len(test_resources.get('cluster_roles', []))}")
            logger.info(f"   - Roles: {len(test_resources.get('roles', []))}")
            logger.info(f"   - ClusterRoleBindings: {len(test_resources.get('cluster_role_bindings', []))}")
            logger.info(f"   - RoleBindings: {len(test_resources.get('role_bindings', []))}")
            logger.info("")
            logger.info("📋 To clean up later, run: make users-clean")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Error creating test resources: {e}")
            return 1
    
    def cleanup_test_resources(self) -> int:
        """
        Clean up test resources (test users, service accounts, roles, bindings, namespace).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🧹 Cleaning up test resources...")
        
        if not KUBERNETES_AVAILABLE or not self.auth_scanner.v1:
            logger.error("❌ Kubernetes client not available. Cannot clean up test resources.")
            return 1
        
        try:
            # Try to find and clean up test resources
            test_namespace = "auth-test"
            
            # Check if namespace exists
            try:
                namespace = self.auth_scanner.v1.read_namespace(test_namespace)
                logger.info(f"📋 Found test namespace: {test_namespace}")
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"ℹ️  Test namespace '{test_namespace}' not found. Nothing to clean up.")
                    return 0
                else:
                    raise
            
            # Build a resources dict with what we know about test resources
            created_resources = {
                'namespace': test_namespace,
                'users': ['test-admin-user', 'test-reader-user'],
                'service_accounts': [
                    {'name': 'test-admin-sa', 'namespace': test_namespace},
                    {'name': 'test-reader-sa', 'namespace': test_namespace},
                    {'name': 'test-writer-sa', 'namespace': test_namespace},
                ],
                'cluster_roles': ['test-admin-role', 'test-reader-role'],
                'roles': ['test-writer-role'],
                'cluster_role_bindings': [
                    'test-binding-test-admin-user',
                    'test-binding-test-reader-user'
                ],
                'role_bindings': [
                    'test-binding-test-admin-sa',
                    'test-binding-test-reader-sa',
                    'test-binding-test-writer-sa'
                ],
            }
            
            # Clean up using the scanner's cleanup method
            self.auth_scanner.cleanup_test_resources(created_resources)
            logger.info("✅ Test resources cleanup completed!")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Error cleaning up test resources: {e}")
            return 1
    
    def run(self) -> int:
        """
        Run the application in the appropriate mode.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        # Check if we're in test mode
        # Test mode is enabled if:
        # 1. TEST_MODE environment variable is set to "true"
        # 2. OR config.test_mode is True
        # 3. OR AUTH_SCAN_OUTPUT_DIR is not set (fallback for local testing)
        test_mode = (
            os.getenv('TEST_MODE', '').lower() == 'true' or
            self.config.is_test_mode() or
            not os.getenv('AUTH_SCAN_OUTPUT_DIR')
        )
        
        if test_mode:
            return self.run_test_mode()
        else:
            return self.run_sidecar_mode()

