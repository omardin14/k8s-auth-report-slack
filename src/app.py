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
        Run in test mode (sending test messages).
        
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
            
            # Test auth report functionality with dummy data
            logger.info("🔐 Testing auth report functionality...")
            dummy_data = self.auth_analyzer.create_dummy_data()
            analysis = self.auth_analyzer.analyze_results(dummy_data)
            self.slack_notifier.send_auth_report(dummy_data, analysis, self.config.get_slack_channel())
            
            # Test HTML report generation and upload
            logger.info("🎨 Testing HTML report generation...")
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmppath = Path(tmpdir)
                    
                    # Save JSON file
                    json_path = tmppath / "test-results.json"
                    with open(json_path, 'w') as f:
                        json.dump(dummy_data, f, indent=2)
                    
                    # Generate HTML report
                    html_path = tmppath / "test-report.html"
                    html_generator = HTMLReportGenerator()
                    html_generator.generate_auth_report(dummy_data, analysis, str(html_path))
                    
                    # Upload HTML report
                    logger.info("📤 Uploading HTML report to Slack...")
                    self.slack_client.upload_file(
                        file_path=str(html_path),
                        channel=self.config.get_slack_channel(),
                        title="Test Authorization Audit Report (HTML)",
                        initial_comment="🎨 Test HTML report with all auth details - Download and open in your browser!"
                    )
                    
                    logger.info("✅ HTML report uploaded successfully!")
                    
            except Exception as e:
                logger.warning(f"⚠️ HTML/JSON upload test failed: {e}")
                # Don't fail the whole test
            
            logger.info("🎉 All tests completed successfully!")
            logger.info("✅ Your Kubernetes authorization audit Slack integration is ready to use!")
            logger.info("📊 Check your Slack channel for the HTML report!")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            return 1
    
    def run(self) -> int:
        """
        Run the application in the appropriate mode.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        # Check if we're in test mode (no AUTH_SCAN_OUTPUT_DIR environment variable)
        if not os.getenv('AUTH_SCAN_OUTPUT_DIR'):
            return self.run_test_mode()
        else:
            return self.run_sidecar_mode()

