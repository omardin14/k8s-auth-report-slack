"""
Slack Notifier Module

Handles sending auth scan results to Slack with proper formatting.
"""

import os
import json
import time
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from .client import SlackClient
from .formatter import SlackFormatter
from utils.html_report import HTMLReportGenerator

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Handles sending auth scan results to Slack."""
    
    def __init__(self, client: SlackClient):
        """
        Initialize the Slack notifier.
        
        Args:
            client: SlackClient instance for API interactions
        """
        self.client = client
        self.formatter = SlackFormatter()
    
    def send_auth_report(self, scan_data: Dict[str, Any], analysis: Dict[str, Any] = None,
                        channel: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a formatted auth audit report to Slack.
        
        Args:
            scan_data: Auth scan results
            analysis: Auth analysis results (optional)
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
        
        Returns:
            Response from Slack API
        """
        # Extract summary information
        summary = self.formatter.parse_auth_summary(scan_data)
        
        # Create rich blocks for the report
        blocks = self.formatter.create_auth_blocks(summary, analysis)
        
        # Create fallback text
        fallback_text = f"🔐 Kubernetes Authorization Audit - {summary['total_users']} users, {summary['high_privilege_users']} high privilege"
        
        try:
            response = self.client.send_rich_message(
                channel=channel,
                text=fallback_text,
                blocks=blocks
            )
            logger.info(f"Auth report sent successfully to {channel or self.client.default_channel}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending auth report: {e}")
            raise
    
    def send_test_message(self, channel: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a test message to verify Slack connection.
        
        Args:
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
        
        Returns:
            Response from Slack API
        """
        try:
            # Send simple test message
            response = self.client.send_message(
                "🧪 Test message from Kubernetes auth reporter! 🔐",
                channel=channel
            )
            
            # Send rich test message
            blocks = self.formatter.create_test_blocks()
            self.client.send_rich_message(blocks, channel=channel)
            
            logger.info(f"Test messages sent successfully to {channel or self.client.default_channel}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending test message: {e}")
            raise
    
    def send_data_as_json(self, data: Dict[str, Any], channel: Optional[str] = None, 
                         title: str = "Data Export") -> Dict[str, Any]:
        """
        Send structured data as a formatted JSON message.
        
        Args:
            data: Dictionary of data to send
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            title: Title for the data
        
        Returns:
            Response from Slack API
        """
        blocks = self.formatter.format_json_data(data, title)
        
        try:
            response = self.client.send_rich_message(blocks, channel=channel)
            logger.info(f"JSON data sent successfully to {channel or self.client.default_channel}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending JSON data: {e}")
            raise
    
    def monitor_auth_scan(self, output_dir: str, channel: Optional[str] = None, 
                         max_wait_time: int = 300) -> bool:
        """
        Monitor auth scan output directory and send results when available.
        
        Args:
            output_dir: Directory to monitor for scan results
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            max_wait_time: Maximum time to wait for results (seconds)
        
        Returns:
            True if report was sent successfully, False otherwise
        """
        output_path = Path(output_dir)
        
        logger.info(f"Monitoring auth scan output directory: {output_dir}")
        
        # Wait for scan results
        start_time = time.time()
        last_file_found = None
        
        while time.time() - start_time < max_wait_time:
            # Look for JSON output files
            json_files = list(output_path.glob("*.json"))
            
            if json_files:
                # Process the most recent JSON file
                latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
                
                # Only log once when we first find the file
                if latest_file != last_file_found:
                    logger.info(f"Found auth scan output file: {latest_file}")
                    last_file_found = latest_file
                
                # Check if file is complete (size stable for 3 seconds)
                try:
                    initial_size = latest_file.stat().st_size
                    if initial_size == 0:
                        logger.debug("File is empty, waiting...")
                        time.sleep(2)
                        continue
                    
                    # Wait and check if size is stable
                    time.sleep(3)
                    final_size = latest_file.stat().st_size
                    
                    if initial_size == final_size:
                        logger.info("File appears complete, processing...")
                        
                        try:
                            with open(latest_file, 'r') as f:
                                scan_data = json.load(f)
                            
                            # Analyze results
                            from auth_analyzer import AuthAnalyzer
                            from utils import Config
                            
                            # Initialize analyzer with OpenAI if enabled
                            config = Config()
                            if config.is_openai_enabled():
                                analyzer = AuthAnalyzer(
                                    openai_api_key=config.get_openai_api_key(),
                                    openai_model=config.get_openai_model()
                                )
                                logger.info("🤖 AI-powered auth analysis enabled")
                            else:
                                analyzer = AuthAnalyzer()
                            
                            analysis = analyzer.analyze_results(scan_data)
                            
                            # Send the formatted report
                            self.send_auth_report(scan_data, analysis, channel)
                            
                            # Generate HTML report
                            logger.info("📊 Generating HTML report...")
                            try:
                                timestamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
                                html_path = output_path / f"auth-report-{timestamp}.html"
                                
                                html_generator = HTMLReportGenerator()
                                html_generator.generate_auth_report(scan_data, analysis, str(html_path))
                                
                                # Upload the HTML report
                                logger.info("📤 Uploading HTML report...")
                                self.client.upload_file(
                                    file_path=str(html_path),
                                    channel=channel,
                                    title=f"Authorization Audit Report - {timestamp}",
                                    initial_comment="🎨 Interactive HTML report with all auth details - Download and open in your browser!"
                                )
                                logger.info("✅ HTML report uploaded successfully!")
                            except Exception as e:
                                logger.warning(f"⚠️ Could not generate/upload HTML report: {e}")
                                # Don't fail the whole process if HTML generation fails
                            
                            logger.info("✅ Auth report sent successfully! Exiting...")
                            return True
                            
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid JSON in auth scan output: {e}")
                            logger.info("File may still be writing, waiting...")
                            time.sleep(2)
                            continue
                        except Exception as e:
                            logger.error(f"Error processing auth scan output: {e}")
                            # Send error notification
                            self.client.send_message(f"❌ Error processing auth scan results: {str(e)}", channel)
                            return False
                    else:
                        logger.debug(f"File still being written (size changed from {initial_size} to {final_size}), waiting...")
                        
                except Exception as e:
                    logger.error(f"Error checking file: {e}")
                    time.sleep(2)
                    continue
            
            time.sleep(2)  # Check every 2 seconds
        
        logger.warning(f"⚠️ No complete auth scan output found after {max_wait_time} seconds")
        self.client.send_message("⚠️ Auth scan timed out - no results found", channel)
        return False

