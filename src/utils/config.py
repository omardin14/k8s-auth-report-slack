"""
Configuration Module

Handles application configuration from YAML files and environment variables.
"""

import os
import yaml
from typing import Optional, Dict, Any
from pathlib import Path


class Config:
    """Application configuration manager."""
    
    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialize configuration from YAML file with fallback to environment variables.
        
        Args:
            config_file: Path to config YAML file (default: config.yaml)
        """
        self.config_file = config_file
        self.config_data = {}
        
        # Try to find config.yaml in current directory or parent directory
        config_paths = [
            config_file,  # Current directory
            os.path.join(os.path.dirname(os.path.dirname(__file__)), config_file),  # Parent directory (project root)
            os.path.join("..", config_file),  # Parent directory (relative)
        ]
        
        config_found = None
        for path in config_paths:
            if os.path.exists(path):
                config_found = path
                break
        
        # Try to load from YAML file
        if config_found:
            try:
                with open(config_found, 'r') as f:
                    self.config_data = yaml.safe_load(f) or {}
                print(f"✅ Loaded configuration from {config_found}")
                self.config_file = config_found
            except Exception as e:
                print(f"⚠️ Could not load config file: {e}, using environment variables")
        else:
            print(f"⚠️ config.yaml not found in {', '.join(config_paths)}, using environment variables")
        
        # Load values (YAML first, then env vars as fallback)
        self.slack_bot_token = self._get_value(['slack', 'bot_token'], 'SLACK_BOT_TOKEN')
        self.slack_channel = self._get_value(['slack', 'channel'], 'SLACK_CHANNEL', '#kube-auth')
        self.slack_default_channel = self._get_value(['slack', 'default_channel'], 'DEFAULT_CHANNEL', '#general')
        self.output_dir = self._get_value(['kubernetes', 'output_dir'], 'AUTH_SCAN_OUTPUT_DIR', '/tmp/auth-scan-results')
        self.max_wait_time = int(self._get_value(['kubernetes', 'max_wait_time'], 'MAX_WAIT_TIME', '300'))
        self.namespace = self._get_value(['kubernetes', 'namespace'], 'NAMESPACE', 'kube-auth')
        self.max_users = int(self._get_value(['kubernetes', 'max_users'], 'MAX_USERS', '10'))
        
        # Docker config
        self.docker_username = self._get_value(['docker', 'username'], 'DOCKER_USERNAME', None)
        self.docker_image_name = self._get_value(['docker', 'image_name'], 'IMAGE_NAME', 'kube-auth-manager')
        self.docker_image_tag = self._get_value(['docker', 'image_tag'], 'IMAGE_TAG', 'latest')
        
        # OpenAI config
        self.openai_api_key = self._get_value(['openai', 'api_key'], 'OPENAI_API_KEY', None)
        self.openai_enabled = self._get_value(['openai', 'enabled'], 'OPENAI_ENABLED', 'true').lower() == 'true'
        self.openai_model = self._get_value(['openai', 'model'], 'OPENAI_MODEL', 'gpt-4')
        
        # App config
        self.debug = self._get_value(['app', 'debug'], 'DEBUG', 'false').lower() == 'true'
        self.test_mode = self._get_value(['app', 'test_mode'], 'TEST_MODE', 'false').lower() == 'true'
        self.log_level = self._get_value(['app', 'log_level'], 'LOG_LEVEL', 'INFO')
    
    def _get_value(self, yaml_path: list, env_var: str, default: str = None) -> str:
        """Get value from YAML config or environment variable with fallback."""
        # Try YAML first
        value = self.config_data
        for key in yaml_path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                value = None
                break
        
        if value is not None:
            return str(value)
        
        # Try environment variable
        env_value = os.getenv(env_var)
        if env_value:
            return env_value
        
        # Return default
        return default
    
    def validate(self) -> bool:
        """
        Validate required configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        if not self.slack_bot_token:
            return False
        return True
    
    def get_slack_token(self) -> Optional[str]:
        """Get Slack bot token."""
        return self.slack_bot_token
    
    def get_slack_channel(self) -> str:
        """Get Slack channel."""
        return self.slack_channel
    
    def get_output_dir(self) -> str:
        """Get output directory."""
        return self.output_dir
    
    def get_max_wait_time(self) -> int:
        """Get maximum wait time for scan output."""
        return self.max_wait_time
    
    def get_max_users(self) -> int:
        """Get maximum number of users to scan."""
        return self.max_users
    
    def is_debug(self) -> bool:
        """Check if debug mode is enabled."""
        return self.debug
    
    def is_test_mode(self) -> bool:
        """Check if test mode is enabled."""
        return self.test_mode
    
    def get_openai_api_key(self) -> Optional[str]:
        """Get OpenAI API key."""
        return self.openai_api_key
    
    def get_openai_model(self) -> str:
        """Get OpenAI model."""
        return self.openai_model
    
    def is_openai_enabled(self) -> bool:
        """Check if OpenAI is enabled."""
        return self.openai_enabled and self.openai_api_key is not None
    
    def get_docker_config(self) -> Dict[str, str]:
        """Get Docker configuration."""
        return {
            'username': self.docker_username,
            'image_name': self.docker_image_name,
            'image_tag': self.docker_image_tag
        }

