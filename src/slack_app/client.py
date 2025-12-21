"""
Slack Client Module

Handles the core Slack API interactions and authentication.
"""

import os
import logging
from typing import Optional, Dict, Any, List
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)


class SlackClient:
    """Core Slack client for API interactions."""
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize the Slack client.
        
        Args:
            token: Slack OAuth token. If not provided, will try to get from environment.
        """
        self.token = token or os.getenv('SLACK_BOT_TOKEN')
        if not self.token:
            raise ValueError("Slack OAuth token is required. Set SLACK_BOT_TOKEN environment variable or pass token directly.")
        
        self.client = WebClient(token=self.token)
        self.default_channel = os.getenv('DEFAULT_CHANNEL', '#general')
        self._channel_id_cache = {}  # Cache channel IDs to avoid repeated lookups
    
    def send_message(self, text: str, channel: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Send a simple text message to Slack.
        
        Args:
            text: Message text to send
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            **kwargs: Additional parameters for the Slack API
        
        Returns:
            Response from Slack API
        """
        channel = channel or self.default_channel
        
        try:
            response = self.client.chat_postMessage(
                channel=channel,
                text=text,
                **kwargs
            )
            # Cache the channel ID from the response
            if 'channel' in response.data:
                self._channel_id_cache[channel] = response.data['channel']
            
            logger.info(f"Message sent successfully to {channel}")
            return response.data
            
        except SlackApiError as e:
            logger.error(f"Error sending message: {e.response['error']}")
            raise
    
    def send_rich_message(self, blocks: List[Dict], channel: Optional[str] = None, text: str = None, **kwargs) -> Dict[str, Any]:
        """
        Send a rich message with blocks to Slack.
        
        Args:
            blocks: List of block elements for rich formatting
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            text: Fallback text for notifications
            **kwargs: Additional parameters for the Slack API
        
        Returns:
            Response from Slack API
        """
        channel = channel or self.default_channel
        
        try:
            response = self.client.chat_postMessage(
                channel=channel,
                blocks=blocks,
                text=text,
                **kwargs
            )
            # Cache the channel ID from the response
            if 'channel' in response.data:
                self._channel_id_cache[channel] = response.data['channel']
            
            logger.info(f"Rich message sent successfully to {channel}")
            return response.data
            
        except SlackApiError as e:
            logger.error(f"Error sending rich message: {e.response['error']}")
            raise
    
    def _get_channel_id(self, channel: str) -> str:
        """
        Get channel ID from channel name.
        
        Args:
            channel: Channel name (e.g., #kube-auth) or ID
        
        Returns:
            Channel ID
        """
        # Check cache first
        if channel in self._channel_id_cache:
            return self._channel_id_cache[channel]
        
        # If it's already an ID (doesn't start with #), return as-is
        if not channel.startswith('#'):
            return channel
        
        # Remove # prefix
        channel_name = channel.lstrip('#')
        
        try:
            # List all channels and find the matching one
            response = self.client.conversations_list(types="public_channel,private_channel")
            for ch in response.get('channels', []):
                if ch.get('name') == channel_name:
                    channel_id = ch.get('id')
                    # Cache it for future use
                    self._channel_id_cache[channel] = channel_id
                    return channel_id
            
            # If not found, return the original (might be a DM or already an ID)
            logger.warning(f"Could not find channel ID for {channel}, using as-is")
            return channel
            
        except SlackApiError as e:
            logger.warning(f"Error resolving channel ID: {e.response['error']}, using channel name as-is")
            return channel
    
    def send_file(self, file_path: str, channel: Optional[str] = None, 
                  title: Optional[str] = None, comment: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a file to Slack using the new files_upload_v2 API.
        
        Args:
            file_path: Path to the file to upload
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            title: Title for the file
            comment: Comment to include with the file
        
        Returns:
            Response from Slack API
        """
        channel = channel or self.default_channel
        
        try:
            # Resolve channel name to ID for files_upload_v2
            channel_id = self._get_channel_id(channel)
            
            response = self.client.files_upload_v2(
                channel=channel_id,
                file=file_path,
                title=title,
                initial_comment=comment
            )
            logger.info(f"File sent successfully to {channel}")
            return response.data
            
        except SlackApiError as e:
            logger.error(f"Error sending file: {e.response['error']}")
            raise
    
    def upload_file(self, file_path: str, channel: Optional[str] = None,
                   title: Optional[str] = None, initial_comment: Optional[str] = None) -> Dict[str, Any]:
        """
        Upload a file to Slack (alias for send_file for consistency).
        
        Args:
            file_path: Path to the file to upload
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
            title: Title for the file
            initial_comment: Comment to include with the file
        
        Returns:
            Response from Slack API
        """
        return self.send_file(file_path, channel, title, initial_comment)
    
    def get_channel_info(self, channel: str) -> Dict[str, Any]:
        """
        Get information about a channel.
        
        Args:
            channel: Channel name or ID
        
        Returns:
            Channel information
        """
        try:
            response = self.client.conversations_info(channel=channel)
            return response.data
            
        except SlackApiError as e:
            logger.error(f"Error getting channel info: {e.response['error']}")
            raise
    
    def list_channels(self) -> List[Dict[str, Any]]:
        """
        List all channels the bot has access to.
        
        Returns:
            List of channel information
        """
        try:
            response = self.client.conversations_list()
            return response.data.get('channels', [])
            
        except SlackApiError as e:
            logger.error(f"Error listing channels: {e.response['error']}")
            raise

