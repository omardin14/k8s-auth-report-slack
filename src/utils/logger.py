"""
Logging Module

Handles application logging configuration.
"""

import logging
import sys
from typing import Optional


def setup_logging(level: str = "INFO", debug: bool = False) -> None:
    """
    Set up application logging.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        debug: Enable debug mode
    """
    # Configure logging level
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Configure specific loggers
    if debug:
        logging.getLogger('slack_sdk').setLevel(logging.DEBUG)
    else:
        logging.getLogger('slack_sdk').setLevel(logging.WARNING)
    
    # Suppress some noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    # Suppress httpx INFO logs for OpenAI requests (we log our own)
    logging.getLogger('httpx').setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

