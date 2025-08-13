"""Logging configuration for Illumio MCP server"""
import logging
from pathlib import Path
from .config import IS_DOCKER

def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Determine log path based on environment
    if IS_DOCKER:
        log_path = Path('/var/log/illumio-mcp/illumio-mcp.log')
    else:
        # Use home directory for local logging
        log_path = './illumio-mcp.log'
    
    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    # Prevent logs from propagating to root logger
    logger.propagate = False
    
    return logger

# Initialize logger
logger = setup_logging()
logger.debug("Logging initialized")