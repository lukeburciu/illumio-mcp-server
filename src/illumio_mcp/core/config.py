"""Configuration management for Illumio MCP server"""
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

# PCE Configuration
PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

# Server Configuration
READ_ONLY = os.getenv("READ_ONLY", "false").lower() in ["true", "1", "yes"]

# API Limits
MCP_BUG_MAX_RESULTS = 500

# Docker detection
IS_DOCKER = bool(os.environ.get('DOCKER_CONTAINER'))