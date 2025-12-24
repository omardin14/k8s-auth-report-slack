"""
Main Entry Point

This is the main entry point for the Kubernetes authorization audit application.
"""

import sys
import os
from app import KubeAuthManagerApp
from utils import Config

def main():
    """Main entry point."""
    try:
        # Create configuration
        config = Config()
        
        # Create application
        app = KubeAuthManagerApp(config)
        
        # Check for special modes
        if os.getenv('CLEANUP_TEST_RESOURCES', '').lower() == 'true':
            exit_code = app.cleanup_test_resources()
        elif os.getenv('CREATE_TEST_USERS_ONLY', '').lower() == 'true':
            exit_code = app.create_test_users_only()
        else:
            exit_code = app.run()
        
        sys.exit(exit_code)
            
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


