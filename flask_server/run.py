#!/usr/bin/env python3
"""
AES Crypto Tool - Flask Backend Server
Run this file to start the server locally
"""

import os
import sys
from app import app, logger

def main():
    """Main function to run the Flask server"""
    try:
        # Configuration
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "127.0.0.1")
        debug = os.environ.get("DEBUG", "True").lower() == "true"
        
        print("=" * 60)
        print("🔐 AES Crypto Tool - Backend Server")
        print("=" * 60)
        print(f"🌐 Server running at: http://{host}:{port}")
        print(f"🔧 Debug mode: {debug}")
        print("📍 Available endpoints:")
        print("   • GET  /health           - Health check")
        print("   • POST /encrypt          - Encrypt data")
        print("   • POST /decrypt          - Decrypt data")
        print("   • POST /generate-key     - Generate random key")
        print("   • POST /generate-iv      - Generate random IV")
        print("=" * 60)
        print("✅ Frontend connection: http://localhost:8080")
        print("🛑 Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Start the server
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()