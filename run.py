#!/usr/bin/env python3
"""
CTI Nexus - Root Launcher
Launches the CTI Nexus platform server with proper working directory context.
"""
import os
import sys

def main():
    # Resolve platform directory
    root_dir = os.path.dirname(os.path.abspath(__file__))
    platform_dir = os.path.join(root_dir, "platform")
    
    # Switch working directory to platform/ so static files, templates, and certificates resolve seamlessly
    os.chdir(platform_dir)
    if platform_dir not in sys.path:
        sys.path.insert(0, platform_dir)
        
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=5443,
        reload=True,
        ssl_keyfile="key.pem" if os.path.exists("key.pem") else None,
        ssl_certfile="cert.pem" if os.path.exists("cert.pem") else None,
        env_file=".env" if os.path.exists(".env") else None
    )

if __name__ == "__main__":
    main()
