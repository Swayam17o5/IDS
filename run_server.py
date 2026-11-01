#!/usr/bin/env python
"""
Direct server entry point for FastAPI app.
"""
import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Set up logging to see startup errors
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    try:
        print("[run_server.py] Importing app...")
        from services.inference.app import app
        print("[run_server.py] App imported successfully")
        
        # Check if the route is registered
        print("[run_server.py] Checking routes...")
        for route in app.routes:
            if hasattr(route, 'path') and 'genuine' in route.path:
                print(f"[run_server.py] Found route: {route.path} {route.methods if hasattr(route, 'methods') else 'N/A'}")
        
        import uvicorn
        print("[run_server.py] Starting uvicorn...")
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="debug")
    except Exception as e:
        print(f"[run_server.py] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
