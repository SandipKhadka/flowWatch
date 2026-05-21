# main.py - Entry point for the application
#!/usr/bin/env python3
"""
SecureNet AI - Advanced Intrusion Detection System
Final Year Project 2026

This is the main entry point for the application.
Run this file to start the IDS system.
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def check_requirements():
    """Check if all requirements are installed"""
    print("🔍 Checking requirements...")
    
    required_packages = [
        'streamlit', 'pandas', 'numpy', 'scikit-learn', 
        'xgboost', 'plotly', 'joblib', 'scapy'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package} - NOT INSTALLED")
            missing.append(package)
    
    if missing:
        print(f"\n⚠️ Missing packages: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    return True

def check_model_files():
    """Check if model files exist"""
    print("\n🔍 Checking model files...")
    
    model_dir = "src/models"
    required_models = ['xgb_model.pkl', 'scaler.pkl', 'target_encoder.pkl']
    
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
        print(f"  ⚠️ Created {model_dir} directory")
        print("  ⚠️ Please place your trained model files in this directory")
        return False
    
    all_exist = True
    for model in required_models:
        path = os.path.join(model_dir, model)
        if os.path.exists(path):
            size = os.path.getsize(path) / (1024 * 1024)
            print(f"  ✅ {model} ({size:.2f} MB)")
        else:
            print(f"  ❌ {model} - MISSING")
            all_exist = False
    
    return all_exist

def check_directories():
    """Create necessary directories"""
    print("\n🔍 Creating directories...")
    
    directories = [
        'data', 'logs', 'reports', 'exports', 
        'config', 'src/visualization', 'src/intelligence',
        'src/response', 'src/integration', 'src/notifications',
        'src/export', 'src/reports', 'src/api', 'src/ml'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"  ✅ {directory}")
    
    return True

def check_database():
    """Initialize database"""
    print("\n🔍 Checking database...")
    
    try:
        from src.utils.database_manager import DatabaseManager
        db = DatabaseManager()
        print("  ✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"  ❌ Database error: {e}")
        return False

def start_streamlit(port=8501, host='localhost'):
    """Start Streamlit application"""
    print(f"\n🚀 Starting SecureNet AI IDS...")
    print(f"📍 URL: http://{host}:{port}")
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)
    
    # Run streamlit
    cmd = [
        sys.executable, '-m', 'streamlit', 'run', 'app.py',
        '--server.port', str(port),
        '--server.address', host,
        '--browser.gatherUsageStats', 'false'
    ]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n\n⛔ Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")

def start_api_only(port=5000):
    """Start only the API server"""
    print(f"\n🚀 Starting SecureNet AI API Server...")
    print(f"📍 API URL: http://localhost:{port}")
    
    try:
        from src.api.rest_api import IDSAPI
        from src.detection.demo_mode import DemoModeIDS
        
        ids = DemoModeIDS()
        api = IDSAPI(ids)
        api.start(port)
        
        print("✅ API Server running. Press Ctrl+C to stop.")
        
        # Keep running
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n⛔ API Server stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

def run_demo():
    """Run demo mode without web interface"""
    print("\n🎮 Running SecureNet AI in Demo Mode...")
    
    try:
        from src.detection.demo_mode import DemoModeIDS
        import time
        
        ids = DemoModeIDS()
        ids.start_sniffing("demo")
        
        print("✅ Demo mode active. Simulating network traffic...")
        print("Press Ctrl+C to stop\n")
        
        while True:
            time.sleep(5)
            stats = ids.get_stats()
            alerts = ids.get_alerts()
            
            print(f"\r📊 Packets: {stats['packets_processed']} | "
                  f"Threats: {stats['threats_detected']} | "
                  f"Rate: {stats['threats_detected']/max(stats['packets_processed'],1)*100:.1f}%", end="")
            
    except KeyboardInterrupt:
        print("\n\n⛔ Demo mode stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SecureNet AI - Advanced Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start web interface
  python main.py --port 8080        # Start on custom port
  python main.py --api-only         # Start only API server
  python main.py --demo             # Run in demo mode
  python main.py --check            # Check system requirements
        """
    )
    
    parser.add_argument('--port', type=int, default=8501,
                       help='Port for web interface (default: 8501)')
    parser.add_argument('--host', default='localhost',
                       help='Host address (default: localhost)')
    parser.add_argument('--api-only', action='store_true',
                       help='Start only the API server')
    parser.add_argument('--demo', action='store_true',
                       help='Run in demo mode (no web interface)')
    parser.add_argument('--check', action='store_true',
                       help='Check system requirements and exit')
    
    args = parser.parse_args()
    
    # Print banner
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███████╗███████╗██╗   ██╗██████╗ ███████╗███╗   ██╗███████╗████████╗
    ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝████╗  ██║██╔════╝╚══██╔══╝
    ║   ███████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║█████╗     ██║   
    ║   ╚════██║██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║██╔══╝     ██║   
    ║   ███████║███████╗╚██████╔╝██║  ██║███████╗██║ ╚████║██║        ██║   
    ║   ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝        ╚═╝   
    ║                                                               ║
    ║         Advanced Hybrid Intrusion Detection System            ║
    ║                   Final Year Project 2026                      ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Check mode
    if args.check:
        print("🔍 SYSTEM CHECK\n" + "="*50)
        check_requirements()
        check_model_files()
        check_directories()
        check_database()
        print("\n✅ System check completed!")
        return
    
    if args.demo:
        run_demo()
        return
    
    if args.api_only:
        start_api_only(port=args.port)
        return
    
    # Full web interface mode
    print("🔍 Running pre-flight checks...\n")
    
    req_ok = check_requirements()
    dirs_ok = check_directories()
    db_ok = check_database()
    
    if not req_ok:
        print("\n❌ Missing requirements. Please run: pip install -r requirements.txt")
        return
    
    # Check models (warning only, not fatal)
    models_exist = check_model_files()
    if not models_exist:
        print("\n⚠️ WARNING: Model files not found. The application will run in demo mode.")
        print("   Place your trained models in 'src/models/' directory for full functionality.\n")
    
    # Start application
    start_streamlit(port=args.port, host=args.host)

if __name__ == "__main__":
    main()
