from src.utils.logger import setup_logger
import sys
import os

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    logger = setup_logger()
    logger.info("🚀 AI-Powered Intrusion Detection System Started")
    logger.info("Project setup completed successfully!")
    
    print("✅ IDS Project is ready!")
    print("Next steps:")
    print("1. Download dataset")
    print("2. Run preprocessing")
    print("3. Train models")

if __name__ == "__main__":
    main()
