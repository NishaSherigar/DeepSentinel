"""
Configuration file for paths
"""

import os

# Base paths - UPDATE THESE!
PROJECT_DIR = r'C:\Users\Dell\Desktop\insepticon'
MODEL_DIR = r'C:\Users\Dell\Desktop\maker\models'
DATA_DIR = r'C:\Users\Dell\Desktop\maker\data'

# Server config
SERVER_IP = '192.168.0.107'
SERVER_PORT = 5000
SERVER_URL = f'http://{SERVER_IP}:{SERVER_PORT}/receive_log'

# Agent config
AGENT_ID = 'DESKTOP-HU8FK9B'

# Model files
MODEL_FILES = {
    'isolation_forest': os.path.join(MODEL_DIR, 'isolation_forest_finetuned.pkl'),
    'autoencoder': os.path.join(MODEL_DIR, 'autoencoder_finetuned.pth'),
    'scaler': os.path.join(MODEL_DIR, 'scaler.pkl')
}

# Check if files exist
def check_files():
    print("🔍 Checking configuration...")
    
    # Check model directory
    if os.path.exists(MODEL_DIR):
        print(f"✅ Model directory found: {MODEL_DIR}")
    else:
        print(f"❌ Model directory not found: {MODEL_DIR}")
    
    # Check model files
    for name, path in MODEL_FILES.items():
        if os.path.exists(path):
            print(f"✅ {name}: Found")
        else:
            print(f"⚠️ {name}: Not found - {path}")
    
    print()

if __name__ == "__main__":
    check_files()