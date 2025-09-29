#!/usr/bin/env python3
"""
AION Setup Script
Helps users configure their environment for the AION Security Platform.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_docker():
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ Docker is not installed or not in PATH")
    print("   Please install Docker Desktop from: https://www.docker.com/products/docker-desktop")
    return False

def check_docker_compose():
    """Check if Docker Compose is available."""
    try:
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker Compose: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ Docker Compose is not installed or not in PATH")
    return False

def setup_environment():
    """Set up the .env file from template."""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("✅ .env file already exists")
        return True
    
    if not env_example.exists():
        print("❌ .env.example file not found")
        return False
    
    # Copy .env.example to .env
    try:
        with open(env_example, 'r') as src, open(env_file, 'w') as dst:
            dst.write(src.read())
        print("✅ Created .env file from template")
        print("⚠️  Please edit .env file and add your Groq API key")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False

def install_dependencies():
    """Install Python dependencies."""
    try:
        print("📦 Installing Python dependencies...")
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Dependencies installed successfully")
            return True
        else:
            print(f"❌ Failed to install dependencies: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def start_elasticsearch():
    """Start Elasticsearch and Kibana using Docker Compose."""
    try:
        print("🐳 Starting Elasticsearch and Kibana...")
        result = subprocess.run(['docker-compose', 'up', '-d'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Elasticsearch and Kibana started successfully")
            print("   Elasticsearch: http://localhost:9200")
            print("   Kibana: http://localhost:5601")
            return True
        else:
            print(f"❌ Failed to start services: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error starting services: {e}")
        return False

def verify_elasticsearch():
    """Verify Elasticsearch is running and accessible."""
    try:
        import requests
        response = requests.get("http://localhost:9200", timeout=10)
        if response.status_code == 200:
            print("✅ Elasticsearch is running and accessible")
            return True
    except Exception as e:
        print(f"❌ Elasticsearch verification failed: {e}")
        return False

def main():
    """Main setup function."""
    print("🚀 AION Security Platform Setup")
    print("=" * 40)
    
    # Check prerequisites
    print("\n📋 Checking prerequisites...")
    checks_passed = 0
    total_checks = 5
    
    if check_python_version():
        checks_passed += 1
    
    if check_docker():
        checks_passed += 1
    
    if check_docker_compose():
        checks_passed += 1
    
    if setup_environment():
        checks_passed += 1
    
    if install_dependencies():
        checks_passed += 1
    
    print(f"\n📊 Prerequisites: {checks_passed}/{total_checks} passed")
    
    if checks_passed < total_checks:
        print("\n❌ Some prerequisites failed. Please fix the issues above and run setup again.")
        return False
    
    # Start services
    print("\n🐳 Starting services...")
    if not start_elasticsearch():
        print("❌ Failed to start Elasticsearch. Please check Docker is running.")
        return False
    
    # Wait a moment for services to start
    print("⏳ Waiting for services to start...")
    import time
    time.sleep(10)
    
    # Verify services
    print("\n🔍 Verifying services...")
    if not verify_elasticsearch():
        print("❌ Elasticsearch verification failed. Services may still be starting.")
        print("   Wait a few minutes and try: curl http://localhost:9200")
        return False
    
    # Final instructions
    print("\n🎉 Setup completed successfully!")
    print("\n📝 Next steps:")
    print("1. Edit .env file and add your Groq API key:")
    print("   - Get your key from: https://console.groq.com/keys")
    print("   - Add it to the GROQ_API_KEY variable in .env")
    print("\n2. Run the demo:")
    print("   python run_demo.py")
    print("\n3. Or start the real-time service:")
    print("   python orchestrator.py --service")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
