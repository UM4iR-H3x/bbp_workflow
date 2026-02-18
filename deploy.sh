#!/bin/bash
# Ultimate Recon Framework - VPS Deployment Script
# Run this on your local machine to deploy to VPS

set -e

# Configuration
VPS_HOST="45.13.225.105"
VPS_USER_password="ukcq7H1hIQ7tSwFlc9TB"
PROJECT_DIR="/path/to/project/on/vps"
REMOTE_PYTHON="/usr/bin/python3"

echo "🚀 Deploying Ultimate Recon Framework to VPS..."

# 1. Create project directory on VPS
echo "📁 Creating project directory..."
ssh $VPS_USER@$VPS_HOST "mkdir -p $PROJECT_DIR"

# 2. Copy all files to VPS
echo "📤 Copying framework files..."
rsync -avz --exclude='.git' --exclude='__pycache__' --exclude='output' --exclude='tmp' \
    ./ $VPS_USER@$VPS_HOST:$PROJECT_DIR/

# 3. Setup on VPS
echo "🔧 Setting up environment on VPS..."
ssh $VPS_USER@$VPS_HOST << EOF
    cd $PROJECT_DIR

    # Install Python dependencies
    echo "📦 Installing Python dependencies..."
    $REMOTE_PYTHON -m pip install --user -r requirements.txt

    # Install Go tools (if not already installed)
    echo "🛠️ Installing Go security tools..."
    if ! command -v subfinder &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    fi
    if ! command -v httpx &> /dev/null; then
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
    if ! command -v gau &> /dev/null; then
        go install -v github.com/lc/gau/v2/cmd/gau@latest
    fi
    if ! command -v katana &> /dev/null; then
        go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    fi
    if ! command -v waybackurls &> /dev/null; then
        go install -v github.com/tomnomnom/waybackurls@latest
    fi

    # Create necessary directories
    mkdir -p output tmp

    # Make main script executable
    chmod +x main.py

    # Setup config (copy example and remind user to edit)
    if [ ! -f config/config.py ]; then
        cp config/config.example.py config/config.py
        echo "⚠️  IMPORTANT: Edit config/config.py with your Discord webhooks!"
    fi

    echo "✅ Deployment completed!"
    echo "🎯 To run: cd $PROJECT_DIR && python3 main.py example.com"
EOF

echo "🎉 Framework deployed successfully to $VPS_HOST:$PROJECT_DIR"
echo ""
echo "📋 Next steps:"
echo "1. SSH to your VPS: ssh $VPS_USER@$VPS_HOST"
echo "2. Edit config: nano $PROJECT_DIR/config/config.py (add Discord webhooks)"
echo "3. Test: cd $PROJECT_DIR && python3 main.py --test-webhooks"
echo "4. Run scan: python3 main.py your-target.com"
