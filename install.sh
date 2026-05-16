#!/bin/bash
set -e
echo "🛡️ Pipeline Sentinel – Quick Install"
echo "------------------------------------"
# Install dependencies
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Please install Python 3.10+."
    exit 1
fi
pip install devsecops-radar
# Setup Ollama
if ! command -v ollama &> /dev/null; then
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo "Pulling AI model (llama3.2)..."
ollama pull llama3.2:latest
# Run wizard
devsecops-radar --wizard