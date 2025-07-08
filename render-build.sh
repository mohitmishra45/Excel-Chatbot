#!/usr/bin/env bash
# exit on error
set -o errexit

# Set the Python version
render-python-version 3.11

# Upgrade build tools
pip install --upgrade pip setuptools wheel

# Install system dependencies
apt-get update && apt-get install -y tesseract-ocr libgl1-mesa-glx libglib2.0-0

# Install Python dependencies
pip install -r requirements.txt
