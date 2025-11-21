#!/usr/bin/env bash
# exit on error
set -o errexit

echo "Starting build process..."

# Upgrade pip to latest version
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install wheel for better package building
echo "Installing wheel..."
pip install wheel

# Install dependencies with no cache and force reinstall
echo "Installing dependencies..."
pip install --no-cache-dir --force-reinstall -r requirements-minimal.txt

# Set Django settings module for production
echo "Setting production environment..."
export DJANGO_SETTINGS_MODULE=cybersecurity.settings_production

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --no-input

# Run migrations
echo "Running database migrations..."
python manage.py migrate

echo "Build completed successfully!"