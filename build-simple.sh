#!/usr/bin/env bash
# exit on error
set -o errexit

echo "Starting simple build process..."

# Upgrade pip
python -m pip install --upgrade pip

# Install minimal dependencies
pip install -r requirements-render.txt

# Set Django settings module for production
export DJANGO_SETTINGS_MODULE=cybersecurity.settings_production

# Collect static files
python manage.py collectstatic --no-input

# Run migrations
python manage.py migrate

echo "Build completed successfully!"