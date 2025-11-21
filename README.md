# CyberGuard AI - Advanced Cybersecurity System

A comprehensive Django-based cybersecurity system with real-time attack detection, firewall protection, and automated email alerts.

## Features

- 🛡️ **Real-time Attack Detection** - AI-powered threat detection using machine learning
- 🔥 **Intelligent Firewall** - Automatic IP blocking and traffic filtering
- 📧 **Email Alerts** - Instant notifications for security threats
- 📊 **Security Dashboard** - Real-time monitoring and analytics
- 🎯 **Attack Mitigation** - Detailed guidance for threat response
- ⚡ **Emergency Controls** - Admin override and unblock capabilities
- 🌍 **EAT Timezone** - Localized for East Africa Time

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cybersecurity
   ```

2. **Install dependencies**
   ```bash
   # For minimal installation
   pip install -r requirements-minimal.txt
   
   # For full installation with optional features
   pip install -r requirements.txt
   ```

3. **Database setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

4. **Create admin user**
   ```bash
   python manage.py createsuperuser
   ```

5. **Configure email settings**
   - Update `EMAIL_HOST_USER` and `EMAIL_HOST_PASSWORD` in `settings.py`
   - Use Gmail App Password for authentication

6. **Run the server**
   ```bash
   python manage.py runserver
   ```

## Usage

### Access Points
- **Main Dashboard**: `http://localhost:8000/dashboard/`
- **Admin Panel**: `http://localhost:8000/admin/`
- **Blocked Attacks**: `http://localhost:8000/security/blocked-attacks/`
- **Security Alerts**: `http://localhost:8000/security/alerts/`
- **Firewall Management**: `http://localhost:8000/firewall/`

### Testing the System
- **Admin Test**: Visit `/test-attack/` to simulate attacks safely
- **Real Attack Simulation**: Try accessing `/wp-admin/` or use scanner user agents
- **Emergency Unblock**: Use `/emergency-unblock/` if needed

### Email Configuration
The system sends email alerts to `obernard377@gmail.com` by default. To change:
1. Update `EMAIL_HOST_USER` in settings.py
2. Update admin email in firewall.py and monitoring.py
3. Configure Gmail App Password

## System Components

### Core Modules
- **Firewall System** (`firewall.py`) - IP blocking and attack prevention
- **Monitoring System** (`monitoring.py`) - Real-time threat detection
- **Attack Detection** (`views.py`) - ML-based traffic analysis
- **Admin Dashboard** (`admin_views.py`) - Management interface

### Machine Learning Models
- **Stacked Ensemble Model** - Primary attack detection
- **Top 13 Features** - Optimized feature selection
- **Multiple Attack Types** - DDoS, XSS, SQL Injection, Brute Force, etc.

### Database Models
- **AttackLog** - All detected attacks
- **BlockedAttack** - Firewall-blocked threats
- **SecurityAlert** - Email notifications
- **FirewallRule** - IP blocking rules
- **FirewallConfig** - System configuration

## Security Features

### Attack Detection
- Real-time traffic analysis
- ML-based threat classification
- Confidence scoring
- Severity assessment

### Firewall Protection
- Automatic IP blocking
- Whitelist management
- Configurable block duration
- Emergency unblock controls

### Email Alerts
- Instant threat notifications
- Detailed attack information
- Machine specifications
- Traffic analysis data

## Configuration

### Firewall Settings
- **Block Duration**: Default 3600 seconds (1 hour)
- **Severity Threshold**: Medium and above
- **Confidence Threshold**: 70%
- **Whitelist IPs**: Admin IP addresses

### Email Settings
- **SMTP Server**: Gmail (smtp.gmail.com)
- **Port**: 587 (TLS)
- **Authentication**: App Password required
- **Recipient**: Admin email address

## Troubleshooting

### Common Issues
1. **Email not sending**: Check Gmail App Password configuration
2. **IP blocked**: Use emergency unblock at `/emergency-unblock/`
3. **Database errors**: Run migrations with `python manage.py migrate`
4. **Model loading errors**: Ensure ML model files are present

### Emergency Access
If locked out of the system:
1. Visit `/emergency-unblock/` (admin only)
2. Use Django shell to disable firewall
3. Check whitelist configuration

## Development

### Project Structure
```
cybersecurity/
├── cyberattack/           # Main application
│   ├── models.py         # Database models
│   ├── views.py          # Web views
│   ├── firewall.py       # Firewall system
│   ├── monitoring.py     # Threat monitoring
│   └── templates/        # HTML templates
├── cybersecurity/        # Django project
│   └── settings.py       # Configuration
└── requirements.txt      # Dependencies
```

### Adding New Features
1. Update models in `models.py`
2. Create migrations: `python manage.py makemigrations`
3. Apply migrations: `python manage.py migrate`
4. Update views and templates as needed

## License

This project is developed for educational and security research purposes.

## Support

For issues and questions, contact the development team or check the system logs at `security.log`.