# Cybersecurity Monitoring System - Features Guide

## 🚀 Quick Start

1. **Start the server:**
   ```bash
   python manage.py runserver 8000
   ```

2. **Create an admin user (if you haven't already):**
   ```bash
   python manage.py createsuperuser
   ```

## 📊 Main Features

### 1. Enhanced Prediction Interface
**URL:** `http://localhost:8000/`

**New Features:**
- **Automatic Simulation Buttons:**
  - "Simulate Benign Traffic" - Generates normal network traffic
  - "Simulate DDoS Attack" - Generates DDoS attack patterns
  - "Random Simulation" - Random traffic generation

- **Predefined Attack Scenarios:**
  - Normal Web Browsing
  - Email Traffic (SMTP)
  - Volumetric DDoS Attack
  - SYN Flood Attack
  - FTP-Patator Attack
  - SSH-Patator Attack
  - DoS Hulk Attack
  - DoS Slowloris Attack
  - Heartbleed Attack
  - Web Attack – XSS
  - Web Attack – SQL Injection
  - Infiltration Attack

- **Manual Input Form** (Original form with all 13 features)

### 2. Admin Security Dashboard
**URL:** `http://localhost:8000/dashboard/`

**Features:**
- Real-time attack statistics (24h, 7d, total)
- Recent attacks list with severity indicators
- Attack type distribution charts
- System health monitoring (CPU, Memory)
- Pending alerts counter

### 3. Attack Logs Management
**URL:** `http://localhost:8000/dashboard/attacks/`

**Features:**
- Complete attack history with filtering
- Filter by attack type, severity, status, date range
- Detailed view for each attack
- Investigation status tracking
- Mark attacks as false positives

### 4. Security Alerts System
**URL:** `http://localhost:8000/dashboard/alerts/`

**Features:**
- Email alert management
- Webhook alert support
- Alert acknowledgment system
- Failed alert tracking

### 5. System Metrics
**URL:** `http://localhost:8000/dashboard/metrics/`

**Features:**
- System performance charts
- Attack detection rates
- Resource utilization monitoring
- Historical data visualization

### 6. Monitoring Configuration
**URL:** `http://localhost:8000/dashboard/config/`

**Features:**
- Enable/disable monitoring
- Email alert configuration
- Severity thresholds
- Rate limiting settings
- Webhook configuration

## 🔧 Configuration

### Email Alerts Setup
1. Edit `cybersecurity/settings.py`
2. Update email configuration:
   ```python
   EMAIL_HOST_USER = 'your-email@gmail.com'
   EMAIL_HOST_PASSWORD = 'your-app-password'
   ```

### Admin Email Setup
```bash
python manage.py setup_monitoring --admin-email your-admin@email.com
```

## 🎯 Testing the System

### Test Different Attack Types:
1. Go to `http://localhost:8000/`
2. Click on predefined scenarios:
   - **"FTP-Patator Attack"** → Should detect as FTP-Patator
   - **"Volumetric DDoS Attack"** → Should detect as DoS Hulk
   - **"Web Attack – XSS"** → Should detect as Web Attack – XSS
   - **"Normal Web Browsing"** → Should detect as BENIGN

### View Results:
1. After each prediction, check the results page
2. Go to admin dashboard to see logged attacks
3. Check attack logs for detailed information

## 📈 Real-time Monitoring

### Background Monitoring Service:
```bash
python manage.py start_monitoring
```

This starts continuous monitoring that:
- Logs all predictions to database
- Sends email alerts for threats
- Updates system metrics
- Cleans up old data

## 🔍 Database Tables Created

The system now includes these new database tables:
- `AttackLog` - All detected attacks with features
- `SecurityAlert` - Email/webhook alerts sent
- `MonitoringConfig` - System configuration
- `SystemMetrics` - Performance metrics

## 🚨 Alert System

### Automatic Alerts Sent When:
- Attack severity ≥ configured threshold
- Confidence score ≥ configured threshold
- Rate limiting allows (not too many alerts)

### Alert Channels:
- **Email** - HTML formatted security alerts
- **Webhook** - JSON payload to external systems
- **Dashboard** - Real-time notifications

## 📊 Enhanced Results Page

The results page now shows:
- Attack type with specific icons
- Severity-based color coding
- Detailed mitigation strategies
- Technical analysis
- Immediate action recommendations
- Long-term security solutions

## 🔐 Security Features

- Input validation and sanitization
- CSRF protection
- XSS filtering
- Secure session handling
- SQL injection prevention
- Rate limiting for alerts