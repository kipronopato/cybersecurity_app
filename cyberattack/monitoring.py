import logging
import smtplib
import requests
import threading
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from django.db import transaction
from .models import AttackLog, SecurityAlert, MonitoringConfig, SystemMetrics
from .utils import get_attack_name, detect_attack_type, get_attack_code
from .firewall import firewall

logger = logging.getLogger(__name__)

class SecurityMonitor:
    def __init__(self):
        self.config = None
        self.alert_cache = {}  # For rate limiting
    
    def get_config(self):
        """Lazy load configuration"""
        if self.config is None:
            try:
                from .models import MonitoringConfig
                self.config = MonitoringConfig.get_config()
            except Exception:
                # Return default config if database not ready
                class DefaultConfig:
                    monitoring_enabled = True
                    email_enabled = False
                    admin_emails = ''
                    email_threshold = 'Medium'
                    confidence_threshold = 0.7
                    max_alerts_per_hour = 10
                    cooldown_period = 300
                    webhook_enabled = False
                    webhook_url = ''
                self.config = DefaultConfig()
        return self.config
        
    def log_attack(self, traffic_data, prediction, scenario_name, request=None):
        """Log detected attack to database"""
        try:
            with transaction.atomic():
                # Extract additional information from request
                source_ip = None
                user_agent = None
                request_path = None
                
                if request:
                    source_ip = self.get_client_ip(request)
                    user_agent = request.META.get('HTTP_USER_AGENT', '')
                    request_path = request.path
                
                # Calculate confidence score based on prediction certainty
                confidence_score = self.calculate_confidence(traffic_data, prediction)
                
                # Determine severity
                severity = self.determine_severity(traffic_data, prediction)
                
                # Create attack log entry
                attack_log = AttackLog.objects.create(
                    attack_type=prediction,
                    attack_name=get_attack_name(prediction),
                    severity=severity,
                    confidence_score=confidence_score,
                    scenario_name=scenario_name,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    request_path=request_path,
                    **traffic_data
                )
                
                # Check if attack should be blocked by firewall
                if prediction != 0:  # Attack detected
                    if firewall.should_block_attack(prediction, severity, confidence_score):
                        # Block the attack
                        traffic_data_dict = {
                            'destination_port': traffic_data.get('destination_port', 0),
                            'flow_bytes_s': traffic_data.get('flow_bytes_s', 0),
                            'flow_packets_s': traffic_data.get('flow_packets_s', 0),
                        }
                        
                        firewall.block_attack(
                            request=request,
                            attack_type=prediction,
                            attack_name=get_attack_name(prediction),
                            severity=severity,
                            confidence=confidence_score,
                            traffic_data=traffic_data_dict
                        )
                
                # Send alerts if attack is detected (not benign)
                if prediction != 0 and self.should_alert(attack_log):
                    self.send_alerts(attack_log)
                    logger.info(f'Email alert sent for {attack_log.attack_name} attack')
                
                # Update system metrics
                self.update_metrics(prediction != 0)
                
                logger.info(f"Attack logged: {attack_log.attack_name} from {source_ip}")
                return attack_log
                
        except Exception as e:
            logger.error(f"Error logging attack: {str(e)}")
            return None
    
    def get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def calculate_confidence(self, traffic_data, prediction):
        """Calculate confidence score based on traffic characteristics"""
        if prediction == 0:  # Benign
            return 0.95
        
        # Calculate based on how extreme the values are
        confidence = 0.5
        
        # High flow rates increase confidence
        if traffic_data.get('flow_bytes_s', 0) > 1000000:
            confidence += 0.2
        if traffic_data.get('flow_packets_s', 0) > 5000:
            confidence += 0.2
        
        # Short intervals increase confidence for attacks
        if traffic_data.get('flow_iat_min', 0) < 1000:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def determine_severity(self, traffic_data, prediction):
        """Determine attack severity based on traffic characteristics"""
        if prediction == 0:
            return 'Low'
        
        flow_bytes_s = traffic_data.get('flow_bytes_s', 0)
        flow_packets_s = traffic_data.get('flow_packets_s', 0)
        
        if flow_bytes_s > 5000000 or flow_packets_s > 10000:
            return 'Critical'
        elif flow_bytes_s > 1000000 or flow_packets_s > 5000:
            return 'High'
        elif flow_bytes_s > 100000 or flow_packets_s > 1000:
            return 'Medium'
        else:
            return 'Low'
    
    def should_alert(self, attack_log):
        """Determine if an alert should be sent based on configuration and rate limiting"""
        config = self.get_config()
        if not config.monitoring_enabled:
            return False
        
        # Check confidence threshold
        if attack_log.confidence_score < config.confidence_threshold:
            return False
        
        # Check severity threshold
        severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        if severity_levels.get(attack_log.severity, 0) < severity_levels.get(config.email_threshold, 2):
            return False
        
        # Rate limiting
        cache_key = f"{attack_log.attack_type}_{attack_log.source_ip}"
        now = timezone.now()
        
        if cache_key in self.alert_cache:
            last_alert = self.alert_cache[cache_key]
            if (now - last_alert).seconds < config.cooldown_period:
                return False
        
        # Check hourly limit
        hour_ago = now - timedelta(hours=1)
        recent_alerts = SecurityAlert.objects.filter(
            created_at__gte=hour_ago
        ).count()
        
        if recent_alerts >= config.max_alerts_per_hour:
            return False
        
        self.alert_cache[cache_key] = now
        return True
    
    def send_alerts(self, attack_log):
        """Send alerts via configured channels"""
        try:
            config = self.get_config()
            # Email alerts
            if config.email_enabled and config.admin_emails:
                self.send_email_alert(attack_log)
            
            # Webhook alerts
            if config.webhook_enabled and config.webhook_url:
                self.send_webhook_alert(attack_log)
            
        except Exception as e:
            logger.error(f"Error sending alerts: {str(e)}")
    
    def send_email_alert(self, attack_log):
        """Send email alert to administrators"""
        try:
            config = self.get_config()
            emails = [email.strip() for email in config.admin_emails.split(',')]
            
            subject = f"🚨 SECURITY ALERT: {attack_log.attack_name} Detected"
            
            # Create HTML email content
            html_content = render_to_string('cyberattack/email_alert.html', {
                'attack_log': attack_log,
                'features': attack_log.get_features_dict(),
            })
            
            # Create text content
            text_content = f"""
SECURITY ALERT: {attack_log.attack_name} Detected

Severity: {attack_log.severity}
Time: {attack_log.timestamp}
Source IP: {attack_log.source_ip or 'Unknown'}
Confidence: {attack_log.confidence_score:.2%}

Attack Details:
- Type: {attack_log.attack_name}
- Destination Port: {attack_log.destination_port}
- Flow Rate: {attack_log.flow_bytes_s:.2f} bytes/s
- Packet Rate: {attack_log.flow_packets_s:.2f} packets/s

Please investigate immediately.
            """
            
            # Send email
            for email in emails:
                try:
                    send_mail(
                        subject=subject,
                        message=text_content,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        html_message=html_content,
                        fail_silently=False
                    )
                    
                    # Log successful alert
                    SecurityAlert.objects.create(
                        attack_log=attack_log,
                        alert_type=f'Email Alert: {attack_log.attack_name}',
                        severity=attack_log.severity,
                        source_ip=attack_log.source_ip,
                        description=f'Email alert sent to {email} for {attack_log.attack_name} attack',
                        metadata=f'Recipient: {email}, Status: sent',
                        is_resolved=True
                    )
                    
                except Exception as e:
                    # Log failed alert
                    SecurityAlert.objects.create(
                        attack_log=attack_log,
                        alert_type=f'Email Alert Failed: {attack_log.attack_name}',
                        severity=attack_log.severity,
                        source_ip=attack_log.source_ip,
                        description=f'Failed to send email alert to {email} for {attack_log.attack_name} attack',
                        metadata=f'Recipient: {email}, Error: {str(e)}',
                        is_resolved=False
                    )
                    logger.error(f"Failed to send email to {email}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in send_email_alert: {str(e)}")
    
    def send_webhook_alert(self, attack_log):
        """Send webhook alert"""
        try:
            config = self.get_config()
            
            payload = {
                'alert_type': 'security_attack',
                'attack_name': attack_log.attack_name,
                'severity': attack_log.severity,
                'timestamp': attack_log.timestamp.isoformat(),
                'source_ip': attack_log.source_ip,
                'confidence': attack_log.confidence_score,
                'features': attack_log.get_features_dict()
            }
            
            response = requests.post(
                config.webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                SecurityAlert.objects.create(
                    attack_log=attack_log,
                    alert_type=f'Webhook Alert: {attack_log.attack_name}',
                    severity=attack_log.severity,
                    source_ip=attack_log.source_ip,
                    description=f'Webhook alert sent for {attack_log.attack_name} attack',
                    metadata=f'URL: {config.webhook_url}, Status: sent',
                    is_resolved=True
                )
            else:
                SecurityAlert.objects.create(
                    attack_log=attack_log,
                    alert_type=f'Webhook Alert Failed: {attack_log.attack_name}',
                    severity=attack_log.severity,
                    source_ip=attack_log.source_ip,
                    description=f'Failed to send webhook alert for {attack_log.attack_name} attack',
                    metadata=f'URL: {config.webhook_url}, Error: HTTP {response.status_code}',
                    is_resolved=False
                )
                
        except Exception as e:
            config = self.get_config()
            SecurityAlert.objects.create(
                attack_log=attack_log,
                alert_type=f'Webhook Alert Failed: {attack_log.attack_name}',
                severity=attack_log.severity,
                source_ip=attack_log.source_ip,
                description=f'Webhook alert failed for {attack_log.attack_name} attack',
                metadata=f'URL: {config.webhook_url}, Error: {str(e)}',
                is_resolved=False
            )
            logger.error(f"Webhook alert failed: {str(e)}")
    
    def update_metrics(self, is_attack):
        """Update system metrics"""
        try:
            now = timezone.now()
            # Get or create metrics for current hour
            hour_start = now.replace(minute=0, second=0, microsecond=0)
            
            metrics, created = SystemMetrics.objects.get_or_create(
                timestamp=hour_start,
                defaults={
                    'total_requests': 0,
                    'attacks_detected': 0,
                    'false_positives': 0
                }
            )
            
            metrics.total_requests += 1
            if is_attack:
                metrics.attacks_detected += 1
            
            metrics.save()
            
        except Exception as e:
            logger.error(f"Error updating metrics: {str(e)}")

# Global monitor instance
security_monitor = SecurityMonitor()

class RealTimeMonitor:
    """Background monitoring service"""
    
    def __init__(self):
        self.running = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start background monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logger.info("Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Simulate network monitoring (in real implementation, this would
                # capture actual network packets or system logs)
                self._check_system_health()
                self._cleanup_old_data()
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(10)
    
    def _check_system_health(self):
        """Check system health and performance"""
        try:
            import psutil
            
            # Get system metrics
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            # Update metrics
            now = timezone.now()
            hour_start = now.replace(minute=0, second=0, microsecond=0)
            
            metrics, created = SystemMetrics.objects.get_or_create(
                timestamp=hour_start,
                defaults={'total_requests': 0, 'attacks_detected': 0}
            )
            
            metrics.system_load = cpu_percent
            metrics.memory_usage = memory.percent
            metrics.save()
            
        except ImportError:
            # psutil not available, skip system monitoring
            pass
        except Exception as e:
            logger.error(f"Error checking system health: {str(e)}")
    
    def _cleanup_old_data(self):
        """Clean up old logs and metrics"""
        try:
            # Keep logs for 30 days
            cutoff_date = timezone.now() - timedelta(days=30)
            
            old_logs = AttackLog.objects.filter(timestamp__lt=cutoff_date)
            deleted_count = old_logs.count()
            old_logs.delete()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old attack logs")
            
            # Keep metrics for 7 days
            metrics_cutoff = timezone.now() - timedelta(days=7)
            old_metrics = SystemMetrics.objects.filter(timestamp__lt=metrics_cutoff)
            old_metrics.delete()
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {str(e)}")

# Global real-time monitor instance
real_time_monitor = RealTimeMonitor()