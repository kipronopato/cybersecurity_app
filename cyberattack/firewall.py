import re
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from .models import FirewallRule, BlockedAttack, FirewallConfig, AttackLog
from .utils import get_attack_name

logger = logging.getLogger(__name__)

class FirewallSystem:
    def __init__(self):
        self.config = None
    
    def get_config(self):
        if self.config is None:
            try:
                self.config = FirewallConfig.get_config()
            except Exception:
                # Default config if database not ready
                class DefaultConfig:
                    firewall_enabled = True
                    auto_block_enabled = True
                    block_duration = 3600
                    max_attempts = 5
                    whitelist_ips = ''
                    block_threshold = 'Medium'
                self.config = DefaultConfig()
        return self.config
    
    def is_ip_blocked(self, ip_address):
        """Check if IP is currently blocked"""
        try:
            # Check for active IP block rules
            active_rules = FirewallRule.objects.filter(
                rule_type='block_ip',
                rule_value=ip_address,
                is_active=True
            )
            
            for rule in active_rules:
                if rule.expires_at and rule.expires_at < timezone.now():
                    rule.is_active = False
                    rule.save()
                else:
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking IP block status: {str(e)}")
            return False
    
    def is_whitelisted(self, ip_address):
        """Check if IP is whitelisted"""
        try:
            config = self.get_config()
            if config.whitelist_ips:
                whitelist = [ip.strip() for ip in config.whitelist_ips.split(',')]
                return ip_address in whitelist
            return False
        except Exception:
            return False
    
    def should_block_attack(self, attack_type, severity, confidence):
        """Determine if attack should be blocked"""
        config = self.get_config()
        
        if not config.firewall_enabled or not config.auto_block_enabled:
            return False
        
        # Check severity threshold
        severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        if severity_levels.get(severity, 0) < severity_levels.get(config.block_threshold, 2):
            return False
        
        # Always block high-confidence attacks
        if confidence > 0.8:
            return True
        
        # Block known attack types
        if attack_type != 0:  # Not BENIGN
            return True
        
        return False
    
    def extract_machine_specs(self, request):
        """Extract machine specifications from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        specs = {
            'os_info': self.extract_os_info(user_agent),
            'browser_info': self.extract_browser_info(user_agent),
            'device_type': self.extract_device_type(user_agent),
            'language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
            'timezone': request.META.get('HTTP_X_TIMEZONE', ''),
        }
        
        return specs
    
    def extract_os_info(self, user_agent):
        """Extract OS information from user agent"""
        os_patterns = {
            'Windows NT 10.0': 'Windows 10',
            'Windows NT 6.3': 'Windows 8.1',
            'Windows NT 6.2': 'Windows 8',
            'Windows NT 6.1': 'Windows 7',
            'Mac OS X': 'macOS',
            'Linux': 'Linux',
            'Android': 'Android',
            'iPhone OS': 'iOS',
        }
        
        for pattern, os_name in os_patterns.items():
            if pattern in user_agent:
                return os_name
        
        return 'Unknown OS'
    
    def extract_browser_info(self, user_agent):
        """Extract browser information from user agent"""
        browser_patterns = {
            'Chrome': 'Google Chrome',
            'Firefox': 'Mozilla Firefox',
            'Safari': 'Safari',
            'Edge': 'Microsoft Edge',
            'Opera': 'Opera',
            'Internet Explorer': 'Internet Explorer',
        }
        
        for pattern, browser_name in browser_patterns.items():
            if pattern in user_agent:
                # Try to extract version
                version_match = re.search(f'{pattern}/([\\d.]+)', user_agent)
                if version_match:
                    return f"{browser_name} {version_match.group(1)}"
                return browser_name
        
        return 'Unknown Browser'
    
    def extract_device_type(self, user_agent):
        """Extract device type from user agent"""
        if 'Mobile' in user_agent or 'Android' in user_agent:
            return 'Mobile'
        elif 'Tablet' in user_agent or 'iPad' in user_agent:
            return 'Tablet'
        else:
            return 'Desktop'
    
    def block_attack(self, request, attack_type, attack_name, severity, confidence, traffic_data):
        """Block an attack and record details"""
        try:
            config = self.get_config()
            ip_address = self.get_client_ip(request)
            
            # Don't block whitelisted IPs
            if self.is_whitelisted(ip_address):
                return False
            
            # Extract machine specifications
            machine_specs = self.extract_machine_specs(request)
            
            # Create firewall rule
            expires_at = timezone.now() + timedelta(seconds=config.block_duration)
            firewall_rule = FirewallRule.objects.create(
                rule_type='block_ip',
                rule_value=ip_address,
                auto_created=True,
                expires_at=expires_at,
                description=f'Auto-blocked due to {attack_name} attack'
            )
            
            # Record blocked attack
            blocked_attack = BlockedAttack.objects.create(
                attack_type=attack_type,
                attack_name=attack_name,
                severity=severity,
                confidence_score=confidence,
                source_ip=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method,
                firewall_rule=firewall_rule,
                block_duration=config.block_duration,
                destination_port=traffic_data.get('destination_port', 0),
                flow_bytes_s=traffic_data.get('flow_bytes_s', 0),
                flow_packets_s=traffic_data.get('flow_packets_s', 0),
                **machine_specs
            )
            
            # Create security alert
            self.create_security_alert(blocked_attack)
            
            # Send email notification
            self.send_attack_notification(blocked_attack, machine_specs, traffic_data)
            
            logger.warning(f'Blocked {attack_name} attack from {ip_address}')
            return True
            
        except Exception as e:
            logger.error(f'Error blocking attack: {str(e)}')
            return False
    
    def send_attack_notification(self, blocked_attack, machine_specs, traffic_data):
        """Send email notification about blocked attack"""
        try:
            admin_email = 'obernard377@gmail.com'
            subject = f'SECURITY ALERT: {blocked_attack.attack_name} Attack Blocked'
            
            logger.info(f'Preparing to send email notification for {blocked_attack.attack_name} attack')
            
            message = f"""
SECURITY ALERT - ATTACK BLOCKED

Attack Details:
- Attack Type: {blocked_attack.attack_name}
- Severity: {blocked_attack.severity}
- Confidence Score: {blocked_attack.confidence_score:.2%}
- Source IP: {blocked_attack.source_ip}
- Blocked At: {blocked_attack.blocked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Block Duration: {blocked_attack.block_duration} seconds

Request Information:
- Path: {blocked_attack.request_path}
- Method: {blocked_attack.request_method}
- User Agent: {blocked_attack.user_agent}

Machine Specifications:
- Operating System: {machine_specs.get('os_info', 'Unknown')}
- Browser: {machine_specs.get('browser_info', 'Unknown')}
- Device Type: {machine_specs.get('device_type', 'Unknown')}
- Language: {machine_specs.get('language', 'Unknown')}
- Timezone: {machine_specs.get('timezone', 'Unknown')}

Traffic Data:
- Destination Port: {traffic_data.get('destination_port', 'N/A')}
- Flow Bytes/s: {traffic_data.get('flow_bytes_s', 'N/A')}
- Flow Packets/s: {traffic_data.get('flow_packets_s', 'N/A')}

The IP address has been automatically blocked and will be unblocked at: {blocked_attack.firewall_rule.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if blocked_attack.firewall_rule and blocked_attack.firewall_rule.expires_at else 'N/A'}

This is an automated security notification from your Cybersecurity System.
"""
            
            result = send_mail(
                subject=subject,
                message=message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@cybersecurity.com'),
                recipient_list=[admin_email],
                fail_silently=False
            )
            
            logger.info(f'Attack notification email sent to {admin_email}, result: {result}')
            print(f'EMAIL SENT: {subject} to {admin_email}')  # Console output for debugging
            
        except Exception as e:
            logger.error(f'Failed to send attack notification email: {str(e)}')
    
    def create_security_alert(self, blocked_attack):
        """Create security alert for blocked attack"""
        try:
            from .models import SecurityAlert, AttackLog
            
            # Create AttackLog entry
            attack_log = AttackLog.objects.create(
                attack_type=blocked_attack.attack_type,
                attack_name=blocked_attack.attack_name,
                severity=blocked_attack.severity,
                confidence_score=blocked_attack.confidence_score,
                destination_port=blocked_attack.destination_port,
                flow_iat_min=0,  # Default values for required fields
                init_win_bytes_forward=0,
                flow_duration=0,
                total_length_of_fwd_packets=0,
                init_win_bytes_backward=0,
                flow_bytes_s=blocked_attack.flow_bytes_s,
                fwd_iat_min=0,
                bwd_packets_s=0,
                fwd_packet_length_max=0,
                bwd_iat_total=0,
                fin_flag_count=0,
                flow_packets_s=blocked_attack.flow_packets_s,
                source_ip=blocked_attack.source_ip,
                user_agent=blocked_attack.user_agent,
                request_path=blocked_attack.request_path,
                scenario_name=f'Blocked {blocked_attack.attack_name}',
                status='resolved'  # Already blocked
            )
            
            # Create SecurityAlert entry
            SecurityAlert.objects.create(
                attack_log=attack_log,
                alert_type=f'{blocked_attack.attack_name} Attack Blocked',
                severity=blocked_attack.severity,
                source_ip=blocked_attack.source_ip,
                description=f'Blocked {blocked_attack.attack_name} attack from {blocked_attack.source_ip}. Email notification sent to admin.',
                metadata=f'Confidence: {blocked_attack.confidence_score:.1%}, Block Duration: {blocked_attack.block_duration}s',
                is_resolved=True  # Already blocked
            )
            
            logger.info(f'Security alert created for blocked attack: {blocked_attack.attack_name}')
            
        except Exception as e:
            logger.error(f'Failed to create security alert: {str(e)}')
    
    def get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def create_block_response(self, request, blocked_attack):
        """Create HTTP response for blocked requests"""
        content = render_to_string('cyberattack/blocked.html', {
            'blocked_attack': blocked_attack,
            'block_expires': blocked_attack.firewall_rule.expires_at if blocked_attack.firewall_rule else None
        }, request=request)
        
        return HttpResponseForbidden(content)

# Global firewall instance
firewall = FirewallSystem()