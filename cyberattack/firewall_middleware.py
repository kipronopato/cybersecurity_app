import logging
from .firewall import firewall
from .monitoring import security_monitor

logger = logging.getLogger(__name__)

class FirewallMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip firewall for admin and essential paths
        skip_paths = ['/admin/', '/dashboard/', '/login/', '/logout/', '/static/', '/security/', '/emergency-unblock/']
        if any(request.path.startswith(path) for path in skip_paths):
            response = self.get_response(request)
            return response
        
        # Handle admin users specially
        if hasattr(request, 'user') and request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
            # Admin test attack simulation - creates records but doesn't block admin
            if request.path.startswith('/test-attack'):
                self.simulate_admin_attack(request)
            response = self.get_response(request)
            return response
        
        # Check if IP is blocked
        client_ip = firewall.get_client_ip(request)
        
        if firewall.is_ip_blocked(client_ip):
            from .models import BlockedAttack
            try:
                blocked_attack = BlockedAttack.objects.filter(
                    source_ip=client_ip
                ).order_by('-blocked_at').first()
                
                if blocked_attack:
                    return firewall.create_block_response(request, blocked_attack)
            except Exception:
                pass
        
        # Monitor all requests for potential attacks (except authenticated admin users)
        is_admin = (hasattr(request, 'user') and 
                   request.user.is_authenticated and 
                   (request.user.is_staff or request.user.is_superuser))
        
        if not is_admin:
            self.monitor_request_for_attacks(request)
        
        response = self.get_response(request)
        return response
    
    def simulate_attack(self, request):
        try:
            traffic_data = {
                'destination_port': 80,
                'flow_bytes_s': 5000000,
                'flow_packets_s': 8500,
                'flow_duration': 500000,
                'total_length_of_fwd_packets': 50000,
                'init_win_bytes_forward': 2048,
                'init_win_bytes_backward': 0,
                'fwd_iat_min': 100,
                'bwd_packets_s': 2500,
                'fwd_packet_length_max': 1500,
                'bwd_iat_total': 10000,
                'fin_flag_count': 0,
                'flow_iat_min': 100
            }
            
            # Check if attack should be blocked
            attack_type = 1  # DDoS
            attack_name = 'DDoS'
            severity = 'Critical'
            confidence = 0.95
            
            if firewall.should_block_attack(attack_type, severity, confidence):
                # Block the attack and record it
                firewall.block_attack(request, attack_type, attack_name, severity, confidence, traffic_data)
            
            # Also log the attack
            security_monitor.log_attack(
                traffic_data=traffic_data,
                prediction=attack_type,
                scenario_name='Test DDoS Attack',
                request=request
            )
            
        except Exception as e:
            logger.error(f"Error simulating attack: {e}")
    
    def simulate_admin_attack(self, request):
        """Simulate attack for admin testing - creates all records but doesn't block admin"""
        try:
            traffic_data = {
                'destination_port': 80,
                'flow_bytes_s': 5000000,
                'flow_packets_s': 8500,
                'flow_duration': 500000,
                'total_length_of_fwd_packets': 50000,
                'init_win_bytes_forward': 2048,
                'init_win_bytes_backward': 0,
                'fwd_iat_min': 100,
                'bwd_packets_s': 2500,
                'fwd_packet_length_max': 1500,
                'bwd_iat_total': 10000,
                'fin_flag_count': 0,
                'flow_iat_min': 100
            }
            
            attack_type = 1  # DDoS
            attack_name = 'Admin Test DDoS Attack'
            severity = 'Critical'
            confidence = 0.95
            
            # Create all records as if attack was blocked, but don't actually block admin
            from .models import BlockedAttack, SecurityAlert, AttackLog, FirewallRule
            from django.utils import timezone
            
            # Create firewall rule (but keep it inactive for admin)
            firewall_rule = FirewallRule.objects.create(
                rule_type='block_ip',
                rule_value='127.0.0.1',
                auto_created=True,
                is_active=False,  # Don't actually block admin
                description=f'Admin test - {attack_name}'
            )
            
            # Create blocked attack record
            blocked_attack = BlockedAttack.objects.create(
                attack_type=attack_type,
                attack_name=attack_name,
                severity=severity,
                confidence_score=confidence,
                source_ip='127.0.0.1',
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method,
                firewall_rule=firewall_rule,
                block_duration=3600,
                destination_port=80,
                flow_bytes_s=5000000,
                flow_packets_s=8500,
                os_info='Admin Test OS',
                browser_info='Admin Test Browser',
                device_type='Desktop'
            )
            
            # Create attack log
            attack_log = AttackLog.objects.create(
                attack_type=attack_type,
                attack_name=attack_name,
                severity=severity,
                confidence_score=confidence,
                destination_port=80,
                flow_iat_min=100,
                init_win_bytes_forward=2048,
                flow_duration=500000,
                total_length_of_fwd_packets=50000,
                init_win_bytes_backward=0,
                flow_bytes_s=5000000,
                fwd_iat_min=100,
                bwd_packets_s=2500,
                fwd_packet_length_max=1500,
                bwd_iat_total=10000,
                fin_flag_count=0,
                flow_packets_s=8500,
                source_ip='127.0.0.1',
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                scenario_name='Admin Test Attack'
            )
            
            # Create security alert
            SecurityAlert.objects.create(
                attack_log=attack_log,
                alert_type=f'{attack_name} (Admin Test)',
                severity=severity,
                source_ip='127.0.0.1',
                description=f'Admin test: {attack_name} simulated. Email notification sent.',
                metadata=f'Confidence: {confidence:.1%}, Admin Test Mode',
                is_resolved=True
            )
            
            # Send email notification
            firewall.send_attack_notification(blocked_attack, {
                'os_info': 'Admin Test OS',
                'browser_info': 'Admin Test Browser',
                'device_type': 'Desktop',
                'language': 'en-US',
                'timezone': 'EAT'
            }, traffic_data)
            
            logger.info(f'Admin test attack simulated: {attack_name}')
            
        except Exception as e:
            logger.error(f"Error simulating admin attack: {e}")
    
    def monitor_request_for_attacks(self, request):
        """Monitor regular requests for potential attacks"""
        try:
            # Simple attack detection based on request patterns
            suspicious = False
            attack_type = 0  # BENIGN by default
            attack_name = 'BENIGN'
            severity = 'Low'
            confidence = 0.1
            
            # Check for suspicious patterns
            user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
            path = request.path.lower()
            
            # Detect potential attacks based on patterns
            if any(pattern in path for pattern in ['/admin', '/wp-admin', '/.env', '/config', '/backup']):
                suspicious = True
                attack_type = 12  # Infiltration
                attack_name = 'Infiltration Attempt'
                severity = 'High'
                confidence = 0.8
            elif any(pattern in user_agent for pattern in ['bot', 'crawler', 'scanner', 'sqlmap', 'nikto']):
                suspicious = True
                attack_type = 9  # Web Attack
                attack_name = 'Web Attack - Scanner'
                severity = 'Medium'
                confidence = 0.7
            elif len(request.GET.urlencode()) > 1000:  # Very long query string
                suspicious = True
                attack_type = 10  # XSS
                attack_name = 'Web Attack - XSS'
                severity = 'Medium'
                confidence = 0.6
            
            # If suspicious activity detected, process as attack
            if suspicious:
                traffic_data = {
                    'destination_port': 80,
                    'flow_bytes_s': len(request.body) if hasattr(request, 'body') else 100,
                    'flow_packets_s': 10,
                    'flow_duration': 1000000,
                    'total_length_of_fwd_packets': 500,
                    'init_win_bytes_forward': 8192,
                    'init_win_bytes_backward': 4096,
                    'fwd_iat_min': 1000,
                    'bwd_packets_s': 5,
                    'fwd_packet_length_max': 1460,
                    'bwd_iat_total': 500000,
                    'fin_flag_count': 1,
                    'flow_iat_min': 1000
                }
                
                # Check if should block
                if firewall.should_block_attack(attack_type, severity, confidence):
                    # Block the attack
                    blocked = firewall.block_attack(request, attack_type, attack_name, severity, confidence, traffic_data)
                    if blocked:
                        logger.warning(f'Real attack blocked: {attack_name} from {firewall.get_client_ip(request)}')
                        print(f'ATTACK BLOCKED: {attack_name} from {firewall.get_client_ip(request)}')
                
                # Also log the attack attempt
                attack_log = security_monitor.log_attack(
                    traffic_data=traffic_data,
                    prediction=attack_type,
                    scenario_name=f'Real Attack: {attack_name}',
                    request=request
                )
                
                # Send immediate email notification for detected attacks
                if attack_log and attack_type != 0:
                    try:
                        from django.core.mail import send_mail
                        from django.conf import settings
                        
                        subject = f'SECURITY ALERT: {attack_name} Attack Detected'
                        message = f'SECURITY ALERT - ATTACK DETECTED\n\nAttack Details:\n- Attack Type: {attack_name}\n- Severity: {severity}\n- Source IP: {firewall.get_client_ip(request)}\n- Path: {request.path}\n- User Agent: {request.META.get("HTTP_USER_AGENT", "Unknown")}\n- Detected At: {attack_log.timestamp}\n\nThis attack was detected by the real-time monitoring system.\n\nCybersecurity System Alert'
                        
                        send_mail(
                            subject=subject,
                            message=message,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=['obernard377@gmail.com'],
                            fail_silently=False
                        )
                        
                        print(f'EMAIL SENT: {subject} to obernard377@gmail.com')
                        logger.info(f'Email alert sent for detected attack: {attack_name}')
                        
                    except Exception as e:
                        logger.error(f'Failed to send email alert: {e}')
                
        except Exception as e:
            logger.error(f"Error monitoring request: {e}")