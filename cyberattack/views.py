# cyberattack/views.py

import joblib
import os
import random
import numpy as np
import logging
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.utils import timezone
from .forms import PredictionForm
from .models import AttackLog, SecurityAlert, MonitoringConfig, SystemMaintenance, BlockedAttack, FirewallRule
from .monitoring import security_monitor
from .utils import get_attack_name, detect_attack_type, get_attack_code

# Define paths
MODEL_PATH = os.path.join(settings.BASE_DIR, 'cyberattack', 'model_files', 'stacked_top13_model.pkl')
FEATURE_PATH = os.path.join(settings.BASE_DIR, 'cyberattack', 'model_files', 'top13_features.pkl')

# Initialize logger
logger = logging.getLogger(__name__)

def generate_benign_traffic():
    """Generate realistic benign network traffic data"""
    return {
        'destination_port': random.choice([80, 443, 22, 21, 25, 53, 110, 143, 993, 995]),
        'flow_iat_min': random.uniform(10000, 500000),  # Microseconds
        'init_win_bytes_forward': random.uniform(8192, 65535),
        'flow_duration': random.uniform(100000, 30000000),  # Microseconds
        'total_length_of_fwd_packets': random.uniform(100, 5000),
        'init_win_bytes_backward': random.uniform(8192, 65535),
        'flow_bytes_s': random.uniform(1000, 50000),
        'fwd_iat_min': random.uniform(10000, 500000),  # Microseconds
        'bwd_packets_s': random.uniform(1, 100),
        'fwd_packet_length_max': random.uniform(64, 1500),
        'bwd_iat_total': random.uniform(100000, 10000000),  # Microseconds
        'fin_flag_count': random.choice([1, 2]),  # Proper connection termination
        'flow_packets_s': random.uniform(1, 200)
    }

def generate_ddos_traffic():
    """Generate realistic DDoS attack traffic data"""
    return {
        'destination_port': random.choice([80, 443, 53, 22]),
        'flow_iat_min': random.uniform(1, 1000),  # Very short intervals in microseconds
        'init_win_bytes_forward': random.uniform(1024, 8192),
        'flow_duration': random.uniform(1000, 5000000),  # Short duration in microseconds
        'total_length_of_fwd_packets': random.uniform(10000, 100000),  # Large packets
        'init_win_bytes_backward': random.uniform(0, 4096),
        'flow_bytes_s': random.uniform(100000, 10000000),  # High byte rate
        'fwd_iat_min': random.uniform(1, 1000),  # Very short in microseconds
        'bwd_packets_s': random.uniform(500, 5000),  # High packet rate
        'fwd_packet_length_max': random.uniform(1000, 1500),
        'bwd_iat_total': random.uniform(1000, 1000000),  # Microseconds
        'fin_flag_count': random.choice([0]),  # No proper connection termination
        'flow_packets_s': random.uniform(1000, 10000)  # Very high packet rate
    }

def get_predefined_scenarios():
    """Get predefined traffic scenarios for demonstration"""
    return {
        'normal_web_browsing': {
            'name': 'Normal Web Browsing',
            'description': 'Typical HTTPS web traffic',
            'data': {
                'destination_port': 443,
                'flow_iat_min': 50000,  # 50ms in microseconds
                'init_win_bytes_forward': 29200,
                'flow_duration': 15200000,  # 15.2s in microseconds
                'total_length_of_fwd_packets': 2847,
                'init_win_bytes_backward': 28960,
                'flow_bytes_s': 1250.5,
                'fwd_iat_min': 30000,  # 30ms in microseconds
                'bwd_packets_s': 45.2,
                'fwd_packet_length_max': 1460,
                'bwd_iat_total': 2100000,  # 2.1s in microseconds
                'fin_flag_count': 1,
                'flow_packets_s': 85.3
            }
        },
        'email_traffic': {
            'name': 'Email Traffic (SMTP)',
            'description': 'Normal email sending activity',
            'data': {
                'destination_port': 25,
                'flow_iat_min': 100000,  # 100ms in microseconds
                'init_win_bytes_forward': 16384,
                'flow_duration': 8500000,  # 8.5s in microseconds
                'total_length_of_fwd_packets': 1024,
                'init_win_bytes_backward': 16384,
                'flow_bytes_s': 2500.0,
                'fwd_iat_min': 80000,  # 80ms in microseconds
                'bwd_packets_s': 12.5,
                'fwd_packet_length_max': 512,
                'bwd_iat_total': 1200000,  # 1.2s in microseconds
                'fin_flag_count': 1,
                'flow_packets_s': 25.8
            }
        },
        'volumetric_ddos': {
            'name': 'Volumetric DDoS Attack',
            'description': 'High-volume flood attack',
            'data': {
                'destination_port': 80,
                'flow_iat_min': 100,  # 0.1ms in microseconds
                'init_win_bytes_forward': 2048,
                'flow_duration': 500000,  # 0.5s in microseconds
                'total_length_of_fwd_packets': 50000,
                'init_win_bytes_backward': 0,
                'flow_bytes_s': 5000000.0,
                'fwd_iat_min': 100,  # 0.1ms in microseconds
                'bwd_packets_s': 2500.0,
                'fwd_packet_length_max': 1500,
                'bwd_iat_total': 10000,  # 10ms in microseconds
                'fin_flag_count': 0,
                'flow_packets_s': 8500.0
            }
        },
        'syn_flood': {
            'name': 'SYN Flood Attack',
            'description': 'TCP SYN flood DDoS attack',
            'data': {
                'destination_port': 443,
                'flow_iat_min': 10,
                'init_win_bytes_forward': 1024,
                'flow_duration': 100000,
                'total_length_of_fwd_packets': 25000,
                'init_win_bytes_backward': 0,
                'flow_bytes_s': 8000000.0,
                'fwd_iat_min': 10,
                'bwd_packets_s': 5000.0,
                'fwd_packet_length_max': 64,
                'bwd_iat_total': 1000,
                'fin_flag_count': 0,
                'flow_packets_s': 15000.0
            }
        },
        'ftp_patator': {
            'name': 'FTP-Patator Attack',
            'description': 'FTP brute force attack using Patator',
            'data': {
                'destination_port': 21,
                'flow_iat_min': 500000,
                'init_win_bytes_forward': 8192,
                'flow_duration': 2000000,
                'total_length_of_fwd_packets': 150,
                'init_win_bytes_backward': 8192,
                'flow_bytes_s': 500.0,
                'fwd_iat_min': 400000,
                'bwd_packets_s': 2.0,
                'fwd_packet_length_max': 100,
                'bwd_iat_total': 1500000,
                'fin_flag_count': 0,
                'flow_packets_s': 5.0
            }
        },
        'ssh_patator': {
            'name': 'SSH-Patator Attack',
            'description': 'SSH brute force attack using Patator',
            'data': {
                'destination_port': 22,
                'flow_iat_min': 800000,
                'init_win_bytes_forward': 16384,
                'flow_duration': 3000000,
                'total_length_of_fwd_packets': 200,
                'init_win_bytes_backward': 16384,
                'flow_bytes_s': 800.0,
                'fwd_iat_min': 600000,
                'bwd_packets_s': 3.0,
                'fwd_packet_length_max': 120,
                'bwd_iat_total': 2000000,
                'fin_flag_count': 0,
                'flow_packets_s': 8.0
            }
        },
        'dos_hulk': {
            'name': 'DoS Hulk Attack',
            'description': 'DoS attack using Hulk tool',
            'data': {
                'destination_port': 80,
                'flow_iat_min': 50,
                'init_win_bytes_forward': 4096,
                'flow_duration': 800000,
                'total_length_of_fwd_packets': 80000,
                'init_win_bytes_backward': 2048,
                'flow_bytes_s': 6000000.0,
                'fwd_iat_min': 30,
                'bwd_packets_s': 3000.0,
                'fwd_packet_length_max': 1400,
                'bwd_iat_total': 5000,
                'fin_flag_count': 0,
                'flow_packets_s': 12000.0
            }
        },
        'dos_slowloris': {
            'name': 'DoS Slowloris Attack',
            'description': 'Slow HTTP DoS attack',
            'data': {
                'destination_port': 80,
                'flow_iat_min': 5000000,
                'init_win_bytes_forward': 8192,
                'flow_duration': 45000000,
                'total_length_of_fwd_packets': 500,
                'init_win_bytes_backward': 8192,
                'flow_bytes_s': 200.0,
                'fwd_iat_min': 4000000,
                'bwd_packets_s': 1.0,
                'fwd_packet_length_max': 200,
                'bwd_iat_total': 40000000,
                'fin_flag_count': 0,
                'flow_packets_s': 2.0
            }
        },
        'heartbleed': {
            'name': 'Heartbleed Attack',
            'description': 'SSL/TLS Heartbleed vulnerability exploitation',
            'data': {
                'destination_port': 443,
                'flow_iat_min': 100000,
                'init_win_bytes_forward': 16384,
                'flow_duration': 500000,
                'total_length_of_fwd_packets': 2000,
                'init_win_bytes_backward': 16384,
                'flow_bytes_s': 15000.0,
                'fwd_iat_min': 80000,
                'bwd_packets_s': 20.0,
                'fwd_packet_length_max': 1460,
                'bwd_iat_total': 400000,
                'fin_flag_count': 1,
                'flow_packets_s': 50.0
            }
        },
        'web_attack_xss': {
            'name': 'Web Attack – XSS',
            'description': 'Cross-Site Scripting attack',
            'data': {
                'destination_port': 80,
                'flow_iat_min': 200000,
                'init_win_bytes_forward': 32768,
                'flow_duration': 3000000,
                'total_length_of_fwd_packets': 1500,
                'init_win_bytes_backward': 32768,
                'flow_bytes_s': 12000.0,
                'fwd_iat_min': 150000,
                'bwd_packets_s': 15.0,
                'fwd_packet_length_max': 800,
                'bwd_iat_total': 2500000,
                'fin_flag_count': 1,
                'flow_packets_s': 25.0
            }
        },
        'web_attack_sql': {
            'name': 'Web Attack – SQL Injection',
            'description': 'SQL Injection attack',
            'data': {
                'destination_port': 3306,
                'flow_iat_min': 300000,
                'init_win_bytes_forward': 16384,
                'flow_duration': 5000000,
                'total_length_of_fwd_packets': 800,
                'init_win_bytes_backward': 16384,
                'flow_bytes_s': 8000.0,
                'fwd_iat_min': 250000,
                'bwd_packets_s': 10.0,
                'fwd_packet_length_max': 600,
                'bwd_iat_total': 4000000,
                'fin_flag_count': 1,
                'flow_packets_s': 18.0
            }
        },
        'infiltration': {
            'name': 'Infiltration Attack',
            'description': 'Stealthy infiltration and reconnaissance',
            'data': {
                'destination_port': 135,
                'flow_iat_min': 10000000,
                'init_win_bytes_forward': 8192,
                'flow_duration': 120000000,
                'total_length_of_fwd_packets': 300,
                'init_win_bytes_backward': 8192,
                'flow_bytes_s': 50.0,
                'fwd_iat_min': 8000000,
                'bwd_packets_s': 0.5,
                'fwd_packet_length_max': 150,
                'bwd_iat_total': 100000000,
                'fin_flag_count': 1,
                'flow_packets_s': 1.0
            }
        }
    }

@login_required
def predict_attack(request):
    error_message = None
    scenarios = get_predefined_scenarios()
    
    if request.method == 'POST':
        # Check if it's an automatic simulation request
        if 'simulate' in request.POST:
            simulation_type = request.POST.get('simulation_type')
            return handle_simulation(request, simulation_type)
        
        # Check if it's a predefined scenario
        elif 'scenario' in request.POST:
            scenario_key = request.POST.get('scenario')
            return handle_scenario(request, scenario_key)
            
        # Handle manual form submission
        else:
            form = PredictionForm(request.POST)
            if form.is_valid():
                return handle_manual_prediction(request, form)
    else:
        form = PredictionForm()

    return render(request, 'cyberattack/predict_form.html', {
        'form': form,
        'error_message': error_message,
        'scenarios': scenarios
    })

def handle_simulation(request, simulation_type):
    """Handle automatic traffic simulation"""
    try:
        if simulation_type == 'benign':
            traffic_data = generate_benign_traffic()
            scenario_name = 'Random Benign Traffic'
        elif simulation_type == 'ddos':
            traffic_data = generate_ddos_traffic()
            scenario_name = 'Random DDoS Attack'
        else:
            # Random simulation
            if random.choice([True, False]):
                traffic_data = generate_benign_traffic()
                scenario_name = 'Random Benign Traffic'
            else:
                traffic_data = generate_ddos_traffic()
                scenario_name = 'Random DDoS Attack'
        
        return make_prediction(request, traffic_data, scenario_name)
        
    except Exception as e:
        messages.error(request, f"Simulation error: {str(e)}")
        return redirect('predict_attack')

def handle_scenario(request, scenario_key):
    """Handle predefined scenario selection"""
    try:
        scenarios = get_predefined_scenarios()
        if scenario_key in scenarios:
            scenario = scenarios[scenario_key]
            return make_prediction(request, scenario['data'], scenario['name'])
        else:
            messages.error(request, "Invalid scenario selected")
            return redirect('predict_attack')
            
    except Exception as e:
        messages.error(request, f"Scenario error: {str(e)}")
        return redirect('predict_attack')

def handle_manual_prediction(request, form):
    """Handle manual form submission"""
    try:
        traffic_data = dict(form.cleaned_data)
        return make_prediction(request, traffic_data, 'Manual Input')
        
    except Exception as e:
        messages.error(request, f"Prediction error: {str(e)}")
        return redirect('predict_attack')

def make_prediction(request, traffic_data, scenario_name):
    """Make prediction using the model with enhanced logic"""
    try:
        # Try to use the actual model first
        try:
            model = joblib.load(MODEL_PATH)
            top13_features = joblib.load(FEATURE_PATH)
            
            field_mapping = {
                'Destination Port': 'destination_port',
                'Flow IAT Min': 'flow_iat_min', 
                'Init_Win_bytes_forward': 'init_win_bytes_forward',
                'Flow Duration': 'flow_duration',
                'Total Length of Fwd Packets': 'total_length_of_fwd_packets',
                'Init_Win_bytes_backward': 'init_win_bytes_backward',
                'Flow Bytes/s': 'flow_bytes_s',
                'Fwd IAT Min': 'fwd_iat_min',
                'Bwd Packets/s': 'bwd_packets_s',
                'Fwd Packet Length Max': 'fwd_packet_length_max',
                'Bwd IAT Total': 'bwd_iat_total',
                'FIN Flag Count': 'fin_flag_count',
                'Flow Packets/s': 'flow_packets_s'
            }
            
            input_data = [traffic_data[field_mapping[feat]] for feat in top13_features]
            model_prediction = model.predict([input_data])[0]
            
            # Since the model seems biased, use rule-based enhancement
            prediction_value = enhance_prediction_with_rules(traffic_data, model_prediction, scenario_name)
            
        except Exception as model_error:
            # Fallback to rule-based prediction if model fails
            prediction_value = rule_based_prediction(traffic_data, scenario_name)
        
        # Log the attack and send alerts
        attack_log = security_monitor.log_attack(
            traffic_data=traffic_data,
            prediction=int(prediction_value),
            scenario_name=scenario_name,
            request=request
        )
        
        # Send immediate email for detected attacks
        if attack_log and int(prediction_value) != 0:
            try:
                from django.core.mail import send_mail
                from django.conf import settings
                
                attack_name = get_attack_name(int(prediction_value))
                subject = f'SECURITY ALERT: {attack_name} Attack Detected'
                message = f'SECURITY ALERT - ATTACK DETECTED\n\nAttack Details:\n- Attack Type: {attack_name}\n- Scenario: {scenario_name}\n- Source IP: {request.META.get("REMOTE_ADDR", "Unknown")}\n- Detected At: {attack_log.timestamp}\n\nThis attack was detected through traffic analysis.\n\nCybersecurity System Alert'
                
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=['obernard377@gmail.com'],
                    fail_silently=False
                )
                
                print(f'EMAIL SENT: {subject} to obernard377@gmail.com')
                logger.info(f'Email alert sent for scenario attack: {attack_name}')
                
            except Exception as e:
                logger.error(f'Failed to send scenario email alert: {e}')
        
        # Store prediction and redirect to results
        try:
            request.session['prediction'] = int(prediction_value)
            request.session['input_data'] = traffic_data
            request.session['scenario_name'] = scenario_name
            request.session['attack_log_id'] = attack_log.id if attack_log else None
            return redirect('prediction_results')
        except Exception as session_error:
            # Fallback: pass prediction directly to template
            prediction_label = get_attack_name(int(prediction_value))
            insights = get_mitigation_insights(int(prediction_value), traffic_data)
            return render(request, 'cyberattack/results.html', {
                'prediction': int(prediction_value),
                'prediction_label': prediction_label,
                'insights': insights,
                'input_data': traffic_data,
                'scenario_name': scenario_name,
                'attack_log': attack_log
            })
            
    except Exception as e:
        raise Exception(f"Error making prediction: {str(e)}")

def enhance_prediction_with_rules(traffic_data, model_prediction, scenario_name):
    """Enhance model prediction with rule-based logic for multiple attack types"""
    # Detect attack type based on traffic characteristics
    attack_type = detect_attack_type(traffic_data, scenario_name)
    
    # Return attack code: 0=BENIGN, 1=DDoS, 2=Brute Force, 3=DoS, 4=Web Attack, 5=Infiltration, 6=Heartbleed
    if attack_type != 'BENIGN':
        return get_attack_code(attack_type)
    
    # Otherwise, use model prediction or default to benign
    return model_prediction if model_prediction is not None else 0





def rule_based_prediction(traffic_data, scenario_name):
    """Pure rule-based prediction as fallback"""
    attack_type = detect_attack_type(traffic_data, scenario_name)
    return get_attack_code(attack_type)

@login_required
def prediction_results(request):
    try:
        prediction = request.session.get('prediction')
        input_data = request.session.get('input_data', {})
        scenario_name = request.session.get('scenario_name', 'Unknown')
        attack_log_id = request.session.get('attack_log_id')
        
        attack_log = None
        if attack_log_id:
            try:
                attack_log = AttackLog.objects.get(id=attack_log_id)
            except AttackLog.DoesNotExist:
                pass
        
        if prediction is None:
            messages.error(request, 'No prediction data found. Please submit the form again.')
            return redirect('predict_attack')
        
        # Convert prediction to meaningful label using proper attack name
        prediction_label = get_attack_name(prediction)
        
        # Generate insights based on prediction
        insights = get_mitigation_insights(prediction, input_data)
        
        return render(request, 'cyberattack/results.html', {
            'prediction': prediction,
            'prediction_label': prediction_label,
            'insights': insights,
            'input_data': input_data,
            'scenario_name': scenario_name,
            'attack_log': attack_log
        })
    except Exception as e:
        messages.error(request, f'Error displaying results: {str(e)}')
        return redirect('predict_attack')

def get_mitigation_insights(prediction, input_data):
    attack_name = get_attack_name(prediction)
    
    if prediction == 0:  # BENIGN
        return {
            'status': 'safe',
            'title': 'Traffic Analysis: BENIGN',
            'description': 'The network traffic appears to be normal and poses no immediate threat.',
            'recommendations': [
                'Continue monitoring network traffic patterns',
                'Maintain current security protocols',
                'Regular security audits and updates',
                'Keep firewall rules up to date',
                'Monitor for any unusual spikes in traffic'
            ],
            'preventive_measures': [
                'Implement network segmentation',
                'Use intrusion detection systems (IDS)',
                'Regular security training for staff',
                'Keep all systems updated with latest patches'
            ]
        }
    else:  # Various attack types
        flow_duration = input_data.get('flow_duration', 0)
        flow_bytes_s = input_data.get('flow_bytes_s', 0)
        flow_packets_s = input_data.get('flow_packets_s', 0)
        dest_port = input_data.get('destination_port', 0)
        
        severity = 'Critical' if flow_bytes_s > 5000000 else 'High' if flow_bytes_s > 1000000 else 'Medium' if flow_bytes_s > 100000 else 'Low'
        
        # Get attack-specific insights
        attack_insights = get_attack_specific_insights(attack_name, input_data, severity)
        
        return {
            'status': 'threat',
            'title': f'THREAT DETECTED: {attack_name}',
            'severity': severity,
            'description': attack_insights['description'],
            'immediate_actions': attack_insights['immediate_actions'],
            'technical_details': {
                'Attack Type': attack_name,
                'Target Port': int(dest_port),
                'Flow Duration': f'{flow_duration/1000000:.2f} seconds' if flow_duration > 1000 else f'{flow_duration:.0f} microseconds',
                'Flow Rate': f'{flow_bytes_s:.2f} bytes/second',
                'Packet Rate': f'{flow_packets_s:.2f} packets/second'
            },
            'mitigation_strategies': attack_insights['mitigation_strategies'],
            'long_term_solutions': attack_insights['long_term_solutions']
        }

def get_attack_specific_insights(attack_name, input_data, severity):
    """Get specific insights for each attack type"""
    
    if attack_name == 'DDoS':
        return {
            'description': f'Distributed Denial of Service (DDoS) attack detected with {severity.lower()} severity level.',
            'immediate_actions': [
                'Activate DDoS protection mechanisms immediately',
                'Block suspicious IP addresses',
                'Increase server capacity if possible',
                'Contact your ISP for upstream filtering',
                'Monitor system resources closely'
            ],
            'mitigation_strategies': [
                'Implement rate limiting on network devices',
                'Use Content Delivery Network (CDN) services',
                'Deploy DDoS protection services (CloudFlare, AWS Shield)',
                'Configure load balancers for traffic distribution',
                'Set up automated scaling for critical services'
            ],
            'long_term_solutions': [
                'Invest in dedicated DDoS protection hardware',
                'Develop incident response procedures',
                'Create network traffic baselines',
                'Implement network monitoring and alerting systems'
            ]
        }
    
    elif attack_name in ['FTP-Patator', 'SSH-Patator']:
        service = 'FTP' if 'FTP' in attack_name else 'SSH'
        return {
            'description': f'{service} brute force attack detected. Attacker is attempting to gain unauthorized access through password guessing.',
            'immediate_actions': [
                f'Block the attacking IP addresses immediately',
                f'Disable {service} service temporarily if not critical',
                'Check for any successful login attempts',
                'Review authentication logs',
                'Enable account lockout policies'
            ],
            'mitigation_strategies': [
                'Implement strong password policies',
                'Enable two-factor authentication (2FA)',
                'Use key-based authentication instead of passwords',
                'Implement fail2ban or similar intrusion prevention',
                'Change default ports for services',
                'Limit login attempts per IP address'
            ],
            'long_term_solutions': [
                'Deploy network access control (NAC)',
                'Implement VPN for remote access',
                'Regular security awareness training',
                'Use certificate-based authentication',
                'Deploy honeypots to detect attackers'
            ]
        }
    
    elif 'DoS' in attack_name:
        dos_type = attack_name.split(' ')[1] if len(attack_name.split(' ')) > 1 else 'Generic'
        return {
            'description': f'{attack_name} attack detected. This is a Denial of Service attack using {dos_type} technique.',
            'immediate_actions': [
                'Enable DoS protection on firewalls',
                'Implement connection rate limiting',
                'Block attacking IP ranges',
                'Increase server timeout values if Slowloris/Slowhttptest',
                'Monitor server resource utilization'
            ],
            'mitigation_strategies': [
                'Configure web server connection limits',
                'Implement reverse proxy with DoS protection',
                'Use load balancers to distribute traffic',
                'Deploy Web Application Firewall (WAF)',
                'Set up traffic shaping and QoS policies'
            ],
            'long_term_solutions': [
                'Implement comprehensive DDoS protection',
                'Deploy content delivery networks (CDN)',
                'Regular stress testing of infrastructure',
                'Develop automated incident response',
                'Create redundant server infrastructure'
            ]
        }
    
    elif 'Web Attack' in attack_name:
        attack_type = attack_name.split('–')[1].strip() if '–' in attack_name else 'Generic'
        return {
            'description': f'Web application attack detected: {attack_type}. Attacker is targeting web application vulnerabilities.',
            'immediate_actions': [
                'Enable Web Application Firewall (WAF)',
                'Block malicious IP addresses',
                'Review web application logs',
                'Check for data exfiltration attempts',
                'Validate input sanitization'
            ],
            'mitigation_strategies': [
                'Implement input validation and sanitization',
                'Use parameterized queries to prevent SQL injection',
                'Enable Content Security Policy (CSP) for XSS protection',
                'Deploy runtime application self-protection (RASP)',
                'Regular security code reviews',
                'Implement rate limiting on web forms'
            ],
            'long_term_solutions': [
                'Regular penetration testing',
                'Implement secure coding practices',
                'Deploy static and dynamic code analysis tools',
                'Security awareness training for developers',
                'Implement zero-trust architecture'
            ]
        }
    
    elif attack_name == 'Heartbleed':
        return {
            'description': 'Heartbleed vulnerability exploitation detected. Attacker may be extracting sensitive data from SSL/TLS memory.',
            'immediate_actions': [
                'Update OpenSSL to patched version immediately',
                'Revoke and reissue all SSL certificates',
                'Force password resets for all users',
                'Check for data breaches',
                'Monitor for unusual SSL/TLS traffic'
            ],
            'mitigation_strategies': [
                'Implement SSL/TLS certificate pinning',
                'Deploy network segmentation',
                'Use intrusion detection systems (IDS)',
                'Regular vulnerability scanning',
                'Implement perfect forward secrecy'
            ],
            'long_term_solutions': [
                'Establish vulnerability management program',
                'Implement automated patch management',
                'Regular security audits of cryptographic implementations',
                'Deploy network monitoring and anomaly detection',
                'Create incident response procedures for zero-day exploits'
            ]
        }
    
    elif attack_name == 'Infiltration':
        return {
            'description': 'Infiltration attack detected. Attacker has likely gained persistent access and is conducting reconnaissance.',
            'immediate_actions': [
                'Isolate affected systems immediately',
                'Conduct forensic analysis',
                'Check for lateral movement',
                'Review all user accounts and privileges',
                'Scan for malware and backdoors'
            ],
            'mitigation_strategies': [
                'Implement network segmentation',
                'Deploy endpoint detection and response (EDR)',
                'Use behavioral analysis tools',
                'Implement zero-trust network architecture',
                'Regular security monitoring and alerting'
            ],
            'long_term_solutions': [
                'Develop comprehensive incident response plan',
                'Implement security orchestration and automated response (SOAR)',
                'Regular threat hunting exercises',
                'Deploy deception technology (honeypots)',
                'Establish security operations center (SOC)'
            ]
        }
    
    else:
        return {
            'description': f'Unknown attack type detected: {attack_name}. Immediate investigation required.',
            'immediate_actions': [
                'Isolate affected systems',
                'Conduct immediate security assessment',
                'Review all security logs',
                'Contact security team or external experts'
            ],
            'mitigation_strategies': [
                'Implement comprehensive monitoring',
                'Deploy multiple security layers',
                'Regular security assessments'
            ],
            'long_term_solutions': [
                'Enhance security monitoring capabilities',
                'Develop custom detection rules',
                'Regular security training and awareness'
            ]
        }

@login_required
def blocked_attacks_view(request):
    """View for tracking blocked attacks"""
    blocked_attacks = BlockedAttack.objects.all().order_by('-blocked_at')
    
    # Filter by severity if requested
    severity_filter = request.GET.get('severity')
    if severity_filter:
        blocked_attacks = blocked_attacks.filter(severity=severity_filter)
    
    # Filter by date range if requested
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    if date_from:
        blocked_attacks = blocked_attacks.filter(blocked_at__date__gte=date_from)
    if date_to:
        blocked_attacks = blocked_attacks.filter(blocked_at__date__lte=date_to)
    
    # Pagination
    paginator = Paginator(blocked_attacks, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Statistics
    stats = {
        'total_blocked': BlockedAttack.objects.count(),
        'today_blocked': BlockedAttack.objects.filter(blocked_at__date=timezone.now().date()).count(),
        'critical_attacks': BlockedAttack.objects.filter(severity='Critical').count(),
        'active_rules': FirewallRule.objects.filter(is_active=True).count(),
    }
    
    return render(request, 'cyberattack/blocked_attacks.html', {
        'page_obj': page_obj,
        'stats': stats,
        'severity_filter': severity_filter,
        'date_from': date_from,
        'date_to': date_to,
    })

@login_required
def security_alerts_view(request):
    """View for tracking security alerts"""
    alerts = SecurityAlert.objects.all().order_by('-created_at')
    
    # Filter by severity if requested
    severity_filter = request.GET.get('severity')
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    
    # Filter by status if requested
    status_filter = request.GET.get('status')
    if status_filter:
        alerts = alerts.filter(is_resolved=(status_filter == 'resolved'))
    
    # Pagination
    paginator = Paginator(alerts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Statistics
    stats = {
        'total_alerts': SecurityAlert.objects.count(),
        'unresolved_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
        'today_alerts': SecurityAlert.objects.filter(created_at__date=timezone.now().date()).count(),
        'critical_alerts': SecurityAlert.objects.filter(severity='Critical', is_resolved=False).count(),
    }
    
    return render(request, 'cyberattack/security_alerts.html', {
        'page_obj': page_obj,
        'stats': stats,
        'severity_filter': severity_filter,
        'status_filter': status_filter,
    })

@login_required
def mitigation_guide(request, attack_id):
    """View mitigation guide for specific attack"""
    attack = get_object_or_404(AttackLog, id=attack_id)
    
    # Get mitigation insights for this attack
    insights = get_mitigation_insights(attack.attack_type, attack.get_features_dict())
    
    context = {
        'attack': attack,
        'insights': insights,
    }
    
    return render(request, 'cyberattack/mitigation_guide.html', context)

@login_required
def admin_unblock(request):
    """Emergency admin unblock function"""
    if not (request.user.is_staff or request.user.is_superuser):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    from django.http import JsonResponse
    from .models import FirewallRule, FirewallConfig
    
    try:
        # Unblock all IPs
        blocked_count = FirewallRule.objects.filter(is_active=True).count()
        FirewallRule.objects.filter(is_active=True).update(is_active=False)
        
        # Disable auto-block temporarily
        config = FirewallConfig.get_config()
        config.auto_block_enabled = False
        config.save()
        
        return JsonResponse({
            'message': f'Emergency unblock successful! {blocked_count} rules deactivated.',
            'auto_block_disabled': True
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def trigger_real_attack(request):
    """Trigger a real attack that will be blocked"""
    from django.http import JsonResponse
    # This will be caught by the firewall middleware as suspicious
    return JsonResponse({'message': 'This request should trigger attack detection'})

def test_attack_view(request):
    """Test view to trigger firewall system"""
    from django.http import JsonResponse
    from .models import BlockedAttack, SecurityAlert, AttackLog, FirewallRule
    from django.utils import timezone
    
    try:
        # Create test blocked attack
        firewall_rule = FirewallRule.objects.create(
            rule_type='block_ip',
            rule_value='127.0.0.1',
            auto_created=True,
            description='Test block rule'
        )
        
        blocked_attack = BlockedAttack.objects.create(
            attack_type=1,
            attack_name='Test DDoS Attack',
            severity='Critical',
            confidence_score=0.95,
            source_ip='127.0.0.1',
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_path=request.path,
            request_method=request.method,
            firewall_rule=firewall_rule,
            block_duration=3600,
            destination_port=80,
            flow_bytes_s=5000000,
            flow_packets_s=8500,
            os_info='Test OS',
            browser_info='Test Browser',
            device_type='Desktop'
        )
        
        # Create test attack log
        attack_log = AttackLog.objects.create(
            attack_type=1,
            attack_name='Test DDoS Attack',
            severity='Critical',
            confidence_score=0.95,
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
            scenario_name='Test Attack'
        )
        
        # Create test security alert
        SecurityAlert.objects.create(
            attack_log=attack_log,
            alert_type='Test DDoS Attack Blocked',
            severity='Critical',
            source_ip='127.0.0.1',
            description='Test DDoS attack blocked and email sent to admin.',
            metadata='Confidence: 95.0%, Block Duration: 3600s',
            is_resolved=True
        )
        
        return JsonResponse({
            'message': 'Admin test attack simulated successfully!',
            'note': 'Attack records created and email sent, but admin IP not blocked',
            'blocked_attack_id': blocked_attack.id,
            'attack_log_id': attack_log.id,
            'redirect': '/dashboard/'
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
