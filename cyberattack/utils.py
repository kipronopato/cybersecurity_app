"""
Utility functions for attack detection and classification
"""

def get_attack_name(attack_code):
    """Convert numeric code to attack name"""
    attack_names = {
        0: 'BENIGN',
        1: 'DDoS',
        2: 'FTP-Patator',
        3: 'SSH-Patator',
        4: 'DoS Hulk',
        5: 'DoS GoldenEye',
        6: 'DoS Slowloris',
        7: 'DoS Slowhttptest',
        8: 'Heartbleed',
        9: 'Web Attack – Brute Force',
        10: 'Web Attack – XSS',
        11: 'Web Attack – SQL Injection',
        12: 'Infiltration'
    }
    return attack_names.get(attack_code, 'BENIGN')

def get_attack_code(attack_type):
    """Convert attack type to numeric code"""
    attack_codes = {
        'BENIGN': 0,
        'DDoS': 1,
        'FTP-Patator': 2,
        'SSH-Patator': 3,
        'DoS Hulk': 4,
        'DoS GoldenEye': 5,
        'DoS Slowloris': 6,
        'DoS Slowhttptest': 7,
        'Heartbleed': 8,
        'Web Attack – Brute Force': 9,
        'Web Attack – XSS': 10,
        'Web Attack – SQL Injection': 11,
        'Infiltration': 12
    }
    return attack_codes.get(attack_type, 0)

def detect_attack_type(traffic_data, scenario_name):
    """Detect specific attack type based on traffic patterns"""
    dest_port = traffic_data.get('destination_port', 0)
    flow_bytes_s = traffic_data.get('flow_bytes_s', 0)
    flow_packets_s = traffic_data.get('flow_packets_s', 0)
    flow_duration = traffic_data.get('flow_duration', 0)
    flow_iat_min = traffic_data.get('flow_iat_min', 0)
    fin_flag_count = traffic_data.get('fin_flag_count', 1)
    bwd_packets_s = traffic_data.get('bwd_packets_s', 0)
    total_fwd_packets = traffic_data.get('total_length_of_fwd_packets', 0)
    
    # Check scenario name first for explicit attack types
    scenario_lower = scenario_name.lower()
    
    if any(keyword in scenario_lower for keyword in ['ftp-patator', 'ftp patator', 'ssh-patator', 'ssh patator']):
        return 'FTP-Patator' if 'ftp' in scenario_lower else 'SSH-Patator'
    
    if any(keyword in scenario_lower for keyword in ['hulk', 'goldeneye', 'slowloris', 'slowhttptest']):
        if 'hulk' in scenario_lower:
            return 'DoS Hulk'
        elif 'goldeneye' in scenario_lower:
            return 'DoS GoldenEye'
        elif 'slowloris' in scenario_lower:
            return 'DoS Slowloris'
        else:
            return 'DoS Slowhttptest'
    
    if 'heartbleed' in scenario_lower:
        return 'Heartbleed'
    
    if any(keyword in scenario_lower for keyword in ['web attack', 'brute force', 'xss', 'sql injection']):
        if 'brute force' in scenario_lower:
            return 'Web Attack – Brute Force'
        elif 'xss' in scenario_lower:
            return 'Web Attack – XSS'
        elif 'sql' in scenario_lower:
            return 'Web Attack – SQL Injection'
        else:
            return 'Web Attack – Brute Force'
    
    if 'infiltration' in scenario_lower:
        return 'Infiltration'
    
    if any(keyword in scenario_lower for keyword in ['ddos', 'flood']):
        return 'DDoS'
    
    # Pattern-based detection
    
    # FTP/SSH Brute Force (Patator) - Multiple failed connections on ports 21/22
    if dest_port in [21, 22] and flow_duration < 5000000 and fin_flag_count == 0:
        return 'FTP-Patator' if dest_port == 21 else 'SSH-Patator'
    
    # DoS Hulk - High volume, short duration attacks
    if (flow_bytes_s > 5000000 and flow_packets_s > 10000 and 
        flow_duration < 2000000 and dest_port in [80, 443]):
        return 'DoS Hulk'
    
    # DoS GoldenEye - Moderate volume with specific patterns
    if (flow_bytes_s > 1000000 and flow_packets_s > 3000 and 
        dest_port in [80, 443] and flow_iat_min < 5000):
        return 'DoS GoldenEye'
    
    # DoS Slowloris - Low volume, long duration
    if (dest_port in [80, 443] and flow_duration > 30000000 and 
        flow_bytes_s < 10000 and flow_packets_s < 100):
        return 'DoS Slowloris'
    
    # DoS Slowhttptest - Similar to Slowloris but different pattern
    if (dest_port in [80, 443] and flow_duration > 20000000 and 
        flow_bytes_s < 50000 and flow_packets_s < 500):
        return 'DoS Slowhttptest'
    
    # Heartbleed - SSL/TLS vulnerability exploitation
    if dest_port == 443 and total_fwd_packets > 1000 and flow_duration < 1000000:
        return 'Heartbleed'
    
    # Web Attack - Brute Force
    if (dest_port in [80, 443] and flow_packets_s > 100 and 
        flow_duration < 10000000 and bwd_packets_s < 50):
        return 'Web Attack – Brute Force'
    
    # Web Attack - XSS (Cross-Site Scripting)
    if (dest_port in [80, 443] and total_fwd_packets > 500 and 
        flow_bytes_s > 10000 and flow_duration < 5000000):
        return 'Web Attack – XSS'
    
    # Web Attack - SQL Injection
    if (dest_port in [80, 443, 3306, 1433, 5432] and 
        total_fwd_packets > 200 and flow_bytes_s > 5000):
        return 'Web Attack – SQL Injection'
    
    # Infiltration - Stealthy, long-duration attacks
    if (flow_duration > 60000000 and flow_bytes_s < 100000 and 
        flow_packets_s < 1000 and dest_port not in [80, 443]):
        return 'Infiltration'
    
    # DDoS - High volume attacks
    if (flow_bytes_s > 1000000 or flow_packets_s > 5000 or 
        (flow_iat_min < 1000 and fin_flag_count == 0)):
        return 'DDoS'
    
    return 'BENIGN'