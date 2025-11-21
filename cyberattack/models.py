from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone as django_timezone
import json

class AttackLog(models.Model):
    ATTACK_TYPES = [
        (0, 'BENIGN'),
        (1, 'DDoS'),
        (2, 'FTP-Patator'),
        (3, 'SSH-Patator'),
        (4, 'DoS Hulk'),
        (5, 'DoS GoldenEye'),
        (6, 'DoS Slowloris'),
        (7, 'DoS Slowhttptest'),
        (8, 'Heartbleed'),
        (9, 'Web Attack – Brute Force'),
        (10, 'Web Attack – XSS'),
        (11, 'Web Attack – SQL Injection'),
        (12, 'Infiltration'),
    ]
    
    SEVERITY_LEVELS = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('detected', 'Detected'),
        ('investigating', 'Under Investigation'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    # Attack Information
    attack_type = models.IntegerField(choices=ATTACK_TYPES, default=0)
    attack_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='Medium')
    confidence_score = models.FloatField(default=0.0)
    
    # Network Features (Top 13)
    destination_port = models.FloatField()
    flow_iat_min = models.FloatField()
    init_win_bytes_forward = models.FloatField()
    flow_duration = models.FloatField()
    total_length_of_fwd_packets = models.FloatField()
    init_win_bytes_backward = models.FloatField()
    flow_bytes_s = models.FloatField()
    fwd_iat_min = models.FloatField()
    bwd_packets_s = models.FloatField()
    fwd_packet_length_max = models.FloatField()
    bwd_iat_total = models.FloatField()
    fin_flag_count = models.FloatField()
    flow_packets_s = models.FloatField()
    
    # Additional Information
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    request_path = models.CharField(max_length=500, null=True, blank=True)
    
    # Metadata
    timestamp = models.DateTimeField(default=django_timezone.now)
    scenario_name = models.CharField(max_length=200, default='Unknown')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='detected')
    
    # Investigation
    investigated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    investigation_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['attack_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.get_attack_type_display()} - {self.severity} - {self.timestamp}"
    
    def get_features_dict(self):
        return {
            'destination_port': self.destination_port,
            'flow_iat_min': self.flow_iat_min,
            'init_win_bytes_forward': self.init_win_bytes_forward,
            'flow_duration': self.flow_duration,
            'total_length_of_fwd_packets': self.total_length_of_fwd_packets,
            'init_win_bytes_backward': self.init_win_bytes_backward,
            'flow_bytes_s': self.flow_bytes_s,
            'fwd_iat_min': self.fwd_iat_min,
            'bwd_packets_s': self.bwd_packets_s,
            'fwd_packet_length_max': self.fwd_packet_length_max,
            'bwd_iat_total': self.bwd_iat_total,
            'fin_flag_count': self.fin_flag_count,
            'flow_packets_s': self.flow_packets_s,
        }

class SecurityAlert(models.Model):
    ALERT_TYPES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('webhook', 'Webhook'),
        ('dashboard', 'Dashboard'),
    ]
    
    ALERT_STATUS = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('acknowledged', 'Acknowledged'),
    ]
    
    attack_log = models.ForeignKey(AttackLog, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    alert_type = models.CharField(max_length=50, default='Security Alert')
    severity = models.CharField(max_length=20, choices=AttackLog.SEVERITY_LEVELS, default='Medium')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    metadata = models.TextField(blank=True)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=django_timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.created_at}"

class MonitoringConfig(models.Model):
    # Email Configuration
    email_enabled = models.BooleanField(default=True)
    admin_emails = models.TextField(help_text="Comma-separated list of admin emails")
    email_threshold = models.CharField(max_length=20, default='Medium', 
                                     choices=AttackLog.SEVERITY_LEVELS)
    
    # Monitoring Settings
    monitoring_enabled = models.BooleanField(default=True)
    auto_block_enabled = models.BooleanField(default=False)
    confidence_threshold = models.FloatField(default=0.7)
    
    # Rate Limiting
    max_alerts_per_hour = models.IntegerField(default=10)
    cooldown_period = models.IntegerField(default=300, help_text="Seconds between similar alerts")
    
    # Webhook Configuration
    webhook_url = models.URLField(blank=True)
    webhook_enabled = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Monitoring Configuration"
        verbose_name_plural = "Monitoring Configurations"
    
    def __str__(self):
        return f"Monitoring Config - Updated {self.updated_at}"
    
    @classmethod
    def get_config(cls):
        config, created = cls.objects.get_or_create(pk=1)
        return config

class SystemMetrics(models.Model):
    timestamp = models.DateTimeField(default=django_timezone.now)
    total_requests = models.IntegerField(default=0)
    attacks_detected = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    system_load = models.FloatField(default=0.0)
    memory_usage = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Metrics - {self.timestamp}"

class SystemMaintenance(models.Model):
    is_maintenance_mode = models.BooleanField(default=False)
    maintenance_message = models.TextField(default="System is under maintenance. Please try again later.")
    maintenance_start = models.DateTimeField(null=True, blank=True)
    maintenance_end = models.DateTimeField(null=True, blank=True)
    enabled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "System Maintenance"
        verbose_name_plural = "System Maintenance"
    
    def __str__(self):
        return f"Maintenance Mode: {'ON' if self.is_maintenance_mode else 'OFF'}"
    
    @classmethod
    def get_status(cls):
        maintenance, created = cls.objects.get_or_create(pk=1)
        return maintenance

class FirewallRule(models.Model):
    RULE_TYPES = [
        ('block_ip', 'Block IP Address'),
        ('block_attack', 'Block Attack Type'),
        ('rate_limit', 'Rate Limiting'),
        ('geo_block', 'Geographic Block'),
    ]
    
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    rule_value = models.CharField(max_length=200)  # IP, attack type, etc.
    is_active = models.BooleanField(default=True)
    auto_created = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    description = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.get_rule_type_display()}: {self.rule_value}"

class BlockedAttack(models.Model):
    # Attack Information
    attack_type = models.IntegerField(choices=AttackLog.ATTACK_TYPES)
    attack_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=AttackLog.SEVERITY_LEVELS)
    confidence_score = models.FloatField()
    
    # Attacker Information
    source_ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    
    # Machine Specifications
    os_info = models.CharField(max_length=200, blank=True)
    browser_info = models.CharField(max_length=200, blank=True)
    device_type = models.CharField(max_length=100, blank=True)
    screen_resolution = models.CharField(max_length=50, blank=True)
    timezone = models.CharField(max_length=100, blank=True)
    language = models.CharField(max_length=50, blank=True)
    
    # Network Information
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    isp = models.CharField(max_length=200, blank=True)
    
    # Firewall Action
    firewall_rule = models.ForeignKey(FirewallRule, on_delete=models.SET_NULL, null=True, blank=True)
    blocked_at = models.DateTimeField(default=django_timezone.now)
    block_duration = models.IntegerField(default=3600)  # seconds
    
    # Traffic Features
    destination_port = models.FloatField()
    flow_bytes_s = models.FloatField()
    flow_packets_s = models.FloatField()
    
    class Meta:
        ordering = ['-blocked_at']
        indexes = [
            models.Index(fields=['source_ip']),
            models.Index(fields=['blocked_at']),
            models.Index(fields=['attack_type']),
        ]
    
    def __str__(self):
        return f"Blocked {self.attack_name} from {self.source_ip}"

class FirewallConfig(models.Model):
    firewall_enabled = models.BooleanField(default=True)
    auto_block_enabled = models.BooleanField(default=True)
    block_duration = models.IntegerField(default=3600)  # seconds
    max_attempts = models.IntegerField(default=5)
    whitelist_ips = models.TextField(blank=True, help_text="Comma-separated IP addresses")
    block_threshold = models.CharField(max_length=20, default='Medium', choices=AttackLog.SEVERITY_LEVELS)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Firewall Configuration"
        verbose_name_plural = "Firewall Configurations"
    
    def __str__(self):
        return f"Firewall Config - {'Enabled' if self.firewall_enabled else 'Disabled'}"
    
    @classmethod
    def get_config(cls):
        config, created = cls.objects.get_or_create(pk=1)
        return config