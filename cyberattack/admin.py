from django.contrib import admin
from django.utils.html import format_html
from .models import AttackLog, FirewallRule, BlockedAttack, FirewallConfig

@admin.register(BlockedAttack)
class BlockedAttackAdmin(admin.ModelAdmin):
    list_display = ['attack_name', 'severity', 'source_ip', 'confidence_score', 'blocked_at', 'status_badge']
    list_filter = ['severity', 'attack_type', 'blocked_at', 'device_type']
    search_fields = ['source_ip', 'attack_name', 'user_agent']
    readonly_fields = ['blocked_at']
    date_hierarchy = 'blocked_at'
    
    def status_badge(self, obj):
        if obj.severity == 'Critical':
            color = 'red'
        elif obj.severity == 'High':
            color = 'orange'
        elif obj.severity == 'Medium':
            color = 'yellow'
        else:
            color = 'green'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.severity
        )
    status_badge.short_description = 'Status'

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ['rule_type', 'rule_value', 'is_active', 'auto_created', 'created_at', 'expires_at']
    list_filter = ['rule_type', 'is_active', 'auto_created', 'created_at']
    search_fields = ['rule_value', 'description']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'

@admin.register(AttackLog)
class AttackLogAdmin(admin.ModelAdmin):
    list_display = ['attack_type', 'severity', 'source_ip', 'confidence_score', 'timestamp', 'status']
    list_filter = ['attack_type', 'severity', 'status', 'timestamp']
    search_fields = ['source_ip', 'user_agent']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'

@admin.register(FirewallConfig)
class FirewallConfigAdmin(admin.ModelAdmin):
    list_display = ['firewall_enabled', 'auto_block_enabled', 'block_threshold', 'block_duration']
    
    def has_add_permission(self, request):
        return not FirewallConfig.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        return False
