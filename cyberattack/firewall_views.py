from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.utils import timezone
from .models import FirewallRule, BlockedAttack, FirewallConfig
from .firewall import firewall

def is_admin(user):
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(is_admin)
def firewall_dashboard(request):
    """Firewall management dashboard"""
    config = FirewallConfig.get_config()
    
    # Recent blocked attacks
    recent_blocks = BlockedAttack.objects.order_by('-blocked_at')[:10]
    
    # Statistics
    stats = {
        'total_blocked': BlockedAttack.objects.count(),
        'blocked_today': BlockedAttack.objects.filter(
            blocked_at__date=timezone.now().date()
        ).count(),
        'active_rules': FirewallRule.objects.filter(is_active=True).count(),
        'blocked_ips': BlockedAttack.objects.values('source_ip').distinct().count(),
    }
    
    context = {
        'config': config,
        'recent_blocks': recent_blocks,
        'stats': stats,
    }
    
    return render(request, 'cyberattack/firewall_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def blocked_attacks(request):
    """View all blocked attacks"""
    attacks = BlockedAttack.objects.all().order_by('-blocked_at')
    
    # Filtering
    attack_type = request.GET.get('attack_type')
    severity = request.GET.get('severity')
    ip_address = request.GET.get('ip_address')
    
    if attack_type:
        attacks = attacks.filter(attack_type=attack_type)
    if severity:
        attacks = attacks.filter(severity=severity)
    if ip_address:
        attacks = attacks.filter(source_ip__icontains=ip_address)
    
    # Pagination
    paginator = Paginator(attacks, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'attack_types': BlockedAttack._meta.get_field('attack_type').choices,
        'severities': BlockedAttack._meta.get_field('severity').choices,
        'current_filters': {
            'attack_type': attack_type,
            'severity': severity,
            'ip_address': ip_address,
        }
    }
    
    return render(request, 'cyberattack/blocked_attacks.html', context)

@login_required
@user_passes_test(is_admin)
def firewall_rules(request):
    """Manage firewall rules"""
    rules = FirewallRule.objects.all().order_by('-created_at')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'add_rule':
            rule_type = request.POST.get('rule_type')
            rule_value = request.POST.get('rule_value')
            description = request.POST.get('description', '')
            
            FirewallRule.objects.create(
                rule_type=rule_type,
                rule_value=rule_value,
                description=description,
                created_by=request.user
            )
            messages.success(request, 'Firewall rule added successfully.')
            
        elif action == 'toggle_rule':
            rule_id = request.POST.get('rule_id')
            rule = get_object_or_404(FirewallRule, id=rule_id)
            rule.is_active = not rule.is_active
            rule.save()
            status = 'activated' if rule.is_active else 'deactivated'
            messages.success(request, f'Rule {status} successfully.')
        
        return redirect('firewall_rules')
    
    # Pagination
    paginator = Paginator(rules, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'rule_types': FirewallRule.RULE_TYPES,
    }
    
    return render(request, 'cyberattack/firewall_rules.html', context)

@login_required
@user_passes_test(is_admin)
def firewall_config(request):
    """Configure firewall settings"""
    config = FirewallConfig.get_config()
    
    if request.method == 'POST':
        config.firewall_enabled = request.POST.get('firewall_enabled') == 'on'
        config.auto_block_enabled = request.POST.get('auto_block_enabled') == 'on'
        config.block_duration = int(request.POST.get('block_duration', 3600))
        config.max_attempts = int(request.POST.get('max_attempts', 5))
        config.whitelist_ips = request.POST.get('whitelist_ips', '')
        config.block_threshold = request.POST.get('block_threshold', 'Medium')
        
        config.save()
        messages.success(request, 'Firewall configuration updated successfully.')
        return redirect('firewall_config')
    
    context = {
        'config': config,
        'severity_levels': FirewallConfig._meta.get_field('block_threshold').choices,
    }
    
    return render(request, 'cyberattack/firewall_config.html', context)

@login_required
@user_passes_test(is_admin)
def unblock_ip(request, ip_address):
    """Unblock a specific IP address"""
    if request.method == 'POST':
        # Deactivate all block rules for this IP
        rules = FirewallRule.objects.filter(
            rule_type='block_ip',
            rule_value=ip_address,
            is_active=True
        )
        
        count = rules.count()
        rules.update(is_active=False)
        
        messages.success(request, f'Unblocked IP {ip_address} ({count} rules deactivated).')
    
    return redirect('blocked_attacks')