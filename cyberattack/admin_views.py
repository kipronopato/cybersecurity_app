from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
from .models import AttackLog, SecurityAlert, MonitoringConfig, SystemMetrics
from .monitoring import security_monitor, real_time_monitor

def is_admin(user):
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Main admin dashboard"""
    # Get recent statistics
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    stats = {
        'total_attacks': AttackLog.objects.exclude(attack_type=0).count(),
        'attacks_24h': AttackLog.objects.exclude(attack_type=0).filter(timestamp__gte=last_24h).count(),
        'attacks_7d': AttackLog.objects.exclude(attack_type=0).filter(timestamp__gte=last_7d).count(),
        'pending_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
        'critical_attacks': AttackLog.objects.filter(severity='Critical').count(),
    }
    
    # Recent attacks
    recent_attacks = AttackLog.objects.exclude(attack_type=0).order_by('-timestamp')[:10]
    
    # Attack types distribution
    attack_distribution = AttackLog.objects.exclude(attack_type=0).values('attack_name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Severity distribution
    severity_distribution = AttackLog.objects.exclude(attack_type=0).values('severity').annotate(
        count=Count('id')
    )
    
    # System metrics
    latest_metrics = SystemMetrics.objects.first()
    
    context = {
        'stats': stats,
        'recent_attacks': recent_attacks,
        'attack_distribution': attack_distribution,
        'severity_distribution': severity_distribution,
        'latest_metrics': latest_metrics,
    }
    
    return render(request, 'cyberattack/admin_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def attack_logs(request):
    """View all attack logs with filtering"""
    logs = AttackLog.objects.all().order_by('-timestamp')
    
    # Filtering
    attack_type = request.GET.get('attack_type')
    severity = request.GET.get('severity')
    status = request.GET.get('status')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    if attack_type:
        logs = logs.filter(attack_type=attack_type)
    if severity:
        logs = logs.filter(severity=severity)
    if status:
        logs = logs.filter(status=status)
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    
    # Pagination
    paginator = Paginator(logs, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get filter choices
    attack_types = AttackLog.ATTACK_TYPES
    severities = AttackLog.SEVERITY_LEVELS
    statuses = AttackLog.STATUS_CHOICES
    
    context = {
        'page_obj': page_obj,
        'attack_types': attack_types,
        'severities': severities,
        'statuses': statuses,
        'current_filters': {
            'attack_type': attack_type,
            'severity': severity,
            'status': status,
            'date_from': date_from,
            'date_to': date_to,
        }
    }
    
    return render(request, 'cyberattack/attack_logs.html', context)

@login_required
@user_passes_test(is_admin)
def attack_detail(request, attack_id):
    """View detailed information about a specific attack"""
    attack = get_object_or_404(AttackLog, id=attack_id)
    alerts = SecurityAlert.objects.filter(attack_log=attack)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_status':
            new_status = request.POST.get('status')
            notes = request.POST.get('notes', '')
            
            attack.status = new_status
            attack.investigated_by = request.user
            attack.investigation_notes = notes
            
            if new_status == 'resolved':
                attack.resolved_at = timezone.now()
            
            attack.save()
            messages.success(request, 'Attack status updated successfully.')
            
        elif action == 'mark_false_positive':
            attack.status = 'false_positive'
            attack.investigated_by = request.user
            attack.save()
            messages.success(request, 'Marked as false positive.')
    
    context = {
        'attack': attack,
        'alerts': alerts,
        'features': attack.get_features_dict(),
    }
    
    return render(request, 'cyberattack/attack_detail.html', context)

@login_required
@user_passes_test(is_admin)
def security_alerts(request):
    """View all security alerts"""
    alerts = SecurityAlert.objects.all().order_by('-created_at')
    
    # Filtering
    alert_type = request.GET.get('alert_type')
    status = request.GET.get('status')
    
    if alert_type:
        alerts = alerts.filter(alert_type__icontains=alert_type)
    if status:
        if status == 'resolved':
            alerts = alerts.filter(is_resolved=True)
        elif status == 'unresolved':
            alerts = alerts.filter(is_resolved=False)
    
    # Pagination
    paginator = Paginator(alerts, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'current_filters': {
            'alert_type': alert_type,
            'status': status,
        }
    }
    
    return render(request, 'cyberattack/security_alerts.html', context)

@login_required
@user_passes_test(is_admin)
def monitoring_config(request):
    """Configure monitoring settings"""
    config = MonitoringConfig.get_config()
    
    if request.method == 'POST':
        # Update configuration
        config.email_enabled = request.POST.get('email_enabled') == 'on'
        config.admin_emails = request.POST.get('admin_emails', '')
        config.email_threshold = request.POST.get('email_threshold', 'Medium')
        config.monitoring_enabled = request.POST.get('monitoring_enabled') == 'on'
        config.auto_block_enabled = request.POST.get('auto_block_enabled') == 'on'
        config.confidence_threshold = float(request.POST.get('confidence_threshold', 0.7))
        config.max_alerts_per_hour = int(request.POST.get('max_alerts_per_hour', 10))
        config.cooldown_period = int(request.POST.get('cooldown_period', 300))
        config.webhook_url = request.POST.get('webhook_url', '')
        config.webhook_enabled = request.POST.get('webhook_enabled') == 'on'
        
        config.save()
        
        # Restart monitoring if needed
        if config.monitoring_enabled:
            real_time_monitor.start_monitoring()
        else:
            real_time_monitor.stop_monitoring()
        
        messages.success(request, 'Monitoring configuration updated successfully.')
        return redirect('monitoring_config')
    
    context = {
        'config': config,
        'severity_levels': AttackLog.SEVERITY_LEVELS,
    }
    
    return render(request, 'cyberattack/monitoring_config.html', context)

@login_required
@user_passes_test(is_admin)
def system_metrics(request):
    """View system metrics and performance"""
    # Get metrics for the last 24 hours
    last_24h = timezone.now() - timedelta(hours=24)
    metrics = SystemMetrics.objects.filter(timestamp__gte=last_24h).order_by('timestamp')
    
    # Prepare data for charts
    chart_data = {
        'timestamps': [m.timestamp.strftime('%H:%M') for m in metrics],
        'attacks': [m.attacks_detected for m in metrics],
        'requests': [m.total_requests for m in metrics],
        'system_load': [m.system_load for m in metrics],
        'memory_usage': [m.memory_usage for m in metrics],
    }
    
    # Summary statistics
    total_requests = sum(m.total_requests for m in metrics)
    total_attacks = sum(m.attacks_detected for m in metrics)
    avg_system_load = sum(m.system_load for m in metrics) / len(metrics) if metrics else 0
    avg_memory_usage = sum(m.memory_usage for m in metrics) / len(metrics) if metrics else 0
    
    context = {
        'chart_data': chart_data,
        'total_requests': total_requests,
        'total_attacks': total_attacks,
        'avg_system_load': avg_system_load,
        'avg_memory_usage': avg_memory_usage,
        'latest_metrics': metrics.last() if metrics else None,
    }
    
    return render(request, 'cyberattack/system_metrics.html', context)

@login_required
@user_passes_test(is_admin)
def acknowledge_alert(request, alert_id):
    """Acknowledge a security alert"""
    if request.method == 'POST':
        alert = get_object_or_404(SecurityAlert, id=alert_id)
        alert.is_resolved = True
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.save()
        
        return JsonResponse({'status': 'success'})
    
    return JsonResponse({'status': 'error'})

@login_required
@user_passes_test(is_admin)
def dashboard_api(request):
    """API endpoint for dashboard data"""
    action = request.GET.get('action')
    
    if action == 'recent_attacks':
        attacks = AttackLog.objects.exclude(attack_type=0).order_by('-timestamp')[:5]
        data = [{
            'id': attack.id,
            'attack_name': attack.attack_name,
            'severity': attack.severity,
            'timestamp': attack.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': attack.source_ip or 'Unknown'
        } for attack in attacks]
        
        return JsonResponse({'attacks': data})
    
    elif action == 'stats':
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        
        stats = {
            'attacks_24h': AttackLog.objects.exclude(attack_type=0).filter(timestamp__gte=last_24h).count(),
            'pending_alerts': SecurityAlert.objects.filter(is_resolved=False).count(),
            'system_status': 'online' if MonitoringConfig.get_config().monitoring_enabled else 'offline'
        }
        
        return JsonResponse(stats)
    
    return JsonResponse({'error': 'Invalid action'})