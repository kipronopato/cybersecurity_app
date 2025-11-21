from django.urls import path
from . import views, admin_views, auth_views, firewall_views, health_views

urlpatterns = [
    path('', views.predict_attack, name='predict_attack'),
    path('results/', views.prediction_results, name='prediction_results'),
    
    # Authentication URLs
    path('login/', auth_views.user_login, name='login'),
    path('logout/', auth_views.user_logout, name='logout'),
    path('maintenance/', auth_views.admin_maintenance, name='admin_maintenance'),
    
    # Security Dashboard URLs
    path('dashboard/', admin_views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/attacks/', admin_views.attack_logs, name='attack_logs'),
    path('dashboard/attacks/<int:attack_id>/', admin_views.attack_detail, name='attack_detail'),
    path('dashboard/alerts/', admin_views.security_alerts, name='security_alerts'),
    path('dashboard/alerts/<int:alert_id>/acknowledge/', admin_views.acknowledge_alert, name='acknowledge_alert'),
    path('dashboard/config/', admin_views.monitoring_config, name='monitoring_config'),
    path('dashboard/metrics/', admin_views.system_metrics, name='system_metrics'),
    path('dashboard/api/', admin_views.dashboard_api, name='dashboard_api'),
    
    # Firewall URLs
    path('firewall/', firewall_views.firewall_dashboard, name='firewall_dashboard'),
    path('firewall/blocked/', firewall_views.blocked_attacks, name='blocked_attacks'),
    path('firewall/rules/', firewall_views.firewall_rules, name='firewall_rules'),
    path('firewall/config/', firewall_views.firewall_config, name='firewall_config'),
    path('firewall/unblock/<str:ip_address>/', firewall_views.unblock_ip, name='unblock_ip'),
    
    # Security Tracking URLs
    path('security/blocked-attacks/', views.blocked_attacks_view, name='blocked_attacks_tracking'),
    path('security/alerts/', views.security_alerts_view, name='security_alerts_tracking'),
    
    # Test URL for firewall
    path('test-attack/', views.test_attack_view, name='test_attack'),
    path('trigger-attack/', views.trigger_real_attack, name='trigger_real_attack'),
    
    # Dashboard API
    path('dashboard/api/', admin_views.dashboard_api, name='dashboard_api'),
    
    # Mitigation guide
    path('mitigation/<int:attack_id>/', views.mitigation_guide, name='mitigation_guide'),
    
    # Admin emergency unblock
    path('emergency-unblock/', views.admin_unblock, name='admin_unblock'),
    
    # Health check for deployment
    path('health/', health_views.health_check, name='health_check'),
]