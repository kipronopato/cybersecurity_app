from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from .models import SystemMaintenance

class MaintenanceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if system is in maintenance mode
        try:
            maintenance = SystemMaintenance.get_status()
        except:
            # If maintenance model doesn't exist yet, continue normally
            return self.get_response(request)
        
        # Allow access to admin, login, logout, and maintenance URLs
        allowed_paths = [
            '/login/',
            '/logout/',
            '/maintenance/',
            '/admin/',
        ]
        
        # Check if current path is allowed
        path_allowed = any(request.path.startswith(path) for path in allowed_paths)
        
        # If in maintenance mode and user is not admin and path not allowed
        if (maintenance.is_maintenance_mode and 
            not path_allowed and 
            not (request.user.is_authenticated and request.user.is_staff)):
            
            # Render maintenance page
            content = render_to_string('cyberattack/maintenance.html', {
                'maintenance': maintenance
            }, request=request)
            return HttpResponse(content, status=503)
        
        response = self.get_response(request)
        return response