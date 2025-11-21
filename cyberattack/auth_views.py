from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from .models import SystemMaintenance

def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('predict_attack')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()
    
    return render(request, 'cyberattack/login.html', {'form': form})

@login_required
def user_logout(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

def is_admin(user):
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(is_admin)
def admin_maintenance(request):
    maintenance = SystemMaintenance.get_status()
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'enable_maintenance':
            maintenance.is_maintenance_mode = True
            maintenance.maintenance_start = timezone.now()
            maintenance.enabled_by = request.user
            maintenance.maintenance_message = request.POST.get('message', 'System is under maintenance. Please try again later.')
            maintenance.save()
            messages.success(request, 'Maintenance mode enabled.')
            
        elif action == 'disable_maintenance':
            maintenance.is_maintenance_mode = False
            maintenance.maintenance_end = timezone.now()
            maintenance.save()
            messages.success(request, 'Maintenance mode disabled.')
            
        return redirect('admin_maintenance')
    
    context = {
        'maintenance': maintenance,
    }
    
    return render(request, 'cyberattack/admin_maintenance.html', context)