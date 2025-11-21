from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from cyberattack.models import MonitoringConfig

class Command(BaseCommand):
    help = 'Setup initial monitoring configuration'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--admin-email',
            type=str,
            help='Admin email for alerts',
        )
        parser.add_argument(
            '--create-superuser',
            action='store_true',
            help='Create a superuser for admin access',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('Setting up monitoring configuration...')
        
        # Create or update monitoring config
        config = MonitoringConfig.get_config()
        
        if options['admin_email']:
            config.admin_emails = options['admin_email']
            config.email_enabled = True
            self.stdout.write(
                self.style.SUCCESS(f'Admin email set to: {options["admin_email"]}')
            )
        
        config.monitoring_enabled = True
        config.save()
        
        # Create superuser if requested
        if options['create_superuser']:
            if not User.objects.filter(is_superuser=True).exists():
                username = input('Enter superuser username: ')
                email = input('Enter superuser email: ')
                password = input('Enter superuser password: ')
                
                User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'Superuser "{username}" created successfully!')
                )
            else:
                self.stdout.write(
                    self.style.WARNING('Superuser already exists.')
                )
        
        self.stdout.write(
            self.style.SUCCESS('Monitoring setup completed!')
        )
        self.stdout.write('You can now access the admin dashboard at /admin/dashboard/')