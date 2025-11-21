from django.core.management.base import BaseCommand
from cyberattack.monitoring import real_time_monitor
import signal
import sys

class Command(BaseCommand):
    help = 'Start real-time security monitoring service'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='Run as daemon process',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting real-time security monitoring...')
        )
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            self.stdout.write(
                self.style.WARNING('Stopping monitoring service...')
            )
            real_time_monitor.stop_monitoring()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Start monitoring
            real_time_monitor.start_monitoring()
            
            self.stdout.write(
                self.style.SUCCESS('Monitoring service started successfully!')
            )
            self.stdout.write('Press Ctrl+C to stop...')
            
            # Keep the process running
            if options['daemon']:
                import time
                while real_time_monitor.running:
                    time.sleep(1)
            else:
                signal.pause()
                
        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING('Monitoring service stopped.')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error starting monitoring: {str(e)}')
            )