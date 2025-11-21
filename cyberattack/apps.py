from django.apps import AppConfig

class CyberattackConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cyberattack'
    
    def ready(self):
        # Import monitoring to initialize the system
        # Don't start monitoring during migrations or initial setup
        pass