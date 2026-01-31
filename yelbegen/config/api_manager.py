"""API Key Management CLI"""
from pathlib import Path


class APIManager:
    """Manage API keys via CLI"""
    
    ENV_FILE = Path(__file__).parent.parent.parent / '.env'
    
    VALID_SERVICES = {
        'virustotal': 'VIRUSTOTAL_API_KEY',
        'securitytrails': 'SECURITYTRAILS_API_KEY',
        'shodan': 'SHODAN_API_KEY',
        'urlscan': 'URLSCAN_API_KEY',
        'google_safebrowsing': 'GOOGLE_SAFEBROWSING_KEY',
        'binaryedge': 'BINARYEDGE_KEY',
        'hunter': 'HUNTER_KEY'
    }
    
    @classmethod
    def upload_key(cls, service, api_key):
        """
        Add/update API key
        Usage: yelbegen -ua virustotal ABC123
        """
        service = service.lower()
        
        if service not in cls.VALID_SERVICES:
            print(f"[X] Unknown service: {service}")
            print(f"Valid services: {', '.join(cls.VALID_SERVICES.keys())}")
            return False
        
        env_var = cls.VALID_SERVICES[service]
        
        # Read existing .env
        lines = []
        if cls.ENV_FILE.exists():
            lines = cls.ENV_FILE.read_text().splitlines()
        
        # Update or append
        updated = False
        for i, line in enumerate(lines):
            if line.startswith(f'{env_var}='):
                lines[i] = f'{env_var}={api_key}'
                updated = True
                break
        
        if not updated:
            lines.append(f'{env_var}={api_key}')
        
        # Write back
        cls.ENV_FILE.parent.mkdir(exist_ok=True)
        cls.ENV_FILE.write_text('\n'.join(lines) + '\n')
        print(f"[OK] API key for {service} saved to .env!")
        return True
    
    @classmethod
    def list_keys(cls):
        """Show which keys are configured"""
        from .settings import config
        
        print("\n[KEY] API Key Status:\n")
        for service in cls.VALID_SERVICES:
            status = "[OK] Configured" if config.has_key(service) else "[X] Not set"
            print(f"  {service.capitalize()}: {status}")
        print()
        
        available = config.get_available_services()
        if available:
            print(f"[TIP] Use -f flag to enable: {', '.join(available)}\n")
        else:
            print("[TIP] Add keys with: yelbegen -ua <service> <key>\n")
