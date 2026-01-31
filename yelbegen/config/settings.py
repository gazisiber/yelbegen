"""Central configuration with API key support"""
from pathlib import Path
from dotenv import load_dotenv
import os


class Config:
    """Central configuration with API key support"""
    
    # Project root
    ROOT_DIR = Path(__file__).parent.parent.parent
    ENV_FILE = ROOT_DIR / '.env'
    
    def __init__(self):
        # Load .env if exists
        if self.ENV_FILE.exists():
            load_dotenv(self.ENV_FILE)
    
    # API Keys (returns None if not set)
    @property
    def virustotal_key(self):
        return os.getenv('VIRUSTOTAL_API_KEY')
    
    @property
    def securitytrails_key(self):
        return os.getenv('SECURITYTRAILS_API_KEY')
    
    @property
    def shodan_key(self):
        return os.getenv('SHODAN_API_KEY')
    
    @property
    def urlscan_key(self):
        return os.getenv('URLSCAN_API_KEY')
    
    @property
    def google_safebrowsing_key(self):
        return os.getenv('GOOGLE_SAFEBROWSING_KEY')
    
    @property
    def binaryedge_key(self):
        return os.getenv('BINARYEDGE_KEY')
    
    @property
    def hunter_key(self):
        return os.getenv('HUNTER_KEY')
    
    def has_key(self, service):
        """Check if API key exists for a service"""
        service_map = {
            'virustotal': 'virustotal_key',
            'securitytrails': 'securitytrails_key',
            'shodan': 'shodan_key',
            'urlscan': 'urlscan_key',
            'google_safebrowsing': 'google_safebrowsing_key',
            'binaryedge': 'binaryedge_key',
            'hunter': 'hunter_key'
        }
        attr = service_map.get(service.lower())
        if not attr:
            return False
        return getattr(self, attr) is not None
    
    def get_available_services(self):
        """List services with valid keys"""
        services = ['virustotal', 'securitytrails', 'shodan', 'urlscan', 'google_safebrowsing', 'binaryedge', 'hunter']
        return [s for s in services if self.has_key(s)]


# Singleton instance
config = Config()
