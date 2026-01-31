import requests
import socket
import json
from typing import Dict, Any, List
from urllib.parse import quote


def scan_crtsh(target: str) -> Dict[str, Any]:
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for subdomain in name_value.split('\n'):
                subdomain = subdomain.strip()
                if subdomain and subdomain not in subdomains:
                    subdomains.add(subdomain)
        
        return {
            'source': 'crt.sh',
            'type': 'subdomains',
            'data': {
                'total_certificates': len(data),
                'unique_subdomains': sorted(list(subdomains)),
                'count': len(subdomains)
            }
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'crt.sh',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except json.JSONDecodeError:
        return {
            'source': 'crt.sh',
            'type': 'error',
            'data': {'error': 'Invalid JSON response'}
        }
    except Exception as e:
        return {
            'source': 'crt.sh',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def scan_internetdb(target: str) -> Dict[str, Any]:
    try:
        ip = target
        if not _is_valid_ip(target):
            ip = socket.gethostbyname(target)
        
        url = f"https://internetdb.shodan.io/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'source': 'InternetDB',
            'type': 'ip_info',
            'data': {
                'ip': ip,
                'hostname': data.get('hostnames', []),
                'ports': data.get('ports', []),
                'cpes': data.get('cpes', []),
                'vulns': data.get('vulns', []),
                'tags': data.get('tags', [])
            }
        }
    except socket.gaierror:
        return {
            'source': 'InternetDB',
            'type': 'error',
            'data': {'error': f'Could not resolve hostname: {target}'}
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'InternetDB',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except Exception as e:
        return {
            'source': 'InternetDB',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def scan_geoip(target: str) -> Dict[str, Any]:
    try:
        ip = target
        if not _is_valid_ip(target):
            ip = socket.gethostbyname(target)
        
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'fail':
            return {
                'source': 'GeoIP',
                'type': 'error',
                'data': {'error': data.get('message', 'Unknown error')}
            }
        
        return {
            'source': 'GeoIP',
            'type': 'geolocation',
            'data': {
                'ip': ip,
                'country': data.get('country', 'N/A'),
                'country_code': data.get('countryCode', 'N/A'),
                'region': data.get('regionName', 'N/A'),
                'city': data.get('city', 'N/A'),
                'zip': data.get('zip', 'N/A'),
                'lat': data.get('lat', 'N/A'),
                'lon': data.get('lon', 'N/A'),
                'timezone': data.get('timezone', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'org': data.get('org', 'N/A'),
                'as': data.get('as', 'N/A')
            }
        }
    except socket.gaierror:
        return {
            'source': 'GeoIP',
            'type': 'error',
            'data': {'error': f'Could not resolve hostname: {target}'}
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'GeoIP',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except Exception as e:
        return {
            'source': 'GeoIP',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def scan_hackertarget_dns(target: str) -> Dict[str, Any]:
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={target}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.text
        
        if 'error' in data.lower():
            return {
                'source': 'HackerTarget DNS',
                'type': 'error',
                'data': {'error': data}
            }
        
        dns_records = [line.strip() for line in data.split('\n') if line.strip()]
        
        return {
            'source': 'HackerTarget DNS',
            'type': 'dns_records',
            'data': {
                'target': target,
                'records': dns_records,
                'count': len(dns_records)
            }
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'HackerTarget DNS',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except Exception as e:
        return {
            'source': 'HackerTarget DNS',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def scan_alienvault_otx(target: str) -> Dict[str, Any]:
    try:
        url = f"https://otx.alienvault.com/otxapi/indicators/domain/whois/{target}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'source': 'AlienVault OTX',
            'type': 'threat_intel',
            'data': {
                'target': target,
                'whois_data': data
            }
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'AlienVault OTX',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except json.JSONDecodeError:
        return {
            'source': 'AlienVault OTX',
            'type': 'error',
            'data': {'error': 'Invalid JSON response'}
        }
    except Exception as e:
        return {
            'source': 'AlienVault OTX',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def scan_urlscan(target: str) -> Dict[str, Any]:
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        results = data.get('results', [])
        
        return {
            'source': 'URLScan',
            'type': 'web_analysis',
            'data': {
                'target': target,
                'total_results': data.get('total', 0),
                'scans': results[:10],
                'count': len(results[:10])
            }
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'URLScan',
            'type': 'error',
            'data': {'error': str(e)}
        }
    except json.JSONDecodeError:
        return {
            'source': 'URLScan',
            'type': 'error',
            'data': {'error': 'Invalid JSON response'}
        }
    except Exception as e:
        return {
            'source': 'URLScan',
            'type': 'error',
            'data': {'error': f'Unexpected error: {str(e)}'}
        }


def _is_valid_ip(ip_str: str) -> bool:
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False


AVAILABLE_MODULES = {
    'crt.sh': {
        'name': 'crt.sh',
        'description': 'Certificate Transparency',
        'function': scan_crtsh,
        'enabled': True
    },
    'InternetDB': {
        'name': 'InternetDB',
        'description': 'Shodan InternetDB',
        'function': scan_internetdb,
        'enabled': True
    },
    'GeoIP': {
        'name': 'GeoIP',
        'description': 'IP Geolocation',
        'function': scan_geoip,
        'enabled': True
    },
    'HackerTarget': {
        'name': 'HackerTarget DNS',
        'description': 'DNS Records',
        'function': scan_hackertarget_dns,
        'enabled': True
    },
    'AlienVault': {
        'name': 'AlienVault OTX',
        'description': 'Threat Intelligence',
        'function': scan_alienvault_otx,
        'enabled': True
    },
    'URLScan': {
        'name': 'URLScan',
        'description': 'Web Scan History',
        'function': scan_urlscan,
        'enabled': True
    }
}
