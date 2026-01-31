import requests
import socket
import json
from typing import Dict, Any, List
from urllib.parse import quote


def scan_crtsh(target: str) -> Dict[str, Any]:
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=20)  # Increased timeout
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


def scan_urlscan_api(target: str, api_key: str = None) -> Dict[str, Any]:
    """
    URLScan.io API - Detailed URL analysis (OPTIONAL - requires API key)
    """
    if not api_key:
        return {
            'source': 'URLScan API',
            'type': 'skipped',
            'data': {'message': '[WARNING] No API key provided'}
        }
    
    try:
        # Submit URL for scanning
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
        data = {'url': f'http://{target}', 'visibility': 'public'}
        
        submit_response = requests.post(submit_url, headers=headers, json=data, timeout=10)
        
        if submit_response.status_code == 401:
            return {
                'source': 'URLScan API',
                'type': 'error',
                'data': {'error': '[LOCK] Invalid API key'}
            }
        
        submit_response.raise_for_status()
        submit_data = submit_response.json()
        
        # Get scan UUID
        scan_uuid = submit_data.get('uuid')
        result_url = submit_data.get('result')
        
        if not scan_uuid:
            return {
                'source': 'URLScan API',
                'type': 'error',
                'data': {'error': 'Failed to submit scan'}
            }
        
        # Wait a bit for scan to complete
        import time
        time.sleep(3)
        
        # Fetch results
        result_response = requests.get(result_url, timeout=15)
        
        if result_response.status_code == 404:
            return {
                'source': 'URLScan API',
                'type': 'info',
                'data': {
                    'message': 'Scan submitted, results pending',
                    'uuid': scan_uuid,
                    'url': f'https://urlscan.io/result/{scan_uuid}/'
                }
            }
        
        result_response.raise_for_status()
        result_data = result_response.json()
        
        # Extract useful information
        page = result_data.get('page', {})
        stats = result_data.get('stats', {})
        
        return {
            'source': 'URLScan API',
            'type': 'url_analysis',
            'data': {
                'url': page.get('url'),
                'domain': page.get('domain'),
                'ip': page.get('ip'),
                'country': page.get('country'),
                'city': page.get('city'),
                'server': page.get('server'),
                'title': page.get('title'),
                'ptr': page.get('ptr'),
                'tls_issuer': page.get('tlsIssuer'),
                'tls_age': page.get('tlsAge'),
                'malicious': stats.get('malicious', 0),
                'requests': stats.get('requests', 0),
                'domains': stats.get('domains', 0),
                'scan_url': f'https://urlscan.io/result/{scan_uuid}/',
                'screenshot_url': submit_data.get('screenshotURL')
            }
        }
    
    except requests.exceptions.Timeout:
        return {
            'source': 'URLScan API',
            'type': 'error',
            'data': {'error': 'Request timeout - scan may still be processing'}
        }
    except Exception as e:
        return {
            'source': 'URLScan API',
            'type': 'error',
            'data': {'error': str(e)[:100]}
        }



def scan_archive_org(target: str) -> Dict[str, Any]:
    """
    Archive.org Wayback Machine - Check for historical snapshots
    """
    try:
        url = f"http://archive.org/wayback/available?url={target}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
            closest = data["archived_snapshots"]["closest"]
            archive_url = closest.get('url', '')
            timestamp = closest.get('timestamp', '')
            
            return {
                'source': 'Archive.org',
                'type': 'archive',
                'data': {
                    'available': True,
                    'last_snapshot': timestamp,
                    'url': archive_url,
                    'formatted': f"[OK] Archive found! Last snapshot: {timestamp}"
                }
            }
        
        return {
            'source': 'Archive.org',
            'type': 'info',
            'data': {
                'available': False,
                'message': 'No archive records found'
            }
        }
    
    except requests.exceptions.RequestException as e:
        return {
            'source': 'Archive.org',
            'type': 'error',
            'data': {'error': f'Connection error: {str(e)[:50]}'}
        }
    except Exception as e:
        return {
            'source': 'Archive.org',
            'type': 'error',
            'data': {'error': str(e)[:50]}
        }


def scan_google_dorks(target: str) -> Dict[str, Any]:
    """
    Generate Google Dork search queries for OSINT
    """
    try:
        from urllib.parse import quote
        
        dorks = [
            f"site:{target} ext:pdf",
            f"site:{target} inurl:admin",
            f"site:{target} ext:xml | ext:conf | ext:cnf",
            f"site:{target} inurl:login",
            f"site:{target} pastebin",
            f"site:{target} ext:sql",
            f"site:{target} ext:env",
            f"site:{target} intitle:index.of"
        ]
        
        # Create clickable Google search URLs
        dork_urls = []
        for dork in dorks:
            safe_query = quote(dork)
            google_url = f"https://www.google.com/search?q={safe_query}"
            dork_urls.append({
                'query': dork,
                'url': google_url
            })
        
        return {
            'source': 'Google Dorks',
            'type': 'dorks',
            'data': {
                'dorks': dork_urls,
                'count': len(dork_urls)
            }
        }
    
    except Exception as e:
        return {
            'source': 'Google Dorks',
            'type': 'error',
            'data': {'error': str(e)[:50]}
        }


def scan_http_headers(target: str) -> Dict[str, Any]:
    """
    HTTP Headers Analysis - Technology Detection (Basic Wappalyzer)
    """
    try:
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                response.raise_for_status()
                
                headers = response.headers
                
                return {
                    'source': 'HTTP Headers',
                    'type': 'technology',
                    'data': {
                        'server': headers.get('Server', 'Hidden'),
                        'powered_by': headers.get('X-Powered-By', 'Unknown'),
                        'content_type': headers.get('Content-Type', 'Unknown'),
                        'framework': headers.get('X-Framework', 'Unknown'),
                        'status_code': response.status_code,
                        'protocol': protocol.upper()
                    }
                }
            except:
                continue
        
        return {
            'source': 'HTTP Headers',
            'type': 'error',
            'data': {'error': 'Site unreachable'}
        }
    
    except Exception as e:
        return {
            'source': 'HTTP Headers',
            'type': 'error',
            'data': {'error': str(e)[:50]}
        }



def scan_virustotal(target: str, api_key: str = None) -> Dict[str, Any]:
    """VirusTotal Domain/IP Report (OPTIONAL - requires API key)"""
    if not api_key:
        return {
            'source': 'VirusTotal',
            'type': 'skipped',
            'data': {'message': '[WARNING]  No API key', 'help': 'yelbegen -ua virustotal YOUR_KEY'}
        }
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            return {'source': 'VirusTotal', 'type': 'error', 'data': {'error': 'Invalid API key'}}
        if response.status_code == 404:
            return {'source': 'VirusTotal', 'type': 'info', 'data': {'message': 'Not in VT database'}}
        
        response.raise_for_status()
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        results = attributes.get('last_analysis_results', {})
        
        # Extract ACTUAL detections with details
        malicious_detections = []
        suspicious_detections = []
        
        for engine_name,result in results.items():
            category = result.get('category', '')
            verdict = result.get('result', 'flagged')
            
            if category == 'malicious':
                malicious_detections.append({'engine': engine_name, 'verdict': verdict})
            elif category == 'suspicious':
                suspicious_detections.append({'engine': engine_name, 'verdict': verdict})
        
        # Extract additional details
        whois_date = attributes.get('whois_date')
        creation_date = attributes.get('creation_date')
        last_analysis_date = attributes.get('last_analysis_date')
        tags = attributes.get('tags', [])
        popularity = attributes.get('popularity_ranks', {})
        
        return {
            'source': 'VirusTotal',
            'type': 'security',
            'data': {
                'target': target,
                'reputation': attributes.get('reputation', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'malicious_detections': malicious_detections,
                'suspicious_detections': suspicious_detections,
                'categories': attributes.get('categories', {}),
                'tags': tags,
                'whois_date': whois_date,
                'creation_date': creation_date,
                'last_analysis_date': last_analysis_date,
                'popularity': popularity
            }
        }
    except Exception as e:
        return {'source': 'VirusTotal', 'type': 'error', 'data': {'error': str(e)[:80]}}


def scan_securitytrails(target: str, api_key: str = None) -> Dict[str, Any]:
    """SecurityTrails DNS History (OPTIONAL - requires API key)"""
    if not api_key:
        return {
            'source': 'SecurityTrails',
            'type': 'skipped',
            'data': {'message': '[WARNING]  No API key', 'help': 'yelbegen -ua securitytrails YOUR_KEY'}
        }
    
    try:
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        headers = {'APIKEY': api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            return {'source': 'SecurityTrails', 'type': 'error', 'data': {'error': '[LOCK] Invalid API key'}}
        if response.status_code == 429:
            return {'source': 'SecurityTrails', 'type': 'error', 'data': {'error': '[RATE-LIMIT] Rate limit'}}
        
        response.raise_for_status()
        data = response.json()
        subs = data.get('subdomains', [])
        full_subs = [f"{s}.{target}" for s in subs[:50]]
        
        return {
            'source': 'SecurityTrails',
            'type': 'subdomains',
            'data': {'total': len(subs), 'subdomains': full_subs}
        }
    except Exception as e:
        return {'source': 'SecurityTrails', 'type': 'error', 'data': {'error': str(e)[:80]}}


def scan_shodan_api(target: str, api_key: str = None) -> Dict[str, Any]:
    """Shodan API (OPTIONAL - more detailed than free InternetDB)"""
    if not api_key:
        return {
            'source': 'Shodan API',
            'type': 'skipped',
            'data': {'message': '[WARNING]  No API key', 'help': 'yelbegen -ua shodan YOUR_KEY'}
        }
    
    try:
        ip = socket.gethostbyname(target)
        url = f"https://api.shodan.io/shodan/host/{ip}"
        response = requests.get(url, params={'key': api_key}, timeout=15)
        
        if response.status_code == 401:
            return {'source': 'Shodan API', 'type': 'error', 'data': {'error': '[LOCK] Invalid API key'}}
        if response.status_code == 404:
            return {'source': 'Shodan API', 'type': 'info', 'data': {'message': 'No info available'}}
        
        response.raise_for_status()
        data = response.json()
        
        return {
            'source': 'Shodan API',
            'type': 'host_info',
            'data': {
                'ip': ip,
                'ports': data.get('ports', []),
                'vulns': list(data.get('vulns', [])),
                'os': data.get('os'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'asn': data.get('asn'),
                'city': data.get('city'),
                'country_name': data.get('country_name'),
                'last_update': data.get('last_update'),
                'hostnames': data.get('hostnames', []),
                'domains': data.get('domains', []),
                'tags': data.get('tags', [])
            }
        }
    except socket.gaierror:
        return {'source': 'Shodan API', 'type': 'error', 'data': {'error': 'DNS failed'}}
    except Exception as e:
        return {'source': 'Shodan API', 'type': 'error', 'data': {'error': str(e)[:80]}}





def scan_rapiddns(target: str) -> Dict[str, Any]:
    """
    RapidDNS.io - Fast subdomain enumeration (FREE)
    """
    try:
        url = f"https://rapiddns.io/subdomain/{target}?full=1"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # Parse HTML to extract subdomains
        import re
        subdomains = set()
        # RapidDNS shows subdomains in table rows
        pattern = r'<td>([a-zA-Z0-9.-]+\.' + re.escape(target) + r')</td>'
        matches = re.findall(pattern, response.text)
        subdomains.update(matches)
        
        return {
            'source': 'RapidDNS.io',
            'type': 'subdomains',
            'data': {
                'count': len(subdomains),
                'subdomains': sorted(list(subdomains))[:50]
            }
        }
    except Exception as e:
        return {
            'source': 'RapidDNS.io',
            'type': 'error',
            'data': {'error': str(e)[:80]}
        }


def scan_threatminer(target: str) -> Dict[str, Any]:
    """
    ThreatMiner - Threat intelligence data (FREE)
    """
    try:
        # Get domain report
        url = f"https://api.threatminer.org/v2/domain.php?q={target}&rt=5"
        response = requests.get(url, timeout=10)
        
        # Handle specific HTTP errors
        if response.status_code == 500:
            return {
                'source': 'ThreatMiner',
                'type': 'error',
                'data': {'error': 'Service temporarily unavailable'}
            }
        
        response.raise_for_status()
        data = response.json()
        
        if data.get('status_code') != '200':
            return {
                'source': 'ThreatMiner',
                'type': 'info',
                'data': {'message': 'No threat data available'}
            }
        
        results = data.get('results', [])
        
        return {
            'source': 'ThreatMiner',
            'type': 'threat_intel',
            'data': {
                'subdomains': results[:30] if results else [],
                'count': len(results)
            }
        }
    except requests.exceptions.Timeout:
        return {
            'source': 'ThreatMiner',
            'type': 'error',
            'data': {'error': 'Request timeout'}
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'ThreatMiner',
            'type': 'error',
            'data': {'error': f'Connection error: {str(e)[:50]}'}
        }
    except Exception as e:
        return {
            'source': 'ThreatMiner',
            'type': 'error',
            'data': {'error': str(e)[:80]}
        }


def scan_anubisdb(target: str) -> Dict[str, Any]:
    """
    AnubisDB - Subdomain enumeration (FREE)
    """
    try:
        url = f"https://jonlu.ca/anubis/subdomains/{target}"
        response = requests.get(url, timeout=10)
        
        # Handle specific HTTP errors
        if response.status_code == 404:
            return {
                'source': 'AnubisDB',
                'type': 'info',
                'data': {'message': 'No subdomains found'}
            }
        
        if response.status_code >= 500:
            return {
                'source': 'AnubisDB',
                'type': 'error',
                'data': {'error': 'Service temporarily unavailable'}
            }
        
        response.raise_for_status()
        subdomains = response.json()
        
        # Handle empty results
        if not subdomains or len(subdomains) == 0:
            return {
                'source': 'AnubisDB',
                'type': 'info',
                'data': {'message': 'No subdomains found'}
            }
        
        return {
            'source': 'AnubisDB',
            'type': 'subdomains',
            'data': {
                'count': len(subdomains),
                'subdomains': sorted(subdomains)[:50]
            }
        }
    except requests.exceptions.Timeout:
        return {
            'source': 'AnubisDB',
            'type': 'error',
            'data': {'error': 'Request timeout'}
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'AnubisDB',
            'type': 'error',
            'data': {'error': f'Connection error: {str(e)[:50]}'}
        }
    except json.JSONDecodeError:
        return {
            'source': 'AnubisDB',
            'type': 'error',
            'data': {'error': 'Invalid response format'}
        }
    except Exception as e:
        return {
            'source': 'AnubisDB',
            'type': 'error',
            'data': {'error': str(e)[:80]}
        }


def scan_greynoise(target: str) -> Dict[str, Any]:
    """
    GreyNoise Community API - IP reputation (FREE)
    """
    try:
        # Resolve domain to IP if needed
        ip = target
        if not _is_valid_ip(target):
            ip = socket.gethostbyname(target)
        
        url = f"https://api.greynoise.io/v3/community/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'source': 'GreyNoise',
            'type': 'ip_reputation',
            'data': {
                'ip': data.get('ip', ip),
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'classification': data.get('classification', 'unknown'),
                'name': data.get('name', 'N/A'),
                'link': data.get('link', '')
            }
        }
    except Exception as e:
        return {
            'source': 'GreyNoise',
            'type': 'error',
            'data': {'error': str(e)[:80]}
        }


def scan_google_safebrowsing(target: str, api_key: str = None) -> Dict[str, Any]:
    """Google Safe Browsing API (OPTIONAL - requires API key)"""
    if not api_key:
        return {
            'source': 'Google Safe Browsing',
            'type': 'skipped',
            'data': {'message': '[WARNING] No API key', 'help': 'yelbegen -ua google_safebrowsing YOUR_KEY'}
        }
    
    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "yelbegen",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{target}"},
                    {"url": f"https://{target}"}
                ]
            }
        }
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code != 200:
            return {'source': 'Google Safe Browsing', 'type': 'error', 'data': {'error': f'API Error: {response.status_code}'}}
        
        data = response.json()
        matches = data.get('matches', [])
        
        return {
            'source': 'Google Safe Browsing',
            'type': 'security',
            'data': {
                'safe': len(matches) == 0,
                'matches': matches,
                'count': len(matches)
            }
        }
    except Exception as e:
        return {'source': 'Google Safe Browsing', 'type': 'error', 'data': {'error': str(e)[:100]}}


def scan_binaryedge(target: str, api_key: str = None) -> Dict[str, Any]:
    """BinaryEdge API (OPTIONAL - requires API key)"""
    if not api_key:
        return {
            'source': 'BinaryEdge',
            'type': 'skipped',
            'data': {'message': '[WARNING] No API key', 'help': 'yelbegen -ua binaryedge YOUR_KEY'}
        }
    
    try:
        # Check if target is IP or Domain to decide endpoint
        is_ip = _is_valid_ip(target)
        if not is_ip:
            # Resolve to IP for host details, or use domain endpoints
            # For free tier, v2/query/datastore/ is versatile but v2/services/ip/ is good for host details
            # Let's try to resolve IP first
            try:
                ip = socket.gethostbyname(target)
                target_query = ip
            except:
                return {'source': 'BinaryEdge', 'type': 'error', 'data': {'error': 'Could not resolve domain'}}
        else:
            target_query = target
            
        url = f"https://api.binaryedge.io/v2/query/ip/{target_query}"
        headers = {'X-Key': api_key}
        
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 401:
            return {'source': 'BinaryEdge', 'type': 'error', 'data': {'error': 'Invalid API name/key'}}
        if response.status_code == 404:
            return {'source': 'BinaryEdge', 'type': 'info', 'data': {'message': 'No data found'}}
        
        response.raise_for_status()
        data = response.json()
        
        events = data.get('events', [])
        ports = set()
        for event in events:
            for result in event.get('results', []):
                ports.add(result.get('target', {}).get('port'))
        
        return {
            'source': 'BinaryEdge',
            'type': 'host_info',
            'data': {
                'ip': data.get('query'),
                'ports': sorted(list(ports)),
                'events_count': len(events)
            }
        }
        
    except Exception as e:
        return {'source': 'BinaryEdge', 'type': 'error', 'data': {'error': str(e)[:100]}}


def scan_hunter(target: str, api_key: str = None) -> Dict[str, Any]:
    """Hunter.io API (OPTIONAL - requires API key)"""
    if not api_key:
        return {
            'source': 'Hunter.io',
            'type': 'skipped',
            'data': {'message': '[WARNING] No API key', 'help': 'yelbegen -ua hunter YOUR_KEY'}
        }
    
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={api_key}&limit=10"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 401:
            return {'source': 'Hunter.io', 'type': 'error', 'data': {'error': 'Invalid API key'}}
        
        # Hunter returns 200 even for errors in meta, usually
        data = response.json()
        
        if 'errors' in data:
            return {'source': 'Hunter.io', 'type': 'error', 'data': {'error': str(data['errors'][0].get('details'))}}
            
        data = data.get('data', {})
        
        return {
            'source': 'Hunter.io',
            'type': 'email_discovery',
            'data': {
                'domain': target,
                'organization': data.get('organization'),
                'pattern': data.get('pattern'),
                'emails': data.get('emails', []),
                'count': len(data.get('emails', []))
            }
        }
    except Exception as e:
        return {'source': 'Hunter.io', 'type': 'error', 'data': {'error': str(e)[:100]}}


AVAILABLE_MODULES = {
    # FREE MODULES (always enabled)
    'crt.sh': {
        'name': 'crt.sh',
        'description': 'Certificate Transparency Logs',
        'function': scan_crtsh,
        'enabled': True,
        'requires_key': False
    },
    'InternetDB': {
        'name': 'InternetDB',
        'description': 'Shodan InternetDB (Free)',
        'function': scan_internetdb,
        'enabled': True,
        'requires_key': False
    },
    'GeoIP': {
        'name': 'GeoIP',
        'description': 'IP Geolocation',
        'function': scan_geoip,
        'enabled': True,
        'requires_key': False
    },
    'HackerTarget': {
        'name': 'HackerTarget',
        'description': 'DNS Records',
        'function': scan_hackertarget_dns, # Corrected function name
        'enabled': True,
        'requires_key': False
    },
    'URLScan': {
        'name': 'URLScan',
        'description': 'URL Scan History',
        'function': scan_urlscan,
        'enabled': True,
        'requires_key': False
    },
    'AlienVault': {
        'name': 'AlienVault OTX',
        'description': 'Threat Intelligence',
        'function': scan_alienvault_otx,
        'enabled': True,
        'requires_key': False
    },
    'Archive.org': {
        'name': 'Archive.org',
        'description': 'Wayback Machine History',
        'function': scan_archive_org,
        'enabled': True,
        'requires_key': False
    },
    'GoogleDorks': {
        'name': 'Google Dorks',
        'description': 'OSINT Search Queries',
        'function': scan_google_dorks,
        'enabled': True,
        'requires_key': False
    },
    'HTTPHeaders': {
        'name': 'HTTP Headers',
        'description': 'Technology Detection',
        'function': scan_http_headers,
        'enabled': True,
        'requires_key': False
    },
    
    'RapidDNS': {
        'name': 'RapidDNS.io',
        'description': 'Fast Subdomain Enumeration',
        'function': scan_rapiddns,
        'enabled': True,
        'requires_key': False
    },
    
    'ThreatMiner': {
        'name': 'ThreatMiner',
        'description': 'Threat Intelligence',
        'function': scan_threatminer,
        'enabled': True,
        'requires_key': False
    },
    
    'AnubisDB': {
        'name': 'AnubisDB',
        'description': 'Subdomain Discovery',
        'function': scan_anubisdb,
        'enabled': True,
        'requires_key': False
    },
    
    'GreyNoise': {
        'name': 'GreyNoise',
        'description': 'IP Reputation',
        'function': scan_greynoise,
        'enabled': True,
        'requires_key': False
    },

    # OPTIONAL API MODULES (require API keys, enabled only in full mode)
    'VirusTotal': {
        'name': 'VirusTotal',
        'description': 'Security & Reputation Analysis',
        'function': scan_virustotal,
        'enabled': False,
        'requires_key': True
    },
    'SecurityTrails': {
        'name': 'SecurityTrails',
        'description': 'DNS History & Subdomains',
        'function': scan_securitytrails,
        'enabled': False,
        'requires_key': True
    },
    'Shodan': {
        'name': 'Shodan API',
        'description': 'Comprehensive Host Information',
        'function': scan_shodan_api,
        'enabled': False,
        'requires_key': True
    },
    'GoogleSafeBrowsing': {
        'name': 'Google Safe Browsing',
        'description': 'Check for malware/phishing',
        'function': scan_google_safebrowsing,
        'enabled': False,
        'requires_key': True
    },
    'BinaryEdge': {
        'name': 'BinaryEdge',
        'description': 'Internet Scanning Data',
        'function': scan_binaryedge,
        'enabled': False,
        'requires_key': True
    },
    'Hunter': {
        'name': 'Hunter.io',
        'description': 'Email Discovery',
        'function': scan_hunter,
        'enabled': False,
        'requires_key': True
    }
}


