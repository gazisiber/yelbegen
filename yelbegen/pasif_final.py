import argparse
import time
import socket
import requests
import whois
import dns.resolver
import urllib.parse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box
from rich.text import Text

def scan_geoip(target):
    """IP ve Konum Bilgisi - Link Açıkça Gösteriliyor"""
    try:
        try:
            ip_addr = socket.gethostbyname(target)
        except:
            ip_addr = target
        
        response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            lat = data.get('lat')
            lon = data.get('lon')
            map_url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            
            # Linki hem gizli link hem de açık metin olarak veriyoruz
            return "geoip", f"[bold]IP:[/bold] {data.get('query')}\n[bold]Ülke:[/bold] {data.get('country')}\n[bold]Şehir:[/bold] {data.get('city')}\n[bold]ISP:[/bold] {data.get('isp')}\n\n[link={map_url}][bold cyan]🌍 Haritada Aç (CTRL+Tık)[/bold cyan][/link]\n[dim]Link: {map_url}[/dim]"
        return "geoip", "Bulunamadı"
    except Exception as e:
        return "geoip", f"Hata: {str(e)}"

def scan_whois(target):
    try:
        w = whois.whois(target)
        registrar = w.registrar if w.registrar else "Bilinmiyor"
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return "whois", f"[bold]Registrar:[/bold] {registrar}\n[bold]Oluşturma:[/bold] {creation}\n[bold]Org:[/bold] {w.org}"
    except Exception:
        return "whois", "Whois verisi gizli veya çekilemedi."

def scan_dns(target):
    records = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    for r_type in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = resolver.resolve(target, r_type)
            for rdata in answers:
                txt = rdata.to_text()
                if len(txt) > 50: txt = txt[:47] + "..." 
                records.append(f"[{r_type}] {txt}")
        except: continue
    return "dns", records if records else ["Kayıt Yok"]

def scan_subdomains(target):
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name_value = entry['name_value']
                sub_entries = name_value.split('\n')
                for sub in sub_entries:
                    if "*" not in sub and sub != target: subs.add(sub)
            return "subdomains", list(subs)[:10]
        return "subdomains", ["Veri alınamadı"]
    except Exception:
        return "subdomains", ["Zaman aşımı"]

def scan_archive(target):
    """Archive.org - Link Açıkça Gösteriliyor"""
    try:
        url = f"http://archive.org/wayback/available?url={target}"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
            closest = data["archived_snapshots"]["closest"]
            archive_url = closest['url']
            # DEĞİŞİKLİK: Linki açıkça yazdırdık
            return "archive", f"[green]Kayıt Var![/green]\nSon: {closest['timestamp']}\n\n[link={archive_url}][bold blue]🔗 Arşivi Aç (CTRL+Tık)[/bold blue][/link]\n[dim]Link: {archive_url}[/dim]"
        return "archive", "[red]Arşiv kaydı bulunamadı.[/red]"
    except:
        return "archive", "Arşiv bağlantı hatası"

def scan_headers(target):
    try:
        resp = requests.get(f"http://{target}", timeout=5)
        headers = resp.headers
        server = headers.get('Server', 'Gizli')
        powered = headers.get('X-Powered-By', 'Bilinmiyor')
        return "tech", f"[bold]Server:[/bold] {server}\n[bold]Teknoloji:[/bold] {powered}"
    except:
        return "tech", "Siteye erişilemedi"

def generate_dorks(target):
    dorks = [
        f"site:{target} ext:pdf",
        f"site:{target} inurl:admin",
        f"site:{target} ext:xml | ext:conf | ext:cnf",
        f"site:{target} pastebin"
    ]
    formatted_dorks = []
    for dork in dorks:
        safe_query = urllib.parse.quote(dork)
        google_url = f"https://www.google.com/search?q={safe_query}"
        # Dorklar için de aynı şekilde
        formatted_dorks.append(f"[link={google_url}]🔍 {dork}[/link]")
        
    return "dorks", formatted_dorks

# --- CONFIG VE API YÖNETİMİ ---

def load_api_keys():
    """Config dosyasından API key'leri yükler"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

# --- GÜNCELLENMİŞ FONKSİYONLAR (GARANTİ LİNK) ---

def scan_virustotal(target, api_key):
    """VirusTotal - Domain güvenlik analizi"""
    if not api_key:
        return "virustotal", "[yellow]API key girilmemiş[/yellow]\n[dim]config.json dosyasına key ekleyin[/dim]"
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            return "virustotal", "[red]Geçersiz API key[/red]"
        elif response.status_code == 404:
            return "virustotal", "[yellow]Domain bulunamadı[/yellow]"
        elif response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            clean = stats.get('harmless', 0)
            
            vt_url = f"https://www.virustotal.com/gui/domain/{target}"
            
            if malicious > 0:
                color = "red"
                status = "⚠️ TEHLİKELİ"
            elif suspicious > 0:
                color = "yellow"
                status = "⚠️ ŞÜPHELİ"
            else:
                color = "green"
                status = "✓ TEMİZ"
            
            return "virustotal", f"[bold {color}]{status}[/bold {color}]\n\n[bold]Kötücül:[/bold] {malicious}\n[bold]Şüpheli:[/bold] {suspicious}\n[bold]Temiz:[/bold] {clean}\n\n[link={vt_url}][bold cyan]🔍 VirusTotal'da Aç[/bold cyan][/link]\n[dim]{vt_url}[/dim]"
        else:
            return "virustotal", f"[red]HTTP {response.status_code}[/red]"
            
    except requests.Timeout:
        return "virustotal", "[red]Zaman aşımı[/red]"
    except Exception as e:
        return "virustotal", f"[red]Hata: {str(e)[:50]}[/red]"

def scan_urlscan(target, api_key):
    """URLScan.io - URL analizi ve screenshot"""
    if not api_key:
        return "urlscan", "[yellow]API key girilmemiş[/yellow]\n[dim]config.json dosyasına key ekleyin[/dim]"
    
    try:
        # URLScan'e tarama gönder
        url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": api_key}
        data = {"url": f"http://{target}", "visibility": "public"}
        
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        if response.status_code == 401:
            return "urlscan", "[red]Geçersiz API key[/red]"
        elif response.status_code == 200:
            result = response.json()
            scan_url = result.get('result')
            uuid = result.get('uuid')
            
            return "urlscan", f"[green]✓ Tarama başlatıldı[/green]\n\n[bold]UUID:[/bold] {uuid[:16]}...\n\n[link={scan_url}][bold cyan]🔍 Sonuçları Görüntüle[/bold cyan][/link]\n[dim]{scan_url}[/dim]\n\n[dim]Not: Sonuçlar 10-30 sn içinde hazır olur[/dim]"
        else:
            return "urlscan", f"[red]HTTP {response.status_code}[/red]"
            
    except requests.Timeout:
        return "urlscan", "[red]Zaman aşımı[/red]"
    except Exception as e:
        return "urlscan", f"[red]Hata: {str(e)[:50]}[/red]"

def scan_shodan(target, api_key):
    """Shodan - Port ve servis taraması"""
    if not api_key:
        return "shodan", "[yellow]API key girilmemiş[/yellow]\n[dim]config.json dosyasına key ekleyin[/dim]"
    
    try:
        # Domain'i IP'ye çevir
        try:
            ip_addr = socket.gethostbyname(target)
        except:
            ip_addr = target
        
        url = f"https://api.shodan.io/shodan/host/{ip_addr}?key={api_key}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 401:
            return "shodan", "[red]Geçersiz API key[/red]"
        elif response.status_code == 404:
            return "shodan", "[yellow]Shodan'da veri bulunamadı[/yellow]"
        elif response.status_code == 200:
            data = response.json()
            
            # Açık portlar
            ports = data.get('ports', [])
            port_count = len(ports)
            ports_str = ', '.join(str(p) for p in ports[:5])
            if len(ports) > 5:
                ports_str += f" ... (+{len(ports)-5})"
            
            # Organizasyon ve ISP
            org = data.get('org', 'Bilinmiyor')
            country = data.get('country_name', 'N/A')
            
            # Güvenlik açıkları var mı
            vulns = data.get('vulns', [])
            vuln_count = len(vulns)
            
            shodan_url = f"https://www.shodan.io/host/{ip_addr}"
            
            if vuln_count > 0:
                color = "red"
                status = f"⚠️ {vuln_count} AÇIK TESPİT EDİLDİ"
            else:
                color = "green"
                status = "✓ AÇIK TESPİT EDİLMEDİ"
            
            return "shodan", f"[bold {color}]{status}[/bold {color}]\n\n[bold]IP:[/bold] {ip_addr}\n[bold]Açık Portlar:[/bold] {port_count}\n[dim]{ports_str}[/dim]\n\n[bold]Org:[/bold] {org}\n[bold]Ülke:[/bold] {country}\n\n[link={shodan_url}][bold cyan]🔍 Shodan'da Aç[/bold cyan][/link]\n[dim]{shodan_url}[/dim]"
        else:
            return "shodan", f"[red]HTTP {response.status_code}[/red]"
            
    except requests.Timeout:
        return "shodan", "[red]Zaman aşımı[/red]"
    except Exception as e:
        return "shodan", f"[red]Hata: {str(e)[:50]}[/red]"

def scan_securitytrails(target, api_key):
    """SecurityTrails - DNS geçmişi ve subdomain bilgisi"""
    if not api_key:
        return "securitytrails", "[yellow]API key girilmemiş[/yellow]\n[dim]config.json dosyasına key ekleyin[/dim]"
    
    try:
        url = f"https://api.securitytrails.com/v1/domain/{target}"
        headers = {"APIKEY": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:
            return "securitytrails", "[red]Geçersiz API key[/red]"
        elif response.status_code == 404:
            return "securitytrails", "[yellow]Domain bulunamadı[/yellow]"
        elif response.status_code == 200:
            data = response.json()
            
            # DNS kayıtları sayısı
            current_dns = data.get('current_dns', {})
            a_records = len(current_dns.get('a', {}).get('values', []))
            mx_records = len(current_dns.get('mx', {}).get('values', []))
            ns_records = len(current_dns.get('ns', {}).get('values', []))
            
            # Subdomain sayısı
            subdomain_count = data.get('subdomain_count', 0)
            
            st_url = f"https://securitytrails.com/domain/{target}/dns"
            
            return "securitytrails", f"[bold green]✓ DNS GEÇMİŞİ BULUNDU[/bold green]\n\n[bold]Subdomain Sayısı:[/bold] {subdomain_count}\n[bold]A Kayıtları:[/bold] {a_records}\n[bold]MX Kayıtları:[/bold] {mx_records}\n[bold]NS Kayıtları:[/bold] {ns_records}\n\n[link={st_url}][bold cyan]🔍 SecurityTrails'de Aç[/bold cyan][/link]\n[dim]{st_url}[/dim]"
        else:
            return "securitytrails", f"[red]HTTP {response.status_code}[/red]"
            
    except requests.Timeout:
        return "securitytrails", "[red]Zaman aşımı[/red]"
    except Exception as e:
        return "securitytrails", f"[red]Hata: {str(e)[:50]}[/red]"


# --- UI VE ANA PROGRAM ---

class PassiveScannerThreaded:
    def __init__(self, target, mode='full'):
        self.target = target
        self.mode = mode  # 'basic', 'api', 'full'
        self.api_keys = load_api_keys()
        self.results = {
            "geoip": "...", "whois": "...", "dns": [], 
            "subdomains": [], "archive": "...", "tech": "...", "dorks": [],
            "virustotal": "...", "urlscan": "...", "shodan": "...", "securitytrails": "..."
        }
        self.is_finished = False

    def make_layout(self):
        layout = Layout()
        
        if self.mode == 'basic':
            # Sadece temel taramalar
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="upper", size=10),
                Layout(name="middle"),
                Layout(name="lower", size=8),
                Layout(name="footer", size=3)
            )
            layout["upper"].split_row(
                Layout(name="whois_panel"),
                Layout(name="geoip_panel"),
                Layout(name="tech_panel")
            )
            layout["middle"].split_row(
                Layout(name="dns_panel"),
                Layout(name="subdomain_panel")
            )
            layout["lower"].split_row(
                Layout(name="archive_panel"),
                Layout(name="dork_panel")
            )
        
        elif self.mode == 'api':
            # Sadece API taramalar (2x2 grid)
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="api_top", size=12),
                Layout(name="api_bottom", size=12),
                Layout(name="footer", size=3)
            )
            layout["api_top"].split_row(
                Layout(name="virustotal_panel"),
                Layout(name="urlscan_panel")
            )
            layout["api_bottom"].split_row(
                Layout(name="shodan_panel"),
                Layout(name="securitytrails_panel")
            )
        
        else:  # full
            # Her ikisi de
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="upper", size=10),
                Layout(name="middle"),
                Layout(name="api_section", size=15),
                Layout(name="lower", size=8),
                Layout(name="footer", size=3)
            )
            layout["upper"].split_row(
                Layout(name="whois_panel"),
                Layout(name="geoip_panel"),
                Layout(name="tech_panel")
            )
            layout["middle"].split_row(
                Layout(name="dns_panel"),
                Layout(name="subdomain_panel")
            )
            # 4 API paneli (2x2)
            layout["api_section"].split_column(
                Layout(name="api_top"),
                Layout(name="api_bottom")
            )
            layout["api_top"].split_row(
                Layout(name="virustotal_panel"),
                Layout(name="urlscan_panel")
            )
            layout["api_bottom"].split_row(
                Layout(name="shodan_panel"),
                Layout(name="securitytrails_panel")
            )
            layout["lower"].split_row(
                Layout(name="archive_panel"),
                Layout(name="dork_panel")
            )
        
        return layout

    def update_display(self, layout):
        # Header - mod bilgisi ile
        mode_text = {"basic": "TEMEL TARAMA", "api": "API TARAMA", "full": "TAM TARAMA"}
        layout["header"].update(Panel(f"[bold white on blue] {mode_text.get(self.mode, 'PASİF TARAMA')} [/] - [bold green]{self.target}[/]", box=box.HEAVY))
        
        # Basic mod panelleri (basic ve full modlarda)
        if self.mode in ['basic', 'full']:
            layout["whois_panel"].update(Panel(self.results["whois"], title="Whois", border_style="cyan"))
            layout["geoip_panel"].update(Panel(self.results["geoip"], title="GeoIP / Konum", border_style="magenta"))
            layout["tech_panel"].update(Panel(self.results["tech"], title="Teknoloji (Headers)", border_style="white"))

            dns_table = Table(show_header=False, box=None, padding=(0,1))
            for r in self.results["dns"]: dns_table.add_row(r)
            layout["dns_panel"].update(Panel(dns_table, title="DNS Kayıtları", border_style="yellow"))

            sub_table = Table(show_header=False, box=None, padding=(0,1))
            if self.results["subdomains"]:
                for s in self.results["subdomains"]: sub_table.add_row(s)
            else: sub_table.add_row("Aranıyor...")
            layout["subdomain_panel"].update(Panel(sub_table, title="Subdomainler (crt.sh)", border_style="green"))

            layout["archive_panel"].update(Panel(self.results["archive"], title="Wayback Machine", border_style="red"))
            
            dorks_content = "\n".join(self.results["dorks"]) if self.results["dorks"] else "Hesaplanıyor..."
            layout["dork_panel"].update(Panel(dorks_content, title="Google Dorkları (Tıkla ve Ara)", border_style="blue"))

        # API panelleri (api ve full modlarda)
        if self.mode in ['api', 'full']:
            layout["virustotal_panel"].update(Panel(self.results["virustotal"], title="🛡️ VirusTotal", border_style="bright_red"))
            layout["urlscan_panel"].update(Panel(self.results["urlscan"], title="🔍 URLScan.io", border_style="bright_blue"))
            layout["shodan_panel"].update(Panel(self.results["shodan"], title="🔥 Shodan", border_style="bright_magenta"))
            layout["securitytrails_panel"].update(Panel(self.results["securitytrails"], title="📊 SecurityTrails", border_style="bright_cyan"))

        status = "[bold red]Çalışıyor...[/bold red]" if not self.is_finished else "[bold green]Bitti[/bold green]"
        
        if self.mode == 'full':
            api_status = f" | API Key'ler: {len([k for k in self.api_keys.values() if k])} / 4"
            layout["footer"].update(Panel(f"Durum: {status}{api_status}", box=box.ROUNDED))
        else:
            layout["footer"].update(Panel(f"Durum: {status}", box=box.ROUNDED))

    def run(self):
        layout = self.make_layout()
        with Live(layout, refresh_per_second=4, screen=True):
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = []
                
                # Basic taramalar (basic ve full modlarda)
                if self.mode in ['basic', 'full']:
                    futures.extend([
                        executor.submit(scan_geoip, self.target),
                        executor.submit(scan_whois, self.target),
                        executor.submit(scan_dns, self.target),
                        executor.submit(scan_subdomains, self.target),
                        executor.submit(scan_archive, self.target),
                        executor.submit(scan_headers, self.target),
                        executor.submit(generate_dorks, self.target)
                    ])
                
                # API taramalar (api ve full modlarda)
                if self.mode in ['api', 'full']:
                    futures.extend([
                        executor.submit(scan_virustotal, self.target, self.api_keys.get('virustotal', '')),
                        executor.submit(scan_urlscan, self.target, self.api_keys.get('urlscan', '')),
                        executor.submit(scan_shodan, self.target, self.api_keys.get('shodan', '')),
                        executor.submit(scan_securitytrails, self.target, self.api_keys.get('securitytrails', ''))
                    ])
                for future in as_completed(futures):
                    try:
                        key, value = future.result()
                        self.results[key] = value
                        self.update_display(layout)
                    except: pass
                self.is_finished = True
                self.update_display(layout)
            try:
                while True: time.sleep(1)
            except KeyboardInterrupt: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Pasif OSINT Tarayıcı - Üç farklı mod ile çalışır",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Kullanım Örnekleri:
  python pasif_final.py google.com                 # Tam tarama (varsayılan)
  python pasif_final.py google.com --mode basic    # Sadece temel taramalar (API'siz)
  python pasif_final.py google.com --mode api      # Sadece API taramalar
  python pasif_final.py google.com --mode full     # Hepsi
        """
    )
    parser.add_argument("target", help="Hedef Domain veya IP adresi")
    parser.add_argument(
        "--mode", 
        choices=['basic', 'api', 'full'], 
        default='full',
        help="Tarama modu: basic (API'siz), api (sadece API), full (hepsi, varsayılan)"
    )
    args = parser.parse_args()
    scanner = PassiveScannerThreaded(args.target, mode=args.mode)
    scanner.run()
