import argparse
import time
import socket
import requests
import whois
import dns.resolver
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box
from rich.text import Text

# --- GÜNCELLENMİŞ FONKSİYONLAR (GARANTİ LİNK) ---

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
            
            # DEĞİŞİKLİK: Linki hem gizli link hem de açık metin olarak veriyoruz
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

# --- UI VE ANA PROGRAM ---

class PassiveScannerThreaded:
    def __init__(self, target):
        self.target = target
        self.results = {
            "geoip": "...", "whois": "...", "dns": [], 
            "subdomains": [], "archive": "...", "tech": "...", "dorks": []
        }
        self.is_finished = False

    def make_layout(self):
        layout = Layout()
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
        return layout

    def update_display(self, layout):
        layout["header"].update(Panel(f"[bold white on blue] PRO PASİF TARAMA ARACI (GARANTİ LİNK) [/] - [bold green]{self.target}[/]", box=box.HEAVY))
        
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

        status = "[bold red]Çalışıyor...[/bold red]" if not self.is_finished else "[bold green]Bitti[/bold green]"
        layout["footer"].update(Panel(f"Durum: {status} | Tıklanmıyorsa linki kopyalayın", box=box.ROUNDED))

    def run(self):
        layout = self.make_layout()
        with Live(layout, refresh_per_second=4, screen=True):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(scan_geoip, self.target),
                    executor.submit(scan_whois, self.target),
                    executor.submit(scan_dns, self.target),
                    executor.submit(scan_subdomains, self.target),
                    executor.submit(scan_archive, self.target),
                    executor.submit(scan_headers, self.target),
                    executor.submit(generate_dorks, self.target)
                ]
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
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Hedef Domain")
    args = parser.parse_args()
    scanner = PassiveScannerThreaded(args.target)
    scanner.run()
