import argparse
import time
import socket
import requests
import whois
import dns.resolver
import json
import urllib.parse
from concurrent.futures import ProcessPoolExecutor, as_completed
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box
from rich.text import Text

console = Console()

# --- IMPROVED FUNCTIONS (WITH CLICKABLE LINKS) ---

def scan_geoip(target):
    """IP and Geolocation Information - With Clickable Links - Improved"""
    try:
        # Resolve IP
        try:
            ip_addr = socket.gethostbyname(target)
        except socket.gaierror:
            return "geoip", f"[red]DNS resolution failed: {target}[/red]"
        
        response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') == 'fail':
            return "geoip", f"[red]GeoIP error: {data.get('message', 'Unknown error')}[/red]"
        
        if data.get('status') == 'success':
            lat = data.get('lat')
            lon = data.get('lon')
            
            # Build result with proper null checks
            result_text = (
                f"[bold]IP:[/bold] {data.get('query', ip_addr)}\n"
                f"[bold]Country:[/bold] {data.get('country', 'N/A')}\n"
                f"[bold]City:[/bold] {data.get('city', 'N/A')}\n"
                f"[bold]ISP:[/bold] {data.get('isp', 'N/A')}"
            )
            
            # Only add map link if coordinates are valid
            if lat is not None and lon is not None:
                map_url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
                result_text += f"\n\n[bold cyan]Map:[/bold cyan] [link={map_url}]LINK[/link]"
            
            return "geoip", result_text
        return "geoip", "Not found"
    except requests.exceptions.RequestException as e:
        return "geoip", f"[red]Request error: {str(e)[:50]}[/red]"
    except Exception as e:
        return "geoip", f"[red]Error: {str(e)[:50]}[/red]"

def scan_whois(target):
    """Whois Information"""
    try:
        w = whois.whois(target)
        registrar = w.registrar if w.registrar else "Unknown"
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return "whois", f"[bold]Registrar:[/bold] {registrar}\n[bold]Created:[/bold] {creation}\n[bold]Org:[/bold] {w.org}"
    except Exception:
        return "whois", "Whois data unavailable or hidden."

def scan_dns(target):
    """DNS Records - Improved"""
    records = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    for r_type in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = resolver.resolve(target, r_type)
            for rdata in answers:
                txt = rdata.to_text()
                if len(txt) > 50:
                    txt = txt[:47] + "..."
                records.append(f"[{r_type}] {txt}")
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.Timeout:
            records.append(f"[{r_type}] Timeout")
        except Exception:
            continue
    return "dns", records if records else ["[dim]No records found[/dim]"]

def scan_subdomains(target):
    """Subdomains via crt.sh - Improved"""
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        
        data = resp.json()
        subs = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            sub_entries = name_value.split('\n')
            for sub in sub_entries:
                sub = sub.strip()
                # Filter wildcards and self
                if sub and "*" not in sub and sub != target:
                    subs.add(sub)
        return "subdomains", list(subs)[:10]
    except requests.exceptions.RequestException as e:
        return "subdomains", [f"Request error: {str(e)[:50]}"]
    except json.JSONDecodeError:
        return "subdomains", ["JSON parse error"]
    except Exception as e:
        return "subdomains", [f"Error: {str(e)[:50]}"]

def scan_archive(target):
    """Archive.org - With Clickable Link"""
    try:
        url = f"http://archive.org/wayback/available?url={target}"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
            closest = data["archived_snapshots"]["closest"]
            archive_url = closest['url']
            return "archive", f"[green]Archive found![/green]\nLast: {closest['timestamp']}\n\n[bold cyan]Source:[/bold cyan] [link={archive_url}]LINK[/link]"
        return "archive", "[red]No archive records found.[/red]"
    except:
        return "archive", "Archive connection error"

def scan_headers(target):
    """HTTP Header Analysis"""
    try:
        resp = requests.get(f"http://{target}", timeout=5)
        headers = resp.headers
        server = headers.get('Server', 'Hidden')
        powered = headers.get('X-Powered-By', 'Unknown')
        return "tech", f"[bold]Server:[/bold] {server}\n[bold]Technology:[/bold] {powered}"
    except:
        return "tech", "Unable to reach site"

def generate_dorks(target):
    """Generates Google Dork Links"""
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
        formatted_dorks.append(f"{dork}\n[bold cyan]Search:[/bold cyan] [link={google_url}]LINK[/link]")
        
    return "dorks", formatted_dorks

# --- UI AND MAIN PROGRAM ---

class PassiveScannerThreaded:
    def __init__(self, target):
        self.target = target
        self.results = {
            "geoip": "[dim]Loading...[/dim]",
            "whois": "[dim]Loading...[/dim]",
            "dns": "[dim]Loading...[/dim]",
            "subdomains": "[dim]Loading...[/dim]",
            "archive": "[dim]Loading...[/dim]",
            "headers": "[dim]Loading...[/dim]",
            "dorks": "[dim]Loading...[/dim]",
            "rapiddns": "[dim]Loading...[/dim]",
            "threatminer": "[dim]Loading...[/dim]",
            "anubisdb": "[dim]Loading...[/dim]",
            "greynoise": "[dim]Loading...[/dim]"
        }
        self.is_finished = False

    def make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="upper", size=10),
            Layout(name="middle"),
            Layout(name="lower", size=10),
            Layout(name="footer", size=3)
        )
        layout["upper"].split_row(
            Layout(name="whois_panel"),
            Layout(name="geoip_panel"),
            Layout(name="tech_panel"),
            Layout(name="rapiddns_panel")
        )
        layout["middle"].split_row(
            Layout(name="dns_panel"),
            Layout(name="subdomain_panel"),
            Layout(name="threatminer_panel")
        )
        layout["lower"].split_row(
            Layout(name="archive_panel"),
            Layout(name="dork_panel"),
            Layout(name="anubisdb_panel"),
            Layout(name="greynoise_panel")
        )
        return layout

    def update_display(self, layout):
        layout["header"].update(Panel(f"[bold white on blue] YELBEGEN [/] - [bold green]{self.target}[/]", box=box.HEAVY))
        
        layout["whois_panel"].update(Panel(self.results["whois"], title="Whois", border_style="cyan"))
        layout["geoip_panel"].update(Panel(self.results["geoip"], title="GeoIP / Location", border_style="magenta"))
        layout["tech_panel"].update(Panel(self.results["tech"], title="Technology (Headers)", border_style="white"))

        dns_table = Table(show_header=False, box=None, padding=(0,1))
        for r in self.results["dns"]: dns_table.add_row(r)
        layout["dns_panel"].update(Panel(dns_table, title="DNS Records", border_style="yellow"))

        sub_table = Table(show_header=False, box=None, padding=(0,1))
        if self.results["subdomains"]:
            for s in self.results["subdomains"]: sub_table.add_row(s)
        else: sub_table.add_row("Searching...")
        layout["subdomain_panel"].update(Panel(sub_table, title="Subdomains (crt.sh)", border_style="green"))

        layout["archive_panel"].update(Panel(self.results["archive"], title="Wayback Machine", border_style="red"))
        
        dorks_content = "\n".join(self.results["dorks"]) if self.results["dorks"] else "Calculating..."
        layout["dork_panel"].update(Panel(dorks_content, title="Google Dorks (Click to Search)", border_style="blue"))
        layout["rapiddns_panel"].update(Panel(self.results.get("rapiddns", "[dim]Loading...[/dim]"), title="[bold cyan]RapidDNS.io", box=box.ROUNDED))
        layout["threatminer_panel"].update(Panel(self.results.get("threatminer", "[dim]Loading...[/dim]"), title="[bold yellow]ThreatMiner", box=box.ROUNDED))
        layout["anubisdb_panel"].update(Panel(self.results.get("anubisdb", "[dim]Loading...[/dim]"), title="[bold cyan]AnubisDB", box=box.ROUNDED))
        layout["greynoise_panel"].update(Panel(self.results.get("greynoise", "[dim]Loading...[/dim]"), title="[bold green]GreyNoise", box=box.ROUNDED))

        status = "[bold red]Running...[/bold red]" if not self.is_finished else "[bold green]Done[/bold green]"
        layout["footer"].update(Panel(f"Status: {status} | Copy links if not clickable", box=box.ROUNDED))

    def run(self):
        layout = self.make_layout()
        # Remove screen=True so output persists in terminal
        with Live(layout, refresh_per_second=4):
            with ProcessPoolExecutor(max_workers=11) as executor:
                futures = [
                    executor.submit(scan_geoip, self.target),
                    executor.submit(scan_whois, self.target),
                    executor.submit(scan_dns, self.target),
                    executor.submit(scan_subdomains, self.target),
                    executor.submit(scan_archive, self.target),
                    executor.submit(scan_headers, self.target),
                    executor.submit(generate_dorks, self.target),
                    executor.submit(scan_rapiddns_wrapper, self.target),
                    executor.submit(scan_threatminer_wrapper, self.target),
                    executor.submit(scan_anubisdb_wrapper, self.target),
                    executor.submit(scan_greynoise_wrapper, self.target)
                ]
                for future in as_completed(futures):
                    try:
                        key, value = future.result()
                        self.results[key] = value
                        self.update_display(layout)
                    except: 
                        pass
                self.is_finished = True
                self.update_display(layout)
            
            # Display final results for 2 seconds
            time.sleep(2)
        
        # Output stays visible in terminal - no need to reprint
        console.print(f"\n[bold green]✓ Scan complete![/] Results saved above.\n")




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target Domain")
    args = parser.parse_args()
    scanner = PassiveScannerThreaded(args.target)
    scanner.run()


def scan_rapiddns_wrapper(target):
    """RapidDNS wrapper"""
    from yelbegen.scanner.modules import scan_rapiddns
    result = scan_rapiddns(target)
    if result.get('type') == 'error':
        return "rapiddns", f"[red]Error: {result['data'].get('error')}[/red]"
    
    data = result.get('data', {})
    count = data.get('count', 0)
    subs = data.get('subdomains', [])
    
    output = f"[bold green]Total:[/bold green] {count} subdomains\n\n"
    if subs:
        output += "[bold]Subdomains:[/bold]\n"
        for sub in subs[:15]:
            output += f"  [cyan]-[/cyan] {sub}\n"
        if len(subs) > 15:
            output += f"  [dim]+ {len(subs) - 15} more[/dim]\n"
    
    source_url = f"https://rapiddns.io/subdomain/{target}"
    output += f"\n[bold cyan]Source:[/bold cyan] [link={source_url}]LINK[/link]"
    return "rapiddns", output


def scan_threatminer_wrapper(target):
    """ThreatMiner wrapper"""
    from yelbegen.scanner.modules import scan_threatminer
    result = scan_threatminer(target)
    if result.get('type') == 'error':
        return "threatminer", f"[red]Error: {result['data'].get('error')}[/red]"
    if result.get('type') == 'info':
        return "threatminer", f"[yellow]{result['data'].get('message')}[/yellow]"
    
    data = result.get('data', {})
    count = data.get('count', 0)
    subs = data.get('subdomains', [])
    
    output = f"[bold green]Found:[/bold green] {count} related domains\n\n"
    if subs:
        output += "[bold]Related Domains:[/bold]\n"
        for sub in subs[:12]:
            output += f"  [yellow]-[/yellow] {sub}\n"
        if len(subs) > 12:
            output += f"  [dim]+ {len(subs) - 12} more[/dim]\n"
    
    source_url = f"https://www.threatminer.org/domain.php?q={target}"
    output += f"\n[bold cyan]Source:[/bold cyan] [link={source_url}]LINK[/link]"
    return "threatminer", output


def scan_anubisdb_wrapper(target):
    """AnubisDB wrapper"""
    from yelbegen.scanner.modules import scan_anubisdb
    result = scan_anubisdb(target)
    if result.get('type') == 'error':
        return "anubisdb", f"[red]Error: {result['data'].get('error')}[/red]"
    if result.get('type') == 'info':
        return "anubisdb", f"[yellow]{result['data'].get('message')}[/yellow]"
    
    data = result.get('data', {})
    count = data.get('count', 0)
    subs = data.get('subdomains', [])
    
    output = f"[bold green]Total:[/bold green] {count} subdomains\n\n"
    if subs:
        output += "[bold]Discovered:[/bold]\n"
        for sub in subs[:15]:
            output += f"  [cyan]-[/cyan] {sub}\n"
        if len(subs) > 15:
            output += f"  [dim]+ {len(subs) - 15} more[/dim]\n"
    
    source_url = "https://jonlu.ca/anubis"
    output += f"\n[bold cyan]Source:[/bold cyan] [link={source_url}]LINK[/link]"
    return "anubisdb", output


def scan_greynoise_wrapper(target):
    """GreyNoise wrapper"""
    from yelbegen.scanner.modules import scan_greynoise
    result = scan_greynoise(target)
    if result.get('type') == 'error':
        return "greynoise", f"[red]Error: {result['data'].get('error')}[/red]"
    
    data = result.get('data', {})
    ip = data.get('ip', target)
    noise = data.get('noise', False)
    riot = data.get('riot', False)
    classification = data.get('classification', 'unknown')
    name = data.get('name', 'N/A')
    
    output = f"[bold]IP:[/bold] {ip}\n"
    output += f"[bold]Classification:[/bold] {classification}\n"
    output += f"[bold]Internet Noise:[/bold] {'Yes' if noise else 'No'}\n"
    output += f"[bold]RIOT (Benign):[/bold] {'Yes' if riot else 'No'}\n"
    if name != 'N/A':
        output += f"[bold]Name:[/bold] {name}\n"
    
    source_url = f"https://viz.greynoise.io/ip/{ip}"
    output += f"\n[bold cyan]Source:[/bold cyan] [link={source_url}]LINK[/link]"
    return "greynoise", output
