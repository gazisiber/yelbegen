"""
API-Enhanced Scanner - Requires API Keys
Uses VirusTotal, SecurityTrails, and Shodan API
"""
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import box

# Import API scanner functions
import sys
sys.path.insert(0, '/home/godfry/Desktop/Github/yelbegen/yelbegen-main')
sys.path.insert(0, '/home/godfry/Desktop/Github/yelbegen/yelbegen-main')
from yelbegen.scanner.modules import (
    scan_virustotal, scan_securitytrails, scan_shodan_api, scan_urlscan_api,
    scan_google_safebrowsing, scan_binaryedge, scan_hunter
)
from yelbegen.config.settings import config

console = Console()


class APIScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            "virustotal": "...",
            "securitytrails": "...", 
            "shodan": "...",
            "urlscan": "...",
            "safebrowsing": "...",
            "binaryedge": "...",
            "hunter": "..."
        }
        self.is_finished = False
        
    def make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["main"].split_column(
            Layout(name="row1", ratio=1),
            Layout(name="row2", ratio=1),
            Layout(name="row3", ratio=1)
        )
        layout["row1"].split_row(
            Layout(name="virustotal_panel"),
            Layout(name="securitytrails_panel")
        )
        layout["row2"].split_row(
            Layout(name="shodan_panel"),
            Layout(name="urlscan_panel")
        )
        layout["row3"].split_row(
            Layout(name="safebrowsing_panel"),
            Layout(name="binaryedge_panel"),
            Layout(name="hunter_panel")
        )
        return layout
    
    def update_display(self, layout):
        layout["header"].update(Panel(
            f"[bold white on red] YELBEGEN - API MODE [/] - [bold green]{self.target}[/]", 
            box=box.HEAVY
        ))
        
        layout["virustotal_panel"].update(Panel(self.results["virustotal"], title="VirusTotal", border_style="red"))
        layout["securitytrails_panel"].update(Panel(self.results["securitytrails"], title="SecurityTrails", border_style="blue"))
        layout["shodan_panel"].update(Panel(self.results["shodan"], title="Shodan API", border_style="magenta"))
        layout["urlscan_panel"].update(Panel(self.results["urlscan"], title="URLScan.io API", border_style="cyan"))
        
        layout["safebrowsing_panel"].update(Panel(self.results["safebrowsing"], title="Google Safe Browsing", border_style="green"))
        layout["binaryedge_panel"].update(Panel(self.results["binaryedge"], title="BinaryEdge", border_style="yellow"))
        layout["hunter_panel"].update(Panel(self.results["hunter"], title="Hunter.io (Email)", border_style="white"))
        
        status = "[bold red]Scanning...[/bold red]" if not self.is_finished else "[bold green]Done[/bold green]"
        layout["footer"].update(Panel(
            f"Status: {status} | API Mode - Enhanced Intelligence", 
            box=box.ROUNDED
        ))
    
    def format_virustotal_result(self, data):
        """Format VirusTotal API response"""
        if data.get('type') == 'skipped':
            return f"[yellow]{data['data'].get('message', 'No API key')}[/yellow]"
        if data.get('type') == 'error':
            return f"[red]Error: {data['data'].get('error', 'Unknown')}[/red]"
        
        result_data = data.get('data', {})
        output = ""
        output += f"[bold]Reputation:[/bold] {result_data.get('reputation', 'N/A')}\n"
        output += f"[bold red]Malicious:[/bold red] {result_data.get('malicious', 0)}\n"
        output += f"[bold yellow]Suspicious:[/bold yellow] {result_data.get('suspicious', 0)}\n"
        output += f"[bold green]Harmless:[/bold green] {result_data.get('harmless', 0)}\n"
        
        # Show malicious detections
        mal_dets = result_data.get('malicious_detections', [])
        if mal_dets:
            output += "\n[bold red]Malicious Engines:[/bold red]\n"
            for det in mal_dets[:8]:
                output += f"  [red]-[/red] {det.get('engine')}: {det.get('verdict')}\n"
            if len(mal_dets) > 8:
                output += f"  [dim]+ {len(mal_dets) - 8} more[/dim]\n"
        
        # Show suspicious detections  
        sus_dets = result_data.get('suspicious_detections', [])
        if sus_dets:
            output += "\n[bold yellow]Suspicious Engines:[/bold yellow]\n"
            for det in sus_dets[:5]:
                output += f"  [yellow]-[/yellow] {det.get('engine')}: {det.get('verdict')}\n"
            if len(sus_dets) > 5:
                output += f"  [dim]+ {len(sus_dets) - 5} more[/dim]\n"
        
        # Additional Info
        tags = result_data.get('tags', [])
        if tags:
            output += f"\n[bold]Tags:[/bold] {', '.join(tags[:5])}\n"
        
        last_date = result_data.get('last_analysis_date')
        if last_date:
            import datetime
            dt = datetime.datetime.fromtimestamp(last_date).strftime('%Y-%m-%d')
            output += f"[bold]Last Scan:[/bold] {dt}\n"

        target_url = f"https://www.virustotal.com/gui/domain/{self.target}"
        output += f"\n[bold cyan]Source:[/bold cyan] [link={target_url}]LINK[/link]"
        
        return output
    def format_securitytrails_result(self, data):
        """Format SecurityTrails API response"""
        if data.get('type') == 'skipped':
            return f"[yellow]{data['data'].get('message', 'No API key')}[/yellow]"
        if data.get('type') == 'error':
            return f"[red]Error: {data['data'].get('error', 'Unknown')}[/red]"
        
        result_data = data.get('data', {})
        count = result_data.get('count', 0)
        subdomains = result_data.get('subdomains', [])
        
        output = f"[bold]Subdomain Count:[/bold] {count}\n\n"
        output += "[bold]Top Subdomains:[/bold]\n"
        for sub in subdomains[:10]:
            output += f"  • {sub}\n"
        
        output += f"\n[bold cyan]Source:[/bold cyan] [link=https://securitytrails.com/domain/{self.target}/dns]LINK[/link]"
        return output
    
    def format_shodan_result(self, data):
        """Format Shodan API response"""
        if data.get('type') == 'skipped':
            return f"[yellow]{data['data'].get('message', 'No API key')}[/yellow]"
        if data.get('type') == 'error':
            return f"[red]Error: {data['data'].get('error', 'Unknown')}[/red]"
        
        result_data = data.get('data', {})
        output = ""
        
        ports = result_data.get('ports', [])
        output += f"[bold]Open Ports:[/bold] {', '.join(map(str, ports[:10]))}\n\n"
        
        if result_data.get('os'):
            output += f"[bold]OS:[/bold] {result_data['os']}\n"
        if result_data.get('isp'):
            output += f"[bold]ISP:[/bold] {result_data['isp']}\n"
        
        if result_data.get('org'):
            output += f"[bold]Org:[/bold] {result_data['org']}\n"
        if result_data.get('asn'):
            output += f"[bold]ASN:[/bold] {result_data['asn']}\n"
        if result_data.get('city') or result_data.get('country_name'):
            loc = filter(None, [result_data.get('city'), result_data.get('country_name')])
            output += f"[bold]Location:[/bold] {', '.join(loc)}\n"
            
        hostnames = result_data.get('hostnames', [])
        if hostnames:
            output += f"\n[bold]Hostnames:[/bold]\n"
            for h in hostnames[:3]:
                output += f"  • {h}\n"
        
        vulns = result_data.get('vulns', [])
        if vulns:
            output += f"\n[bold red]Vulnerabilities ({len(vulns)}):[/bold red]\n"
            for v in vulns[:5]:
                output += f"  • {v}\n"
            if len(vulns) > 5:
                output += f"  [dim]+ {len(vulns) - 5} more[/dim]\n"
        
        ip = result_data.get('ip')
        if ip:
            output += f"\n[bold cyan]Source:[/bold cyan] [link=https://www.shodan.io/host/{ip}]LINK[/link]"
        
        return output if output else "No data available"
    
    def format_urlscan_result(self, data):
        """Format URLScan API response"""
        if data.get('type') == 'skipped':
            return f"[yellow]{data['data'].get('message', 'No API key')}[/yellow]"
        if data.get('type') == 'error':
            return f"[red]Error: {data['data'].get('error', 'Unknown')}[/red]"
        if data.get('type') == 'info':
            result_data = data.get('data', {})
            return f"[yellow]{result_data.get('message')}[/yellow]\n\n[bold]View results:[/bold]\n{result_data.get('url', 'N/A')}"
        
        result_data = data.get('data', {})
        output = ""
        
        if result_data.get('title'):
            output += f"[bold]Title:[/bold] {result_data.get('title')}\n"
        
        output += f"[bold]URL:[/bold] {result_data.get('url', 'N/A')}\n"
        output += f"[bold]IP:[/bold] {result_data.get('ip', 'N/A')}\n"
        
        loc = []
        if result_data.get('city'): loc.append(result_data.get('city'))
        if result_data.get('country'): loc.append(result_data.get('country'))
        if loc:
            output += f"[bold]Location:[/bold] {', '.join(loc)}\n"
            
        output += f"[bold]Server:[/bold] {result_data.get('server', 'N/A')}\n"
        output += f"[bold]Stats:[/bold] {result_data.get('requests', 0)} reqs, {result_data.get('domains', 0)} domains\n"
        
        malicious = result_data.get('malicious', 0)
        if malicious > 0:
            output += f"\n[bold red][WARNING] Malicious:[/bold red] {malicious}\n"
        
        screenshot = result_data.get('screenshot_url')
        if screenshot:
            output += f"\n[bold cyan]Screenshot:[/bold cyan] [link={screenshot}]LINK[/link]\n"
        
        scan_url = result_data.get('scan_url')
        if scan_url:
            output += f"\n[bold cyan]Source:[/bold cyan] [link={scan_url}]LINK[/link]"
        
        return output

    def format_safebrowsing_result(self, data):
        """Format Google Safe Browsing API response"""
        if data.get('type') == 'skipped': return f"[yellow]{data['data'].get('message')}[/yellow]"
        if data.get('type') == 'error': return f"[red]{data['data'].get('error')}[/red]"
        
        res = data.get('data', {})
        safe = res.get('safe', False)
        status = "[bold green]SAFE[/bold green]" if safe else "[bold red]UNSAFE[/bold red]"
        output = f"[bold]Status:[/bold] {status}\n"
        
        matches = res.get('matches', [])
        if matches:
            output += "\n[bold red]Threats Found:[/bold red]\n"
            for m in matches:
                output += f"  - {m.get('threatType')} ({m.get('platformType')})\n"
        
        link = f"https://transparencyreport.google.com/safe-browsing/search?url={self.target}"
        output += f"\n[bold cyan]Source:[/bold cyan] [link={link}]LINK[/link]"
        return output

    def format_binaryedge_result(self, data):
        """Format BinaryEdge API response"""
        if data.get('type') == 'skipped': return f"[yellow]{data['data'].get('message')}[/yellow]"
        if data.get('type') == 'error': return f"[red]{data['data'].get('error')}[/red]"
        if data.get('type') == 'info': return f"[yellow]{data['data'].get('message')}[/yellow]"

        res = data.get('data', {})
        output = f"[bold]IP:[/bold] {res.get('ip')}\n"
        output += f"[bold]Events:[/bold] {res.get('events_count')}\n"
        
        ports = res.get('ports', [])
        if ports:
            output += f"[bold]Ports:[/bold] {', '.join(map(str, ports[:10]))}\n"
            if len(ports) > 10: output += f"  [dim]+ {len(ports)-10} more[/dim]\n"
            
        output += f"\n[bold cyan]Source:[/bold cyan] [link=https://app.binaryedge.io]LINK[/link]"
        return output

    def format_hunter_result(self, data):
        """Format Hunter.io API response"""
        if data.get('type') == 'skipped': return f"[yellow]{data['data'].get('message')}[/yellow]"
        if data.get('type') == 'error': return f"[red]{data['data'].get('error')}[/red]"
        
        res = data.get('data', {})
        org = res.get('organization') or 'Unknown'
        output = f"[bold]Organization:[/bold] {org}\n"
        output += f"[bold]Pattern:[/bold] {res.get('pattern', 'N/A')}\n"
        
        emails = res.get('emails', [])
        if emails:
            output += f"[bold]Emails Found:[/bold] {res.get('count')}\n"
            for e in emails[:5]:
                val = e.get('value')
                typ = e.get('type')
                output += f"  - {val} ([dim]{typ}[/dim])\n"
        else:
            output += "[yellow]No emails found[/yellow]\n"
            
        link = f"https://hunter.io/search/{self.target}"
        output += f"\n[bold cyan]Source:[/bold cyan] [link={link}]LINK[/link]"
        return output
    
    def run(self):
        # Check if any API keys are configured
        # Check if any API keys are configured (at least one)
        has_vt = config.virustotal_key is not None
        has_st = config.securitytrails_key is not None
        has_shodan = config.shodan_key is not None
        has_urlscan = config.urlscan_key is not None
        has_gsb = config.google_safebrowsing_key is not None
        has_be = config.binaryedge_key is not None
        has_hu = config.hunter_key is not None
        
        if not (has_vt or has_st or has_shodan or has_urlscan or has_gsb or has_be or has_hu):
            console.print("\n[bold red][X] No API keys configured![/bold red]\n")
            console.print("Add API keys with:")
            console.print("  [cyan]yelbegen -ua virustotal YOUR_KEY[/cyan]")
            console.print("  [cyan]yelbegen -ua securitytrails YOUR_KEY[/cyan]")
            console.print("  [cyan]yelbegen -ua shodan YOUR_KEY[/cyan]\n")
            console.print("  [cyan]yelbegen -ua google_safebrowsing YOUR_KEY[/cyan]")
            console.print("  [cyan]yelbegen -ua binaryedge YOUR_KEY[/cyan]")
            console.print("  [cyan]yelbegen -ua hunter YOUR_KEY[/cyan]")
            console.print("\nCheck status: [cyan]yelbegen -la[/cyan]\n")
            return
        
        layout = self.make_layout()
        with Live(layout, refresh_per_second=4):
            with ProcessPoolExecutor(max_workers=7) as executor:
                futures = []
                
                # Submit only if API key exists
                if has_vt:
                    futures.append(('virustotal', executor.submit(scan_virustotal, self.target, config.virustotal_key)))
                else:
                    self.results['virustotal'] = "[yellow][WARNING] No API key configured[/yellow]"
                
                if has_st:
                    futures.append(('securitytrails', executor.submit(scan_securitytrails, self.target, config.securitytrails_key)))
                else:
                    self.results['securitytrails'] = "[yellow][WARNING] No API key configured[/yellow]"
                
                if has_shodan:
                    futures.append(('shodan', executor.submit(scan_shodan_api, self.target, config.shodan_key)))
                else:
                    self.results['shodan'] = "[yellow][WARNING] No API key configured[/yellow]"
                
                if has_urlscan:
                    futures.append(('urlscan', executor.submit(scan_urlscan_api, self.target, config.urlscan_key)))
                else:
                    self.results['urlscan'] = "[yellow][WARNING] No API key configured[/yellow]"

                # Google Safe Browsing
                if config.google_safebrowsing_key:
                    futures.append(('safebrowsing', executor.submit(scan_google_safebrowsing, self.target, config.google_safebrowsing_key)))
                else:
                    self.results['safebrowsing'] = "[yellow][WARNING] No API key[/yellow]"
                
                # BinaryEdge
                if config.binaryedge_key:
                    futures.append(('binaryedge', executor.submit(scan_binaryedge, self.target, config.binaryedge_key)))
                else:
                    self.results['binaryedge'] = "[yellow][WARNING] No API key[/yellow]"

                # Hunter.io
                if config.hunter_key:
                    futures.append(('hunter', executor.submit(scan_hunter, self.target, config.hunter_key)))
                else:
                    self.results['hunter'] = "[yellow][WARNING] No API key[/yellow]"
                
                self.update_display(layout)
                
                # Collect results
                for key, future in futures:
                    try:
                        result = future.result()
                        if key == 'virustotal':
                            self.results[key] = self.format_virustotal_result(result)
                        elif key == 'securitytrails':
                            self.results[key] = self.format_securitytrails_result(result)
                        elif key == 'shodan':
                            self.results[key] = self.format_shodan_result(result)
                        elif key == 'urlscan':
                            self.results[key] = self.format_urlscan_result(result)
                        elif key == 'safebrowsing':
                            self.results[key] = self.format_safebrowsing_result(result)
                        elif key == 'binaryedge':
                            self.results[key] = self.format_binaryedge_result(result)
                        elif key == 'hunter':
                            self.results[key] = self.format_hunter_result(result)
                        
                        self.update_display(layout)
                    except Exception as e:
                        self.results[key] = f"[red]Error: {str(e)[:100]}[/red]"
                        self.update_display(layout)
                
                self.is_finished = True
                self.update_display(layout)
            
            # Display final results for 2 seconds
            time.sleep(2)
        
        # Print static summary
        console.print(f"\n[bold green]✓ API scan complete![/] Results saved above.\n")
