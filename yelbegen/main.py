import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

from yelbegen.scanner.engine import ReconEngine
from yelbegen.scanner.modules import AVAILABLE_MODULES


console = Console()


class YelbegenDashboard:
    def __init__(self, target: str, mode: str = 'basic'):
        self.target = target
        self.mode = mode
        self.engine = ReconEngine()
        self.results = {
            'whois': {},
            'dns': {},
            'geo': {},
            'subdomains': {}
        }
    
    def create_header(self) -> Panel:
        mode_text = "BASIC (Free)" if self.mode == 'basic' else "FULL (API Enhanced)"
        header_text = Text()
        header_text.append("YELBEGEN", style="bold cyan")
        header_text.append(f" - {mode_text}\n", style="dim yellow")
        header_text.append(f"Target: ", style="dim")
        header_text.append(self.target, style="bold yellow")
        header_text.append(f" | {datetime.now().strftime('%H:%M:%S')}", style="dim")
        
        return Panel(header_text, box=box.DOUBLE, style="cyan")
    
    def create_whois_panel(self) -> Panel:
        if not self.results['whois']:
            content = "[dim]Veri bekleniyor...[/dim]"
        else:
            lines = []
            for key, value in self.results['whois'].items():
                if not isinstance(value, (list, dict)):
                    lines.append(f"[cyan]{key}:[/cyan] {value}")
            content = "\n".join(lines) if lines else "[dim]Veri yok[/dim]"
        
        return Panel(content, title="[bold magenta]Whois Bilgisi[/bold magenta]", 
                    border_style="magenta", box=box.ROUNDED, height=12)
    
    def create_dns_panel(self) -> Panel:
        if not self.results['dns']:
            content = "[dim]Veri bekleniyor...[/dim]"
        else:
            table = Table(show_header=True, box=box.SIMPLE, expand=True)
            table.add_column("Kayıt", style="cyan")
            table.add_column("Değer", style="yellow")
            
            for key, value in self.results['dns'].items():
                if isinstance(value, list):
                    for item in value[:5]:
                        table.add_row(key, str(item))
                elif not isinstance(value, dict):
                    table.add_row(key, str(value))
            
            content = table if table.row_count > 0 else "[dim]Veri yok[/dim]"
        
        return Panel(content, title="[bold yellow]DNS Kayıtları[/bold yellow]", 
                    border_style="yellow", box=box.ROUNDED, height=12)
    
    def create_geo_panel(self) -> Panel:
        if not self.results['geo']:
            content = "[dim]Veri bekleniyor...[/dim]"
        else:
            lines = []
            for key, value in self.results['geo'].items():
                if not isinstance(value, (list, dict)):
                    lines.append(f"[green]{key}:[/green] {value}")
            content = "\n".join(lines) if lines else "[dim]Veri yok[/dim]"
        
        return Panel(content, title="[bold #ff00ff]Coğrafi Konum[/bold #ff00ff]", 
                    border_style="#ff00ff", box=box.ROUNDED, height=12)
    
    def create_subdomain_panel(self) -> Panel:
        if not self.results['subdomains']:
            content = "[dim]Veri bekleniyor...[/dim]"
        else:
            subdomains = self.results['subdomains'].get('unique_subdomains', [])
            if subdomains:
                lines = [f"[cyan]•[/cyan] {sub}" for sub in subdomains[:15]]
                if len(subdomains) > 15:
                    lines.append(f"\n[dim]... ve {len(subdomains) - 15} subdomain daha[/dim]")
                content = "\n".join(lines)
            else:
                content = "[dim]Veri yok[/dim]"
        
        return Panel(content, title="[bold cyan]Pasif Subdomainler (crt.sh)[/bold cyan]", 
                    border_style="cyan", box=box.ROUNDED, height=12)
    
    def create_dashboard(self) -> Layout:
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["header"].update(self.create_header())
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["body"]["left"].split_column(
            Layout(name="whois"),
            Layout(name="geo")
        )
        
        layout["body"]["right"].split_column(
            Layout(name="dns"),
            Layout(name="subdomains")
        )
        
        layout["body"]["left"]["whois"].update(self.create_whois_panel())
        layout["body"]["left"]["geo"].update(self.create_geo_panel())
        layout["body"]["right"]["dns"].update(self.create_dns_panel())
        layout["body"]["right"]["subdomains"].update(self.create_subdomain_panel())
        
        status_text = Text("Durum: Tarama devam ediyor... | ", style="green")
        status_text.append("CTRL+C ile çıkış", style="dim")
        layout["footer"].update(Panel(status_text, style="green"))
        
        return layout
    
    def run(self):
        from yelbegen.config.settings import config
        
        # Select modules based on mode
        if self.mode == 'basic':
            # BASIC MODE: Only free modules (no API keys needed)
            # Includes: Whois, GeoIP, DNS, crt.sh, Archive.org, Dorks, Headers, etc.
            modules = [m for m in AVAILABLE_MODULES.values() if not m.get('requires_key', False)]
        else:
            # FULL MODE: ALL modules (free + API enhanced)
            # Includes: ALL basic modules PLUS VirusTotal, SecurityTrails, Shodan API
            modules = list(AVAILABLE_MODULES.values())
        
        # Prepare module configs with API keys
        module_configs = []
        for m in modules:
            config_dict = {
                'name': m['name'],
                'function': m['function'],
                'requires_key': m.get('requires_key', False)
            }
            
            # Add API key if module requires it
            if m.get('requires_key'):
                service_name = m['name'].lower().replace(' api', '').replace(' ', '')
                api_key = getattr(config, f'{service_name}_key', None)
                config_dict['api_key'] = api_key
            
            module_configs.append(config_dict)
        
        result_queue = self.engine.start_scan(self.target, module_configs, self.mode)
        
        completed_modules = set()
        workers_done = set()  # Track which workers sent 'done' signal
        total_modules = len(module_configs)
        
        with Live(self.create_dashboard(), refresh_per_second=4, console=console) as live:
            try:
                # Continue until all workers send 'done' signal
                while len(workers_done) < total_modules:
                    try:
                        # Blocking get with timeout - wait for messages
                        result = result_queue.get(timeout=0.5)
                        
                        if result.get('type') == 'worker_done':
                            # Worker finished - track it
                            workers_done.add(result['module'])
                        else:
                            # Process result normally
                            self.process_result(result, completed_modules)
                        
                        # Update UI after processing message
                        live.update(self.create_dashboard())
                        
                    except:
                        # No message in 0.5s (queue.Empty), just update UI
                        live.update(self.create_dashboard())
                        continue
                        
            except KeyboardInterrupt:
                console.print("\n[yellow]Scan stopped by user[/yellow]")
                self.engine.stop_scan()
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
        
        self.engine.cleanup()
        
        # Final display
        layout = self.create_dashboard()
        status_text = Text("Status: Completed | ", style="green bold")
        status_text.append(f"Total modules: {total_modules}", style="dim")
        layout["footer"].update(Panel(status_text, style="green"))
        
        
        console.print(layout)
        console.print("\n[green]Scan completed![/green]")

        
        # Display results for 2 seconds then exit
        time.sleep(2)
        console.print("\n[bold green]Scan complete![/] Results saved above.\n")
    
    def process_result(self, result: dict, completed_modules: set):
        result_type = result.get('type')
        
        if result_type == 'result':
            completed_modules.add(result.get('module'))
            data = result.get('data', {})
            source = data.get('source', '').lower()
            result_data = data.get('data', {})
            
            if 'whois' in source or 'otx' in source or 'alienvault' in source:
                self.results['whois'].update(result_data)
            elif 'dns' in source or 'hackertarget' in source:
                self.results['dns'].update(result_data)
            elif 'geo' in source or 'ip-api' in source:
                self.results['geo'].update(result_data)
            elif 'crt' in source or 'subdomain' in data.get('type', '').lower():
                self.results['subdomains'].update(result_data)


def main():
    """Main entry point with CLI argument parsing"""
    import argparse
    from yelbegen.config.api_manager import APIManager
    from yelbegen.config.settings import config
    
    parser = argparse.ArgumentParser(
        description="Yelbegen - Passive OSINT Scanner",
        epilog="Examples:\n"
               "  yelbegen google.com          # Basic scan (modular mode)\n"
               "  yelbegen -f google.com        # Full scan (ProcessPoolExecutor with clickable links)\n"
               "  yelbegen -ua virustotal KEY   # Upload API key\n"
               "  yelbegen -la                  # List API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # API Key Management
    parser.add_argument('-ua', '--upload-api', nargs=2, 
                        metavar=('SERVICE', 'KEY'),
                        help='Upload API key (virustotal, securitytrails, shodan)')
    
    parser.add_argument('-la', '--list-api', action='store_true',
                        help='List configured API keys')
    
    # Scanning modes
    parser.add_argument('target', nargs='?', help='Domain or IP to scan')
    parser.add_argument('-f', '--full', action='store_true',
                        help='Full mode - free scanners with clickable links (ProcessPoolExecutor)')
    parser.add_argument('-a', '--api', action='store_true',
                        help='API mode - VirusTotal, SecurityTrails, Shodan (requires API keys)')
    
    args = parser.parse_args()
    
    # Handle API management commands
    if args.upload_api:
        service, key = args.upload_api
        APIManager.upload_key(service, key)
        return
    
    if args.list_api:
        APIManager.list_keys()
        return
    
    # Normal scanning
    if not args.target:
        parser.print_help()
        return
    
    # API MODE: Use API-enhanced scanners (VirusTotal, SecurityTrails, Shodan)
    if args.api:
        console.print(f"\n[cyan]Starting API scan (VirusTotal + SecurityTrails + Shodan) for:[/cyan] [bold]{args.target}[/bold]\n")
        from yelbegen.api_scanner import APIScanner
        scanner = APIScanner(args.target)
        scanner.run()
    # FULL MODE: Use the enhanced full_scanner with clickable links
    elif args.full:
        console.print(f"\n[cyan]Starting FULL scan (ProcessPoolExecutor + Links) for:[/cyan] [bold]{args.target}[/bold]\n")
        from yelbegen.full_scanner import PassiveScannerThreaded
        scanner = PassiveScannerThreaded(args.target)
        scanner.run()
    else:
        # BASIC MODE: Use modular multiprocessing scanner
        console.print(f"\n[cyan]Starting BASIC scan (Modular) for:[/cyan] [bold]{args.target}[/bold]\n")
        dashboard = YelbegenDashboard(args.target, 'basic')
        dashboard.run()


if __name__ == "__main__":
    main()
