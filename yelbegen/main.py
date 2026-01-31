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
    def __init__(self, target: str):
        self.target = target
        self.engine = ReconEngine()
        self.results = {
            'whois': {},
            'dns': {},
            'geo': {},
            'subdomains': {}
        }
    
    def create_header(self) -> Panel:
        header_text = Text()
        header_text.append("YELBEGEN", style="bold cyan")
        header_text.append(" - Pasif OSINT Tarama\n", style="dim")
        header_text.append(f"Hedef: ", style="dim")
        header_text.append(self.target, style="bold yellow")
        header_text.append(f" | Zaman: {datetime.now().strftime('%H:%M:%S')}", style="dim")
        
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
        selected_modules = list(AVAILABLE_MODULES.values())
        module_configs = [{'name': m['name'], 'function': m['function']} for m in selected_modules]
        
        result_queue = self.engine.start_scan(self.target, module_configs)
        
        completed_modules = set()
        total_modules = len(module_configs)
        
        with Live(self.create_dashboard(), refresh_per_second=4, console=console) as live:
            while True:
                try:
                    while not result_queue.empty():
                        result = result_queue.get_nowait()
                        self.process_result(result, completed_modules)
                        live.update(self.create_dashboard())
                    
                    if self.engine.is_scan_complete() and len(completed_modules) >= total_modules:
                        break
                    
                    time.sleep(0.25)
                    
                except KeyboardInterrupt:
                    console.print("\n[yellow]Tarama kullanıcı tarafından durduruldu[/yellow]")
                    self.engine.stop_scan()
                    break
                except Exception as e:
                    console.print(f"\n[red]Hata: {e}[/red]")
                    break
        
        self.engine.cleanup()
        
        layout = self.create_dashboard()
        status_text = Text("Durum: Tamamlandı | ", style="green bold")
        status_text.append(f"Toplam modül: {total_modules}", style="dim")
        layout["footer"].update(Panel(status_text, style="green"))
        
        console.print(layout)
        console.print("\n[green]Tarama tamamlandı![/green]")
    
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
    import sys
    
    if len(sys.argv) < 2:
        console.print("[red]Hata:[/red] Hedef belirtilmedi")
        console.print("Kullanım: [cyan]yelbegen <hedef>[/cyan]")
        console.print("Örnek: [cyan]yelbegen google.com[/cyan]")
        sys.exit(1)
    
    target = sys.argv[1]
    dashboard = YelbegenDashboard(target)
    dashboard.run()


if __name__ == "__main__":
    main()
