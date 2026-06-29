from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from .config import (
    DisplayConfig,
    FilterConfig,
    InterceptConfig,
    ProxyConfig,
    SESSIONS_DIR,
)
from .display import (
    console,
    format_size,
    print_banner,
    print_history_table,
    print_proxy_info,
    print_stats,
    print_traffic_entry,
)
from .exporter import export_har, export_json
from .storage import TrafficStorage

app = typer.Typer(
    name="tian-intercept",
    help="tian-intercept — HTTP/HTTPS Traffic Inspector",
    rich_markup_mode="rich",
    no_args_is_help=False,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)


@app.command("start")
def start(
    port: Annotated[int, typer.Option("--port", "-p", help="Proxy server port")] = 8080,
    host: Annotated[str, typer.Option("--host", "-H", help="Bind address")] = "127.0.0.1",
    url: Annotated[Optional[str], typer.Option("--url", "-u", help="URL filter pattern (glob or regex)")] = None,
    method: Annotated[Optional[List[str]], typer.Option("--method", "-m", help="Filter by HTTP method")] = None,
    status: Annotated[Optional[List[int]], typer.Option("--status", "-s", help="Filter by status code")] = None,
    domain: Annotated[Optional[List[str]], typer.Option("--domain", "-d", help="Filter by host/domain")] = None,
    exclude: Annotated[Optional[List[str]], typer.Option("--exclude", "-e", help="Exclude host/domain")] = None,
    content_type: Annotated[Optional[List[str]], typer.Option("--ct", help="Filter by content-type")] = None,
    include_static: Annotated[bool, typer.Option("--include-static", help="Include static assets (js, css, images)")] = False,
    exclude_html: Annotated[bool, typer.Option("--exclude-html", help="Exclude HTML responses")] = False,
    exclude_cgi: Annotated[bool, typer.Option("--exclude-cgi", help="Exclude CGI/tracking endpoints (e.g. /cdn-cgi/)")] = True,
    no_req_headers: Annotated[bool, typer.Option("--no-req-headers", help="Hide request headers")] = False,
    no_resp_headers: Annotated[bool, typer.Option("--no-resp-headers", help="Hide response headers")] = False,
    no_req_body: Annotated[bool, typer.Option("--no-req-body", help="Hide request body")] = False,
    no_resp_body: Annotated[bool, typer.Option("--no-resp-body", help="Hide response body")] = False,
    full: Annotated[bool, typer.Option("--full", "-f", help="Display full body without truncation")] = False,
    compact: Annotated[bool, typer.Option("--compact", "-c", help="Compact one-line mode")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Capture silently without terminal output")] = False,
    session: Annotated[Optional[str], typer.Option("--session", help="Session name")] = None,
    save: Annotated[bool, typer.Option("--save", help="Auto-save session to disk")] = False,
    upstream: Annotated[Optional[str], typer.Option("--upstream", help="Upstream proxy URL")] = None,
    system_route: Annotated[bool, typer.Option("--route/--no-route", help="Automatically route system/macOS proxy traffic")] = True,
) -> None:
    """
    Start the intercept proxy server.

    Route traffic through the proxy to capture it in real-time.

    Setup:
      export http_proxy=http://127.0.0.1:8080
      export https_proxy=http://127.0.0.1:8080

    HTTPS requires the mitmproxy CA certificate to be installed.
    Run 'tian-intercept cert' for installation instructions.
    """
    print_banner()

    config = InterceptConfig(
        proxy=ProxyConfig(host=host, port=port, upstream_proxy=upstream),
        filters=FilterConfig(
            url_pattern=url,
            methods=method or [],
            status_codes=status or [],
            hosts=domain or [],
            content_types=content_type or [],
            exclude_static=not include_static,
            exclude_hosts=exclude or [],
            exclude_html=exclude_html,
            exclude_cgi=exclude_cgi,
        ),
        display=DisplayConfig(
            show_request_headers=not no_req_headers,
            show_response_headers=not no_resp_headers,
            show_request_body=not no_req_body,
            show_response_body=not no_resp_body,
            full_output=full,
            compact=compact,
        ),
        session_name=session,
        auto_save=save,
        quiet=quiet,
    )

    storage = TrafficStorage(session_name=config.session_name, auto_save=save)
    print_proxy_info(host, port)

    active_filters = _build_filter_summary(url, method, status, domain, exclude)
    if active_filters:
        console.print("[dim]Active filters:[/dim]")
        for f in active_filters:
            console.print(f"  - {f}")
        console.print()

    try:
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy.options import Options
        from .proxy import InterceptAddon
    except ImportError as exc:
        console.print(f"[red]mitmproxy is not installed: {exc}[/red]")
        raise typer.Exit(1)

    addon = InterceptAddon(config=config, storage=storage)

    import subprocess
    import sys
    is_macos = sys.platform == "darwin"
    services = []

    if system_route and is_macos:
        try:
            services = _get_all_network_services()
            console.print(f"[bright_yellow]Enabling macOS system proxy routing on services: {', '.join(services)}...[/bright_yellow]")
            for service in services:
                subprocess.run(["networksetup", "-setwebproxy", service, host, str(port)], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxy", service, host, str(port)], capture_output=True)
                subprocess.run(["networksetup", "-setwebproxystate", service, "on"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxystate", service, "on"], capture_output=True)
            console.print(f"[bright_green]System proxy enabled successfully ({host}:{port}).[/bright_green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to auto-enable macOS system proxy: {e}[/yellow]")

    async def _run() -> None:
        opts = Options(listen_host=host, listen_port=port)
        if upstream:
            opts.update(mode=[f"upstream:{upstream}"])
        master = DumpMaster(opts)
        master.addons.add(addon)
        for name in ("termlog", "dumper"):
            existing = master.addons.get(name)
            if existing:
                master.addons.remove(existing)
        try:
            await master.run()
        except KeyboardInterrupt:
            pass
        finally:
            master.shutdown()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    finally:
        if system_route and is_macos and services:
            console.print(f"[bright_yellow]\nDisabling macOS system proxy routing on services: {', '.join(services)}...[/bright_yellow]")
            for service in services:
                subprocess.run(["networksetup", "-setwebproxystate", service, "off"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxystate", service, "off"], capture_output=True)
            console.print("[bright_green]System proxy disabled successfully.[/bright_green]")
        
        console.print()
        console.print(f"[dim]Proxy stopped. {storage.count} requests captured.[/dim]")
        if save or session:
            saved_path = storage.save()
            console.print(f"[dim]Session saved: {saved_path}[/dim]")
        console.print()


@app.command("show")
def show(
    session: Annotated[Optional[str], typer.Option("--session", "-s", help="Session name")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of entries to display")] = 50,
    detail: Annotated[Optional[str], typer.Option("--id", help="Show detail for a single entry ID")] = None,
    search: Annotated[Optional[str], typer.Option("--search", help="Search term across all traffic")] = None,
    full: Annotated[bool, typer.Option("--full", "-f", help="Display full body")] = False,
) -> None:
    """Display captured traffic history."""
    print_banner()
    storage = _load_session(session)

    if search:
        entries = storage.search(search)
        console.print(f"[dim]Search '{search}': {len(entries)} result(s)[/dim]\n")
    else:
        entries = storage.get_all(limit=limit)

    if detail:
        entry = storage.get_entry(detail)
        if not entry:
            console.print(f"[red]Entry '{detail}' not found.[/red]")
            raise typer.Exit(1)
        print_traffic_entry(
            seq=entry.request.get("_seq", 0),
            entry_id=entry.id,
            request=entry.request,
            response=entry.response,
            duration_ms=entry.duration_ms,
            config=DisplayConfig(full_output=full),
        )
    else:
        print_history_table(entries)
        total = storage.count
        suffix = f" (showing {len(entries)})" if len(entries) < total else ""
        console.print(f"\n[dim]Total: {total} entries{suffix}[/dim]")


@app.command("export")
def export(
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: json or har")] = "json",
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output file path")] = None,
    session: Annotated[Optional[str], typer.Option("--session", "-s", help="Session name")] = None,
    limit: Annotated[Optional[int], typer.Option("--limit", "-n", help="Limit number of entries")] = None,
) -> None:
    """
    Export captured traffic to JSON or HAR format.

    HAR files can be imported in Chrome DevTools via Network > Import HAR.
    """
    print_banner()

    fmt = format.lower()
    if fmt not in ("json", "har"):
        console.print("[red]Invalid format. Use: json or har[/red]")
        raise typer.Exit(1)

    storage = _load_session(session)
    entries = storage.get_all(limit=limit)

    if not entries:
        console.print("[yellow]No traffic to export.[/yellow]")
        raise typer.Exit(0)

    if not output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path(f"tian_intercept_export_{ts}.{fmt}")

    count = export_json(entries, output) if fmt == "json" else export_har(entries, output)
    console.print(f"[green]{count} entries exported to {output}[/green]")

    if fmt == "har":
        console.print("[dim]Import in Chrome: DevTools > Network > Import HAR[/dim]")


@app.command("stats")
def stats(
    session: Annotated[Optional[str], typer.Option("--session", "-s", help="Session name")] = None,
) -> None:
    """Display traffic statistics."""
    print_banner()
    storage = _load_session(session)
    print_stats(storage.get_stats())


@app.command("clear")
def clear(
    session: Annotated[Optional[str], typer.Option("--session", "-s", help="Session name")] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
) -> None:
    """Delete all captured traffic from a session."""
    print_banner()
    storage = _load_session(session)

    if storage.count == 0:
        console.print("[dim]Session is empty.[/dim]")
        return

    if not yes:
        confirmed = Confirm.ask(
            f"Delete {storage.count} entries from session '{storage.session_name}'?"
        )
        if not confirmed:
            console.print("[dim]Aborted.[/dim]")
            return

    deleted = storage.clear()
    if storage.session_file.exists():
        storage.session_file.unlink()
    console.print(f"[green]{deleted} entries deleted.[/green]")


@app.command("sessions")
def sessions() -> None:
    """List all saved sessions."""
    print_banner()
    session_files = sorted(SESSIONS_DIR.glob("*.json"))

    if not session_files:
        console.print("[dim]No saved sessions found.[/dim]")
        return

    table = Table(title="Saved Sessions", box=box.ROUNDED, title_style="bold cyan")
    table.add_column("Session Name", style="bold white")
    table.add_column("Entries", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Path")

    for sf in session_files:
        try:
            with open(sf, "r") as f:
                entry_count = json.load(f).get("entry_count", "?")
        except Exception:
            entry_count = "?"
        table.add_row(sf.stem, str(entry_count), format_size(sf.stat().st_size), str(sf))

    console.print(table)
    console.print(f"\n[dim]Sessions directory: {SESSIONS_DIR}[/dim]")


@app.command("cert")
def cert(
    install: Annotated[bool, typer.Option("--install", help="Install CA cert to macOS system keychain")] = False,
) -> None:
    """
    Display or install the mitmproxy CA certificate for HTTPS interception.

    Run this once after first starting the proxy to enable HTTPS traffic capture.
    """
    print_banner()

    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if not cert_path.exists():
        console.print("[yellow]CA certificate not found. Start the proxy once to generate it.[/yellow]")
        return

    console.print(f"[green]CA certificate found:[/green] [bold]{cert_path}[/bold]\n")
    console.print("[bold]Installation instructions:[/bold]\n")
    console.print("  macOS Keychain:")
    console.print(
        f"    sudo security add-trusted-cert -d -r trustRoot "
        f"-k /Library/Keychains/System.keychain {cert_path}"
    )
    console.print()
    console.print("  Firefox:")
    console.print(f"    Settings > Privacy > Certificates > Import > {cert_path}")
    console.print()
    console.print("  Terminal / curl / Python:")
    console.print("    export http_proxy=http://127.0.0.1:8080")
    console.print("    export https_proxy=http://127.0.0.1:8080")
    console.print("    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem")

    if install:
        import subprocess
        result = subprocess.run(
            [
                "sudo", "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                str(cert_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            console.print("\n[green]CA certificate installed to macOS Keychain.[/green]")
        else:
            console.print(f"\n[red]Certificate installation failed: {result.stderr}[/red]")


def _build_filter_summary(
    url: Optional[str],
    method: Optional[List[str]],
    status: Optional[List[int]],
    domain: Optional[List[str]],
    exclude: Optional[List[str]],
) -> list[str]:
    parts = []
    if url:
        parts.append(f"url: [yellow]{url}[/yellow]")
    if method:
        parts.append(f"method: [yellow]{', '.join(method)}[/yellow]")
    if status:
        parts.append(f"status: [yellow]{', '.join(str(s) for s in status)}[/yellow]")
    if domain:
        parts.append(f"domain: [yellow]{', '.join(domain)}[/yellow]")
    if exclude:
        parts.append(f"exclude: [red]{', '.join(exclude)}[/red]")
    return parts


def _load_session(session_name: Optional[str] = None) -> TrafficStorage:
    if session_name:
        return TrafficStorage(session_name=session_name)
    session_files = sorted(SESSIONS_DIR.glob("*.json"))
    if session_files:
        return TrafficStorage(session_name=session_files[-1].stem)
    return TrafficStorage()


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__
        console.print(f"tian-intercept v{__version__}")
        raise typer.Exit()


def _get_all_network_services() -> list[str]:
    import subprocess
    try:
        res = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True)
        services = []
        for line in res.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("An asterisk") and not line.startswith("*"):
                services.append(line)
        return services if services else ["Wi-Fi", "Ethernet"]
    except Exception:
        return ["Wi-Fi", "Ethernet"]


def interactive_menu() -> None:
    import subprocess
    import shutil

    while True:
        print_banner()
        menu_table = Table(box=box.ROUNDED, show_header=False, border_style="bright_cyan")
        menu_table.add_column("Option", style="bright_yellow", justify="center", width=3)
        menu_table.add_column("Description", style="bright_white", width=42)
        menu_table.add_row("1", "Start Proxy Server")
        menu_table.add_row("2", "Show Captured Traffic History & Inspect")
        menu_table.add_row("3", "Export Traffic (JSON/HAR)")
        menu_table.add_row("4", "Display Traffic Statistics")
        menu_table.add_row("5", "List & Load Saved Sessions")
        menu_table.add_row("6", "Clear Traffic History")
        menu_table.add_row("7", "Install CA Certificate to macOS Keychain")
        menu_table.add_row("8", "Uninstall CA Certificate & Cleanup")
        menu_table.add_row("9", "Turn ON System Proxy Routing (All Interfaces)")
        menu_table.add_row("10", "Turn OFF System Proxy Routing (All Interfaces)")
        menu_table.add_row("11", "Show Proxy Routing Commands & Help")
        menu_table.add_row("12", "Exit")
        
        console.print(menu_table)
        
        choice = typer.prompt("Select option [1-12]", default="1")
        
        if choice == "1":
            port_input = typer.prompt("Enter proxy port", default="8080")
            try:
                port = int(port_input)
            except ValueError:
                port = 8080
            
            exclude_static = Confirm.ask("Exclude static assets (JS, CSS, images, videos)?", default=True)
            exclude_html = Confirm.ask("Exclude HTML pages/responses?", default=False)
            exclude_cgi = Confirm.ask("Exclude CGI/tracking endpoints (e.g. cdn-cgi, cgi-bin)?", default=True)
            domain_filter = typer.prompt("Filter by domain (e.g. api.example.com, leave empty for all)", default="")
            save_session = Confirm.ask("Automatically save traffic session to disk?", default=False)
            
            domains = [domain_filter.strip()] if domain_filter.strip() else None
            
            console.print("[bright_yellow]\nStarting proxy... Press Ctrl+C to stop.\n[/bright_yellow]")
            try:
                start(
                    port=port, 
                    save=save_session, 
                    include_static=not exclude_static,
                    exclude_html=exclude_html,
                    exclude_cgi=exclude_cgi,
                    domain=domains
                )
            except KeyboardInterrupt:
                console.print("[bright_yellow]\nProxy stopped by user.[/bright_yellow]")
            except Exception as e:
                console.print(f"[red]Error starting proxy: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "2":
            limit_input = typer.prompt("Enter maximum entries to show", default="50")
            try:
                limit = int(limit_input)
            except ValueError:
                limit = 50
            search = typer.prompt("Enter search term (leave empty for all)", default="")
            try:
                show(limit=limit, search=search if search else None)
                inspect_id = typer.prompt("Enter Entry ID to view full details (or press Enter to return)", default="")
                if inspect_id.strip():
                    show(detail=inspect_id.strip())
            except KeyboardInterrupt:
                pass
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "3":
            fmt = typer.prompt("Export format (json/har)", default="json").strip().lower()
            out_file = typer.prompt("Output file path (leave empty for auto-generated name)", default="")
            try:
                export(format=fmt, output=Path(out_file) if out_file else None)
            except Exception as e:
                console.print(f"[red]Error exporting: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "4":
            try:
                stats()
            except Exception as e:
                console.print(f"[red]Error loading statistics: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "5":
            try:
                sessions()
                select_session = typer.prompt("Enter session name to view history (or press Enter to return)", default="")
                if select_session.strip():
                    show(session=select_session.strip())
                    inspect_id = typer.prompt("Enter Entry ID to view full details (or press Enter to return)", default="")
                    if inspect_id.strip():
                        show(session=select_session.strip(), detail=inspect_id.strip())
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "6":
            try:
                clear()
            except Exception as e:
                console.print(f"[red]Error clearing history: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "7":
            try:
                cert(install=True)
            except Exception as e:
                console.print(f"[red]Error installing certificate: {e}[/red]")
            typer.prompt("\nPress Enter to return to menu")

        elif choice == "8":
            confirm = Confirm.ask("[bright_red]Are you sure you want to uninstall CA certificate and remove all proxy settings?[/bright_red]", default=False)
            if confirm:
                console.print("[bright_yellow]\n[1/4] Removing CA certificate from macOS Keychain...[/bright_yellow]")
                subprocess.run(["sudo", "security", "delete-certificate", "-c", "mitmproxy", "/Library/Keychains/System.keychain"], capture_output=True)
                subprocess.run(["security", "delete-certificate", "-c", "mitmproxy"], capture_output=True)
                
                console.print("[bright_yellow][2/4] Removing ~/.mitmproxy directory...[/bright_yellow]")
                mitm_dir = Path.home() / ".mitmproxy"
                if mitm_dir.exists():
                    shutil.rmtree(mitm_dir)
                    console.print("      Removed ~/.mitmproxy")
                
                console.print("[bright_yellow][3/4] Removing aliases from ~/.zshrc...[/bright_yellow]")
                zshrc_path = Path.home() / ".zshrc"
                if zshrc_path.exists():
                    content = zshrc_path.read_text()
                    marker = "# >>> intercept-proxy >>>"
                    end_marker = "# <<< intercept-proxy <<<"
                    if marker in content and end_marker in content:
                        parts = content.split(marker)
                        before = parts[0]
                        after = parts[1].split(end_marker)[1]
                        zshrc_path.write_text(before.rstrip() + "\n" + after.lstrip())
                        console.print("      Aliases removed from ~/.zshrc")
                
                console.print("[bright_yellow][4/4] Disabling macOS system proxy settings on all interfaces...[/bright_yellow]")
                services = _get_all_network_services()
                for service in services:
                    subprocess.run(["networksetup", "-setwebproxystate", service, "off"], capture_output=True)
                    subprocess.run(["networksetup", "-setsecurewebproxystate", service, "off"], capture_output=True)
                console.print("      System proxy settings disabled.")
                
                console.print("[bright_green]\nCleanup complete! Run 'source ~/.zshrc' to update your terminal session.[/bright_green]")
            else:
                console.print("[dim]Aborted.[/dim]")
            typer.prompt("\nPress Enter to return to menu")

        elif choice == "9":
            services = _get_all_network_services()
            console.print(f"[bright_yellow]Enabling proxy routing on services: {', '.join(services)}...[/bright_yellow]")
            for service in services:
                subprocess.run(["networksetup", "-setwebproxy", service, "127.0.0.1", "8080"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxy", service, "127.0.0.1", "8080"], capture_output=True)
                subprocess.run(["networksetup", "-setwebproxystate", service, "on"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxystate", service, "on"], capture_output=True)
            console.print(f"[bright_green]System proxy enabled successfully (127.0.0.1:8080).[/bright_green]")
            typer.prompt("\nPress Enter to return to menu")

        elif choice == "10":
            services = _get_all_network_services()
            console.print(f"[bright_yellow]Disabling proxy routing on services: {', '.join(services)}...[/bright_yellow]")
            for service in services:
                subprocess.run(["networksetup", "-setwebproxystate", service, "off"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxystate", service, "off"], capture_output=True)
            console.print(f"[bright_green]System proxy disabled successfully.[/bright_green]")
            typer.prompt("\nPress Enter to return to menu")

        elif choice == "11":
            help_text = Text.assemble(
                ("To route traffic through tian-intercept, use these steps:\n\n", "bright_white"),
                ("1. Terminal Routing:\n", "bold bright_yellow"),
                ("   Run the automatic zsh shortcut command:\n", "bright_white"),
                ("     proxy-on\n", "bold bright_green"),
                ("   To disable it later, run:\n", "bright_white"),
                ("     proxy-off\n\n", "bold bright_red"),
                ("2. System/Browser Routing (macOS):\n", "bold bright_yellow"),
                ("   Use menu options 9 and 10 to toggle all interfaces instantly, or manually configure:\n", "bright_white"),
                ("     System Settings > Network > Wi-Fi > Details > Proxies\n", "bright_cyan"),
                ("     Enable Web Proxy & Secure Web Proxy -> 127.0.0.1:8080\n", "bright_cyan")
            )
            console.print(Panel(help_text, title="Proxy Routing Configuration", border_style="bright_cyan", expand=False))
            typer.prompt("\nPress Enter to return to menu")
            
        elif choice == "12":
            console.print("[bright_green]Goodbye![/bright_green]")
            break
        else:
            console.print("[bright_red]Invalid choice. Please select 1-12.[/bright_red]")
            typer.prompt("\nPress Enter to continue")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-v",
            callback=_version_callback,
            is_eager=True,
            help="Print version and exit",
        ),
    ] = None,
) -> None:
    """
    tian-intercept — HTTP/HTTPS Traffic Inspector.

    Captures and analyzes HTTP/HTTPS traffic passing through a local proxy.
    Equivalent to a lightweight Burp Suite or mitmproxy for the terminal.
    """
    if ctx.invoked_subcommand is None:
        interactive_menu()


if __name__ == "__main__":
    app()
