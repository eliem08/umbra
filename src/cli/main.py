import sys
import os
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

from src.engine.scanner import scan_path
from src.engine.matcher import OpenAPIMatcher
from src.engine.authconfig import load_auth_config
from src.engine.gitdiff import annotate_new_endpoints, GitError
from src.engine.reporters import render_report

# Global console instance for stdout
console = Console()


@click.command(name="umbra")
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
    help="Target directory or source file (Python/Java/JavaScript) to scan."
)
@click.option(
    "--openapi",
    "-o",
    required=True,
    type=str,
    help="Path to the production openapi.json file, URL, or raw JSON string."
)
@click.option(
    "--strict",
    "-s",
    is_flag=True,
    default=False,
    help="Strict mode: Exit with code 1 if any shadow APIs or auth-less endpoints are detected."
)
@click.option(
    "--since",
    default=None,
    help="Only treat endpoints introduced/changed within this git window as 'new' "
         "(e.g. '1 week ago', '2026-05-01', or a baseline ref like 'origin/main'). "
         "Requires --path to be inside a git repository."
)
@click.option(
    "--new-only",
    is_flag=True,
    default=False,
    help="With --since, restrict strict-mode failures to endpoints introduced in the window."
)
@click.option(
    "--format",
    "-f",
    "report_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format. 'sarif' is consumable by GitHub code scanning."
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the report to this file instead of stdout (useful for json/sarif in CI)."
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to a .shadowscan.yml/.json auth-detection config (defaults to one found in --path)."
)
@click.option(
    "--express-entry",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Express app entry file. Enables runtime-assisted discovery (introspects the live "
         "router stack via Node) which supersedes static JS parsing. Requires Node.js."
)
def main(path, openapi, strict, since, new_only, report_format, output, config_path, express_entry):
    """
    Shadow API Scanner:
    Statically analyzes FastAPI/Flask/Spring Boot/Express codebases to identify
    undocumented shadow endpoints and missing authentication.
    """
    text_mode = report_format.lower() == "text"

    if text_mode:
        console.print(Panel(
            Text("UMBRA - Shadow API Posture Report", style="bold white", justify="center"),
            style="bold cyan",
            box=ROUNDED
        ))
        console.print(f"[bold dim]=> Scanning codebase path: {path}[/bold dim]")

    # 1. Run multi-language scan
    try:
        auth_config = load_auth_config(config_path or path)
        scan_result = scan_path(path, auth_config=auth_config, express_entry=express_entry)
    except Exception as e:
        console.print(f"[bold red]Parser Error: {e}[/bold red]")
        sys.exit(2)

    # 2. Optional git attribution ("introduced this week")
    if since:
        try:
            annotate_new_endpoints(scan_result.routes, path, since)
        except GitError as e:
            console.print(f"[bold red]Git Error: {e}[/bold red]")
            sys.exit(2)

    # 3. Run matcher
    if text_mode:
        console.print(f"[bold dim]=> Comparing with OpenAPI definition: {openapi}[/bold dim]")
    try:
        matcher = OpenAPIMatcher(openapi)
        report = matcher.generate_report(scan_result)
    except Exception as e:
        console.print(f"[bold red]Matcher Error: {e}[/bold red]")
        sys.exit(2)

    # 4. Machine-readable output (json/sarif)
    if not text_mode:
        rendered = render_report(report, report_format)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(rendered)
            console.print(f"[bold green]Report written to {output}[/bold green]")
        else:
            click.echo(rendered)
    else:
        if output:
            # Allow writing a JSON report file alongside the text dashboard.
            with open(output, "w", encoding="utf-8") as f:
                f.write(render_report(report, "json"))
        _render_dashboard(report, since)

    # 5. CI/CD gate enforcement
    if new_only and since:
        new_paths = {(r.path, r.method) for r in report.new_endpoints}
        gating_shadow = [r for r in report.shadow_endpoints if (r.path, r.method) in new_paths]
        gating_auth = [r for r in report.missing_auth_endpoints if (r.path, r.method) in new_paths]
    else:
        gating_shadow = report.shadow_endpoints
        gating_auth = report.missing_auth_endpoints
    violations = len(gating_shadow) + len(gating_auth)

    if strict and violations > 0:
        if text_mode:
            console.print(f"[bold red][FAIL] SCAN FAILED: Detected {violations} policy violation(s). Blocking commit/build due to --strict flag.[/bold red]")
        sys.exit(1)

    if text_mode:
        console.print("[bold green][OK] Scan passed successfully.[/bold green]")
    sys.exit(0)


def _render_dashboard(report, since):
    """Render the rich ANSI dashboard for text mode."""
    coverage_color = "red"
    if report.coverage_ratio >= 1.0:
        coverage_color = "green"
    elif report.coverage_ratio >= 0.8:
        coverage_color = "yellow"

    summary_table = Table(title="Summary Statistics", box=ROUNDED, border_style="cyan")
    summary_table.add_column("Metric", style="bold white")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Total Routes Parsed in Code", str(report.parsed_routes_count))
    summary_table.add_row("Total Registered Routes in OpenAPI", str(report.registered_routes_count))
    summary_table.add_row("Shadow Endpoints (Undocumented)", f"[bold red]{len(report.shadow_endpoints)}[/bold red]")
    summary_table.add_row("Endpoints Missing Auth (Risk)", f"[bold yellow]{len(report.missing_auth_endpoints)}[/bold yellow]")
    if since:
        summary_table.add_row("New Endpoints (this window)", f"[bold magenta]{len(report.new_endpoints)}[/bold magenta]")
    summary_table.add_row("OpenAPI Coverage Ratio", f"[bold {coverage_color}]{report.coverage_ratio:.2%}[/bold {coverage_color}]")

    console.print(summary_table)
    console.print()

    if report.shadow_endpoints:
        shadow_table = Table(title="[!] Detected Shadow Endpoints (Undocumented)", box=ROUNDED, border_style="red")
        shadow_table.add_column("Method", style="bold red", width=8)
        shadow_table.add_column("Path", style="bold white")
        shadow_table.add_column("Framework", style="dim cyan", width=12)
        shadow_table.add_column("Location (File:Line)", style="dim white")
        for route in report.shadow_endpoints:
            shadow_table.add_row(route.method, route.path, route.framework, f"{route.source_file}:{route.line_number}")
        console.print(shadow_table)
        console.print()
    else:
        console.print("[bold green][OK] No Shadow APIs detected (100% path coverage).[/bold green]")
        console.print()

    if report.missing_auth_endpoints:
        auth_table = Table(title="[!] Endpoints Lacking Authentication", box=ROUNDED, border_style="yellow")
        auth_table.add_column("Method", style="bold yellow", width=8)
        auth_table.add_column("Path", style="bold white")
        auth_table.add_column("Framework", style="dim cyan", width=12)
        auth_table.add_column("Location (File:Line)", style="dim white")
        for route in report.missing_auth_endpoints:
            auth_table.add_row(route.method, route.path, route.framework, f"{route.source_file}:{route.line_number}")
        console.print(auth_table)
        console.print()
    else:
        console.print("[bold green][OK] All parsed endpoints are secured with authentication middleware.[/bold green]")
        console.print()

    if since and report.new_endpoints:
        new_table = Table(title="[*] New / Changed Endpoints (this window)", box=ROUNDED, border_style="magenta")
        new_table.add_column("Method", style="bold magenta", width=8)
        new_table.add_column("Path", style="bold white")
        new_table.add_column("Auth", width=8)
        new_table.add_column("Change", style="dim cyan", width=10)
        new_table.add_column("Author", style="dim white")
        for route in report.new_endpoints:
            auth_cell = "[green]yes[/green]" if route.auth_required else "[red]NO[/red]"
            new_table.add_row(route.method, route.path, auth_cell, route.change_type or "", route.author or "")
        console.print(new_table)
        console.print()


if __name__ == "__main__":
    main()
