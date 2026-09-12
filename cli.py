import typer
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.models import PackageRecord, Severity
from src.intel.osv import check_osv_vulnerabilities
from src.intel.typosquat import check_typosquat
from src.intel.maintainer import check_registry_anomalies
from src.behavior.fetcher import fetch_and_extract
from src.behavior.patterns import scan_extracted_tarball
from src.hygiene.secrets import scan_repo_secrets
from src.hygiene.workflows import audit_github_workflows
from src.hygiene.dep_confusion import check_dependency_confusion
from src.scoring.engine import calculate_package_score, generate_report

app = typer.Typer(help="Sentinel: Supply Chain Security Scanner[cite: 2]")
console = Console()

@app.callback()
def main():
    """Sentinel Supply Chain Security Scanner."""
    pass

@app.command()
def serve():
    """Launches the local FastAPI dashboard (Phase 6)."""
    console.print("[bold cyan]Starting Sentinel Dashboard on http://localhost:8000...[/]")

@app.command()
def scan(target_dir: str, json_out: bool = typer.Option(False, "--json", help="Export as JSON[cite: 2]")):
    target_path = Path(target_dir)
    if not target_path.exists():
        console.print(f"[bold red]Error:[/] Directory '{target_dir}' does not exist.")
        raise typer.Exit(code=1)

    repo_findings = []
    verdicts = []
    
    # Mock parser: In a full run, this is populated by src/parsers/pypi.py[cite: 2]
    packages = [
        PackageRecord(name="reqeusts", version="2.31.0", ecosystem="pypi", direct=True, source_file="requirements.txt")
    ]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        # L3 Repo Hygiene[cite: 2]
        task_hygiene = progress.add_task("Scanning repo hygiene...", total=1)
        repo_findings.extend(scan_repo_secrets(target_path))
        repo_findings.extend(audit_github_workflows(target_path))
        progress.update(task_hygiene, completed=1)

        # L1 & L2 Package Analysis[cite: 2]
        task_pkgs = progress.add_task("Analyzing dependencies...", total=len(packages))
        for pkg in packages:
            findings = []
            
            # L1
            if tf := check_typosquat(pkg):
                findings.append(tf)
            findings.extend(check_osv_vulnerabilities(pkg))
            findings.extend(check_registry_anomalies(pkg))
            findings.extend(check_dependency_confusion(pkg, is_internal_candidate=True))
            
            # L2
            extract_dir = fetch_and_extract(pkg)
            if extract_dir:
                findings.extend(scan_extracted_tarball(pkg, extract_dir))
                
            verdicts.append(calculate_package_score(pkg, findings))
            progress.update(task_pkgs, advance=1)

    report = generate_report(target_dir, verdicts, repo_findings)

    if json_out:
        with open("sentinel_report.json", "w") as f:
            f.write(report.model_dump_json(indent=2))
        console.print("[bold green]✅ Report exported to sentinel_report.json[/]")
        return

    # Print Dashboard[cite: 2]
    color = "green" if report.project_score >= 80 else "yellow" if report.project_score >= 50 else "red"
    console.print(Panel(f"Project Health Score: [bold {color}]{report.project_score}/100[/]", title="SENTINEL AUDIT REPORT"))

    if repo_findings:
        console.print("\n[bold]Repository Hygiene (L3):[/]")
        for f in repo_findings:
            console.print(f"  [red]⚠️ {f.type}[/] - {f.human_explanation}")

    if verdicts:
        table = Table(title="Top Riskiest Packages[cite: 2]")
        table.add_column("Package", style="cyan")
        table.add_column("Score", style="magenta")
        table.add_column("Critical Flags", style="red")

        # Sort by lowest score first
        verdicts.sort(key=lambda v: v.score)
        for v in verdicts[:10]:
            criticals = sum(1 for f in v.findings if f.severity == Severity.CRITICAL)
            table.add_row(v.record.name, str(v.score), str(criticals) if criticals else "-")
        console.print(table)

if __name__ == "__main__":
    app()