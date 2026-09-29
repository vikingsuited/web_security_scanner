#!/usr/bin/env python3
"""Terminal UI (rich).  Run: python3 ui_scanner.py"""
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from web_scanner import MODES, run_scan

console = Console()
COL = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def main():
    console.print("[bold]Web Security Scanner[/bold] - authorized testing only\n")
    target = Prompt.ask("Target (e.g. example.com)")
    mode = Prompt.ask("Mode", choices=list(MODES), default="medium")
    with console.status(f"Running {mode} scan..."):
        r = run_scan(target, mode)
    console.print(f"\n[bold]Risk {r['risk_score']}/100 [{r['risk_label']}][/bold]  ({r['duration_s']}s)")
    for c in r["categories"]:
        t = Table(title=f"{c['name']} ({c['count']})", show_header=False, expand=True)
        for x in (x for x in r["findings"] if x["category"] == c["id"]):
            t.add_row(f"[{COL[x['severity']]}]{x['severity'].upper()}[/]", x["title"], x["fix"])
        if c["count"]:
            console.print(t)


if __name__ == "__main__":
    main()
