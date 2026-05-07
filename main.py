"""Rich terminal interface for Secure System Observer (SSO).

Run with:
    python3 main.py

Install the visual terminal dependency first:
    python3 -m pip install -r requirements.txt
"""

from __future__ import annotations

import getpass
import os
import select
import sys
import termios
import time
import tty
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover - classroom environment helper
    print("Rich is not installed yet.")
    print("Run: python3 -m pip install -r requirements.txt")
    sys.exit(1)

from sso.logging_integrity import create_snapshot, delete_log_pair, list_logs, verify_log
from sso.monitor import (
    calculate_cpu_percent,
    calculate_process_cpu_percents,
    enumerate_processes_with_metrics,
    format_memory_report,
    format_uptime,
    kb_to_mb,
    process_state_counts,
    read_cpu_times,
    read_load_average,
    read_meminfo,
    read_process_cpu_jiffies,
    read_uptime_seconds,
)
from sso.security import AccessDenied, AuthError, authenticate, audit_event, require_role

console = Console()

SPARK_CHARS = "▁▂▃▄▅▆▇█"


def clear() -> None:
    console.clear()


def bar(percent: float, width: int = 28) -> str:
    percent = max(0.0, min(100.0, percent))
    filled = int(round((percent / 100) * width))
    empty = width - filled
    if percent >= 85:
        style = "red"
    elif percent >= 65:
        style = "yellow"
    else:
        style = "green"
    return f"[{style}]{'█' * filled}[/][dim]{'░' * empty}[/] {percent:5.1f}%"


def sparkline(values: Iterable[float], maximum: float = 100.0) -> str:
    values = list(values)[-40:]
    if not values:
        return ""
    maximum = max(maximum, max(values), 1.0)
    output = []
    for value in values:
        index = int(round((max(0.0, value) / maximum) * (len(SPARK_CHARS) - 1)))
        index = max(0, min(index, len(SPARK_CHARS) - 1))
        output.append(SPARK_CHARS[index])
    return "".join(output)


def percent_used(used: float, total: float) -> float:
    if total <= 0:
        return 0.0
    return round((used / total) * 100, 1)


def login_screen(max_attempts: int = 3) -> Dict[str, str]:
    clear()
    console.print(
        Panel.fit(
            Align.center("[bold cyan]Secure System Observer[/]\n[dim]Protected OS health portal[/]"),
            border_style="cyan",
            box=box.DOUBLE,
        )
    )

    for attempt in range(1, max_attempts + 1):
        username = Prompt.ask("[bold]Username[/]").strip()
        password = getpass.getpass("Password: ")
        user = authenticate(username, password)
        if user:
            console.print(f"[green]Login successful.[/] Welcome, {user['username']} ({user['role']}).")
            time.sleep(0.7)
            return user
        remaining = max_attempts - attempt
        console.print(f"[red]Invalid login.[/] Attempts left: {remaining}")
    raise AuthError("Too many failed login attempts.")


class KeyReader:
    """Tiny Linux terminal key reader so the live dashboard can quit with q."""

    def __enter__(self):
        self.enabled = sys.stdin.isatty()
        self.old_settings = None
        if self.enabled:
            self.old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.enabled and self.old_settings is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def pressed(self) -> str | None:
        if not self.enabled:
            return None
        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if ready:
            return sys.stdin.read(1)
        return None


def build_process_table(processes: List[Dict[str, str]], restricted: bool) -> Table:
    table = Table(title="Top Processes by CPU / RAM", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("CPU %", justify="right", no_wrap=True)
    table.add_column("RSS MB", justify="right", no_wrap=True)
    table.add_column("VSZ MB", justify="right", no_wrap=True)
    table.add_column("Threads", justify="right", no_wrap=True)
    table.add_column("Name", overflow="fold")
    if restricted:
        table.add_column("Owner", no_wrap=True)
        table.add_column("UID", justify="right", no_wrap=True)
        table.add_column("Command", overflow="fold")

    for proc in processes:
        state = f"{proc.get('state_code', '?')} {proc.get('state', 'Unknown')}"
        row = [
            proc.get("pid", "?"),
            state,
            proc.get("cpu_percent", "0.0"),
            proc.get("rss_mb", "0.0"),
            proc.get("vms_mb", "0.0"),
            proc.get("threads", "?"),
            proc.get("name", "?"),
        ]
        if restricted:
            row.extend([
                proc.get("owner", "?"),
                proc.get("uid", "?"),
                proc.get("cmdline", "")[:90],
            ])
        table.add_row(*row)
    return table


def build_state_table(counts: Dict[str, int]) -> Table:
    table = Table(title="Process States", box=box.ROUNDED)
    table.add_column("State")
    table.add_column("Count", justify="right")
    labels = {
        "R": "Running",
        "S": "Sleeping",
        "D": "Disk Sleep",
        "T": "Stopped",
        "Z": "Zombie",
        "I": "Idle Kernel",
    }
    for code, count in sorted(counts.items()):
        table.add_row(f"{code} - {labels.get(code, 'Other')}", str(count))
    return table


def build_dashboard(
    user: Dict[str, str],
    restricted: bool,
    cpu_percent: float,
    cpu_history: List[float],
    ram_history: List[float],
    swap_history: List[float],
    process_history: List[float],
    processes: List[Dict[str, str]],
) -> Group:
    mem = read_meminfo()
    ram_total = kb_to_mb(mem.get("MemTotal", 0))
    ram_used = kb_to_mb(mem.get("MemUsed", 0))
    ram_avail = kb_to_mb(mem.get("MemAvailable", 0))
    swap_total = kb_to_mb(mem.get("SwapTotal", 0))
    swap_used = kb_to_mb(mem.get("SwapUsed", 0))
    swap_free = kb_to_mb(mem.get("SwapFree", 0))
    ram_percent = percent_used(ram_used, ram_total)
    swap_percent = percent_used(swap_used, swap_total)
    load = read_load_average()
    uptime = format_uptime(read_uptime_seconds())
    states = process_state_counts()
    process_count = sum(states.values())

    header = Panel(
        f"[bold cyan]Secure System Observer Live Dashboard[/]\n"
        f"User: [bold]{user['username']}[/]    Role: [bold]{user['role']}[/]    "
        f"Mode: [bold]{'Admin Restricted View' if restricted else 'Auditor-Safe View'}[/]    "
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[dim]Press q to return to the menu. Ctrl+C also exits the dashboard.[/]",
        border_style="cyan",
        box=box.DOUBLE,
    )

    metrics = Table.grid(expand=True)
    metrics.add_column(ratio=1)
    metrics.add_column(ratio=1)
    metrics.add_row(
        Panel(
            f"CPU Usage\n{bar(cpu_percent)}\n"
            f"Load Avg: {load['1m']:.2f} / {load['5m']:.2f} / {load['15m']:.2f}\n"
            f"Uptime: {uptime}",
            title="Processor",
            border_style="green" if cpu_percent < 65 else "yellow" if cpu_percent < 85 else "red",
        ),
        Panel(
            f"RAM Used\n{bar(ram_percent)}\n"
            f"Used: {ram_used:.1f} MB    Available: {ram_avail:.1f} MB    Total: {ram_total:.1f} MB\n"
            f"Swap Used\n{bar(swap_percent)}\n"
            f"Used: {swap_used:.1f} MB    Free: {swap_free:.1f} MB    Total: {swap_total:.1f} MB",
            title="Virtual Memory",
            border_style="magenta",
        ),
    )

    charts = Panel(
        f"CPU     {sparkline(cpu_history)} {cpu_history[-1] if cpu_history else 0:.1f}%\n"
        f"RAM     {sparkline(ram_history)} {ram_history[-1] if ram_history else 0:.1f}%\n"
        f"Swap    {sparkline(swap_history)} {swap_history[-1] if swap_history else 0:.1f}%\n"
        f"Procs   {sparkline(process_history, maximum=max(process_history[-40:] or [1]))} {process_count}",
        title="Moving Performance Charts",
        border_style="blue",
    )

    lower = Table.grid(expand=True)
    lower.add_column(ratio=3)
    lower.add_column(ratio=1)
    lower.add_row(build_process_table(processes, restricted), build_state_table(states))

    return Group(header, metrics, charts, lower)


def live_dashboard(user: Dict[str, str], restricted: bool = False) -> None:
    if restricted:
        require_role(user, {"Administrator"}, "open restricted live dashboard")

    cpu_history: List[float] = []
    ram_history: List[float] = []
    swap_history: List[float] = []
    process_history: List[float] = []

    previous_cpu = read_cpu_times()
    previous_proc = read_process_cpu_jiffies()
    time.sleep(0.2)

    with KeyReader() as keys:
        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while True:
                current_cpu = read_cpu_times()
                current_proc = read_process_cpu_jiffies()
                cpu_percent = calculate_cpu_percent(previous_cpu, current_cpu)
                proc_cpu = calculate_process_cpu_percents(previous_proc, current_proc, previous_cpu, current_cpu)
                processes = enumerate_processes_with_metrics(
                    include_restricted_details=restricted,
                    limit=15,
                    cpu_percents=proc_cpu,
                )

                mem = read_meminfo()
                ram_total = kb_to_mb(mem.get("MemTotal", 0))
                ram_used = kb_to_mb(mem.get("MemUsed", 0))
                swap_total = kb_to_mb(mem.get("SwapTotal", 0))
                swap_used = kb_to_mb(mem.get("SwapUsed", 0))
                states = process_state_counts()

                cpu_history.append(cpu_percent)
                ram_history.append(percent_used(ram_used, ram_total))
                swap_history.append(percent_used(swap_used, swap_total))
                process_history.append(float(sum(states.values())))
                cpu_history[:] = cpu_history[-60:]
                ram_history[:] = ram_history[-60:]
                swap_history[:] = swap_history[-60:]
                process_history[:] = process_history[-60:]

                live.update(
                    build_dashboard(
                        user,
                        restricted,
                        cpu_percent,
                        cpu_history,
                        ram_history,
                        swap_history,
                        process_history,
                        processes,
                    )
                )

                previous_cpu = current_cpu
                previous_proc = current_proc

                for _ in range(10):
                    key = keys.pressed()
                    if key and key.lower() == "q":
                        return
                    time.sleep(0.1)


def show_process_table(user: Dict[str, str], restricted: bool = False) -> None:
    if restricted:
        require_role(user, {"Administrator"}, "view restricted process details")
    previous_cpu = read_cpu_times()
    previous_proc = read_process_cpu_jiffies()
    time.sleep(0.5)
    current_cpu = read_cpu_times()
    current_proc = read_process_cpu_jiffies()
    proc_cpu = calculate_process_cpu_percents(previous_proc, current_proc, previous_cpu, current_cpu)
    processes = enumerate_processes_with_metrics(
        include_restricted_details=restricted,
        limit=30,
        cpu_percents=proc_cpu,
    )
    clear()
    console.print(build_process_table(processes, restricted))
    Prompt.ask("\nPress Enter to return", default="")


def choose_log() -> Path | None:
    logs = list_logs()
    if not logs:
        console.print("[yellow]No snapshot logs found.[/]")
        Prompt.ask("Press Enter to return", default="")
        return None

    table = Table(title="Available Snapshot Logs", box=box.ROUNDED)
    table.add_column("#", justify="right")
    table.add_column("File")
    table.add_column("Modified")
    for i, path in enumerate(logs, start=1):
        modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(str(i), path.name, modified)
    console.print(table)
    choice = Prompt.ask("Choose log number", default="1").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(logs)):
        console.print("[red]Invalid selection.[/]")
        return None
    return logs[int(choice) - 1]


def view_audit_log() -> None:
    from sso.security import AUDIT_LOG

    clear()
    console.print(Panel("Audit events and security alerts", style="bold cyan"))
    if not AUDIT_LOG.exists():
        console.print("[yellow]No audit log found yet.[/]")
    else:
        lines = AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Recent Audit Log Lines", overflow="fold")
        for line in lines:
            style = "red" if "SECURITY_ALERT" in line else "green" if "LOGIN_SUCCESS" in line else "white"
            table.add_row(f"[{style}]{line}[/]")
        console.print(table)
    Prompt.ask("\nPress Enter to return", default="")


def menu_panel(user: Dict[str, str]) -> Panel:
    options = [
        "[bold]1[/] Live performance dashboard",
        "[bold]2[/] Live restricted dashboard [Administrator only]",
        "[bold]3[/] View basic process table",
        "[bold]4[/] View restricted process details [Administrator only]",
        "[bold]5[/] View memory metrics",
        "[bold]6[/] Snapshot current system state to log",
        "[bold]7[/] Verify log integrity",
        "[bold]8[/] Delete a log file [Administrator only]",
        "[bold]9[/] View audit/security log",
        "[bold]10[/] Exit",
    ]
    return Panel(
        "\n".join(options),
        title=f"Secure System Observer | {user['username']} ({user['role']})",
        border_style="cyan",
        box=box.DOUBLE,
    )


def show_menu(user: Dict[str, str]) -> None:
    while True:
        clear()
        console.print(menu_panel(user))
        choice = Prompt.ask("Select option", choices=[str(i) for i in range(1, 11)], default="1")

        try:
            if choice == "1":
                live_dashboard(user, restricted=False)

            elif choice == "2":
                live_dashboard(user, restricted=True)

            elif choice == "3":
                show_process_table(user, restricted=False)

            elif choice == "4":
                show_process_table(user, restricted=True)

            elif choice == "5":
                clear()
                console.print(Panel(format_memory_report(), title="Memory Metrics", border_style="magenta"))
                Prompt.ask("\nPress Enter to return", default="")

            elif choice == "6":
                include_restricted = user["role"] == "Administrator"
                path = create_snapshot(user, include_restricted_details=include_restricted)
                console.print(f"[green]Snapshot saved:[/] {path}")
                console.print(f"[green]Hash saved:[/] {path}.sha256")
                Prompt.ask("Press Enter to return", default="")

            elif choice == "7":
                clear()
                path = choose_log()
                if path:
                    ok = verify_log(path)
                    if ok:
                        console.print("[green]Integrity check PASSED.[/] Log has not been changed.")
                    else:
                        console.print("[red]Integrity check FAILED.[/] Log may have been altered.")
                        audit_event("SECURITY_ALERT", f"Integrity check failed for {path.name}", user["username"])
                    Prompt.ask("Press Enter to return", default="")

            elif choice == "8":
                require_role(user, {"Administrator"}, "delete log files")
                clear()
                path = choose_log()
                if path:
                    delete_log_pair(path, user["username"])
                    console.print("[green]Log and hash file deleted.[/]")
                    Prompt.ask("Press Enter to return", default="")

            elif choice == "9":
                view_audit_log()

            elif choice == "10":
                audit_event("LOGOUT", "User exited SSO", user["username"])
                console.print("[cyan]Goodbye.[/]")
                break

        except AccessDenied as e:
            console.print(f"[red]{e}[/]")
            console.print("[yellow]A SECURITY_ALERT was written to the audit log.[/]")
            Prompt.ask("Press Enter to return", default="")
        except KeyboardInterrupt:
            console.print("\n[yellow]Returned to menu.[/]")
            time.sleep(0.7)
        except FileNotFoundError as e:
            console.print(f"[red]File error:[/] {e}")
            Prompt.ask("Press Enter to return", default="")
        except PermissionError as e:
            console.print(f"[red]Permission error:[/] {e}")
            Prompt.ask("Press Enter to return", default="")
        except Exception as e:  # classroom-friendly error handling
            console.print(f"[red]Unexpected error:[/] {e}")
            audit_event("ERROR", str(e), user.get("username", "unknown"))
            Prompt.ask("Press Enter to return", default="")


def main() -> None:
    try:
        user = login_screen()
    except AuthError as e:
        console.print(f"[red]{e}[/]")
        return
    show_menu(user)


if __name__ == "__main__":
    main()
