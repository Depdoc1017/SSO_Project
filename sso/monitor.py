"""Linux /proc monitoring module for Secure System Observer."""

from __future__ import annotations

import os
import pwd
from pathlib import Path
from typing import Dict, List

PROC_DIR = Path("/proc")

STATE_MAP = {
    "R": "Running",
    "S": "Sleeping",
    "D": "Disk Sleep",
    "T": "Stopped",
    "t": "Tracing Stop",
    "Z": "Zombie",
    "X": "Dead",
    "I": "Idle Kernel Thread",
}


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return ""


def uid_to_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def read_proc_stat(pid: str) -> Dict[str, str] | None:
    """Parse /proc/[pid]/stat safely.

    Format note: the second field is the process name in parentheses and may
    contain spaces, so split around the final ')' instead of normal whitespace.
    """
    stat_path = PROC_DIR / pid / "stat"
    raw = _safe_read_text(stat_path).strip()
    if not raw:
        return None

    try:
        left, right = raw.rsplit(")", 1)
        name = left.split("(", 1)[1]
        parts = right.strip().split()
        state_code = parts[0]
        ppid = parts[1] if len(parts) > 1 else "?"
    except (IndexError, ValueError):
        return None

    return {
        "pid": pid,
        "name": name,
        "state_code": state_code,
        "state": STATE_MAP.get(state_code, "Unknown"),
        "ppid": ppid,
    }


def read_process_owner(pid: str) -> Dict[str, str]:
    try:
        stat_info = os.stat(PROC_DIR / pid)
        uid = stat_info.st_uid
        return {"uid": str(uid), "owner": uid_to_username(uid)}
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return {"uid": "?", "owner": "?"}


def read_cmdline(pid: str) -> str:
    raw = _safe_read_text(PROC_DIR / pid / "cmdline")
    cmd = raw.replace("\x00", " ").strip()
    return cmd if cmd else "[kernel thread or unavailable]"


def enumerate_processes(include_restricted_details: bool = False, limit: int | None = None) -> List[Dict[str, str]]:
    """Return active Linux processes from /proc.

    Basic mode returns PID, name, and state. Restricted/admin mode also returns
    owner, UID, parent PID, and command line.
    """
    processes: List[Dict[str, str]] = []
    pids = sorted([p.name for p in PROC_DIR.iterdir() if p.name.isdigit()], key=int)

    for pid in pids:
        proc = read_proc_stat(pid)
        if not proc:
            continue
        if include_restricted_details:
            proc.update(read_process_owner(pid))
            proc["cmdline"] = read_cmdline(pid)
        processes.append(proc)
        if limit and len(processes) >= limit:
            break

    return processes


def read_meminfo() -> Dict[str, int]:
    """Read physical RAM and swap data from /proc/meminfo in kB."""
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    result: Dict[str, int] = {}
    raw = _safe_read_text(PROC_DIR / "meminfo")
    for line in raw.splitlines():
        key = line.split(":", 1)[0]
        if key in wanted:
            parts = line.split()
            try:
                result[key] = int(parts[1])
            except (IndexError, ValueError):
                result[key] = 0

    mem_total = result.get("MemTotal", 0)
    mem_avail = result.get("MemAvailable", 0)
    swap_total = result.get("SwapTotal", 0)
    swap_free = result.get("SwapFree", 0)

    result["MemUsed"] = max(mem_total - mem_avail, 0)
    result["SwapUsed"] = max(swap_total - swap_free, 0)
    return result


def kb_to_mb(value_kb: int) -> float:
    return round(value_kb / 1024, 2)


def format_memory_report() -> str:
    mem = read_meminfo()
    lines = [
        "Memory Metrics",
        "==============",
        f"Physical RAM Total:     {kb_to_mb(mem.get('MemTotal', 0))} MB",
        f"Physical RAM Available: {kb_to_mb(mem.get('MemAvailable', 0))} MB",
        f"Physical RAM Used:      {kb_to_mb(mem.get('MemUsed', 0))} MB",
        f"Swap Total:             {kb_to_mb(mem.get('SwapTotal', 0))} MB",
        f"Swap Free:              {kb_to_mb(mem.get('SwapFree', 0))} MB",
        f"Swap Used:              {kb_to_mb(mem.get('SwapUsed', 0))} MB",
    ]
    return "\n".join(lines)

# ---------- Rich dashboard helpers ----------

def read_cpu_times() -> Dict[str, int]:
    """Read aggregate CPU counters from /proc/stat.

    Linux exposes CPU time as jiffies. The first line of /proc/stat begins with
    'cpu' followed by counters for user, nice, system, idle, iowait, irq,
    softirq, steal, guest, and guest_nice time.
    """
    raw = _safe_read_text(PROC_DIR / "stat")
    first = raw.splitlines()[0] if raw else ""
    parts = first.split()
    if not parts or parts[0] != "cpu":
        return {"total": 0, "idle": 0, "busy": 0}

    values = []
    for value in parts[1:]:
        try:
            values.append(int(value))
        except ValueError:
            values.append(0)

    # Pad the list so indexing is safe on older kernels.
    values += [0] * (10 - len(values))
    idle = values[3] + values[4]
    total = sum(values[:8])
    busy = max(total - idle, 0)
    return {"total": total, "idle": idle, "busy": busy}


def calculate_cpu_percent(previous: Dict[str, int], current: Dict[str, int]) -> float:
    """Calculate whole-system CPU usage percent between two /proc/stat reads."""
    total_delta = current.get("total", 0) - previous.get("total", 0)
    idle_delta = current.get("idle", 0) - previous.get("idle", 0)
    if total_delta <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 1)


def cpu_core_count() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


def read_load_average() -> Dict[str, float]:
    raw = _safe_read_text(PROC_DIR / "loadavg")
    parts = raw.split()
    try:
        return {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except (IndexError, ValueError):
        return {"1m": 0.0, "5m": 0.0, "15m": 0.0}


def read_uptime_seconds() -> float:
    raw = _safe_read_text(PROC_DIR / "uptime")
    try:
        return float(raw.split()[0])
    except (IndexError, ValueError):
        return 0.0


def format_uptime(seconds: float) -> str:
    seconds_i = int(seconds)
    days, rem = divmod(seconds_i, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def read_process_cpu_jiffies() -> Dict[str, int]:
    """Return PID -> user+system CPU jiffies for active processes."""
    times: Dict[str, int] = {}
    try:
        pids = [p.name for p in PROC_DIR.iterdir() if p.name.isdigit()]
    except FileNotFoundError:
        return times

    for pid in pids:
        raw = _safe_read_text(PROC_DIR / pid / "stat").strip()
        if not raw:
            continue
        try:
            _, right = raw.rsplit(")", 1)
            parts = right.strip().split()
            utime = int(parts[11])
            stime = int(parts[12])
            times[pid] = utime + stime
        except (IndexError, ValueError):
            continue
    return times


def calculate_process_cpu_percents(
    previous_proc: Dict[str, int],
    current_proc: Dict[str, int],
    previous_cpu: Dict[str, int],
    current_cpu: Dict[str, int],
) -> Dict[str, float]:
    """Calculate per-process CPU percent between two samples.

    Percent is normalized so 100% means one full CPU core.
    """
    total_delta = current_cpu.get("total", 0) - previous_cpu.get("total", 0)
    if total_delta <= 0:
        return {}
    cores = cpu_core_count()
    result: Dict[str, float] = {}
    for pid, current_ticks in current_proc.items():
        previous_ticks = previous_proc.get(pid)
        if previous_ticks is None:
            continue
        proc_delta = current_ticks - previous_ticks
        if proc_delta < 0:
            continue
        result[pid] = round((proc_delta / total_delta) * cores * 100, 1)
    return result


def read_process_memory(pid: str) -> Dict[str, float]:
    """Read VmRSS and VmSize from /proc/[pid]/status in MB."""
    raw = _safe_read_text(PROC_DIR / pid / "status")
    rss_kb = 0
    vms_kb = 0
    threads = "?"
    for line in raw.splitlines():
        if line.startswith("VmRSS:"):
            try:
                rss_kb = int(line.split()[1])
            except (IndexError, ValueError):
                rss_kb = 0
        elif line.startswith("VmSize:"):
            try:
                vms_kb = int(line.split()[1])
            except (IndexError, ValueError):
                vms_kb = 0
        elif line.startswith("Threads:"):
            try:
                threads = line.split()[1]
            except IndexError:
                threads = "?"
    return {"rss_mb": round(rss_kb / 1024, 1), "vms_mb": round(vms_kb / 1024, 1), "threads": threads}


def enumerate_processes_with_metrics(
    include_restricted_details: bool = False,
    limit: int | None = None,
    cpu_percents: Dict[str, float] | None = None,
) -> List[Dict[str, str]]:
    """Return processes with CPU and memory metrics for the Rich dashboard."""
    cpu_percents = cpu_percents or {}
    rows = enumerate_processes(include_restricted_details=include_restricted_details, limit=None)
    enriched: List[Dict[str, str]] = []
    for proc in rows:
        pid = proc["pid"]
        mem = read_process_memory(pid)
        proc["cpu_percent"] = str(cpu_percents.get(pid, 0.0))
        proc["rss_mb"] = str(mem["rss_mb"])
        proc["vms_mb"] = str(mem["vms_mb"])
        proc["threads"] = str(mem["threads"])
        enriched.append(proc)

    enriched.sort(key=lambda p: (float(p.get("cpu_percent", 0)), float(p.get("rss_mb", 0))), reverse=True)
    if limit:
        return enriched[:limit]
    return enriched


def process_state_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for proc in enumerate_processes(include_restricted_details=False, limit=None):
        state = proc.get("state_code", "?")
        counts[state] = counts.get(state, 0) + 1
    return counts
