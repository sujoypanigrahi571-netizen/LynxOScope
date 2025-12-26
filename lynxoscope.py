#!/usr/bin/env python3
"""
LynxOScope v3.0 PRO
A lightweight Python-based OSINT and system reconnaissance framework.
Designed for ethical security research and automation.
"""

import os
import sys
import json
import platform
import stat
from typing import Dict, List, Any, Union

# ---------- Helpers ----------
def safe_read(path: str, fallback: str = "N/A") -> str:
    """Safely reads a system file with proper error handling."""
    try:
        if not os.path.exists(path):
            return fallback
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().strip()
    except (OSError, PermissionError):
        return fallback

def safe_lines(path: str) -> List[str]:
    """Safely reads lines from a file, returning an empty list on failure."""
    try:
        if not os.path.exists(path):
            return []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except (OSError, PermissionError):
        return []

# ---------- System Module ----------
def get_ns_info() -> Dict[str, str]:
    """Retrieves namespace information from /proc/self/ns."""
    ns = {}
    base = "/proc/self/ns"
    if os.path.exists(base):
        for f in os.listdir(base):
            try:
                ns[f] = os.readlink(os.path.join(base, f))
            except (OSError, PermissionError):
                ns[f] = "restricted"
    return ns

def get_system_info() -> Dict[str, Any]:
    """Gathers core system metrics."""
    uptime_raw = safe_read("/proc/uptime", "0").split()
    uptime_seconds = float(uptime_raw[0]) if uptime_raw else 0.0
    
    return {
        "kernel": safe_read("/proc/version", platform.platform()),
        "arch": platform.machine(),
        "uptime_hours": round(uptime_seconds / 3600, 2),
        "loadavg": safe_read("/proc/loadavg", "N/A"),
        "namespaces": get_ns_info()
    }

# ---------- Resource Module ----------
def get_cpu_mem_info() -> Dict[str, Any]:
    """Parses CPU and Memory data from /proc."""
    cpuinfo = safe_read("/proc/cpuinfo", "")
    cores = cpuinfo.count("processor")
    model = "Unknown"
    for line in cpuinfo.splitlines():
        if "model name" in line:
            model = line.split(":", 1)[1].strip()
            break

    mem = {}
    for line in safe_lines("/proc/meminfo"):
        if ":" in line:
            k, v = line.split(":", 1)
            mem[k.strip()] = v.strip()

    return {
        "cpu_cores": cores,
        "cpu_model": model,
        "mem_total": mem.get("MemTotal", "N/A"),
        "mem_free": mem.get("MemFree", "N/A"),
        "swap_total": mem.get("SwapTotal", "N/A")
    }

# ---------- Process & Security Module ----------
def get_processes() -> List[Dict[str, Any]]:
    """Scans /proc for active processes and metadata."""
    plist = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return []

    for pid in pids:
        status_path = f"/proc/{pid}/status"
        data = safe_read(status_path, "")
        if not data: continue
        
        info = {}
        for line in data.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        
        plist.append({
            "pid": int(pid),
            "uid": info.get("Uid", "").split()[0] if "Uid" in info else "?",
            "name": info.get("Name", "?"),
            "state": info.get("State", "?"),
            "rss": info.get("VmRSS", "0")
        })
    return plist

def get_privileges(proc_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detects root processes and SUID binaries."""
    suid = []
    for directory in ["/bin", "/usr/bin", "/sbin"]:
        if os.path.exists(directory):
            for f in os.listdir(directory):
                fp = os.path.join(directory, f)
                try:
                    s = os.stat(fp)
                    if s.st_mode & stat.S_ISUID:
                        suid.append(fp)
                except (OSError, PermissionError):
                    continue
    return {
        "root_processes_count": len([p for p in proc_list if p["uid"] == "0"]),
        "suid_binaries": suid
    }

# ---------- Network Module ----------
def get_network_info() -> List[int]:
    """Identifies listening TCP ports."""
    listeners = []
    for line in safe_lines("/proc/net/tcp"):
        parts = line.split()
        if len(parts) > 3 and parts[3] == "0A": # 0A is LISTEN state
            try:
                port = int(parts[1].split(":")[1], 16)
                listeners.append(port)
            except (IndexError, ValueError):
                continue
    return sorted(list(set(listeners)))

# ---------- Main Framework ----------
def main():
    json_mode = "--json" in sys.argv
    results = {}

    # Execution Flow
    try:
        results["system"] = get_system_info()
        results["resources"] = get_cpu_mem_info()
        procs = get_processes()
        results["privileges"] = get_privileges(procs)
        results["network"] = get_network_info()
        
        # Simple Alert Logic
        results["alerts"] = []
        if len([p for p in procs if "Z" in p['state']]) > 5:
            results["alerts"].append("High number of zombie processes detected.")
        if results["network"]:
            results["alerts"].append(f"Active listening ports: {results['network']}")

        if json_mode:
            print(json.dumps(results, indent=4))
            return

        # Terminal Output Formatting
        print("\n" + "🐆 LynxOScope v3.0 PRO".center(40))
        print("-" * 40)
        
        sections = [
            ("System", results["system"]),
            ("Resources", results["resources"]),
            ("Network", {"Listening Ports": results["network"]}),
            ("Security", {"Root Procs": results["privileges"]["root_processes_count"], 
                          "SUID Count": len(results["privileges"]["suid_binaries"])})
        ]

        for title, content in sections:
            print(f"\n[+] {title}")
            for k, v in content.items():
                if k != "namespaces": # Avoid clutter
                    print(f"  {k:15}: {v}")

        if results["alerts"]:
            print("\n[!] Alerts")
            for alert in results["alerts"]:
                print(f"  - {alert}")

    except Exception as e:
        print(f"Error executing LynxOScope: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        sys.exit(0)
        
