#!/usr/bin/env python3
import os
import sys
import json
import platform
import stat

RESULT = {}

# ---------- helpers ----------

def safe_read(path, fallback="N/A"):
    try:
        with open(path) as f:
            return f.read().strip()
    except:
        return fallback

def safe_lines(path):
    try:
        with open(path) as f:
            return f.readlines()
    except:
        return []

# ---------- namespace ----------

def ns_info():
    ns = {}
    base = "/proc/self/ns"
    if os.path.exists(base):
        for f in os.listdir(base):
            try:
                ns[f] = os.readlink(os.path.join(base, f))
            except:
                ns[f] = "restricted"
    return ns

# ---------- system ----------

def system_info():
    kernel = safe_read("/proc/version", platform.platform())

    uptime = 0.0
    try:
        uptime = float(safe_read("/proc/uptime", "0").split()[0])
    except:
        pass

    load = safe_read("/proc/loadavg", "N/A")

    return {
        "kernel": kernel,
        "arch": platform.machine(),
        "uptime_hours": round(uptime / 3600, 2),
        "loadavg": load,
        "namespaces": ns_info()
    }

# ---------- cpu / memory ----------

def cpu_mem():
    cpuinfo = safe_read("/proc/cpuinfo", "")
    cores = cpuinfo.count("processor")

    model = "Unknown"
    for l in cpuinfo.splitlines():
        if "model name" in l:
            model = l.split(":", 1)[1].strip()
            break

    mem = {}
    for l in safe_lines("/proc/meminfo"):
        if ":" in l:
            k, v = l.split(":", 1)
            mem[k] = v.strip()

    return {
        "cpu_cores": cores,
        "cpu_model": model,
        "mem_total": mem.get("MemTotal", "N/A"),
        "mem_free": mem.get("MemFree", "N/A"),
        "swap_total": mem.get("SwapTotal", "N/A"),
        "swap_free": mem.get("SwapFree", "N/A"),
        "hugepages": mem.get("HugePages_Total", "N/A")
    }

# ---------- processes ----------

def processes():
    plist = []

    for pid in filter(str.isdigit, os.listdir("/proc")):
        status_path = f"/proc/{pid}/status"
        if not os.path.exists(status_path):
            continue

        try:
            data = safe_read(status_path, "")
            info = {}
            for l in data.splitlines():
                if ":" in l:
                    k, v = l.split(":", 1)
                    info[k] = v.strip()

            plist.append({
                "pid": int(pid),
                "uid": info.get("Uid", "").split()[0] if "Uid" in info else "?",
                "name": info.get("Name", "?"),
                "state": info.get("State", "?"),
                "rss": info.get("VmRSS", "0")
            })
        except:
            continue

    return plist

# ---------- privileges ----------

def privileges(proc):
    roots = [p for p in proc if p["uid"] == "0"]

    suid = []
    for d in ["/bin", "/usr/bin"]:
        if not os.path.exists(d):
            continue
        for f in os.listdir(d):
            fp = os.path.join(d, f)
            try:
                if os.stat(fp).st_mode & stat.S_ISUID:
                    suid.append(fp)
            except:
                continue

    return {
        "root_processes": roots,
        "suid_binaries": suid
    }

# ---------- network ----------

def network():
    listeners = []

    for l in safe_lines("/proc/net/tcp"):
        if l.strip().startswith("sl"):
            continue
        parts = l.split()
        if len(parts) < 4:
            continue
        state = parts[3]
        if state == "0A":  # LISTEN
            try:
                port = int(parts[1].split(":")[1], 16)
                listeners.append(port)
            except:
                continue

    return sorted(set(listeners))

# ---------- alerts ----------

def alerts(proc, net):
    alerts = []

    hidden = []
    for p in proc:
        try:
            safe_read(f"/proc/{p['pid']}/cmdline")
        except:
            hidden.append(p["pid"])

    if hidden:
        alerts.append({"hidden_processes": hidden})

    zombies = [p["pid"] for p in proc if "Z" in p.get("state", "")]
    if len(zombies) > 5:
        alerts.append({"zombie_flood": zombies})

    if net:
        alerts.append({"listening_ports": net})

    return alerts

# ---------- main ----------

def main():
    json_mode = "--json" in sys.argv

    RESULT["system"] = system_info()
    RESULT["resources"] = cpu_mem()
    RESULT["processes"] = processes()
    RESULT["privileges"] = privileges(RESULT["processes"])
    RESULT["network"] = network()
    RESULT["alerts"] = alerts(RESULT["processes"], RESULT["network"])

    if json_mode:
        print(json.dumps(RESULT, indent=2))
        return

    print("\n🐆 LynxOScope v3.0 PRO\n")

    print("== System ==")
    for k, v in RESULT["system"].items():
        print(f"{k:15}: {v}")

    print("\n== Resources ==")
    for k, v in RESULT["resources"].items():
        print(f"{k:15}: {v}")

    print("\n== Processes (Top 10) ==")
    for p in RESULT["processes"][:10]:
        print(p)

    print("\n== Privileges ==")
    print("Root processes :", len(RESULT["privileges"]["root_processes"]))
    print("SUID binaries  :", len(RESULT["privileges"]["suid_binaries"]))

    print("\n== Network ==")
    print("Listening ports:", RESULT["network"])

    print("\n== Alerts ==")
    if RESULT["alerts"]:
        for a in RESULT["alerts"]:
            print(a)
    else:
        print("No anomalies detected")

if __name__ == "__main__":
    main()
