# app/diagnostics.py
import psutil
import platform
import socket
import subprocess

def get_system_info():
    return {
        "OS": f"{platform.system()} {platform.release()}",
        "Processor": platform.processor(),
        "RAM": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB",
    }

def get_cpu_temperature():
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return "Temperature sensors not supported."
        results = []
        for name, entries in temps.items():
            for entry in entries:
                label = entry.label or "Temp"
                results.append(f"{name} {label}: {entry.current}°C")
        return "\n".join(results)
    except Exception as e:
        return f"Error reading temps: {e}"

def get_usage_stats():
    return {
        "CPU Usage": f"{psutil.cpu_percent()}%",
        "RAM Usage": f"{round(psutil.virtual_memory().percent, 2)}%",
    }

def get_disk_info():
    info = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            info.append(f"{part.device}: {usage.percent}% used")
        except PermissionError:
            continue
    return info

def smart_status():
    try:
        output = subprocess.check_output(["smartctl", "-H", "/dev/sda"], text=True)
        return output
    except Exception as e:
        return f"SMART check failed: {e}"


def get_network_info():
    result = []
    for iface, addrs in psutil.net_if_addrs().items():
        result.append(f"Interface: {iface}")
        for addr in addrs:
            if addr.family == socket.AF_INET:
                result.append(f"  IPv4: {addr.address}")
        result.append("")
    return "\n".join(result)

def get_top_processes():
    cpu_procs = []
    ram_procs = []
    for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
        try:
            name = proc.info['name']
            if name and "idle" not in name.lower():
                cpu_procs.append((name, proc.info['cpu_percent']))
                ram_procs.append((name, proc.info['memory_percent']))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top_cpu = sorted(cpu_procs, key=lambda x: x[1], reverse=True)[:5]
    top_ram = sorted(ram_procs, key=lambda x: x[1], reverse=True)[:5]
    return (
        "\n".join([f"{n}: {c:.1f}%" for n, c in top_cpu]),
        "\n".join([f"{n}: {m:.1f}%" for n, m in top_ram])
    )
