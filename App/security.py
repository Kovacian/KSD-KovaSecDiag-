# app/security.py
import psutil
import subprocess
import os

def check_defender_status():
    try:
        output = subprocess.check_output("powershell Get-MpComputerStatus", shell=True, text=True)
        status = {line.split(':')[0].strip(): line.split(':')[1].strip() for line in output.splitlines() if ':' in line}
        enabled = status.get("AMServiceEnabled", "False") == "True"
        realtime = status.get("RealTimeProtectionEnabled", "False") == "True"
        icon = "✅" if enabled and realtime else "❌"
        return f"{icon} Defender Enabled: {enabled}, Real-Time Protection: {realtime}"
    except Exception as e:
        return f"❌ Defender check failed: {e}"

def check_firewall_status():
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
        enabled = "State ON" in output.upper() or "ON" in output
        icon = "✅" if enabled else "❌"
        return f"{icon} Firewall Status: {'Enabled' if enabled else 'Disabled'}"
    except Exception as e:
        return f"❌ Firewall check failed: {e}"

def scan_suspicious_processes():
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info['exe']
            if exe and any(temp_path in exe.lower() for temp_path in ["temp", "appdata"]):
                suspicious.append(f"⚠️ {proc.info['name']} (PID: {proc.info['pid']}) from {exe}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious or ["✅ No suspicious processes found."]

def scan_temp_executables():
    found = []
    temp_dir = os.getenv('TEMP')
    if temp_dir:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.lower().endswith(('.exe', '.bat', '.cmd')):
                    found.append(f"⚠️ {os.path.join(root, file)}")
    return found or ["✅ No executables found in Temp."]
