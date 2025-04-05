# diagnostic_app.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import platform
import subprocess
import os
import socket
import hashlib
import threading

class DiagnosticApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Diagnostic Tool")
        self.root.geometry("600x700")

        self.core_bars = []
        self.core_labels = []

        self.setup_notebook()
        self.setup_system_tab()
        self.setup_usage_tab()
        self.setup_cpu_detail_tab()
        self.setup_storage_tab()
        self.setup_network_tab()
        self.setup_tools_tab()
        self.setup_security_tab()

        self.refresh_info()

    # ------------------ GUI Setup ------------------

    def setup_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.tabs = {
            'system': ttk.Frame(self.notebook),
            'usage': ttk.Frame(self.notebook),
            'cpu': ttk.Frame(self.notebook),
            'storage': ttk.Frame(self.notebook),
            'network': ttk.Frame(self.notebook),
            'tools': ttk.Frame(self.notebook),
            'security': ttk.Frame(self.notebook),
        }

        for name, tab in self.tabs.items():
            self.notebook.add(tab, text=name.capitalize())

    def setup_system_tab(self):
        tab = self.tabs['system']
        ttk.Label(tab, text="System Information", font=("Helvetica", 14)).pack(pady=5)
        self.system_label = ttk.Label(tab, text="", justify="left")
        self.system_label.pack()

        ttk.Label(tab, text="CPU Temperature", font=("Helvetica", 14)).pack(pady=5)
        self.temp_label = ttk.Label(tab, text="", justify="left")
        self.temp_label.pack()

    def setup_usage_tab(self):
        tab = self.tabs['usage']
        ttk.Label(tab, text="Usage Statistics", font=("Helvetica", 14)).pack(pady=5)

        frame = ttk.Frame(tab)
        frame.pack(pady=2)
        ttk.Label(frame, text="CPU Usage:").pack(side="left")
        self.cpu_bar = ttk.Progressbar(frame, length=200, mode="determinate")
        self.cpu_bar.pack(side="left", padx=5)
        self.cpu_percent_label = ttk.Label(frame, text="")
        self.cpu_percent_label.pack(side="left")

        frame = ttk.Frame(tab)
        frame.pack(pady=2)
        ttk.Label(frame, text="RAM Usage:").pack(side="left")
        self.ram_bar = ttk.Progressbar(frame, length=200, mode="determinate")
        self.ram_bar.pack(side="left", padx=5)
        self.ram_percent_label = ttk.Label(frame, text="")
        self.ram_percent_label.pack(side="left")

        ttk.Label(tab, text="Top CPU Processes", font=("Helvetica", 12)).pack(pady=(10, 2))
        self.cpu_proc_label = ttk.Label(tab, text="", justify="left")
        self.cpu_proc_label.pack()

        ttk.Label(tab, text="Top RAM Processes", font=("Helvetica", 12)).pack(pady=(10, 2))
        self.ram_proc_label = ttk.Label(tab, text="", justify="left")
        self.ram_proc_label.pack()

    def setup_cpu_detail_tab(self):
        tab = self.tabs['cpu']
        ttk.Label(tab, text="CPU Usage by Core", font=("Helvetica", 14)).pack(pady=5)
        for i in range(psutil.cpu_count(logical=True)):
            frame = ttk.Frame(tab)
            frame.pack(pady=2)
            ttk.Label(frame, text=f"Core {i}:").pack(side="left")
            bar = ttk.Progressbar(frame, length=200, mode="determinate")
            bar.pack(side="left", padx=5)
            label = ttk.Label(frame, text="")
            label.pack(side="left")
            self.core_bars.append(bar)
            self.core_labels.append(label)

    def setup_storage_tab(self):
        tab = self.tabs['storage']
        ttk.Label(tab, text="Disk Info", font=("Helvetica", 14)).pack(pady=5)
        self.disk_label = ttk.Label(tab, text="", justify="left")
        self.disk_label.pack()
        ttk.Button(tab, text="Check SMART Status", command=self.check_smart).pack(pady=10)

    def setup_network_tab(self):
        tab = self.tabs['network']
        ttk.Label(tab, text="Network Interfaces", font=("Helvetica", 14)).pack(pady=5)
        self.network_label = ttk.Label(tab, text="", justify="left")
        self.network_label.pack()

    def setup_tools_tab(self):
        tab = self.tabs['tools']
        ttk.Label(tab, text="System Tools", font=("Helvetica", 14)).pack(pady=5)
        ttk.Button(tab, text="Open Task Manager", command=lambda: subprocess.Popen("taskmgr")).pack(pady=2)
        ttk.Button(tab, text="Restart Explorer", command=self.restart_explorer).pack(pady=2)
        ttk.Button(tab, text="Open Command Prompt (Admin)", command=self.open_cmd_as_admin).pack(pady=2)
        ttk.Button(tab, text="Reboot System", command=lambda: os.system("shutdown /r /t 0")).pack(pady=2)
        ttk.Button(tab, text="Shutdown System", command=lambda: os.system("shutdown /s /t 0")).pack(pady=2)
        ttk.Button(tab, text="Clear Temp Files", command=self.clear_temp_files).pack(pady=2)

    def setup_security_tab(self):
        tab = self.tabs['security']
        ttk.Label(tab, text="Windows Defender Status", font=("Helvetica", 12)).pack(pady=5)
        self.defender_label = ttk.Label(tab, text="", justify="left")
        self.defender_label.pack()

        ttk.Label(tab, text="Firewall Status", font=("Helvetica", 12)).pack(pady=5)
        self.firewall_label = ttk.Label(tab, text="", justify="left")
        self.firewall_label.pack()

        ttk.Label(tab, text="Suspicious Processes", font=("Helvetica", 12)).pack(pady=5)
        self.processes_label = ttk.Label(tab, text="", justify="left", wraplength=500)
        self.processes_label.pack()

        ttk.Label(tab, text="Executables in Temp Folder", font=("Helvetica", 12)).pack(pady=5)
        self.temp_exes_label = ttk.Label(tab, text="", justify="left", wraplength=500)
        self.temp_exes_label.pack()

        ttk.Button(tab, text="Run Security Scan", command=self.run_security_scan).pack(pady=10)

    # ------------------ Update & Data Logic ------------------

    def refresh_info(self):
        info = {
            'system': self.get_system_info(),
            'usage': self.get_usage_stats(),
            'disk': self.get_disk_info(),
            'temp': self.get_cpu_temperature(),
            'network': self.get_network_info(),
            'core': psutil.cpu_percent(percpu=True),
            'procs': self.get_top_processes(),
        }

        self.system_label.config(text="\n".join(f"{k}: {v}" for k, v in info['system'].items()))
        self.disk_label.config(text="\n".join(info['disk']))
        self.temp_label.config(text=info['temp'])
        self.network_label.config(text=info['network'])

        self.cpu_bar['value'] = float(info['usage']['CPU Usage'].replace('%', ''))
        self.ram_bar['value'] = float(info['usage']['RAM Usage'].replace('%', ''))
        self.cpu_percent_label.config(text=info['usage']['CPU Usage'])
        self.ram_percent_label.config(text=info['usage']['RAM Usage'])

        self.cpu_proc_label.config(text=info['procs'][0])
        self.ram_proc_label.config(text=info['procs'][1])

        for i, val in enumerate(info['core']):
            self.core_bars[i]['value'] = val
            self.core_labels[i].config(text=f"{val:.1f}%")

        self.root.after(2000, self.refresh_info)

    def get_system_info(self):
        return {
            "OS": f"{platform.system()} {platform.release()}",
            "Processor": platform.processor(),
            "RAM": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB",
        }

    def get_cpu_temperature(self):
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

    def get_usage_stats(self):
        return {
            "CPU Usage": f"{psutil.cpu_percent()}%",
            "RAM Usage": f"{round(psutil.virtual_memory().percent, 2)}%",
        }

    def get_disk_info(self):
        info = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                info.append(f"{part.device}: {usage.percent}% used")
            except PermissionError:
                continue
        return info

    def get_network_info(self):
        result = []
        for iface, addrs in psutil.net_if_addrs().items():
            result.append(f"Interface: {iface}")
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    result.append(f"  IPv4: {addr.address}")
        return "\n".join(result)

    def get_top_processes(self):
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

    def check_smart(self):
        try:
            output = subprocess.check_output(["smartctl", "-H", "/dev/sda"], text=True)
            messagebox.showinfo("SMART Status", output)
        except Exception as e:
            messagebox.showerror("SMART Check", f"Error: {e}")

    def restart_explorer(self):
        subprocess.call(["taskkill", "/f", "/im", "explorer.exe"])
        subprocess.call("explorer")

    def open_cmd_as_admin(self):
        subprocess.call(["powershell", "-Command", "Start-Process cmd -Verb RunAs"])

    def clear_temp_files(self):
        temp_path = os.getenv('TEMP')
        total_freed = 0
        try:
            for filename in os.listdir(temp_path):
                file_path = os.path.join(temp_path, filename)
                if os.path.isfile(file_path):
                    total_freed += os.path.getsize(file_path)
                    os.unlink(file_path)
            messagebox.showinfo("Temp Cleanup", f"Freed: {total_freed / (1024 ** 2):.2f} MB")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_security_scan(self):
        def scan():
            defender = subprocess.getoutput("powershell (Get-MpComputerStatus).RealTimeProtectionEnabled")
            firewall = subprocess.getoutput("netsh advfirewall show allprofiles")
            sus_procs = [p.info['name'] for p in psutil.process_iter(['exe', 'name']) if p.info['exe'] and 'temp' in p.info['exe'].lower()]
            temp_exes = [f for f in os.listdir(os.getenv('TEMP')) if f.endswith('.exe')]

            self.defender_label.config(text=f"Defender Real-Time: {'✅' if 'True' in defender else '❌'}")
            self.firewall_label.config(text=f"Firewall: {'✅' if 'ON' in firewall else '❌'}")
            self.processes_label.config(text="\n".join([f"⚠️ {p}" for p in sus_procs]) or "✅ No suspicious processes.")
            self.temp_exes_label.config(text="\n".join([f"⚠️ {f}" for f in temp_exes]) or "✅ No executables in TEMP.")

        threading.Thread(target=scan).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = DiagnosticApp(root)
    root.mainloop()
