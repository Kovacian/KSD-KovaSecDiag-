# app/app.py
import tkinter as tk
from tkinter import ttk
from App.diagnostics import *
from App.security import *
from App.tools import *
import threading
import psutil
import time

class DiagnosticApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Diagnostic Tool")
        self.root.geometry("600x700")

        self.apply_dark_theme()

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
        self.setup_process_analyzer_tab()

        self.refresh_info()

    def apply_dark_theme(self):
        style = ttk.Style(self.root)
        self.root.tk_setPalette(background="#1e1e2e", foreground="#dcdcdc")
        style.theme_use('default')

        style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#2a2a40", foreground="#dcdcdc", padding=10)
        style.map("TNotebook.Tab", background=[("selected", "#3e445e")])

        style.configure("TFrame", background="#1e1e2e")
        style.configure("TLabel", background="#1e1e2e", foreground="#dcdcdc")
        style.configure("TButton", background="#7aa2f7", foreground="#1e1e2e", padding=6)
        style.map("TButton",
            background=[("active", "#9ece6a"), ("pressed", "#f7768e")],
            foreground=[("disabled", "#666")]
        )
        style.configure("TProgressbar", troughcolor="#3b3b59", background="#7aa2f7", bordercolor="#1e1e2e")

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
            'analyzer': ttk.Frame(self.notebook),
        }

        for name, tab in self.tabs.items():
            self.notebook.add(tab, text=name.capitalize())

    def section(self, parent, text):
        frame = tk.LabelFrame(parent, text=text, bg="#2a2a40", fg="#7aa2f7", bd=2, relief="groove")
        frame.pack(fill="x", padx=10, pady=10, ipadx=5, ipady=5)
        return frame

    def create_scrollable_frame(self, parent):
        canvas = tk.Canvas(parent, bg="#1e1e2e", highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas, style="TFrame")

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return scroll_frame

    def setup_system_tab(self):
        tab = self.tabs['system']
        frame = self.section(tab, "System Information")
        self.system_label = ttk.Label(frame, text="", justify="left")
        self.system_label.pack(anchor="w")

        frame = self.section(tab, "CPU Temperature")
        self.temp_label = ttk.Label(frame, text="", justify="left")
        self.temp_label.pack(anchor="w")

        frame = self.section(tab, "System Uptime")
        self.uptime_label = ttk.Label(frame, text="", justify="left")
        self.uptime_label.pack(anchor="w")

    def setup_usage_tab(self):
        tab = self.tabs['usage']
        frame = self.section(tab, "Usage Statistics")

        cpu_frame = ttk.Frame(frame)
        cpu_frame.pack(pady=5)
        ttk.Label(cpu_frame, text="CPU Usage:").pack(side="left")
        self.cpu_bar = ttk.Progressbar(cpu_frame, length=200, mode="determinate")
        self.cpu_bar.pack(side="left", padx=5)
        self.cpu_percent_label = ttk.Label(cpu_frame, text="")
        self.cpu_percent_label.pack(side="left")

        ram_frame = ttk.Frame(frame)
        ram_frame.pack(pady=5)
        ttk.Label(ram_frame, text="RAM Usage:").pack(side="left")
        self.ram_bar = ttk.Progressbar(ram_frame, length=200, mode="determinate")
        self.ram_bar.pack(side="left", padx=5)
        self.ram_percent_label = ttk.Label(ram_frame, text="")
        self.ram_percent_label.pack(side="left")

        proc_frame = self.section(tab, "Top Processes")
        ttk.Label(proc_frame, text="Top CPU:").pack(anchor="w")
        self.cpu_proc_label = ttk.Label(proc_frame, text="", justify="left")
        self.cpu_proc_label.pack(anchor="w")

        ttk.Label(proc_frame, text="Top RAM:").pack(anchor="w", pady=(10, 0))
        self.ram_proc_label = ttk.Label(proc_frame, text="", justify="left")
        self.ram_proc_label.pack(anchor="w")

    def setup_cpu_detail_tab(self):
        tab = self.tabs['cpu']
        frame = self.section(tab, "CPU Usage by Core")
        for i in range(psutil.cpu_count(logical=True)):
            sub = ttk.Frame(frame)
            sub.pack(pady=3)
            ttk.Label(sub, text=f"Core {i}:").pack(side="left")
            bar = ttk.Progressbar(sub, length=200, mode="determinate")
            bar.pack(side="left", padx=5)
            label = ttk.Label(sub, text="")
            label.pack(side="left")
            self.core_bars.append(bar)
            self.core_labels.append(label)

    def setup_storage_tab(self):
        tab = self.tabs['storage']
        frame = self.section(tab, "Disk Info")
        self.disk_label = ttk.Label(frame, text="", justify="left")
        self.disk_label.pack(anchor="w")
        ttk.Button(tab, text="Check SMART Status", command=self.check_smart).pack(pady=10)

    def setup_network_tab(self):
        tab = self.tabs['network']
        frame = self.section(tab, "Network Interfaces")
        self.network_label = ttk.Label(frame, text="", justify="left")
        self.network_label.pack(anchor="w")

    def setup_tools_tab(self):
        tab = self.tabs['tools']
        center_frame = ttk.Frame(tab)
        center_frame.pack(pady=20, padx=10, expand=True)

        def labeled_button(description, button_text, command):
            ttk.Label(center_frame, text=description, font=("Segoe UI", 8), foreground="#9ece6a", anchor="center", justify="center").pack()
            ttk.Button(center_frame, text=button_text, command=command).pack(pady=(0, 10))

        labeled_button("Open Windows Task Manager to monitor running processes.", "Open Task Manager", open_task_manager)
        labeled_button("Restart Windows Explorer (taskbar and desktop UI).", "Restart Explorer", restart_explorer)
        labeled_button("Launch Command Prompt with Administrator privileges.", "Open Command Prompt (Admin)", open_cmd_as_admin)
        labeled_button("Restart your system immediately.", "Reboot System", reboot_system)
        labeled_button("Shut down your system immediately.", "Shutdown System", shutdown_system)
        labeled_button("Delete temporary files to free up system space.", "Clear Temp Files", clear_temp_files)

        ttk.Label(center_frame, text="Run cleanup, restart Explorer, and check security settings.", font=("Segoe UI", 8), foreground="#9ece6a", anchor="center", justify="center").pack(pady=(10, 0))
        ttk.Button(center_frame, text="Run Quick Fix", command=self.run_quick_fix).pack(pady=5)


    def setup_process_analyzer_tab(self):
        tab = self.tabs['analyzer']

        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.process_list = ttk.Treeview(frame, columns=("Name", "PID", "CPU", "RAM"), show="headings")
        self.process_list.heading("Name", text="Name")
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("CPU", text="CPU %")
        self.process_list.heading("RAM", text="RAM %")
        self.process_list.column("Name", width=200)
        self.process_list.column("PID", width=100)
        self.process_list.column("CPU", width=100)
        self.process_list.column("RAM", width=100)
        self.process_list.tag_configure("suspicious", background="#3c1f1f", foreground="#f7768e")
        self.process_list.pack(fill="both", expand=True)

        refresh_btn = ttk.Button(frame, text="Refresh", command=self.update_process_list)
        refresh_btn.pack(pady=5)

        kill_btn = ttk.Button(frame, text="Kill Selected Process", command=self.kill_selected_process)
        kill_btn.pack(pady=5)

        self.update_process_list()

    def update_process_list(self):
        for item in self.process_list.get_children():
            self.process_list.delete(item)
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                name = (proc.info['name'] or "Unknown").lower()
                pid = proc.info['pid']
                cpu = f"{proc.info['cpu_percent']:.1f}"
                mem = f"{proc.info['memory_percent']:.1f}"
                suspicious = name in ["isass.exe", "svch0st.exe", "winlogonn.exe"]
                self.process_list.insert('', 'end', iid=pid, values=(name, pid, cpu, mem), tags=("suspicious",) if suspicious else ())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def kill_selected_process(self):
        selected = self.process_list.selection()
        if selected:
            pid = int(self.process_list.item(selected[0], 'values')[1])
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                self.update_process_list()
                from tkinter import messagebox
                messagebox.showinfo("Success", f"Terminated process {pid}.")
            except Exception as e:
                from tkinter import messagebox
                messagebox.showerror("Error", f"Could not terminate process: {e}")

    def setup_security_tab(self):
        tab = self.tabs['security']
        scrollable = self.create_scrollable_frame(tab)

        frame = self.section(scrollable, "Windows Defender Status")
        self.defender_label = ttk.Label(frame, text="", justify="left")
        self.defender_label.pack(anchor="w")

        frame = self.section(scrollable, "Firewall Status")
        self.firewall_label = ttk.Label(frame, text="", justify="left")
        self.firewall_label.pack(anchor="w")

        frame = self.section(scrollable, "Suspicious Processes")
        self.processes_label = ttk.Label(frame, text="", justify="left", wraplength=500)
        self.processes_label.pack(anchor="w")

        frame = self.section(scrollable, "Executables in Temp Folder")
        self.temp_exes_label = ttk.Label(frame, text="", justify="left", wraplength=500)
        self.temp_exes_label.pack(anchor="w")

        ttk.Button(scrollable, text="Run Security Scan", command=self.run_security_scan).pack(pady=10)

    def run_quick_fix(self):
        def run():
            clear_temp_files()
            restart_explorer()
            status = check_defender_status()
            fw = check_firewall_status()
            from tkinter import messagebox
            messagebox.showinfo("Quick Fix", f"Cleanup complete.\n\nDefender: {status}\nFirewall: {fw}")
        threading.Thread(target=run).start()

    def get_uptime_text(self):
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        days = int(uptime // (24 * 3600))
        hours = int((uptime % (24 * 3600)) // 3600)
        minutes = int((uptime % 3600) // 60)
        return f"Uptime: {days}d {hours}h {minutes}m"

    def refresh_info(self):
        sys = get_system_info()
        usage = get_usage_stats()
        disk = get_disk_info()
        temps = get_cpu_temperature()
        network = get_network_info()
        core_usages = psutil.cpu_percent(percpu=True)
        cpu_proc_text, ram_proc_text = get_top_processes()

        self.system_label.config(text="\n".join(f"{k}: {v}" for k, v in sys.items()))
        self.disk_label.config(text="\n".join(disk))
        self.temp_label.config(text=temps)
        self.network_label.config(text=network)
        self.uptime_label.config(text=self.get_uptime_text())

        self.cpu_bar["value"] = float(usage["CPU Usage"].replace('%', ''))
        self.ram_bar["value"] = float(usage["RAM Usage"].replace('%', ''))
        self.cpu_percent_label.config(text=usage["CPU Usage"])
        self.ram_percent_label.config(text=usage["RAM Usage"])

        self.cpu_proc_label.config(text=cpu_proc_text)
        self.ram_proc_label.config(text=ram_proc_text)

        for i, val in enumerate(core_usages):
            self.core_bars[i]['value'] = val
            self.core_labels[i].config(text=f"{val:.1f}%")

        self.root.after(2000, self.refresh_info)

    def run_security_scan(self):
        def scan():
            self.defender_label.config(text=check_defender_status())
            self.firewall_label.config(text=check_firewall_status())
            self.processes_label.config(text="\n".join(scan_suspicious_processes()))
            self.temp_exes_label.config(text="\n".join(scan_temp_executables()))
        threading.Thread(target=scan).start()

    def check_smart(self):
        result = smart_status()
        from tkinter import messagebox
        if "SMART check failed" in result:
            messagebox.showerror("SMART Status", result)
        else:
            messagebox.showinfo("SMART Status", result)
