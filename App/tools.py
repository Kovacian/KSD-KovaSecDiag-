# app/tools.py
import subprocess
import os
from tkinter import messagebox

def open_task_manager():
    subprocess.Popen("taskmgr")

def restart_explorer():
    subprocess.call(["taskkill", "/f", "/im", "explorer.exe"])
    subprocess.call("explorer")

def open_cmd_as_admin():
    subprocess.call(["powershell", "-Command", "Start-Process cmd -Verb RunAs"])

def reboot_system():
    os.system("shutdown /r /t 0")

def shutdown_system():
    os.system("shutdown /s /t 0")

def clear_temp_files():
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