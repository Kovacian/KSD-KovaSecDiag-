# main.py
from App.app import DiagnosticApp
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    App = DiagnosticApp(root)
    root.mainloop()
