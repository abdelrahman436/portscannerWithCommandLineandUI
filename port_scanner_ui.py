
import tkinter as tk
import asyncio
import sys
from port_scanner import PortScanner

class PortScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")

        self.ip_label = tk.Label(root, text="Target IP:")
        self.ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(root)
        self.ip_entry.grid(row=0, column=1)

        self.custom_ports_var = tk.IntVar()
        self.custom_ports_checkbox = tk.Checkbutton(root, text="Custom Ports", variable=self.custom_ports_var, command=self.toggle_custom_ports)
        self.custom_ports_checkbox.grid(row=1, column=0, columnspan=2)

        self.from_port_label = tk.Label(root, text="From Port:")
        self.from_port_label.grid(row=2, column=0)
        self.from_port_entry = tk.Entry(root, state=tk.DISABLED)
        self.from_port_entry.grid(row=2, column=1)

        self.to_port_label = tk.Label(root, text="To Port:")
        self.to_port_label.grid(row=3, column=0)
        self.to_port_entry = tk.Entry(root, state=tk.DISABLED)
        self.to_port_entry.grid(row=3, column=1)

        self.scan_button = tk.Button(root, text="Scan", command=self.scan_ports)
        self.scan_button.grid(row=4, column=0, columnspan=2)

        self.result_label = tk.Label(root, text="Scan Results:")
        self.result_label.grid(row=5, column=0, columnspan=2)

        self.result_text = tk.Text(root, height=10, width=50)
        self.result_text.grid(row=6, column=0, columnspan=2)

    def toggle_custom_ports(self):
        if self.custom_ports_var.get() == 1:  # If checkbox is checked
            self.from_port_entry.config(state=tk.NORMAL)
            self.to_port_entry.config(state=tk.NORMAL)
        else:
            self.from_port_entry.config(state=tk.DISABLED)
            self.to_port_entry.config(state=tk.DISABLED)

    def scan_ports(self):
        target_ip = self.ip_entry.get()

        if self.custom_ports_var.get() == 1:
            from_port = int(self.from_port_entry.get())
            to_port = int(self.to_port_entry.get())
        else:
            from_port = None
            to_port = None

        port_scanner = PortScanner()

        # Redirect stdout to the text widget
        sys.stdout = StdoutRedirector(self.result_text)

        try:
            asyncio.run(port_scanner.integrated_scan(target_ip, from_port, to_port))
        except Exception as e:
            self.result_text.insert(tk.END, f"An error occurred: {e}")

class StdoutRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)

def main():
    root = tk.Tk()
    app = PortScannerUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
