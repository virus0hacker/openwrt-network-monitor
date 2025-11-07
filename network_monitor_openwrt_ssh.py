import os, socket, subprocess, platform, threading, time, json, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import paramiko

# ====== Banner ======
BANNER = """
███╗   ██╗███████╗██████╗ ███████╗███████╗███████╗ ██████╗ ██╗   ██╗
████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██║   ██║
██╔██╗ ██║█████╗  ██████╔╝█████╗  █████╗  ███████╗██║   ██║██║   ██║
██║╚██╗██║██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ╚════██║██║   ██║██║   ██║
██║ ╚████║███████╗██║  ██║███████╗███████╗███████║╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ 
                 🇸🇦  snap: ml-ftt — OpenWrt Network Monitor
===============================================================================

"""
print(BANNER)

# ====== Helper Functions ======
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def network_prefix(ip):
    parts = ip.split(".")
    return ".".join(parts[:3])

def ping(ip):
    try:
        if platform.system() == "Windows":
            subprocess.check_output(["ping", "-n", "1", "-w", "700", ip])
        else:
            subprocess.check_output(["ping", "-c", "1", "-W", "1", ip])
        return True
    except:
        return False

def read_arp():
    out = subprocess.getoutput("arp -a")
    lines = out.splitlines()
    result = {}
    for l in lines:
        parts = l.split()
        if len(parts) >= 3 and "." in parts[0]:
            ip = parts[0]
            mac = parts[1].replace("-", ":")
            result[ip] = mac
    return result

# ====== GUI App ======
class NetworkGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor — ViRuS-HaCkEr (snap: ml-ftt 🇸🇦)")
        self.data = {}
        self.scanning = False
        self.build_ui()

    def build_ui(self):
        banner = tk.Label(self.root, text="🇸🇦  Network Monitor — snap: ml-ftt", bg="#063306", fg="white",
                          font=("Segoe UI Black", 18, "bold"))
        banner.pack(fill=tk.X, pady=8)

        frame = tk.Frame(self.root)
        frame.pack(pady=4)
        local_ip = get_local_ip()
        tk.Label(frame, text="Network Prefix:").pack(side=tk.LEFT)
        self.prefix = tk.StringVar(value=network_prefix(local_ip))
        tk.Entry(frame, textvariable=self.prefix, width=12).pack(side=tk.LEFT)
        tk.Label(frame, text="Hosts:").pack(side=tk.LEFT)
        self.range_var = tk.IntVar(value=254)
        tk.Entry(frame, textvariable=self.range_var, width=5).pack(side=tk.LEFT)
        ttk.Button(frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame, text="Stop", command=self.stop_scan).pack(side=tk.LEFT)
        ttk.Button(frame, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame, text="Generate Script", command=self.make_script).pack(side=tk.LEFT, padx=5)

        # SSH control panel
        ssh_frame = tk.LabelFrame(self.root, text="SSH Deploy to OpenWrt", padx=4, pady=4)
        ssh_frame.pack(fill=tk.X, padx=10, pady=4)
        tk.Label(ssh_frame, text="Router IP:").grid(row=0, column=0)
        self.router_ip = tk.StringVar(value="192.168.1.1")
        tk.Entry(ssh_frame, textvariable=self.router_ip, width=12).grid(row=0, column=1)
        tk.Label(ssh_frame, text="User:").grid(row=0, column=2)
        self.router_user = tk.StringVar(value="root")
        tk.Entry(ssh_frame, textvariable=self.router_user, width=10).grid(row=0, column=3)
        tk.Label(ssh_frame, text="Password:").grid(row=0, column=4)
        self.router_pass = tk.StringVar()
        tk.Entry(ssh_frame, textvariable=self.router_pass, width=14, show="*").grid(row=0, column=5)
        ttk.Button(ssh_frame, text="Run Script on Router", command=self.deploy_script).grid(row=0, column=6, padx=6)

        self.tree = ttk.Treeview(self.root, columns=("ip", "mac", "seen"), show="headings")
        for c in ("ip", "mac", "seen"):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=160)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.status = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status, bg="#0b3a0b", fg="white").pack(fill=tk.X)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.status.set("Scanning network...")
        threading.Thread(target=self.scan_thread, daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self.status.set("Stopped.")

    def scan_thread(self):
        prefix = self.prefix.get().strip()
        max_hosts = int(self.range_var.get())
        for i in range(1, max_hosts + 1):
            if not self.scanning:
                break
            ip = f"{prefix}.{i}"
            if ping(ip):
                macs = read_arp()
                mac = macs.get(ip, "")
                self.data[ip] = {"ip": ip, "mac": mac, "seen": datetime.now().isoformat()}
                self.update_tree()
            self.status.set(f"Scanning {ip}")
        self.scanning = False
        self.status.set("Scan complete.")

    def update_tree(self):
        self.tree.delete(*self.tree.get_children())
        for ip, info in self.data.items():
            self.tree.insert("", tk.END, values=(ip, info["mac"], info["seen"]))

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        messagebox.showinfo("Saved", f"Data exported to {path}")

    def make_script(self):
        path = filedialog.asksaveasfilename(defaultextension=".sh", initialfile="openwrt_block.sh")
        if not path:
            return
        lines = [
            "#!/bin/sh",
            "# Generated by Network Monitor — OpenWrt Helper",
            "uci export firewall > /tmp/fw-backup.conf",
            ""
        ]
        for v in self.data.values():
            mac = v["mac"]
            if mac:
                lines += [
                    "uci add firewall rule",
                    f"uci set firewall.@rule[-1].name='block_{mac.replace(':','')}'",
                    "uci set firewall.@rule[-1].src='*'",
                    f"uci set firewall.@rule[-1].target='REJECT'",
                    f"uci set firewall.@rule[-1].mac='{mac}'",
                    "uci set firewall.@rule[-1].enabled='1'",
                    ""
                ]
        lines += ["uci commit firewall", "/etc/init.d/firewall restart"]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        os.chmod(path, 0o755)
        self.last_script = path
        messagebox.showinfo("Saved", f"Script saved: {path}")

    def deploy_script(self):
        if not hasattr(self, "last_script") or not os.path.exists(self.last_script):
            messagebox.showerror("Error", "No script generated yet.")
            return
        ip = self.router_ip.get().strip()
        user = self.router_user.get().strip()
        password = self.router_pass.get().strip()
        if not ip or not user or not password:
            messagebox.showerror("Error", "Fill router IP, user, and password.")
            return

        try:
            self.status.set("Connecting to router...")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=password)
            sftp = ssh.open_sftp()
            remote_path = "/tmp/openwrt_block.sh"
            sftp.put(self.last_script, remote_path)
            sftp.close()
            self.status.set("Executing script on router...")
            stdin, stdout, stderr = ssh.exec_command(f"chmod +x {remote_path} && {remote_path}")
            out = stdout.read().decode()
            err = stderr.read().decode()
            ssh.close()
            messagebox.showinfo("Success", f"Script executed.\n\nOutput:\n{out or '(no output)'}\nErrors:\n{err}")
            self.status.set("Deploy complete.")
        except Exception as e:
            messagebox.showerror("SSH Error", str(e))
            self.status.set("Failed.")

# ====== MAIN ======
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkGUI(root)
    root.mainloop()
