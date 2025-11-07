# openwrt-network-monitor
# 🇸🇦 OpenWrt Network Monitor — snap: ml-ftt

**Author:** ml-ftt  
**Version:** 1.0  
**License:** MIT  
**Language:** Python 3  
**GUI:** Tkinter  
**SSH Library:** Paramiko  

---

## 📜 Overview

This tool provides a **safe, GUI-based network monitoring utility** designed for **OpenWrt** network administrators.

It allows you to:
- Monitor connected devices (IP, MAC address, last seen).
- Generate **OpenWrt firewall scripts** (UCI + iptables).
- Deploy the scripts automatically to your router via SSH.
- Export device data (JSON).
- Identify unwanted or unauthorized devices and safely block them.

---

## ⚠️ Legal & Ethical Notice

> ⚖️ This project is strictly for **educational and administrative use** only.  
> You may only use it on **networks and routers that you legally own or administer**.  
> The tool **does not automatically cut or block connections** — you choose when to run scripts on your router.  
> Any misuse is the sole responsibility of the user.

---

## 💡 Features

| Feature | Description |
|----------|--------------|
| 🖥️ GUI Interface | Simple and intuitive Tkinter interface |
| 🌐 Network Scan | Detect devices via ping + ARP |
| 🧱 OpenWrt Script | Auto-generate UCI/iptables block rules |
| 🔐 SSH Deploy | Upload and execute scripts via SSH |
| 💾 Export Data | Save scan results as JSON |
| 🟢 Banner | Dark green Saudi-themed banner with author credit |
| 🧩 Secure | No remote connections or tracking; all local |

---

## 🧰 Requirements

- Python 3.9 or higher  
- Dependencies:
  ```bash
  pip install paramiko

🚀 Usage:

git clone https://github.com/YOUR_USERNAME/openwrt-network-monitor-mlftt.git

cd openwrt-network-monitor-mlftt

Run the script:
python network_monitor_openwrt_ssh.py

Use the GUI

Click Start Scan to detect devices in your LAN.

Generate a block script (openwrt_block.sh).

Fill in your router’s IP, username, and password.

Click Run Script on Router to upload and execute it safely

uci add firewall rule
uci set firewall.@rule[-1].name='block_70F396FFAB12'
uci set firewall.@rule[-1].src='*'
uci set firewall.@rule[-1].target='REJECT'
uci set firewall.@rule[-1].mac='70:F3:96:FF:AB:12'
uci set firewall.@rule[-1].enabled='1'
uci commit firewall
/etc/init.d/firewall restart


🧱 Safe Firewall Recovery

Before applying any script, backup your firewall configuration:

uci export firewall > /tmp/fw-backup.conf
scp root@192.168.1.1:/tmp/fw-backup.conf .


To restore:

uci import firewall < fw-backup.conf
/etc/init.d/firewall restart


License

MIT License © 2025 — Created by ml-ftt
You are free to use, modify, and distribute this software for legal purposes only.

