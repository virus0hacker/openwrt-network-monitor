# 🇸🇦 OpenWrt Network Monitor — snap: ml-ftt

**Author:** ml-ftt  
**Version:** 1.0  
**Language:** Python 3 (GUI: Tkinter)  
**SSH Library:** Paramiko

---

## 🔎 Project Overview — English

**OpenWrt Network Monitor** is a local, GUI-based tool that helps network administrators monitor devices on a LAN and generate OpenWrt-compatible firewall blocking scripts. It also offers a *safe, authorized* `Disconnect Selected (Safe)` feature that deploys blocking rules to your own OpenWrt router via SSH.

**Key uses**
- Discover connected devices (IP, MAC, hostname, vendor).
- Track `First Seen` and `Last Seen`.
- Export device list as JSON.
- Generate OpenWrt firewall scripts (UCI + iptables).
- Upload and execute scripts on your own OpenWrt router (SSH).
- Disconnect selected devices safely by adding firewall rules on your router.

---

## 🔐 ملاحظة قانونية وأخلاقية — Arabic

> **تنبيه قانوني:** هذه الأداة مخصصة للاستخدام القانوني والإداري فقط.  
> لا تستخدمها على شبكات أو أجهزة لا تملكها أو ليس لديك تصريح إداري بها.  
> ميزة **Disconnect Selected (Safe)** تعمل فقط عبر رفع وتنفيذ سكربت على راوتر **OpenWrt** الذي تديره أنت (بموافقتك وبياناتك المحلية). أي إساءة استخدام تكون مسؤوليتك وحدك.

---

## ✅ Features / المميزات

- GUI (Tkinter) — professional dark-green banner and status.
- LAN scan using `ping` + `arp` to detect active devices.
- Show device details: `IP`, `MAC`, `Hostname`, `Vendor` (if OUI provided), `First Seen`, `Last Seen`.
- Export found devices to JSON.
- Generate OpenWrt block scripts (UCI + optional immediate `iptables` commands).
- `Disconnect Selected (Safe)` — generate and deploy a block script to your OpenWrt router via SSH (requires credentials).
- Dry-run option (script echoes commands instead of applying them) — review before applying.

---

## ⚙️ Requirements / المتطلبات

- Python 3.9+  
- Required Python package:
  pip install paramiko
  

(Optional) oui.txt in repository root to map MAC prefixes to vendors (file format: 001122 Vendor Name per line).


🔧 Installation / التثبيت

Clone the repository:

git clone https://github.com/virus0hacker/openwrt-network-monitor-mlftt.git

cd openwrt-network-monitor-mlftt

Install dependencies:

pip install paramiko


Run the GUI:

python network_monitor_openwrt_disconnect.py


▶️ Quick Usage (GUI) — كيفية الاستخدام

Open the app (python network_monitor_openwrt_disconnect.py).

Press Start Scan to scan your LAN (default /24).

Wait until scan completes. The table shows:

IP — device IP address

MAC — MAC address (lowercase)

Hostname — reverse DNS if available

Vendor — resolved from oui.txt if provided

First Seen / Last Seen timestamps

To create a block script for all discovered devices:

Click Generate Script (all) → choose a path and save.

This produces openwrt_block_all.sh with uci rules and optional iptables lines.



To block particular devices:

Select one or more rows in the table.



Click Disconnect Selected (Safe):

The tool will generate a small script that adds UCI firewall rules matching the selected MAC addresses.

It will then upload and execute that script on your router via SSH (the app will prompt for router IP, user, and password in the SSH panel).

The script backs up firewall config to /tmp/fw-backup.conf before applying changes.



To deploy an existing saved script:

Use Run Last Script On Router after entering router credentials (Router IP / User / Password).


🔁 Example (commands run on your PC)

Copy/paste example (manual deploy):

scp openwrt_block_selected.sh root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'chmod +x /tmp/openwrt_block_selected.sh && /tmp/openwrt_block_selected.sh'


Backup firewall (recommended):

ssh root@192.168.1.1 'uci export firewall > /tmp/fw-backup.conf'
scp root@192.168.1.1:/tmp/fw-backup.conf .


Restore backup:

scp ./fw-backup.conf root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'uci import firewall < /tmp/fw-backup.conf; /etc/init.d/firewall restart'



⚙️ How Disconnect Selected (Safe) works — شرح آلية العمل

The GUI collects selected devices (MAC addresses).


It generates an OpenWrt shell script which:

runs uci add firewall rule for each MAC,

sets target='REJECT' (or DROP if you change it),

commits with uci commit firewall and restarts the firewall.

The app uploads the script to /tmp/ on your router via SFTP (Paramiko) and executes it with SSH.

The router now blocks the specified MAC addresses at the firewall layer — this is local and reversible by restoring the backup.

Note: MAC-based blocking can be bypassed by MAC spoofing. For stronger enforcement, consider DHCP reservations + static firewall rules + client isolation.



🧰 Troubleshooting / استكشاف المشاكل

Paramiko errors: make sure SSH is enabled on the router, credentials are correct, and your PC can reach router_ip:22.

If you lose access after testing a block, restore from the saved firewall backup as shown above.

If some devices show empty MAC: ARP table may not contain them. Try a second scan or check router's DHCP leases.



🔐 Security & Responsibility / الأمن والمسؤولية

You alone are responsible for changes made on your router.

Always backup before applying rules.

Do not use this tool to attack or disrupt networks or devices you do not own or administer. Misuse may be illegal.



📝 License / الترخيص

MIT License © 2025 ml-ftt

(Short summary: you are free to use and modify the code for lawful purposes. See LICENSE file for full terms.)



✉️ Contact / تواصل

Snapchat: ml-ftt

GitHub: https://github.com/virus0hacker/openwrt-network-monitor-mlftt



🔖 Suggested repo files

network_monitor_openwrt_disconnect.py (main script)

README.md (this file)

LICENSE (MIT)

.gitignore (ignore *.pyc, __pycache__, *.json results if you want)

oui.txt (optional vendor mapping)
