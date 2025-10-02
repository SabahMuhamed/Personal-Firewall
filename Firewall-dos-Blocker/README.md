# DoSBlocker

**DoSBlocker** is a lightweight Python-based network defender that detects high packet-rate sources on a local network and automatically blocks them using the host firewall. It's intended for lab, learning, and prototyping use only.

---

## Features

* **Packet-rate detection:** Monitor packets/sec per source IP.
* **Automatic blocking:** Uses `iptables` (Linux) or `netsh advfirewall` (Windows).
* **Duplicate prevention:** Tracks blocked IPs to avoid multiple rules.
* **Optional auto-unblock:** Supports temporary blocking or full ruleset restore.
* **Minimal dependencies:** Only requires Scapy for packet sniffing.
* **Logging:** Human-readable logs to STDOUT; can be extended to file logging.

---

## Requirements

* Python 3.7+
* [Scapy](https://scapy.net/) (`pip install scapy`)
* **Linux:** `iptables` and root privileges.
* **Windows:** Npcap installed; run Python as Administrator. Blocking uses `netsh advfirewall`.

> **Safety Note:** Use only in controlled lab environments. Always whitelist administrative IPs (SSH, RDP) to avoid accidental lockouts.

---

## Installation

```bash
# (optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# install Scapy
pip install --upgrade pip
pip install scapy
```

## Usage

```bash
# Linux (run as root)
sudo python3 dosblocker.py

# Windows (run as Administrator)
python dosblocker.py
```

The script sniff packets on the default interface and counts packets per source IP in 1-second intervals. When the rate exceeds `THRESHOLD`, the IP is blocked automatically.

### Configuration (example in script)

```python
THRESHOLD = 40         # packets per second
AUTO_UNBLOCK_SEC = 300 # seconds to automatically remove block; 0 = never
```

### Example Output

```
THRESHOLD: 40
Monitoring Network Traffic...
Blocking IP: 192.168.56.20, packet rate: 512.00 pkt/s


```
<p align="left">
  <img src="/Screenshots/firewall_dos_blocker.png" width="300" alt="DOS-BLOCKER-SCRIPT"/>
</p>
Script Execution

<p align="right">
  <img src="/Screenshots/dos-attack.png" width="300" alt="DOS-ATTACK"/>
</p>
Dos-Attack using msfconsole

<p align="right">
  <img src="/Screenshots/packets-receiving.png" width="500" alt="TCPDUMP"/>
</p>
incoming traffic captured by tcpdump
<p align="center">
  <img src="/Screenshots/blocked.png" width="500" alt="script blocked ip"/>
</p>
Script blocked the IP

<p align="center">
  <img src="/Screenshots/blocked ip.png" width="500" alt="added to iptables"/>
</p>
Added to the iptable

## Unblocking & Restore

**Linux:**

```bash
sudo iptables -D INPUT -s 192.168.56.20 -j DROP
```

**Windows:**

```powershell
netsh advfirewall firewall delete rule name="Block_192.168.56.20"
```

**Restore full rules (Linux):**

```bash
sudo iptables-restore < /path/to/backup.rules
```

---

## Hardening Suggestions

* Use `ipset` for efficient blocking of many IPs (Linux).
* Rate-limit using `tc` or `nftables` instead of DROP-only.
* Maintain admin IP whitelist.
* Log blocked IPs with timestamps.
* Review blocks manually or use auto-unblock.

---

## Troubleshooting

* **Packets not reaching VM:** Ensure both VMs are on the same subnet in host-only/internal network mode.
* **sendp() issues on Windows:** Ensure Npcap is installed and Python is run as Administrator.
* **Iptables not persistent:** Use `iptables-persistent` or `netfilter-persistent`.

---

## License

MIT License — see `LICENSE` file.

---

## Contributing

Contributions welcome! Open issues for bug reports or feature requests. Fork the repo and submit pull requests with clear descriptions and tests.

---

## Acknowledgements

Built with [Scapy](https://scapy.net/) and standard Linux/Windows firewall tools. Inspired by lab exercises in network security and DDoS mitigation.
