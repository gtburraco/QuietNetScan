# QuietNetScan (for LAN)

A **reliable and accurate network scanner FOR LAN** focused on **host discovery and open port detection**, intentionally designed to be **slow and conservative**.

Most network scanners available today prioritize speed. While fast scans look impressive, they often **miss hosts**, especially in real-world networks where:

- ICMP is blocked
- Firewalls drop packets silently
- Embedded devices respond slowly
- Networks are congested or rate-limited

This project takes the **opposite approach**.

---

## 🎯 Design Philosophy

> **Accuracy over speed**

This scanner is intentionally **slow**, using **high timeouts** and multiple discovery techniques to maximize the chance of finding hosts without stressing the network.

Key principles:

- Prefer **reliable detection** over aggressive probing
- Avoid flooding the network
- Work even when ICMP is blocked
- Discover hosts and ports with multiple fallback strategies

If a device is reachable, this scanner tries hard to find it.

---

## 🔍 Host Discovery Techniques

For each IP address, the scanner applies **multiple layered checks**:

1. **ICMP Echo (Ping)**
   - Extracts TTL and RTT
   - High timeout to avoid false negatives

2. **ARP Request (Local Network)**
   - Detects hosts even when ICMP is blocked
   - Ideal for switches, printers, IoT devices

3. **TCP SYN Probe (Common Ports)**
   - Identifies alive hosts even if ports are closed
   - Uses safe half-open connections

4. **TCP Connect Scan (Common Ports)**
   - Determines if ports are actually open
   - Works without raw sockets

5. **UDP Probe (Common Services)**
   - Detects hosts responding via ICMP Port Unreachable
   - Covers services that do not use TCP

The first successful method determines the **discovery method** shown to the user.

---

## 🚪 Port Scanning

Regardless of how a host is discovered, the scanner will:

- Always scan **common TCP ports**
- Always scan **common UDP ports**
- Distinguish between:
  - Host alive
  - Port open
  - Port closed

### Default ports scanned

**TCP:**
```
22, 80, 135, 443, 445, 631, 3389, 9100
```

**UDP:**
```
53, 123, 137, 138, 161, 389, 1900, 5553
```

These defaults target:
- Windows services
- Web servers
- SSH
- SMB
- RDP
- SNMP
- UPnP
- LDAP

---

## 🐢 Why It Is Slow (On Purpose)

Typical scanners:
- Use very short timeouts
- Drop hosts after a single missed reply
- Flood the network with packets

This scanner:
- Uses **long timeouts**
- Retries when appropriate
- Limits concurrency
- Minimizes packet bursts

Benefits:
- Fewer false negatives
- Better results on unstable networks
- Safer for production environments
- More accurate inventory

This makes it ideal for:
- Corporate networks
- Industrial networks
- Home labs
- Security audits where completeness matters

---

## 🖥 GUI Features

- Qt-based GUI (PySide6)
- Live progress updates
- Graceful stop button
- Table view with:
  - IP address
  - Discovery method
  - Open TCP ports
  - Open UDP ports
  - TTL
  - RTT
  - MAC address
  - Vendor

All GUI updates are performed safely from worker threads using Qt signals.

---

## 📦 Requirements

See `requirements.txt`

```txt
PySide6>=6.5
scapy>=2.5.0
```
## Installation

1. Install Python from:  https://www.python.org
2. Install the required dependencies:  pip install -r requirements.txt
3. Run:  py main.py


### Windows
Binary: https://github.com/gtburraco/QuietNetScan/releases/tag/v1.2
RUN AS ADMINISTRATOR

Scapy on Windows requires **Npcap**:

https://npcap.com/#download/

Enable during installation:
- Install Npcap in WinPcap API-compatible mode

### Linux / macOS

Run with root privileges:

```bash
sudo python main.py
```

---

## ⚠️ Disclaimer

This tool is intended for:

- Network administration
- Asset discovery
- Security testing on networks you own or are authorized to test

**Do not scan networks without permission.**

---

## 🚧 Project Status

- Actively developed
- Focused on correctness and robustness
- Performance optimizations are secondary by design

---

If you want a fast scanner, many already exist.

If you want a scanner that **does not miss hosts**, this one is for you.
