import errno
import ipaddress
import random
import socket
import time
import traceback
from typing import List, Optional

from scapy.asn1.asn1 import ASN1_OID
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.netbios import NBNSQueryRequest
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
from scapy.sendrecv import sr1, srp

MAX_IP_SCAN = 1024
COMMON_TCP_PORTS = [22, 80, 135, 389, 443, 445, 631, 3389, 9100]
COMMON_UDP_PORTS = [53, 123, 137, 138, 161, 389, 1900, 5553]
DEF_TIMEOUT = 1.0


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ip_range(from_ip: str, to_ip: str) -> bool:
    try:
        start = ipaddress.IPv4Address(from_ip)
        end = ipaddress.IPv4Address(to_ip)
        return start <= end
    except ipaddress.AddressValueError:
        return False


def generate_ip_list(from_ip: str, to_ip: str) -> List[str]:
    if not is_valid_ip_range(from_ip, to_ip):
        raise ValueError("Invalid IP range")

    start = int(ipaddress.IPv4Address(from_ip))
    end = int(ipaddress.IPv4Address(to_ip))

    return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]


def get_local_network_prefix() -> str:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "192.168.1.1"

    parts = local_ip.split(".")
    if len(parts) == 4:
        # Classe C: primi 3 ottetti
        return f"{parts[0]}.{parts[1]}.{parts[2]}."
    return "192.168.1."


def get_mac_arp(ip: str, timeout: float = DEF_TIMEOUT) -> str | None:
    try:
        arp_pkt = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_pkt
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        for _, resp in answered:
            return resp.hwsrc
        return None
    except:
        return None


def icmp_ping(ip: str, timeout: float = DEF_TIMEOUT) -> tuple[bool, int | None, float | None]:
    try:
        pkt = IP(dst=ip) / ICMP(type=8)  # Echo Request
        start = time.perf_counter()
        reply = None
        for _ in range(2):
            reply = sr1(pkt, timeout=timeout, verbose=False)
            if reply:
                break
        if reply is None:
            return False, None, None

        if not reply.haslayer(ICMP):
            return False, None, None

        icmp_layer = reply.getlayer(ICMP)
        if icmp_layer.type != 0:  # Echo Reply
            return False, None, None

        ttl = reply.ttl
        rtt = (time.perf_counter() - start) * 1000
        return True, ttl, rtt

    except PermissionError:
        print("Permission error: ICMP requires admin/root")
        return False, None, None
    except Exception as e:
        import traceback
        print(f"Error pinging {ip}: {e}")
        traceback.print_exc()
        return False, None, None


def tcp_syn_probe(ip: str, port: int = 80, timeout: float = DEF_TIMEOUT) -> tuple[bool, float | None]:
    try:
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 4294967295)

        pkt = IP(dst=ip) / TCP(
            sport=sport,
            dport=port,
            flags="S",
            seq=seq
        )

        start = time.perf_counter()
        reply = sr1(pkt, timeout=timeout, verbose=False)

        if reply is None:
            return False, None

        if not reply.haslayer(TCP):
            return False, None

        tcp = reply.getlayer(TCP)

        if tcp.flags & 0x12:  # SYN + ACK
            rtt = (time.perf_counter() - start) * 1000
            rst = IP(dst=ip) / TCP(
                sport=sport,
                dport=port,
                flags="R",
                seq=tcp.ack
            )
            sr1(rst, timeout=0, verbose=False)

            return True, rtt

        if tcp.flags & 0x04:
            rtt = (time.perf_counter() - start) * 1000
            return True, rtt

        return False, None

    except PermissionError:
        print("Permission error: TCP SYN requires admin/root")
        return False, None

    except Exception as e:
        import traceback
        print(f"TCP SYN error on {ip}:{port} → {e}")
        traceback.print_exc()
        return False, None


def tcp_connect_probe(ip: str, port: int = 80, timeout: float = DEF_TIMEOUT) -> tuple[bool, bool, float | None]:
    start = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        result = s.connect_ex((ip, port))

        if result == 0:
            rtt = (time.perf_counter() - start) * 1000
            return True, True, rtt

        if result == errno.ECONNREFUSED:
            rtt = (time.perf_counter() - start) * 1000
            return True, False, rtt

        return False, False, None

    except Exception as e:
        print(f"TCP connect error {ip}:{port} → {e}")
        return False, False, None

    finally:
        s.close()


def udp_probe(ip: str, port: int, timeout: float = DEF_TIMEOUT) -> tuple[bool, bool, float | None]:
    try:
        start = time.perf_counter()
        pkt = None
        # COMMON_UDP_PORTS = [53, 123, 137, 138, 161, 389, 1900, 5553]
        if port == 53:
            # DNS query standard
            pkt = IP(dst=ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        elif port == 123:
            # NTP request minimale
            pkt = IP(dst=ip) / UDP(dport=123) / (b'\x1b' + 47 * b'\0')
        elif port in (137, 138):
            # NetBIOS Name/Datagram Service
            pkt = IP(dst=ip) / UDP(dport=port) / NBNSQueryRequest()
        elif port == 161:
            # SNMP GetRequest community "public"
            pkt = IP(dst=ip) / UDP(dport=161) / SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.3.0"))]))
        elif port == 1900:
            # SSDP M-SEARCH
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST:239.255.255.250:1900\r\n"
                "MAN:\"ssdp:discover\"\r\n"
                "MX:1\r\n"
                "ST:upnp:rootdevice\r\n\r\n"
            )
            pkt = IP(dst=ip) / UDP(dport=1900) / msg.encode()
        elif port == 5353:
            pkt = IP(dst=ip) / UDP(dport=5353) / DNS(
                rd=0,
                qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR")
            )
        else:
            # Pacchetto UDP vuoto generico
            pkt = IP(dst=ip) / UDP(dport=port)

        # --- Invio e ricezione ---
        reply = sr1(pkt, timeout=timeout, verbose=False)
        rtt = (time.perf_counter() - start) * 1000

        if reply is None:
            return False, False, None

        # Se c'è risposta UDP → porta aperta
        if reply.haslayer(UDP):
            return True, True, rtt

        # ICMP Port Unreachable → host vivo ma porta chiusa
        if reply.haslayer(ICMP):
            return True, False, rtt

        return False, False, rtt

    except PermissionError:
        print("Permission error: UDP probe requires admin/root")
        return False, False, None
    except Exception as e:
        print(f"UDP probe error {ip}:{port}: {e}")
        traceback.print_exc()
        return False, False, None


def guess_host_type(
        ttl: Optional[int],
        open_tcp_ports: List[int],
        open_udp_ports: List[int],
        vendor_name: Optional[str] = None
) -> str:
    tcp_ports = set(open_tcp_ports)
    udp_ports = set(open_udp_ports)
    vendor = (vendor_name or "").lower()

    if ttl is not None and (not isinstance(ttl, int) or ttl <= 0 or ttl > 255):
        ttl = None

    if 9100 in tcp_ports:
        return "Printer (Direct)"

    printer_vendors = ["printer", "hp", "epson", "brother", "canon", "ricoh", "lexmark", "xerox"]

    if {515, 631}.intersection(tcp_ports) and any(v in vendor for v in printer_vendors):
        return "Printer"

    if {135, 445}.issubset(tcp_ports):
        if 389 in tcp_ports or 636 in tcp_ports or 88 in tcp_ports:
            return "Windows Server (Domain Controller)"

        if 3389 in tcp_ports or any(p in tcp_ports for p in [1433, 3306, 5985, 5986]):
            return "Windows Server"

        return "Windows Host"

    if 3389 in tcp_ports and ttl and 110 <= ttl <= 140:
        return "Windows Host (RDP)"

    if {22, 445}.issubset(tcp_ports) or (22 in tcp_ports and 2049 in tcp_ports):
        nas_vendors = ["synology", "qnap", "netgear", "wd", "seagate", "buffalo"]
        if any(v in vendor for v in nas_vendors):
            return "NAS / Storage Device"

        if {80, 443, 22, 445}.intersection(tcp_ports) == {80, 443, 22, 445}:
            return "NAS / Storage Device (probable)"

    if 22 in tcp_ports and not {135, 445, 3389}.intersection(tcp_ports):
        if ttl and ttl <= 64:
            return "Linux / Unix Host"

        if any(p in tcp_ports for p in [80, 443, 8080, 3000, 5432, 27017]):
            return "Linux / Unix Host (probable)"

    indicators = 0
    if ttl is not None and ttl >= 200:
        indicators += 1
    if 161 in udp_ports:
        indicators += 1
    if any(p in tcp_ports for p in (80, 443)):
        indicators += 1
    if any(p in tcp_ports for p in (22, 23)):
        indicators += 1
    if indicators >= 2:
        return "Router / Network Device"

    if vendor and "apple" in vendor:
        if 22 in tcp_ports:
            return "macOS Host"
        if 548 in tcp_ports:
            return "macOS Host (AFP)"
        return "Apple Device ? (iOS / iPadOS)"

    if {80, 443}.intersection(tcp_ports) and not {22, 135, 445, 3389}.intersection(tcp_ports):
        if ttl and ttl >= 200:
            return "Embedded / Network Device"
        return "Embedded / Web Device"

    if 161 in udp_ports and not tcp_ports:
        return "Network Device (SNMP only)"

    if {5060, 5061}.intersection(tcp_ports) or 5060 in udp_ports:
        return "VoIP Device / IP Phone"

    if tcp_ports or udp_ports:
        return "Generic Network Host"

    return "??? Unknown ???"
"""
def lookup_mac_vendor_online(mac: str, timeout: float = 1.5) -> str | None:
    try:
        url = f"https://api.macvendors.com/{mac}"
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200 and r.text:
            return "*"+r.text.strip()
    except Exception:
        pass
    return None
"""
