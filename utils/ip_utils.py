import errno
import ipaddress
import random
import socket
import time
import traceback
from typing import List
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr1, srp


MAX_IP_SCAN = 1024
COMMON_PORTS = [80, 135, 443, 22, 445, 3389]
COMMON_UDP_PORTS = [137,138,161,1900,5553, 389]

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

def get_mac_arp(ip: str, timeout: float = 2.0) -> str | None:
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


def icmp_ping(ip: str, timeout: float = 2.0) -> tuple[bool, int | None, float | None]:
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


def tcp_syn_probe(ip: str, port: int = 80, timeout: float = 2.0) -> tuple[bool, float | None]:
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

def tcp_connect_probe(ip: str, port: int = 80, timeout: float = 1.0) -> tuple[bool, bool, float | None]:
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
        return False, False,None

    finally:
        s.close()

def udp_probe(ip: str, port: int, timeout: float = 1.0) -> tuple[bool, bool, float | None]:
    try:
        pkt = IP(dst=ip) / UDP(dport=port)
        start = time.perf_counter()

        reply = sr1(pkt, timeout=timeout, verbose=False)

        if reply is None:
            return False, False, None

        rtt = (time.perf_counter() - start) * 1000

        if reply.haslayer(UDP):
            return True, True, rtt

        if reply.haslayer(ICMP):
            icmp = reply.getlayer(ICMP)
            if icmp.type == 3 and icmp.code == 3:
                return True, False, rtt

        if reply.haslayer(ICMP):
            return True, False, rtt

        return False, False, None

    except PermissionError:
        print("Permission error: UDP probe requires admin/root")
        return False, False, None

    except Exception as e:

        print(f"UDP probe error {ip}:{port}: {e}")
        traceback.print_exc()
        return False, False, None