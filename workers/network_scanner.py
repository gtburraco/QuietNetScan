# workers/network_scanner.py
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from PySide6.QtCore import QThread, Signal

from models.network_object import NetworkObject
from utils.ip_utils import tcp_syn_probe, tcp_connect_probe, icmp_ping, \
    udp_probe, COMMON_UDP_PORTS, get_mac_arp, COMMON_TCP_PORTS
from utils.mac_lookup import MyMacVendorLookup


class MultiThreadScannerWorker(QThread):
    network_object_found = Signal(NetworkObject)
    progress = Signal(int)
    scan_finished = Signal()

    def __init__(self, ip_list: list[str], max_threads: int = 10, vendor_file: str = "", parent=None):
        super().__init__(parent)
        self.ip_list = ip_list
        self.max_threads = max_threads
        self._running = True
        self._lock = threading.Lock()
        self.futures = []
        self.mac_lookup = None
        if vendor_file:
            self.mac_lookup = MyMacVendorLookup(vendor_file)

    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for ip in self.ip_list:
                if not self._running:
                    break
                f = executor.submit(self.scan_host, ip)
                self.futures.append(f)

            for f in as_completed(self.futures):
                if not self._running:
                    break
        self.scan_finished.emit()

    def _check_running(self):
        with self._lock:
            return self._running

    def stop(self):
        with self._lock:
            self._running = False

        for f in self.futures:
            f.cancel()

    def scan_host(self, ip: str):
        if not self._running:
            return

        mac = None
        vendor = None
        discovery_method = None
        ttl = None
        rtt = None
        rtt_icmp = rtt_tcp = rtt_udp = rtt_sync =None

        open_tcp_ports: List[int] = []
        open_udp_ports: List[int] = []


        mac = get_mac_arp(ip)
        if mac:
            discovery_method = "ARP REQ"

        if not self._running:
            return

        # Always ping for ttl
        success, ttl, rtt_icmp = icmp_ping(ip)
        if success and not discovery_method:
            discovery_method = "ICMP"
            if not mac:  # retry
                mac = get_mac_arp(ip)

        if not self._running:
            return

        if not discovery_method:
            for port in COMMON_TCP_PORTS:
                if not self._running:
                    return
                success, rtt_sync = tcp_syn_probe(ip, port)
                if success:
                    discovery_method = f"TCP_SYN:{port}"
                    break

        # Always scan TCP
        for port in COMMON_TCP_PORTS:
            if not self._running:
                return
            tcp_conn_alive, tcp_port_open, rtt_tcp = tcp_connect_probe(ip, port)
            if tcp_conn_alive:
                if not discovery_method:
                    discovery_method = f"TCP_CON:{port}"
            if tcp_port_open:
                open_tcp_ports.append(port)

        # Always scan UDP
        for port in COMMON_UDP_PORTS:
            if not self._running:
                return
            udp_conn_alive, udp_port_open, rtt_udp = udp_probe(ip, port)
            if udp_conn_alive:
                if not discovery_method:
                    discovery_method = f"UDP_CON:{port}"
            if udp_port_open:
                open_udp_ports.append(port)

        # --- Vendor lookup ---
        if mac and self.mac_lookup:
            try:
                vendor = self.mac_lookup.lookup(mac)
            except Exception as e:
                vendor = ""
        rtt = rtt_icmp or rtt_tcp or rtt_udp or rtt_sync

        if discovery_method:
            obj = NetworkObject(discovery_method, ip, open_tcp_ports, open_udp_ports, ttl, rtt, mac, vendor)
            self.network_object_found.emit(obj)

        self.progress.emit(1)
