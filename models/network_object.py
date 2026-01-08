from typing import List

from utils.ip_utils import guess_host_type


class NetworkObject:
    def __init__(
            self,
            discovery_method: str | None,
            address: str,
            open_tcp_ports: List[int] | None,
            open_udp_ports: List[int] | None,
            ttl: int | None = None,
            rtt: float | None = None,
            mac_address: str | None = None,
            vendor: str | None = None,
    ):

        self._discovery_method = discovery_method
        self._address = address
        self._open_tcp_ports = open_tcp_ports
        self._open_udp_ports = open_udp_ports
        self._ttl = ttl
        self._rtt = rtt
        self._mac = mac_address
        self._vendor = vendor

    @property
    def mac(self) -> str | None:
        return self._mac

    @property
    def open_tcp_ports(self) -> str | None:
        if not self._open_tcp_ports:
            return "-"
        return ", ".join(str(p) for p in self._open_tcp_ports)

    @property
    def open_udp_ports(self) -> str | None:
        if not self._open_udp_ports:
            return "_"
        return ", ".join(str(p) for p in self._open_udp_ports)

    @property
    def discovery_method(self) -> str | None:
        return self._discovery_method

    @property
    def vendor(self) -> str | None:
        return self._vendor

    @property
    def rtt(self) -> float | None:
        return self._rtt

    @property
    def address(self) -> str:
        return self._address

    @property
    def ttl(self) -> int | None:
        return self._ttl

    @property
    def os(self) -> str | None:
        return guess_host_type(self._ttl, self._open_tcp_ports, self._open_udp_ports, self._vendor)

    def __repr__(self) -> str:
        return f"NetworkObject(address='{self._address}', ttl={self._ttl})"
