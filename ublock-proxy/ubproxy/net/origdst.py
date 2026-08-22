"""Recover the original destination of a connection redirected by iptables."""

from __future__ import annotations

import socket
import struct
from typing import Optional

SO_ORIGINAL_DST = 80  # include/uapi/linux/netfilter_ipv4.h
IP6T_SO_ORIGINAL_DST = 80  # include/uapi/linux/netfilter_ipv6/ip6_tables.h


def original_destination(sock: socket.socket) -> Optional[tuple[str, int]]:
    """Return ``(ip, port)`` the client meant to reach, or ``None``.

    ``None`` means the connection did not come through a REDIRECT rule — the
    caller then has to fall back on the ``Host`` header / CONNECT target.
    """
    try:
        if sock.family == socket.AF_INET6:
            raw = sock.getsockopt(socket.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, 28)
            port, = struct.unpack_from("!H", raw, 2)
            address = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            if address.startswith("::ffff:"):  # IPv4-mapped
                address = address[7:]
            return address, port
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, = struct.unpack_from("!H", raw, 2)
        address = socket.inet_ntop(socket.AF_INET, raw[4:8])
        return address, port
    except (OSError, AttributeError, struct.error):
        return None
