from __future__ import annotations

import dataclasses as dc
import socket
from typing import ClassVar, Self


def _has_attr(obj: object, attribute_name: str) -> bool:
    """
    return true if `obj` has `attribute_name`.

    this exists because writing `hasattr(x, 'y')` everywhere is not "explicit",
    it's just repetitive.
    """
    return hasattr(obj, attribute_name)


@dc.dataclass(frozen=True, slots=True)
class SocketOptions:
    """socket-level tuning that maps cleanly onto httpcore without fighting httpx
    with ergonomic builder methods that can be chained

    these settings do not override httpx timeouts, pooling, retries, or proxies.
    they only configure kernel socket behavior.

    parameters
    ----------
    tcp_nodelay:
        disables nagle for lower latency.
    keepalive:
        enables tcp keepalive probes.
    keepalive_idle:
        seconds before keepalive probes start (platform dependent).
    keepalive_interval:
        seconds between keepalive probes (platform dependent).
    keepalive_count:
        number of failed probes before considering the connection
        dead (platform dependent)
    recv_buffer:
        socket receive buffer size in bytes.
    send_buffer:
        socket send buffer size in bytes.

    notes
    -----
    if your os ignores these, congratulations, you're learning about sysctls.
    """

    tcp_nodelay: bool = True
    keepalive: bool = True

    # NOTE: these are platform dependent
    keepalive_idle: int | None = None
    keepalive_interval: int | None = None
    keepalive_count: int | None = None

    recv_buffer: int | None = None
    send_buffer: int | None = None

    _PLATFORM_KEEPALIVE_FLAGS: ClassVar[tuple[str, str, str]] = (
        'TCP_KEEPIDLE',
        'TCP_KEEPINTVL',
        'TCP_KEEPCNT',
    )


    def low_latency(self) -> Self:
        """
        return a low-latency preset.

        this is basically "nagle off" plus keepalives, because most http client workloads
        prefer responsiveness over optimizing a packet count graph.
        """
        return dc.replace(
            self,
            tcp_nodelay=True,
            keepalive=True,
        )

    def stable_long_lived(
        self,
        *,
        keepalive_idle: int = 60,
        keepalive_interval: int = 10,
        keepalive_count: int = 5,
    ) -> Self:
        """
        return a preset aimed at long-lived connections through flaky networks.

        parameters
        ----------
        keepalive_idle:
            seconds of idleness before probes begin.
        keepalive_interval:
            seconds between probes.
        keepalive_count:
            failed probes before the socket is considered dead.

        notes
        -----
        this is best-effort and platform-dependent. if you need guaranteed behavior,
        you need an ops policy, not a dataclass.
        """
        return dc.replace(
            self,
            keepalive_idle=keepalive_idle,
            keepalive_interval=keepalive_interval,
            keepalive_count=keepalive_count,
        )

    def high_throughput(
        self,
        *,
        recv_buffer: int = 1_048_576,
        send_buffer: int = 1_048_576,
    ) -> Self:
        """
        return a throughput-leaning preset.

        parameters
        ----------
        recv_buffer:
            requested receive buffer size in bytes.
        send_buffer:
            requested send buffer size in bytes.

        notes
        -----
        buffers are best-effort. your kernel may clamp them. your sysadmin may also
        clamp your dreams. both are valid.
        """
        return dc.replace(
            self,
            tcp_nodelay=True,
            keepalive=True,
            recv_buffer=recv_buffer,
            send_buffer=send_buffer,
        )

    def to_httpcore_options(self) -> list[tuple[int, int, int]]:
        """
        convert to the `socket_options` list expected by httpcore.

        returns
        -------
        list[tuple[int, int, int]]
            a list of (level, optname, value) tuples.
        """
        socket_options: list[tuple[int, int, int]] = []

        if self.tcp_nodelay:
            socket_options.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))

        if self.keepalive:
            socket_options.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))

            if self.keepalive_idle is not None and _has_attr(socket, 'TCP_KEEPIDLE'):
                socket_options.append((
                    socket.IPPROTO_TCP,
                    socket.TCP_KEEPIDLE,
                    int(self.keepalive_idle),
                ))

            if self.keepalive_interval is not None and _has_attr(socket, 'TCP_KEEPINTVL'):
                socket_options.append((
                    socket.IPPROTO_TCP,
                    socket.TCP_KEEPINTVL,
                    int(self.keepalive_interval),
                ))

            if self.keepalive_count is not None and _has_attr(socket, 'TCP_KEEPCNT'):
                socket_options.append((
                    socket.IPPROTO_TCP,
                    socket.TCP_KEEPCNT,
                    int(self.keepalive_count),
                ))

        if self.recv_buffer is not None:
            socket_options.append((
                socket.SOL_SOCKET,
                socket.SO_RCVBUF,
                int(self.recv_buffer),
            ))

        if self.send_buffer is not None:
            socket_options.append((
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                int(self.send_buffer),
            ))

        return socket_options
