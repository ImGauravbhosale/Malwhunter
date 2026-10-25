"""A minimal, in-process recording proxy for the Chamber's sandboxed
container to route through. Lets legitimate traffic complete (so installs
actually finish and produce real signal) while logging everything it
sees: full plain-HTTP requests, and destination host:port for HTTPS
CONNECT tunnels.

Deliberately does NOT attempt TLS interception in v1 — canary/tripwire
matching against request contents only works for plain HTTP today. HTTPS
CONNECT destinations are still logged (so "talks to an unrecognized host"
is a real signal even over HTTPS), but body contents aren't inspected.
Full MITM interception is flagged as a v2 improvement in the project plan,
not silently skipped.

Only *public* destinations are relayed. The proxy is the one door out of
the sandbox, so whatever it can reach, the package under analysis can
reach: without this check, `curl http://127.0.0.1:5432` or a CONNECT to
169.254.169.254 (cloud credentials) would be relayed from wherever the
proxy runs. Every destination is resolved first, refused if any address
is loopback/private/link-local/reserved, and the connection is made to
the exact address that was checked — so a hostname can't pass the check
and then re-resolve somewhere internal (DNS rebinding).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

# How long to wait for the outbound connection to an install script's
# target before giving up. Without this, a black-holed/unroutable
# destination can hang far longer than a real connection failure would,
# which then also delays shutdown since that stuck task has to be waited
# on (or cancelled) before the proxy can stop.
_CONNECT_TIMEOUT_SECONDS = 10


@dataclass
class CapturedHttpRequest:
    method: str
    url: str
    host: str
    headers: dict[str, str]
    body: bytes


@dataclass
class CapturedConnect:
    host: str
    port: int


@dataclass
class CapturedBlocked:
    """A relay the proxy refused because the destination is internal."""

    host: str
    port: int
    address: str


# (kind, record) for every captured event, as it happens — lets the proxy
# stream its log out of a container instead of only holding it in memory.
EventCallback = Callable[[str, object], None]


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is still loopback
    return ip.is_global and not ip.is_multicast


class WiretapProxy:
    def __init__(self, *, allow_internal: bool = False, on_event: EventCallback | None = None) -> None:
        self.http_requests: list[CapturedHttpRequest] = []
        self.connects: list[CapturedConnect] = []
        self.blocked: list[CapturedBlocked] = []
        # Only for the proxy's own tests, which talk to a local echo server.
        self._allow_internal = allow_internal
        self._on_event = on_event
        self._server: asyncio.base_events.Server | None = None

    def _record(self, kind: str, record: object, into: list) -> None:
        into.append(record)
        if self._on_event is not None:
            self._on_event(kind, record)

    async def _open_vetted(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Resolves, refuses internal destinations, then connects to the
        checked address itself. None means refused (and recorded)."""
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = [info[4][0] for info in infos]
        if not self._allow_internal:
            internal = next((a for a in addresses if not is_public_address(a)), None)
            if internal is not None:
                self._record("blocked", CapturedBlocked(host=host, port=port, address=internal), self.blocked)
                return None
        return await asyncio.wait_for(asyncio.open_connection(addresses[0], port), timeout=_CONNECT_TIMEOUT_SECONDS)

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self._server = await asyncio.start_server(self._handle_client, host, port)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

        # Closing the server only stops new connections — any in-flight
        # _handle_client/pump tasks (e.g. a response still being written
        # back as the container tears down) keep running otherwise, and
        # get silently destroyed mid-flight once the event loop stops,
        # which asyncio reports as "Task was destroyed but it is pending!"
        current = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks() if t is not current and not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            first_line = await reader.readline()
            if not first_line:
                return
            parts = first_line.decode("latin-1", errors="replace").strip().split(" ")
            if len(parts) < 3:
                return
            method, target, _version = parts[0], parts[1], parts[2]

            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    k, _, v = line.decode("latin-1", errors="replace").partition(":")
                    headers[k.strip().lower()] = v.strip()

            if method.upper() == "CONNECT":
                host, _, port_str = target.partition(":")
                port = int(port_str) if port_str.isdigit() else 443
                self._record("connect", CapturedConnect(host=host, port=port), self.connects)
                await self._relay_connect(reader, writer, host, port)
                return

            content_length = int(headers.get("content-length", "0") or "0")
            body = await reader.readexactly(content_length) if content_length else b""

            self._record(
                "http",
                CapturedHttpRequest(
                    method=method, url=target, host=headers.get("host", ""), headers=dict(headers), body=body
                ),
                self.http_requests,
            )
            await self._forward_http(writer, method, target, headers, body)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
            pass  # the sandboxed package disconnecting mid-request isn't itself a signal
        finally:
            try:
                writer.close()
            except Exception:  # best-effort close during cleanup, any failure here is moot  # nosec B110
                pass

    async def _relay_connect(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, host: str, port: int
    ) -> None:
        try:
            opened = await self._open_vetted(host, port)
        except (OSError, TimeoutError):
            # A black-holed/unroutable destination (e.g. a non-existent C2
            # server) can otherwise hang here far longer than a real
            # connection failure would — observed in practice connecting
            # to a reserved test address from a different network than
            # the one this was first verified on.
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            return
        if opened is None:
            client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await client_writer.drain()
            return
        remote_reader, remote_writer = opened

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
                pass  # either side closing mid-relay isn't itself a signal
            finally:
                try:
                    dst.close()
                except Exception:  # best-effort close during cleanup, any failure here is moot  # nosec B110
                    pass

        await asyncio.gather(pump(client_reader, remote_writer), pump(remote_reader, client_writer))

    async def _forward_http(
        self,
        client_writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        host_header = headers.get("host", "")
        if not host_header:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            return
        host, _, port_str = host_header.partition(":")
        port = int(port_str) if port_str.isdigit() else 80

        try:
            opened = await self._open_vetted(host, port)
        except (OSError, TimeoutError):
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            return
        if opened is None:
            client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await client_writer.drain()
            return
        remote_reader, remote_writer = opened

        path = target
        if target.startswith("http://") or target.startswith("https://"):
            _, _, after_scheme = target.partition("://")
            _, slash, tail = after_scheme.partition("/")
            path = "/" + tail if slash else "/"

        request_lines = [f"{method} {path} HTTP/1.1\r\n"]
        for k, v in headers.items():
            if k == "proxy-connection":
                continue
            request_lines.append(f"{k}: {v}\r\n")
        request_lines.append("connection: close\r\n\r\n")

        try:
            remote_writer.write("".join(request_lines).encode("latin-1"))
            if body:
                remote_writer.write(body)
            await remote_writer.drain()

            while True:
                chunk = await remote_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
        finally:
            remote_writer.close()
