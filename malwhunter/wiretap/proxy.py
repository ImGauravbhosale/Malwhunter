"""A minimal, in-process recording proxy for the Chamber's sandboxed
container to route through. Lets legitimate traffic complete (so installs
actually finish and produce real signal) while logging everything it
sees: full plain-HTTP requests and, when TLS interception is on, full HTTPS
requests too; otherwise just the destination host:port of HTTPS tunnels.

HTTPS contents: with an `interceptor` (see tls_intercept.py) a CONNECT tunnel
is terminated with a certificate from a per-run CA that only the sandbox is
told to trust, the request is read, then re-sent over a normally verified
TLS connection to the real server. That is what lets the canary tripwires
catch a secret sent over HTTPS. Without an interceptor the tunnel is relayed
blind and only the destination is known. A client that refuses the proxy's
certificate (pinning, or ignoring the CA) simply fails its handshake: the
connection attempt is still recorded, and nothing reaches the network.

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
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

# How long to wait for the outbound connection to an install script's
# target before giving up. Without this, a black-holed/unroutable
# destination can hang far longer than a real connection failure would,
# which then also delays shutdown since that stuck task has to be waited
# on (or cancelled) before the proxy can stop.
_CONNECT_TIMEOUT_SECONDS = 10
_TLS_HANDSHAKE_TIMEOUT_SECONDS = 10
# A request's body is held in memory to be inspected and re-sent. Real
# exfiltration is small; a multi-megabyte upload from an install script is
# refused (and recorded) rather than buffered without limit.
MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_HEADER_LINES = 200
_MAX_LINE_BYTES = 65536


@dataclass
class CapturedHttpRequest:
    method: str
    url: str
    host: str
    headers: dict[str, str]
    body: bytes
    scheme: str = "http"  # "https" when read from inside an intercepted tunnel


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


class Interceptor(Protocol):
    """What the proxy needs from tls_intercept.CertificateAuthority."""

    def server_context(self, host: str) -> ssl.SSLContext: ...


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is still loopback
    return ip.is_global and not ip.is_multicast


class _BadRequest(Exception):
    pass


class _TooLarge(Exception):
    pass


@dataclass
class _Request:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    line = await reader.readline()
    if len(line) > _MAX_LINE_BYTES:
        raise _BadRequest("line too long")
    return line


async def _read_request(reader: asyncio.StreamReader, first_line: bytes | None = None) -> _Request | None:
    """One HTTP/1.x request: head and complete body (Content-Length or
    chunked). None when the peer closed before sending anything."""
    first_line = first_line if first_line is not None else await _read_line(reader)
    if not first_line.strip():
        return None
    parts = first_line.decode("latin-1", errors="replace").strip().split(" ")
    if len(parts) < 3:
        raise _BadRequest("malformed request line")
    method, target = parts[0], parts[1]

    headers: dict[str, str] = {}
    for _ in range(_MAX_HEADER_LINES):
        line = await _read_line(reader)
        if line in (b"\r\n", b"\n", b""):
            break
        if b":" in line:
            k, _, v = line.decode("latin-1", errors="replace").partition(":")
            headers[k.strip().lower()] = v.strip()
    else:
        raise _BadRequest("too many headers")

    if method.upper() == "CONNECT":
        return _Request(method, target, headers, b"")

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = await _read_chunked(reader)
    else:
        length = int(headers.get("content-length", "0") or "0")
        if length < 0 or length > MAX_BODY_BYTES:
            raise _TooLarge(f"request body of {length} bytes")
        body = await reader.readexactly(length) if length else b""
    return _Request(method, target, headers, body)


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while True:
        size_line = (await _read_line(reader)).split(b";", 1)[0].strip()
        size = int(size_line, 16)
        if size == 0:
            while (await _read_line(reader)) not in (b"\r\n", b"\n", b""):
                pass  # trailers
            return bytes(body)
        if len(body) + size > MAX_BODY_BYTES:
            raise _TooLarge("chunked request body")
        body.extend(await reader.readexactly(size))
        await reader.readexactly(2)  # the CRLF that ends the chunk


def _origin_form(target: str) -> str:
    """`http://host/path?q` -> `/path?q`; a request target that is already a path is unchanged."""
    if target.startswith(("http://", "https://")):
        _, _, after_scheme = target.partition("://")
        _, slash, tail = after_scheme.partition("/")
        return "/" + tail if slash else "/"
    return target


def _serialize(request: _Request) -> bytes:
    """The request as it is sent upstream: always `Connection: close`, and a
    body that was chunked is re-framed with a Content-Length."""
    lines = [f"{request.method} {_origin_form(request.target)} HTTP/1.1\r\n"]
    for k, v in request.headers.items():
        if k in ("proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "expect"):
            continue
        lines.append(f"{k}: {v}\r\n")
    if request.body or request.method.upper() in ("POST", "PUT", "PATCH"):
        lines.append(f"content-length: {len(request.body)}\r\n")
    lines.append("connection: close\r\n\r\n")
    return "".join(lines).encode("latin-1", errors="replace") + request.body


class WiretapProxy:
    def __init__(
        self,
        *,
        allow_internal: bool = False,
        on_event: EventCallback | None = None,
        interceptor: Interceptor | None = None,
        upstream_tls: ssl.SSLContext | None = None,
    ) -> None:
        self.http_requests: list[CapturedHttpRequest] = []
        self.connects: list[CapturedConnect] = []
        self.blocked: list[CapturedBlocked] = []
        # Only for the proxy's own tests, which talk to a local echo server.
        self._allow_internal = allow_internal
        self._on_event = on_event
        self._interceptor = interceptor
        self._upstream_tls = upstream_tls
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
            try:
                request = await _read_request(reader)
            except _TooLarge:
                writer.write(b"HTTP/1.1 413 Payload Too Large\r\nconnection: close\r\n\r\n")
                await writer.drain()
                return
            except _BadRequest:
                return
            if request is None:
                return

            if request.method.upper() == "CONNECT":
                host, _, port_str = request.target.partition(":")
                port = int(port_str) if port_str.isdigit() else 443
                self._record("connect", CapturedConnect(host=host, port=port), self.connects)
                if self._interceptor is not None:
                    await self._intercept_connect(reader, writer, host, port)
                else:
                    await self._relay_connect(reader, writer, host, port)
                return

            self._record(
                "http",
                CapturedHttpRequest(
                    method=request.method, url=request.target, host=request.headers.get("host", ""),
                    headers=dict(request.headers), body=request.body,
                ),
                self.http_requests,
            )
            await self._forward_http(writer, request)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
            pass  # the sandboxed package disconnecting mid-request isn't itself a signal
        finally:
            try:
                writer.close()
            except Exception:  # best-effort close during cleanup, any failure here is moot  # nosec B110
                pass

    async def _connect_upstream(self, writer: asyncio.StreamWriter, host: str, port: int):
        """The vetted connection to the destination, or None after the
        client has been told why not (502 unreachable, 403 internal)."""
        try:
            opened = await self._open_vetted(host, port)
        except (OSError, TimeoutError):
            # A black-holed/unroutable destination (e.g. a non-existent C2
            # server) can otherwise hang here far longer than a real
            # connection failure would — observed in practice connecting
            # to a reserved test address from a different network than
            # the one this was first verified on.
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return None
        if opened is None:
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
        return opened

    async def _relay_connect(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, host: str, port: int
    ) -> None:
        opened = await self._connect_upstream(client_writer, host, port)
        if opened is None:
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

    async def _intercept_connect(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, host: str, port: int
    ) -> None:
        """Ends the sandbox's TLS here, records the request inside it, and
        re-sends it to the real server over verified TLS."""
        interceptor = self._interceptor
        if interceptor is None:
            return
        opened = await self._connect_upstream(client_writer, host, port)
        if opened is None:
            return
        remote_reader, remote_writer = opened

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        try:
            await asyncio.wait_for(
                client_writer.start_tls(interceptor.server_context(host)), timeout=_TLS_HANDSHAKE_TIMEOUT_SECONDS
            )
        except (ssl.SSLError, OSError, TimeoutError, ConnectionResetError):
            remote_writer.close()
            return  # the client does not trust the proxy's certificate; the attempt is already recorded as a CONNECT

        try:
            request = await _read_request(client_reader)
        except _TooLarge:
            client_writer.write(b"HTTP/1.1 413 Payload Too Large\r\nconnection: close\r\n\r\n")
            await client_writer.drain()
            remote_writer.close()
            return
        except _BadRequest:
            remote_writer.close()
            return
        if request is None:
            remote_writer.close()
            return

        shown_host = request.headers.get("host") or host
        self._record(
            "http",
            CapturedHttpRequest(
                method=request.method,
                url=f"https://{shown_host}{_origin_form(request.target)}",
                host=shown_host,
                headers=dict(request.headers),
                body=request.body,
                scheme="https",
            ),
            self.http_requests,
        )

        try:
            await asyncio.wait_for(
                remote_writer.start_tls(
                    self._upstream_tls or ssl.create_default_context(), server_hostname=host
                ),
                timeout=_TLS_HANDSHAKE_TIMEOUT_SECONDS,
            )
        except (ssl.SSLError, OSError, TimeoutError):
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
            await client_writer.drain()
            remote_writer.close()
            return

        try:
            remote_writer.write(_serialize(request))
            await remote_writer.drain()
            while True:
                chunk = await remote_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
        finally:
            remote_writer.close()

    async def _forward_http(self, client_writer: asyncio.StreamWriter, request: _Request) -> None:
        host_header = request.headers.get("host", "")
        if not host_header:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            return
        host, _, port_str = host_header.partition(":")
        port = int(port_str) if port_str.isdigit() else 80

        opened = await self._connect_upstream(client_writer, host, port)
        if opened is None:
            return
        remote_reader, remote_writer = opened

        try:
            remote_writer.write(_serialize(request))
            await remote_writer.drain()

            while True:
                chunk = await remote_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
        finally:
            remote_writer.close()
