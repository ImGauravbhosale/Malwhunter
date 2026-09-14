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
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass


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


class WiretapProxy:
    def __init__(self) -> None:
        self.http_requests: list[CapturedHttpRequest] = []
        self.connects: list[CapturedConnect] = []
        self._server: asyncio.base_events.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self._server = await asyncio.start_server(self._handle_client, host, port)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

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
                self.connects.append(CapturedConnect(host=host, port=port))
                await self._relay_connect(reader, writer, host, port)
                return

            content_length = int(headers.get("content-length", "0") or "0")
            body = await reader.readexactly(content_length) if content_length else b""

            self.http_requests.append(
                CapturedHttpRequest(
                    method=method, url=target, host=headers.get("host", ""), headers=dict(headers), body=body
                )
            )
            await self._forward_http(writer, method, target, headers, body)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _relay_connect(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, host: str, port: int
    ) -> None:
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except OSError:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            return

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
                pass
            finally:
                try:
                    dst.close()
                except Exception:
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
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except OSError:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            return

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
