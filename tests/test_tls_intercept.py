"""HTTPS inspection in the Wiretap proxy: a secret sent over TLS must be
readable by the proxy, the real server must still be verified, and a client
that does not trust the proxy must get nothing through."""
from __future__ import annotations

import asyncio
import ssl
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from malwhunter.wiretap import proxy as proxy_mod  # noqa: E402
from malwhunter.wiretap.proxy import WiretapProxy, _read_request  # noqa: E402
from malwhunter.wiretap.tls_intercept import CertificateAuthority  # noqa: E402


def _client_ctx_trusting(ca: CertificateAuthority) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=ca.certificate_pem().decode())
    return ctx


class Upstream:
    """A real HTTPS server with its own CA, standing in for the internet."""

    def __init__(self) -> None:
        self.ca = CertificateAuthority()
        self.hits: list[bytes] = []
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def __aenter__(self):
        async def handle(reader, writer):
            request = await _read_request(reader)
            if request is not None:
                self.hits.append(request.body)
                reply = b"echo:" + request.body
                writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\nconnection: close\r\n\r\n" % len(reply) + reply)
                await writer.drain()
            writer.close()

        self.server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=self.ca.server_context("127.0.0.1"))
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


async def _through_proxy(proxy_port: int, target_port: int, client_ctx: ssl.SSLContext, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nhost: 127.0.0.1:{target_port}\r\n\r\n".encode())
    await writer.drain()
    status = await reader.readline()
    assert b" 200 " in status
    await reader.readline()
    await writer.start_tls(client_ctx, server_hostname="127.0.0.1")
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    return data


def _post(body: bytes, extra: str = "") -> bytes:
    return (
        b"POST /collect HTTP/1.1\r\nhost: 127.0.0.1\r\n" + extra.encode()
        + b"content-length: %d\r\n\r\n" % len(body) + body
    )


async def _make_proxy(upstream: Upstream, **kw):
    ca = CertificateAuthority()
    proxy = WiretapProxy(allow_internal=True, interceptor=ca, upstream_tls=_client_ctx_trusting(upstream.ca), **kw)
    return ca, proxy, await proxy.start()


async def test_https_request_body_is_visible_and_the_response_comes_back():
    async with Upstream() as up:
        ca, proxy, port = await _make_proxy(up)
        reply = await _through_proxy(port, up.port, _client_ctx_trusting(ca), _post(b"token=canary_abc123"))
        await proxy.stop()
    assert reply.endswith(b"echo:token=canary_abc123")
    assert up.hits == [b"token=canary_abc123"]
    [req] = proxy.http_requests
    assert req.scheme == "https" and req.body == b"token=canary_abc123"
    assert req.url == "https://127.0.0.1/collect" and req.method == "POST"
    assert [(c.host, c.port) for c in proxy.connects] == [("127.0.0.1", up.port)]


async def test_chunked_https_body_is_decoded_for_inspection_and_reframed_upstream():
    async with Upstream() as up:
        ca, proxy, port = await _make_proxy(up)
        chunked = (
            b"POST /c HTTP/1.1\r\nhost: 127.0.0.1\r\ntransfer-encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        reply = await _through_proxy(port, up.port, _client_ctx_trusting(ca), chunked)
        await proxy.stop()
    assert proxy.http_requests[0].body == b"hello world" and up.hits == [b"hello world"]
    assert reply.endswith(b"echo:hello world")


async def test_client_that_does_not_trust_the_proxy_gets_nothing_through():
    async with Upstream() as up:
        ca, proxy, port = await _make_proxy(up)
        with pytest.raises((ssl.SSLError, OSError)):
            await _through_proxy(port, up.port, ssl.create_default_context(), _post(b"secret"))
        await asyncio.sleep(0.2)
        await proxy.stop()
    assert up.hits == [] and proxy.http_requests == []
    assert len(proxy.connects) == 1  # the attempt itself is still recorded


async def test_proxy_verifies_the_real_server_and_refuses_an_untrusted_one():
    async with Upstream() as up:
        ca = CertificateAuthority()
        proxy = WiretapProxy(allow_internal=True, interceptor=ca)  # default trust store: does not know Upstream's CA
        port = await proxy.start()
        reply = await _through_proxy(port, up.port, _client_ctx_trusting(ca), _post(b"x"))
        await proxy.stop()
    assert b"502" in reply.split(b"\r\n", 1)[0] and up.hits == []


async def test_oversized_https_body_is_refused_not_buffered(monkeypatch):
    monkeypatch.setattr(proxy_mod, "MAX_BODY_BYTES", 10)
    async with Upstream() as up:
        ca, proxy, port = await _make_proxy(up)
        reply = await _through_proxy(port, up.port, _client_ctx_trusting(ca), _post(b"x" * 100))
        await proxy.stop()
    assert b"413" in reply.split(b"\r\n", 1)[0] and up.hits == []


async def test_internal_destinations_are_still_refused_when_intercepting():
    ca = CertificateAuthority()
    proxy = WiretapProxy(interceptor=ca)  # allow_internal defaults to False
    port = await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nhost: x\r\n\r\n")
    await writer.drain()
    status = await reader.readline()
    writer.close()
    await proxy.stop()
    assert b"403" in status and [b_.host for b_ in proxy.blocked] == ["127.0.0.1"]


async def test_plain_http_chunked_body_is_now_captured():
    received: list[bytes] = []

    async def handle(reader, writer):
        request = await _read_request(reader)
        received.append(request.body)
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    target = server.sockets[0].getsockname()[1]
    proxy = WiretapProxy(allow_internal=True)
    port = await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        f"POST http://127.0.0.1:{target}/c HTTP/1.1\r\nhost: 127.0.0.1:{target}\r\ntransfer-encoding: chunked\r\n\r\n"
        "4\r\ndata\r\n0\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    await proxy.stop()
    server.close()
    assert proxy.http_requests[0].body == b"data" and received == [b"data"]


def test_each_run_gets_its_own_ca_and_hosts_get_distinct_certificates():
    a, b = CertificateAuthority(), CertificateAuthority()
    assert a.certificate_pem() != b.certificate_pem()
    assert a.server_context("example.com") is a.server_context("example.com")  # cached
    assert a.server_context("example.com") is not a.server_context("other.org")
    a.server_context("10.0.0.5")  # IP literals get an IP SAN, not a DNS name


def test_ca_certificate_is_written_without_the_private_key():
    ca = CertificateAuthority()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ca.pem"
        ca.write_certificate(path)
        text = path.read_text()
    assert "BEGIN CERTIFICATE" in text and "PRIVATE KEY" not in text
