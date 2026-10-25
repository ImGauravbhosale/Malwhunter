import asyncio

import pytest

from malwhunter.wiretap.canary import find_leaked_canaries, generate_canaries
from malwhunter.wiretap.proxy import WiretapProxy, is_public_address


async def _run_echo_server() -> tuple[asyncio.base_events.Server, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(65536)
        body = b'{"ok": true}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_plain_http_request_is_captured_and_forwarded():
    echo_server, echo_port = await _run_echo_server()
    proxy = WiretapProxy(allow_internal=True)  # the echo server is on loopback
    proxy_port = await proxy.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    request = (
        f"POST http://127.0.0.1:{echo_port}/beacon HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{echo_port}\r\n"
        f"Content-Length: 11\r\n\r\n"
        f"secret=1234"
    )
    writer.write(request.encode())
    await writer.drain()
    response = await reader.read(4096)
    writer.close()

    assert b"200 OK" in response
    assert len(proxy.http_requests) == 1
    captured = proxy.http_requests[0]
    assert captured.method == "POST"
    assert captured.body == b"secret=1234"

    await proxy.stop()
    echo_server.close()
    await echo_server.wait_closed()


@pytest.mark.asyncio
async def test_connect_destination_is_captured():
    proxy = WiretapProxy()
    proxy_port = await proxy.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    await writer.drain()
    response = await reader.read(100)
    writer.close()

    assert b"200 Connection Established" in response
    assert len(proxy.connects) == 1
    assert proxy.connects[0].host == "example.com"
    assert proxy.connects[0].port == 443

    await proxy.stop()


def test_canary_generation_produces_unique_values():
    canaries = generate_canaries()
    assert "NPM_TOKEN" in canaries
    assert len(set(canaries.values())) == len(canaries)


def test_find_leaked_canaries_detects_substring_match():
    canaries = {"NPM_TOKEN": "canary_abc123"}
    leaked = find_leaked_canaries("POST body: token=canary_abc123&x=1", canaries)
    assert leaked == ["NPM_TOKEN"]


def test_find_leaked_canaries_empty_when_no_match():
    canaries = {"NPM_TOKEN": "canary_abc123"}
    assert find_leaked_canaries("nothing sensitive here", canaries) == []


async def _send_through_proxy(proxy_port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(raw)
    await writer.drain()
    response = await reader.read(4096)
    writer.close()
    return response


@pytest.mark.asyncio
async def test_plain_http_to_a_loopback_service_is_refused_and_recorded():
    # Found by live-testing Detonation: a sandboxed postinstall read a
    # loopback-only host service by asking the proxy to fetch it.
    echo_server, echo_port = await _run_echo_server()
    events = []
    proxy = WiretapProxy(on_event=lambda kind, rec: events.append(kind))
    proxy_port = await proxy.start()

    response = await _send_through_proxy(
        proxy_port, f"GET http://127.0.0.1:{echo_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n".encode()
    )

    assert b"403 Forbidden" in response
    assert b'{"ok": true}' not in response
    assert len(proxy.http_requests) == 1  # still captured: canary matching runs on it regardless
    assert [(b.host, b.port, b.address) for b in proxy.blocked] == [("127.0.0.1", echo_port, "127.0.0.1")]
    assert events == ["http", "blocked"]
    await proxy.stop()
    echo_server.close()
    await echo_server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["127.0.0.1:22", "localhost:5432", "169.254.169.254:80", "10.0.0.5:443"])
async def test_connect_to_internal_destinations_is_refused(target):
    proxy = WiretapProxy()
    proxy_port = await proxy.start()

    response = await _send_through_proxy(proxy_port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())

    assert b"403 Forbidden" in response
    assert len(proxy.connects) == 1
    assert len(proxy.blocked) == 1
    await proxy.stop()


@pytest.mark.parametrize(
    "address,public",
    [
        ("93.184.215.14", True),
        ("2606:4700::6810:84e5", True),
        ("127.0.0.1", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
        ("10.1.2.3", False),
        ("172.17.0.1", False),       # default docker bridge gateway
        ("192.168.1.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("100.64.0.1", False),       # carrier-grade NAT
        ("0.0.0.0", False),
        ("fe80::1%eth0", False),     # link-local with zone id
        ("fd00::1", False),          # unique local
        ("224.0.0.1", False),        # multicast
    ],
)
def test_is_public_address(address, public):
    assert is_public_address(address) is public
