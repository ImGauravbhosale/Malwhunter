import asyncio

import pytest

from malwhunter.wiretap.canary import find_leaked_canaries, generate_canaries
from malwhunter.wiretap.proxy import WiretapProxy


async def _run_echo_server() -> tuple[asyncio.base_events.Server, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(65536)
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
    proxy = WiretapProxy()
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
