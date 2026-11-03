import io
import tarfile
from pathlib import Path

import httpx
import pytest

from malwhunter.intake.registry import (
    PackageFetchError,
    extract_tarball,
    fetch_package_metadata,
    fetch_package_reputation,
    fetch_tarball,
)


def _make_tarball_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _mock_client(metadata_json: dict, tarball_bytes: bytes) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".tgz"):
            return httpx.Response(200, content=tarball_bytes)
        return httpx.Response(200, json=metadata_json)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_package_metadata_success():
    client = _mock_client({"name": "left-pad", "version": "1.3.0"}, b"")
    meta = fetch_package_metadata("left-pad", "1.3.0", client=client)
    assert meta["name"] == "left-pad"


def test_fetch_package_metadata_404_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(PackageFetchError):
        fetch_package_metadata("nope", "0.0.0", client=client)


def test_fetch_and_extract_tarball_round_trip(tmp_path: Path):
    tarball_bytes = _make_tarball_bytes({"package/package.json": b'{"name":"left-pad"}'})
    metadata = {"dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}
    client = _mock_client(metadata, tarball_bytes)

    tarball_path = fetch_tarball("left-pad", "1.3.0", tmp_path, client=client)
    assert tarball_path.exists()

    extracted = extract_tarball(tarball_path, tmp_path / "extracted")
    assert (extracted / "package.json").read_text() == '{"name":"left-pad"}'


def test_extract_tarball_refuses_path_traversal(tmp_path: Path):
    evil_bytes = _make_tarball_bytes({"package/../../evil.sh": b"rm -rf /"})
    tarball_path = tmp_path / "evil.tgz"
    tarball_path.write_bytes(evil_bytes)

    dest = tmp_path / "extracted"
    with pytest.raises(Exception):
        extract_tarball(tarball_path, dest)

    # Whatever happened, nothing must have escaped the destination directory.
    assert not (tmp_path / "evil.sh").exists()


def _mock_reputation_client(time_doc: dict | None, downloads_doc: dict | None, *, time_status=200, downloads_status=200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.npmjs.org":
            if downloads_status != 200:
                return httpx.Response(downloads_status)
            return httpx.Response(200, json=downloads_doc)
        if time_status != 200:
            return httpx.Response(time_status)
        return httpx.Response(200, json={"time": time_doc or {}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_package_reputation_happy_path():
    client = _mock_reputation_client(
        {"1.0.0": "2020-01-01T00:00:00.000Z"},
        {"downloads": 50000},
    )
    rep = fetch_package_reputation("left-pad", "1.0.0", client=client)
    assert rep.downloads_last_month == 50000
    assert rep.age_days is not None and rep.age_days > 1000  # published in 2020


def test_fetch_package_reputation_missing_version_in_time_doc_is_none():
    client = _mock_reputation_client({"0.9.0": "2020-01-01T00:00:00.000Z"}, {"downloads": 10})
    rep = fetch_package_reputation("left-pad", "1.0.0", client=client)
    assert rep.age_days is None


def test_fetch_package_reputation_never_raises_on_registry_errors():
    client = _mock_reputation_client(None, None, time_status=500, downloads_status=500)
    rep = fetch_package_reputation("left-pad", "1.0.0", client=client)
    assert rep.age_days is None
    assert rep.downloads_last_month is None


def _presence_client(status: int, body: dict | None = None, seen: list | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body or {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_presence_of_a_name_nobody_has_published():
    from malwhunter.intake.registry import check_registry_presence

    p = check_registry_presence("made-up-pkg", "1.0.0", client=_presence_client(404))
    assert (p.name_exists, p.version_exists, p.security_holding) == (False, False, False)


def test_presence_of_a_package_npm_security_took_down():
    # Shape of flatmap-stream (the event-stream payload) on the live registry
    from malwhunter.intake.registry import check_registry_presence

    body = {"dist-tags": {"latest": "0.0.1-security"}, "versions": {"0.0.1-security": {}}}
    p = check_registry_presence("flatmap-stream", "0.1.1", client=_presence_client(200, body))
    assert (p.name_exists, p.version_exists, p.security_holding) == (True, False, True)


def test_presence_of_a_real_package_with_a_missing_version():
    from malwhunter.intake.registry import check_registry_presence

    body = {"dist-tags": {"latest": "1.3.0"}, "versions": {"1.3.0": {}, "1.2.0": {}}}
    p = check_registry_presence("left-pad", "9.9.9", client=_presence_client(200, body))
    assert (p.name_exists, p.version_exists, p.security_holding) == (True, False, False)


@pytest.mark.parametrize("status", [500, 503, 429])
def test_presence_is_unknown_not_missing_when_the_registry_errors(status):
    # An outage must never be reported as "this name is unclaimed"
    from malwhunter.intake.registry import check_registry_presence

    assert check_registry_presence("left-pad", "1.3.0", client=_presence_client(status)) is None


def test_presence_asks_for_scoped_names_encoded_and_abbreviated():
    from malwhunter.intake.registry import check_registry_presence

    seen = []
    check_registry_presence("@types/node", "1.0.0", client=_presence_client(404, seen=seen))
    assert seen[0].url.raw_path.endswith(b"/@types%2fnode")
    assert seen[0].headers["accept"] == "application/vnd.npm.install-v1+json"


def test_fetch_error_carries_the_registry_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with pytest.raises(PackageFetchError) as exc:
        fetch_package_metadata("nope", "0.0.0", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert exc.value.status_code == 404
