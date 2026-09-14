import io
import tarfile
from pathlib import Path

import httpx
import pytest

from malwhunter.intake.registry import (
    PackageFetchError,
    extract_tarball,
    fetch_package_metadata,
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
