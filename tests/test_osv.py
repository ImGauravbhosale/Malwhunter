import json

import httpx
import pytest
from click.testing import CliRunner

from malwhunter import cli
from malwhunter.dossier.model import Severity, VerdictLevel
from malwhunter.dossier.verdict import compute_verdict
from malwhunter.intake.osv import find_hit, known_malware_signal, lookup_known_malware


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_lookup_keeps_only_mal_ids_and_sends_one_batch():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        assert request.url.path == "/v1/querybatch"
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "MAL-2025-1234"}, {"id": "GHSA-xxxx-yyyy-zzzz"}]},
            {},
            {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]},
        ]})

    hits = lookup_known_malware(
        [("npm", "evil-pkg", "1.0.0"), ("npm", "left-pad", "1.3.0"), ("pypi", "Requests", "2.31.0")],
        client=_client(handler),
    )
    assert len(seen) == 1
    assert seen[0]["queries"][2]["package"] == {"name": "requests", "ecosystem": "PyPI"}
    assert hits == {("npm", "evil-pkg", "1.0.0"): ["MAL-2025-1234"]}  # a plain CVE/GHSA is not "malware"


def test_pypi_names_are_matched_normalized():
    hits = {("pypi", "my-pkg", "1.0"): ["MAL-2024-1"]}
    assert find_hit(hits, "pypi", "My_Pkg", "1.0") == ["MAL-2024-1"]
    assert find_hit(None, "pypi", "my-pkg", "1.0") == []


@pytest.mark.parametrize("response", [
    httpx.Response(500),
    httpx.Response(200, content=b"not json"),
    httpx.Response(200, json={"results": []}),  # wrong length
    httpx.Response(200, json=["nope"]),
])
def test_lookup_failure_is_unknown_not_clean(response):
    assert lookup_known_malware([("npm", "a", "1.0.0")], client=_client(lambda r: response)) is None


def test_network_error_is_unknown():
    def handler(request):
        raise httpx.ConnectError("offline")

    assert lookup_known_malware([("npm", "a", "1.0.0")], client=_client(handler)) is None


def test_known_malware_signal_alone_is_malicious():
    signal = known_malware_signal("npm", "evil-pkg", "1.0.0", ["MAL-2025-1234"])
    assert signal.severity == Severity.CRITICAL
    assert signal.evidence[0].detail == "https://osv.dev/vulnerability/MAL-2025-1234"
    assert compute_verdict([signal]) == VerdictLevel.MALICIOUS


def _project(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"evil-pkg": "1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"name": "app"}, "node_modules/evil-pkg": {"version": "1.0.0"}},
    }))
    return tmp_path


def test_scan_reports_listed_package_without_downloading_it(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "lookup_known_malware", lambda packages, **kw: {("npm", "evil-pkg", "1.0.0"): ["MAL-2025-1"]})

    def must_not_fetch(*a, **k):
        raise AssertionError("known malware must not be downloaded")

    monkeypatch.setattr(cli, "fetch_tarball", must_not_fetch)
    result = CliRunner().invoke(cli.cli, ["scan", str(_project(tmp_path)), "--no-detonate"])
    assert result.exit_code == cli.EXIT_FINDINGS, result.output
    report = json.loads(result.stdout[result.stdout.index("{"):])["dossiers"]
    assert report[0]["verdict"] == "malicious"
    assert report[0]["signals"][0]["category"] == "known-malware"


def test_scan_no_osv_skips_the_lookup(tmp_path, monkeypatch):
    def must_not_query(*a, **k):
        raise AssertionError("--no-osv must not contact OSV")

    monkeypatch.setattr(cli, "lookup_known_malware", must_not_query)
    monkeypatch.setattr(cli, "fetch_tarball", lambda *a, **k: (_ for _ in ()).throw(cli.PackageFetchError("x")))
    result = CliRunner().invoke(cli.cli, ["scan", str(_project(tmp_path)), "--no-detonate", "--no-osv"])
    assert "AssertionError" not in result.output
    assert result.exit_code == cli.EXIT_ERROR  # fetch failed -> unscanned, as before


def test_inspect_reports_listed_package(monkeypatch):
    monkeypatch.setattr(cli, "lookup_known_malware", lambda packages, **kw: {("pypi", "evil", "0.1"): ["MAL-2024-9"]})
    monkeypatch.setattr(cli, "fetch_package", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no download")))
    result = CliRunner().invoke(cli.cli, ["inspect", "pypi:Evil==0.1", "--no-detonate"])
    assert result.exit_code == cli.EXIT_FINDINGS, result.output
    assert "MAL-2024-9" in result.output
