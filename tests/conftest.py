import pytest


@pytest.fixture(autouse=True)
def _no_real_osv_lookup(monkeypatch):
    """CLI tests must never reach api.osv.dev. Tests of the OSV lookup itself
    call malwhunter.intake.osv directly with a mock client."""
    from malwhunter import cli

    monkeypatch.setattr(cli, "lookup_known_malware", lambda packages, **kw: {})
