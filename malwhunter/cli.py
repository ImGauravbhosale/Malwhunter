from __future__ import annotations

import json
import re
import sys
import tarfile
import tempfile
from pathlib import Path

import click
import httpx

from malwhunter.analyst.session import Analyst
from malwhunter.chamber.trust import (
    DEFAULT_AGE_THRESHOLD_DAYS,
    DEFAULT_DOWNLOADS_THRESHOLD,
    decide_detonation,
)
from malwhunter.dossier.model import Dossier, VerdictLevel
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.intake.ignore import IgnoreFileError, apply_ignore_rules, load_ignore_rules
from malwhunter.intake.manifest import get_lifecycle_scripts, resolve_dependencies
from malwhunter.intake.registry import (
    PackageFetchError,
    extract_tarball,
    fetch_package_reputation,
    fetch_tarball,
)
from malwhunter.recon.scanner import drop_established_typosquats, run_recon
from malwhunter.report.json_report import dossiers_to_json_str, write_json_report
from malwhunter.report.markdown import dossiers_to_markdown, write_markdown_report
from malwhunter.report.terminal import analyzing_line, done_line, dossiers_to_terminal, startup_banner

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# An exact, registry-fetchable version. Anything else — "^1.2.0", "latest",
# a git URL — comes from package.json's declared ranges (no lockfile), and
# fetching it would either 404 or analyze a different version than the one
# that actually gets installed.
_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _select_analyst(use_ai: bool) -> Analyst | None:
    if not use_ai:
        return None
    import shutil

    if shutil.which("claude") is None:
        click.echo(
            "malwhunter: `claude` not found on PATH — ambiguous Recon findings won't get a second look.",
            err=True,
        )
        return None
    return Analyst()


def _analyze_package(
    name: str,
    version: str,
    workdir: Path,
    *,
    detonate_mode: str,
    age_threshold_days: int,
    downloads_threshold: int,
    analyst: Analyst | None,
) -> Dossier:
    dossier = Dossier(package=name, version=version)
    if not _EXACT_VERSION.match(version):
        dossier.scan_error = (
            f"{version!r} is not an exact version — commit a package-lock.json so the exact "
            "installed version can be analyzed"
        )
        click.echo(f"malwhunter: warning: not scanned {name}@{version}: {dossier.scan_error}", err=True)
        return dossier
    try:
        tarball_path = fetch_tarball(name, version, workdir)
        extract_dest = workdir / f"{name.replace('/', '__')}-{version}"
        package_dir = extract_tarball(tarball_path, extract_dest)
    except (PackageFetchError, httpx.HTTPError, tarfile.TarError, OSError) as exc:
        # Fail closed: a package we couldn't look at is UNSCANNED, never
        # silently "clean" just because it produced no signals.
        dossier.scan_error = f"could not fetch/extract: {exc}"
        click.echo(f"malwhunter: warning: not scanned {name}@{version}: {exc}", err=True)
        return dossier

    package_json = {}
    pj_path = package_dir / "package.json"
    if pj_path.exists():
        try:
            package_json = json.loads(pj_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            pass

    recon_signals = run_recon(package_dir, name, package_json, analyst=analyst)
    # One reputation lookup, shared: smart mode needs it to gate Detonation,
    # and a typosquat-candidate needs it to tell a squat from a package
    # that's simply popular itself. Skipped when neither applies.
    reputation = None
    if detonate_mode == "smart" or any(s.category == "typosquat-candidate" for s in recon_signals):
        reputation = fetch_package_reputation(name, version)
        recon_signals = drop_established_typosquats(recon_signals, reputation.downloads_last_month)
    for signal in recon_signals:
        dossier.add_signal(signal)

    if detonate_mode == "never":
        dossier.detonation_decision_reason = "detonation disabled (--no-detonate)"
    else:
        if detonate_mode == "always":
            should_detonate, reason = True, "forced (--always-detonate)"
        else:  # "smart" — the default: cheap reputation lookup gates the expensive Docker pass
            decision = decide_detonation(
                reputation, dossier.signals, age_threshold_days=age_threshold_days, downloads_threshold=downloads_threshold
            )
            should_detonate, reason = decision.should_detonate, decision.reason

        dossier.detonation_decision_reason = reason
        if should_detonate and not get_lifecycle_scripts(package_json):
            # Detonation only executes install lifecycle scripts; with none,
            # no container runs — reporting it as "detonated" would claim a
            # behavioral check that never happened.
            dossier.detonation_decision_reason = (
                f"{reason} — but the package has no preinstall/install/postinstall script, so nothing ran"
            )
        elif should_detonate:
            from malwhunter.chamber.runner import DetonationUnavailable, detonate_package

            try:
                for signal in detonate_package(name, version, package_dir, package_json):
                    dossier.add_signal(signal)
                dossier.detonated = True
            except DetonationUnavailable as exc:
                dossier.detonation_decision_reason = f"{reason} — but detonation was unavailable: {exc}"
                click.echo(f"malwhunter: detonation unavailable for {name}@{version}: {exc}", err=True)

    return dossier


def _render_and_exit(
    dossiers: list[Dossier], target: str, output_format: str, out_path: str | None, fail_on: str
) -> None:
    if output_format == "json":
        rendered = dossiers_to_json_str(dossiers)
        if out_path:
            write_json_report(dossiers, out_path)
    elif output_format == "terminal":
        rendered = dossiers_to_terminal(dossiers, target)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(rendered)
    else:
        rendered = dossiers_to_markdown(dossiers, target)
        if out_path:
            write_markdown_report(dossiers, target, out_path)

    if not out_path:
        click.echo(rendered, color=(output_format == "terminal") or None)
    else:
        # Writing to a file shouldn't mean the CLI goes quiet — show the
        # human-readable view here too, the file write is in addition to
        # that, not instead of it.
        if output_format != "terminal":
            click.echo(dossiers_to_terminal(dossiers, target), color=True)
        else:
            click.echo(rendered, color=True)
        click.echo(f"\nWrote {output_format} report with {len(dossiers)} package(s) to {out_path}")

    verdicts = [dossier_verdict(d) for d in dossiers if not d.ignored]
    qualifies = False
    if fail_on == "malicious":
        qualifies = VerdictLevel.MALICIOUS in verdicts
    elif fail_on == "suspicious":
        qualifies = any(v in (VerdictLevel.MALICIOUS, VerdictLevel.SUSPICIOUS) for v in verdicts)

    if qualifies:
        sys.exit(EXIT_FINDINGS)
    unscanned = verdicts.count(VerdictLevel.UNSCANNED)
    if unscanned:
        # Not "findings", but not a pass either: the gate can't vouch for
        # packages it never looked at. Applies even with --fail-on none.
        click.echo(
            f"malwhunter: error: {unscanned} package(s) could not be scanned — result is incomplete",
            err=True,
        )
        sys.exit(EXIT_ERROR)
    sys.exit(EXIT_OK)


@click.group()
def cli() -> None:
    """MalwHunter — hunts malware hiding in your dependencies."""


def _detonate_options(fn):
    """Shared across scan/inspect so the two commands can't drift apart
    on what "detonate" means. Default mode is "smart": a package only
    pays Docker's cost when it's new, low-adoption, or Recon already
    flagged it — this is what makes `scan .` against a real dependency
    tree (hundreds of packages, most of them boring) practical to run in
    CI instead of timing a pipeline out."""
    fn = click.option(
        "--no-detonate",
        is_flag=True,
        default=False,
        help="Never detonate anything — Recon only, no Docker needed at all, fastest possible run.",
    )(fn)
    fn = click.option(
        "--always-detonate",
        is_flag=True,
        default=False,
        help="Detonate every package regardless of reputation — ignores the smart pre-filter.",
    )(fn)
    fn = click.option(
        "--detonate-age-threshold",
        type=int,
        default=DEFAULT_AGE_THRESHOLD_DAYS,
        show_default=True,
        help="Smart mode: packages published more recently than this (days) always detonate.",
    )(fn)
    fn = click.option(
        "--detonate-downloads-threshold",
        type=int,
        default=DEFAULT_DOWNLOADS_THRESHOLD,
        show_default=True,
        help="Smart mode: packages with fewer monthly downloads than this always detonate.",
    )(fn)
    return fn


def _resolve_detonate_mode(no_detonate: bool, always_detonate: bool) -> str:
    if no_detonate:
        return "never"
    if always_detonate:
        return "always"
    return "smart"


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--format", "output_format", type=click.Choice(["json", "markdown", "terminal"]), default="json")
@click.option("--out", "out_path", type=click.Path(), default=None, help="Write report to this file instead of stdout.")
@_detonate_options
@click.option(
    "--fail-on",
    type=click.Choice(["malicious", "suspicious", "none"]),
    default="malicious",
    help="Exit 1 if any package reaches this verdict level or worse.",
)
@click.option(
    "--ai/--no-ai",
    default=True,
    help="Let the Analyst review genuinely ambiguous Recon findings. Falls back to "
    "Recon-only if `claude` isn't on PATH.",
)
def scan(
    path: str,
    output_format: str,
    out_path: str | None,
    no_detonate: bool,
    always_detonate: bool,
    detonate_age_threshold: int,
    detonate_downloads_threshold: int,
    fail_on: str,
    ai: bool,
) -> None:
    """Resolve PATH's npm dependencies and hunt for malware in each one."""
    project_dir = Path(path)
    click.echo(startup_banner(str(project_dir)), err=True)
    try:
        deps = resolve_dependencies(project_dir)
    except Exception as exc:  # tool/config error — distinct from "findings present"
        click.echo(f"malwhunter: error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    try:
        ignore_rules = load_ignore_rules(project_dir)
    except IgnoreFileError as exc:
        click.echo(f"malwhunter: error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if not deps:
        click.echo("malwhunter: no dependencies found (no package.json/package-lock.json?)", err=True)

    detonate_mode = _resolve_detonate_mode(no_detonate, always_detonate)
    analyst = _select_analyst(ai)
    dossiers: list[Dossier] = []
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        workdir = Path(tmp)
        for dep in deps:
            click.echo(analyzing_line(dep.name, dep.version), err=True)
            dossiers.append(
                _analyze_package(
                    dep.name,
                    dep.version,
                    workdir,
                    detonate_mode=detonate_mode,
                    age_threshold_days=detonate_age_threshold,
                    downloads_threshold=detonate_downloads_threshold,
                    analyst=analyst,
                )
            )
            click.echo(done_line(dep.name, dep.version), err=True)

    if ignore_rules:
        outcome = apply_ignore_rules(dossiers, ignore_rules)
        for d in dossiers:
            rule = outcome.matched.get(d.dossier_key)
            if rule:
                d.ignored = True
                d.ignore_reason = rule.reason
        if outcome.matched:
            click.echo(
                f"malwhunter: {len(outcome.matched)} package(s) excluded from --fail-on via .MHignore "
                f"(still shown in the report)",
                err=True,
            )
        for rule in outcome.expired:
            click.echo(
                f"malwhunter: warning: .MHignore rule for {rule.package}"
                f"{'@' + rule.version if rule.version else ''} expired {rule.expires} — no longer applied, remove or renew it",
                err=True,
            )
        for rule in outcome.unused:
            click.echo(
                f"malwhunter: warning: .MHignore rule for {rule.package}"
                f"{'@' + rule.version if rule.version else ''} never matched a scanned package — stale entry?",
                err=True,
            )

    _render_and_exit(dossiers, str(project_dir), output_format, out_path, fail_on)


@cli.command()
@click.argument("spec")
@click.option("--format", "output_format", type=click.Choice(["json", "markdown", "terminal"]), default="terminal")
@_detonate_options
@click.option("--ai/--no-ai", default=True)
def inspect(
    spec: str,
    output_format: str,
    no_detonate: bool,
    always_detonate: bool,
    detonate_age_threshold: int,
    detonate_downloads_threshold: int,
    ai: bool,
) -> None:
    """Deep-dive a single package, e.g. `malwhunter inspect left-pad@1.3.0`."""
    click.echo(startup_banner(spec), err=True)
    if "@" not in spec.lstrip("@"):
        click.echo("malwhunter: error: expected NAME@VERSION (e.g. left-pad@1.3.0)", err=True)
        sys.exit(EXIT_ERROR)
    name, _, version = spec.rpartition("@")

    detonate_mode = _resolve_detonate_mode(no_detonate, always_detonate)
    analyst = _select_analyst(ai)
    click.echo(analyzing_line(name, version), err=True)
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        dossier = _analyze_package(
            name,
            version,
            Path(tmp),
            detonate_mode=detonate_mode,
            age_threshold_days=detonate_age_threshold,
            downloads_threshold=detonate_downloads_threshold,
            analyst=analyst,
        )
    click.echo(done_line(name, version), err=True)

    _render_and_exit([dossier], f"{name}@{version}", output_format, None, "malicious")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
