from __future__ import annotations

import json
import re
import sys
import tarfile
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
import httpx

from malwhunter.analyst.session import Analyst
from malwhunter.cache import DossierCache
from malwhunter.chamber.trust import (
    DEFAULT_AGE_THRESHOLD_DAYS,
    DEFAULT_DOWNLOADS_THRESHOLD,
    decide_detonation,
)
from malwhunter.dossier.model import (
    Dossier,
    Ecosystem,
    Evidence,
    Severity,
    Signal,
    SignalSource,
    VerdictLevel,
    signal_id,
)
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.intake.ignore import IgnoreFileError, apply_ignore_rules, load_ignore_rules
from malwhunter.intake.manifest import DependencyRef, get_lifecycle_scripts, resolve_dependencies
from malwhunter.intake.pypi_manifest import has_python_manifest, normalize_name, resolve_python_dependencies
from malwhunter.intake.pypi_registry import check_pypi_presence, fetch_package, fetch_pypi_reputation
from malwhunter.intake.registry import (
    PackageFetchError,
    check_registry_presence,
    extract_tarball,
    fetch_package_reputation,
    fetch_tarball,
)
from malwhunter.recon.context import collect_code_context
from malwhunter.recon.python_scanner import run_python_recon
from malwhunter.recon.scanner import drop_established_typosquats, run_recon, scan_typosquat
from malwhunter.report.agent_prompt import dossiers_to_agent_prompt, write_agent_prompt
from malwhunter.report.json_report import dossiers_to_json_str, write_json_report
from malwhunter.report.markdown import dossiers_to_markdown, write_markdown_report
from malwhunter.report.terminal import (
    analyzing_line,
    done_line,
    dossiers_to_terminal,
    help_screen,
    startup_banner,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# An exact, registry-fetchable version. Anything else — "^1.2.0", "latest",
# a git URL — comes from package.json's declared ranges (no lockfile), and
# fetching it would either 404 or analyze a different version than the one
# that actually gets installed.
_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")

# An exact PEP 440 release (1.2.3, 2024.1, 1.0rc1, 1.0.post2, 2.0.dev3, 1.0+local). Ranges
# (">=1.0", "~=1.2") or a missing pin come from a requirements file and can't be fetched.
_EXACT_PEP440 = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[A-Za-z0-9.]+)?$")

# One container run at a time even when --jobs > 1: each detonation starts a
# proxy container and two networks and is CPU/memory heavy, and the point of
# parallelism is the network-bound fetching and static analysis around it.
_DETONATION_LOCK = threading.Lock()


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


def _explain_missing_version(dossier: Dossier) -> bool:
    """The pinned version 404'd: ask the registry why. Returns False when
    it can't tell, leaving the caller's generic "unscanned" in place."""
    name, version = dossier.package, dossier.version
    presence = check_registry_presence(name, version)
    if presence is None:
        return False

    if presence.security_holding and not presence.version_exists:
        # npm itself pulled the version and parked a placeholder on the
        # name — the strongest "this was malware" signal there is, and one
        # no amount of our own analysis could add to.
        dossier.add_signal(
            Signal(
                id=signal_id(SignalSource.RECON, "npm-security-takedown", f"{name}@{version}"),
                source=SignalSource.RECON,
                category="npm-security-takedown",
                severity=Severity.CRITICAL,
                description=(
                    f"npm removed {name}@{version} and replaced the package with a security holding "
                    "placeholder — npm's security team took it down as malicious"
                ),
                evidence=[Evidence(excerpt=f"{name}@{version} not on registry; latest is a -security placeholder",
                                   detail=presence.url)],
            )
        )
        click.echo(f"malwhunter: {name}@{version} was taken down by npm security", err=True)
        return True

    if not presence.name_exists:
        # Nothing to scan, and the gap is itself the risk: whoever publishes
        # this name first gets their code installed — the shape of both
        # AI-hallucinated dependencies ("slopsquatting") and dependency
        # confusion against an internal package name.
        dossier.scan_error = f"no package named {name!r} exists on the npm registry"
        dossier.add_signal(
            Signal(
                id=signal_id(SignalSource.RECON, "unclaimed-package-name", name),
                source=SignalSource.RECON,
                category="unclaimed-package-name",
                severity=Severity.HIGH,
                description=(
                    f"'{name}' does not exist on the public npm registry — anyone can publish a package "
                    "under this name and have it installed here (hallucinated dependency or dependency confusion)"
                ),
                evidence=[Evidence(excerpt=f"GET {presence.url} → 404", detail=presence.url)],
            )
        )
    else:
        dossier.scan_error = f"{name} exists but version {version} is not on the registry (unpublished?)"
    click.echo(f"malwhunter: warning: not scanned {name}@{version}: {dossier.scan_error}", err=True)
    return True


def _explain_missing_pypi_release(dossier: Dossier) -> bool:
    """The release 404'd on PyPI: say why. False when PyPI can't be asked."""
    name, version = dossier.package, dossier.version
    presence = check_pypi_presence(name, version)
    if presence is None:
        return False
    if not presence.name_exists:
        dossier.scan_error = f"no project named {name!r} exists on PyPI"
        dossier.add_signal(
            Signal(
                id=signal_id(SignalSource.RECON, "unclaimed-package-name", name),
                source=SignalSource.RECON,
                category="unclaimed-package-name",
                severity=Severity.HIGH,
                description=(
                    f"'{name}' does not exist on PyPI — anyone can publish a project under this name and have it "
                    "installed here (hallucinated dependency or dependency confusion)"
                ),
                evidence=[Evidence(excerpt=f"GET {presence.url} → 404", detail=presence.url)],
            )
        )
    else:
        dossier.scan_error = f"{name} exists but release {version} is not on PyPI (deleted?)"
    click.echo(f"malwhunter: warning: not scanned {name}=={version}: {dossier.scan_error}", err=True)
    return True


def _analyze_pypi_package(
    name: str,
    version: str,
    workdir: Path,
    *,
    detonate_mode: str,
    age_threshold_days: int,
    downloads_threshold: int,
    analyst: Analyst | None,
) -> Dossier:
    name = normalize_name(name)
    dossier = Dossier(package=name, version=version, ecosystem=Ecosystem.PYPI)
    if not _EXACT_PEP440.match(version):
        dossier.scan_error = (
            f"{version!r} is not an exact version — pin it (name==X.Y.Z) or commit a lockfile so the exact "
            "installed release can be analyzed"
        )
        click.echo(f"malwhunter: warning: not scanned {name}=={version}: {dossier.scan_error}", err=True)
        return dossier
    try:
        package = fetch_package(name, version, workdir)
    except (PackageFetchError, httpx.HTTPError, tarfile.TarError, OSError, ValueError) as exc:
        if isinstance(exc, PackageFetchError) and exc.status_code == 404 and _explain_missing_pypi_release(dossier):
            return dossier
        dossier.scan_error = f"could not fetch/extract: {exc}"
        click.echo(f"malwhunter: warning: not scanned {name}=={version}: {exc}", err=True)
        return dossier

    targets = [(d, label) for d, label in ((package.sdist_dir, "sdist"), (package.wheel_dir, "wheel")) if d is not None]
    recon_signals = (
        [] if detonate_mode == "only" else scan_typosquat(name, "pypi") + run_python_recon(targets, name, analyst=analyst)
    )
    if package.yanked and detonate_mode != "only":
        recon_signals.append(
            Signal(
                id=signal_id(SignalSource.RECON, "yanked-release", f"{name}=={version}"),
                source=SignalSource.RECON,
                category="yanked-release",
                severity=Severity.LOW,
                description="this release has been yanked on PyPI (withdrawn by its maintainers or by PyPI)",
                evidence=[Evidence(excerpt=f"{name}=={version}", detail="yanked")],
            )
        )
    dossier.code_context = collect_code_context(package.root, recon_signals, labelled_roots={label: d for d, label in targets})

    reputation = None
    if detonate_mode == "smart" or any(s.category == "typosquat-candidate" for s in recon_signals):
        reputation = fetch_pypi_reputation(name, version)
        recon_signals = drop_established_typosquats(recon_signals, reputation.downloads_last_month)
    for signal in recon_signals:
        dossier.add_signal(signal)

    if detonate_mode == "never":
        dossier.detonation_decision_reason = "detonation disabled (--no-detonate)"
        return dossier
    if detonate_mode == "always":
        should_detonate, reason = True, "forced (--always-detonate)"
    elif detonate_mode == "only":
        should_detonate, reason = True, "detonation only (--mode detonate-only): static analysis skipped"
    else:
        decision = decide_detonation(
            reputation, dossier.signals, age_threshold_days=age_threshold_days, downloads_threshold=downloads_threshold
        )
        should_detonate, reason = decision.should_detonate, decision.reason
    dossier.detonation_decision_reason = reason
    if not should_detonate:
        return dossier

    from malwhunter.chamber.runner import DetonationUnavailable, detonate_pypi_package

    if package.sdist_dir is not None:
        install_dir, install_target = package.sdist_dir, ""
    elif package.wheel_file is not None:
        install_dir, install_target = package.wheel_file.parent, package.wheel_file.name
    else:  # pragma: no cover - fetch_package guarantees at least one artifact
        return dossier
    summary: dict = {}
    try:
        with _DETONATION_LOCK:
            detonation_signals = detonate_pypi_package(name, version, install_dir, install_target, summary=summary)
        for signal in detonation_signals:
            dossier.add_signal(signal)
        dossier.detonated = True
        dossier.detonation_summary = summary or None
    except DetonationUnavailable as exc:
        dossier.detonation_decision_reason = f"{reason} — but detonation was unavailable: {exc}"
        click.echo(f"malwhunter: detonation unavailable for {name}=={version}: {exc}", err=True)
    _require_observation(dossier, detonate_mode)
    return dossier


def _analyze_package(
    name: str,
    version: str,
    workdir: Path,
    *,
    detonate_mode: str,
    age_threshold_days: int,
    downloads_threshold: int,
    analyst: Analyst | None,
    ecosystem: str = "npm",
) -> Dossier:
    if ecosystem == "pypi":
        return _analyze_pypi_package(
            name, version, workdir, detonate_mode=detonate_mode, age_threshold_days=age_threshold_days,
            downloads_threshold=downloads_threshold, analyst=analyst,
        )
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
        if isinstance(exc, PackageFetchError) and exc.status_code == 404 and _explain_missing_version(dossier):
            return dossier
        # Fail closed: a package we couldn't look at is UNSCANNED, never
        # silently "clean" just because it produced no signals.
        dossier.scan_error = f"could not fetch/extract: {exc}"
        click.echo(f"malwhunter: warning: not scanned {name}@{version}: {exc}", err=True)
        return dossier

    package_json = {}
    pj_path = package_dir / "package.json"
    if pj_path.exists():
        try:
            loaded = json.loads(pj_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, RecursionError):
            loaded = None
        # package.json is written by the package under analysis: anything
        # other than a JSON object is treated as "no metadata", not a crash
        if isinstance(loaded, dict):
            package_json = loaded

    # detonation-only mode skips the static rules on purpose: what the sandbox observes is the whole result
    recon_signals = [] if detonate_mode == "only" else run_recon(package_dir, name, package_json, analyst=analyst)
    # the unpacked package is deleted when the scan ends, so grab the source
    # around each finding now (used by the AI-review handoff)
    dossier.code_context = collect_code_context(package_dir, recon_signals)
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
        elif detonate_mode == "only":
            should_detonate, reason = True, "detonation only (--mode detonate-only): static analysis skipped"
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

            summary: dict = {}
            try:
                with _DETONATION_LOCK:
                    detonation_signals = detonate_package(name, version, package_dir, package_json, summary=summary)
                for signal in detonation_signals:
                    dossier.add_signal(signal)
                dossier.detonated = True
                dossier.detonation_summary = summary or None
            except DetonationUnavailable as exc:
                dossier.detonation_decision_reason = f"{reason} — but detonation was unavailable: {exc}"
                click.echo(f"malwhunter: detonation unavailable for {name}@{version}: {exc}", err=True)

    _require_observation(dossier, detonate_mode)
    return dossier


def _require_observation(dossier: Dossier, detonate_mode: str) -> None:
    """With static analysis off, a package the sandbox did not run was never looked at in any way. That
    is UNSCANNED, never a clean result earned by skipping the checks."""
    if detonate_mode == "only" and not dossier.detonated and dossier.scan_error is None:
        dossier.scan_error = (
            "static analysis is off (--mode detonate-only) and nothing ran in the sandbox "
            "(no install script, or detonation unavailable), so this package was not observed"
        )


def _analyze_safely(name: str, version: str, workdir: Path, **options) -> Dossier:
    """`_analyze_package`, but an unexpected error in one package becomes
    that package's UNSCANNED result instead of killing the whole scan (a
    hostile package must not be able to crash the scanner and with it the
    CI gate)."""
    try:
        return _analyze_package(name, version, workdir, **options)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        dossier = Dossier(
            package=name, version=version,
            ecosystem=Ecosystem.PYPI if options.get("ecosystem") == "pypi" else Ecosystem.NPM,
        )
        dossier.scan_error = f"internal error while analyzing: {type(exc).__name__}: {exc}"
        click.echo(f"malwhunter: warning: not scanned {name}@{version}: {dossier.scan_error}", err=True)
        return dossier


def _resolve_all(project_dir: Path) -> list[DependencyRef]:
    """npm and/or Python dependencies of a project. A directory with neither
    manifest still goes through the npm resolver so the error is the same one
    as before ("no package.json")."""
    has_npm = (project_dir / "package.json").exists() or (project_dir / "package-lock.json").exists()
    has_py = has_python_manifest(project_dir)
    deps: list[DependencyRef] = []
    if has_npm or not has_py:
        deps.extend(resolve_dependencies(project_dir))
    if has_py:
        deps.extend(resolve_python_dependencies(project_dir))
    return deps


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
    elif output_format == "agent-prompt":
        rendered = dossiers_to_agent_prompt(dossiers, target)
        if out_path:
            write_agent_prompt(dossiers, target, out_path)
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


class _MalwHunterGroup(click.Group):
    """The top-level help is a screen of its own (logo, then ready-to-run commands), not click's default."""

    def format_help(self, ctx, formatter):
        formatter.write(help_screen())


@click.group(cls=_MalwHunterGroup, invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """MalwHunter — hunts malware hiding in your dependencies."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def _detonate_options(fn):
    """Shared across scan/inspect so the two commands can't drift apart
    on what "detonate" means. Default mode is "smart": a package only
    pays Docker's cost when it's new, low-adoption, or Recon already
    flagged it — this is what makes `scan .` against a real dependency
    tree (hundreds of packages, most of them boring) practical to run in
    CI instead of timing a pipeline out."""
    fn = click.option(
        "--mode",
        type=_ModeChoice(["static", "detonate-only", "full", "auto"]),
        default=None,
        help="static: read the code only, no Docker needed. detonate-only: run the install scripts in a sandboxed "
        "container and report what they did, skipping static analysis. full: static analysis AND detonation of "
        "every package. auto (default): static analysis, detonating only new, obscure or already-flagged packages. "
        "--no-detonate / --always-detonate are the older spellings of static / full.",
    )(fn)
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


# `detonate` is the older spelling of `full` (static analysis + detonation of everything).
_MODE_TO_DETONATE = {"static": "never", "detonate-only": "only", "full": "always", "detonate": "always", "auto": "smart"}


class _ModeChoice(click.Choice):
    """The four documented modes, plus `detonate` still accepted for `full`."""

    def convert(self, value, param, ctx):
        return super().convert("full" if value == "detonate" else value, param, ctx)


def _resolve_detonate_mode(no_detonate: bool, always_detonate: bool, mode: str | None = None) -> str:
    if mode is not None:
        chosen = _MODE_TO_DETONATE[mode]
        # The older flags still work, but asking for two different things
        # at once is an error, not a silent pick.
        if (no_detonate and chosen != "never") or (always_detonate and chosen != "always"):
            raise click.UsageError(f"--mode {mode} conflicts with --no-detonate/--always-detonate")
        return chosen
    if no_detonate:
        return "never"
    if always_detonate:
        return "always"
    return "smart"


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format", "output_format",
    type=click.Choice(["json", "markdown", "terminal", "agent-prompt"]),
    default="json",
    help="agent-prompt writes a review brief you can paste into any AI agent for a manual second opinion.",
)
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
@click.option("--jobs", type=click.IntRange(1, 16), default=1, show_default=True,
              help="Analyze this many packages at once. Container runs still happen one at a time.")
@click.option(
    "--cache-dir", type=click.Path(file_okay=False), default=None,
    help="Remember each package@version's result here and skip re-analyzing it next time "
    "(delta scan). Entries expire after 7 days or when MalwHunter's rules change.",
)
def scan(
    path: str,
    output_format: str,
    out_path: str | None,
    mode: str | None,
    no_detonate: bool,
    always_detonate: bool,
    detonate_age_threshold: int,
    detonate_downloads_threshold: int,
    fail_on: str,
    ai: bool,
    jobs: int,
    cache_dir: str | None,
) -> None:
    """Resolve PATH's npm dependencies and hunt for malware in each one."""
    project_dir = Path(path)
    click.echo(startup_banner(str(project_dir)), err=True)
    try:
        deps = _resolve_all(project_dir)
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

    detonate_mode = _resolve_detonate_mode(no_detonate, always_detonate, mode)
    analyst = _select_analyst(ai)
    # The AI-review brief quotes the source around each finding, which a
    # cached result doesn't carry — so that format always analyzes fresh.
    cache = (
        DossierCache(Path(cache_dir), mode=detonate_mode, ai=analyst is not None)
        if cache_dir and output_format != "agent-prompt"
        else None
    )
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        workdir = Path(tmp)

        def analyze(dep) -> Dossier:
            click.echo(analyzing_line(dep.name, dep.version), err=True)
            dossier = cache.get(dep.name, dep.version, dep.ecosystem) if cache else None
            if dossier is None:
                dossier = _analyze_safely(
                    dep.name,
                    dep.version,
                    workdir,
                    detonate_mode=detonate_mode,
                    age_threshold_days=detonate_age_threshold,
                    downloads_threshold=detonate_downloads_threshold,
                    analyst=analyst,
                    ecosystem=dep.ecosystem,
                )
                if cache:
                    cache.put(dossier)
            else:
                click.echo(f"malwhunter: {dep.name}@{dep.version} unchanged since last scan (cached)", err=True)
            click.echo(done_line(dep.name, dep.version), err=True)
            return dossier

        if jobs > 1 and len(deps) > 1:
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                dossiers = list(pool.map(analyze, deps))  # map keeps the lockfile's order
        else:
            dossiers = [analyze(dep) for dep in deps]

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
@click.option(
    "--format", "output_format",
    type=click.Choice(["json", "markdown", "terminal", "agent-prompt"]),
    default="terminal",
    help="agent-prompt prints a review brief you can paste into any AI agent for a manual second opinion.",
)
@click.option("--out", "out_path", type=click.Path(), default=None, help="Write report to this file instead of stdout.")
@_detonate_options
@click.option("--ai/--no-ai", default=True)
def inspect(
    spec: str,
    output_format: str,
    out_path: str | None,
    mode: str | None,
    no_detonate: bool,
    always_detonate: bool,
    detonate_age_threshold: int,
    detonate_downloads_threshold: int,
    ai: bool,
) -> None:
    """Deep-dive a single package, e.g. `malwhunter inspect left-pad@1.3.0`."""
    click.echo(startup_banner(spec), err=True)
    ecosystem = "npm"
    if spec.startswith("pypi:"):
        ecosystem, spec = "pypi", spec[5:]
    elif spec.startswith("npm:"):
        spec = spec[4:]
    if ecosystem == "pypi" and "==" in spec:
        name, _, version = spec.partition("==")
    elif "@" not in spec.lstrip("@"):
        click.echo(
            "malwhunter: error: expected NAME@VERSION (e.g. left-pad@1.3.0, or pypi:requests==2.31.0)", err=True
        )
        sys.exit(EXIT_ERROR)
    else:
        name, _, version = spec.rpartition("@")

    detonate_mode = _resolve_detonate_mode(no_detonate, always_detonate, mode)
    analyst = _select_analyst(ai)
    click.echo(analyzing_line(name, version), err=True)
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        dossier = _analyze_safely(
            name,
            version,
            Path(tmp),
            detonate_mode=detonate_mode,
            age_threshold_days=detonate_age_threshold,
            downloads_threshold=detonate_downloads_threshold,
            analyst=analyst,
            ecosystem=ecosystem,
        )
    click.echo(done_line(name, version), err=True)

    _render_and_exit([dossier], f"{name}@{version}", output_format, out_path, "malicious")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
