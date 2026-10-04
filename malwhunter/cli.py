from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import click

from malwhunter.analyst.session import Analyst
from malwhunter.chamber.trust import (
    DEFAULT_AGE_THRESHOLD_DAYS,
    DEFAULT_DOWNLOADS_THRESHOLD,
    decide_detonation,
)
from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict
from malwhunter.intake.ignore import IgnoreFileError, apply_ignore_rules, load_ignore_rules
from malwhunter.intake.manifest import resolve_dependencies
from malwhunter.intake.registry import (
    PackageFetchError,
    extract_tarball,
    fetch_package_reputation,
    fetch_tarball,
)
from malwhunter.recon.scanner import run_recon
from malwhunter.report.json_report import dossiers_to_json_str, write_json_report
from malwhunter.report.markdown import dossiers_to_markdown, write_markdown_report
from malwhunter.report.terminal import dossiers_to_terminal

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


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
    try:
        tarball_path = fetch_tarball(name, version, workdir)
        extract_dest = workdir / f"{name.replace('/', '__')}-{version}"
        package_dir = extract_tarball(tarball_path, extract_dest)
    except PackageFetchError as exc:
        click.echo(f"malwhunter: warning: could not fetch {name}@{version}: {exc}", err=True)
        return dossier

    package_json = {}
    pj_path = package_dir / "package.json"
    if pj_path.exists():
        try:
            package_json = json.loads(pj_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            pass

    for signal in run_recon(package_dir, name, package_json, analyst=analyst):
        dossier.add_signal(signal)

    if detonate_mode == "never":
        dossier.detonation_decision_reason = "detonation disabled (--no-detonate)"
    else:
        if detonate_mode == "always":
            should_detonate, reason = True, "forced (--always-detonate)"
        else:  # "smart" — the default: cheap reputation lookup gates the expensive Docker pass
            reputation = fetch_package_reputation(name, version)
            decision = decide_detonation(
                reputation, dossier.signals, age_threshold_days=age_threshold_days, downloads_threshold=downloads_threshold
            )
            should_detonate, reason = decision.should_detonate, decision.reason

        dossier.detonation_decision_reason = reason
        if should_detonate:
            from malwhunter.chamber.runner import DetonationUnavailable, detonate_package

            try:
                for signal in detonate_package(name, version, package_dir, package_json):
                    dossier.add_signal(signal)
                dossier.detonated = True
            except DetonationUnavailable as exc:
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
        click.echo(f"Wrote {output_format} report with {len(dossiers)} package(s) to {out_path}")

    verdicts = [compute_verdict(d.signals).value for d in dossiers if not d.ignored]
    qualifies = False
    if fail_on == "malicious":
        qualifies = "malicious" in verdicts
    elif fail_on == "suspicious":
        qualifies = any(v in ("malicious", "suspicious") for v in verdicts)

    sys.exit(EXIT_FINDINGS if qualifies else EXIT_OK)


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
            click.echo(f"analyzing {dep.name}@{dep.version}...", err=True)
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
    if "@" not in spec.lstrip("@"):
        click.echo("malwhunter: error: expected NAME@VERSION (e.g. left-pad@1.3.0)", err=True)
        sys.exit(EXIT_ERROR)
    name, _, version = spec.rpartition("@")

    detonate_mode = _resolve_detonate_mode(no_detonate, always_detonate)
    analyst = _select_analyst(ai)
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

    _render_and_exit([dossier], f"{name}@{version}", output_format, None, "malicious")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
