from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import click

from malwhunter.analyst.session import Analyst
from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import compute_verdict
from malwhunter.intake.manifest import resolve_dependencies
from malwhunter.intake.registry import PackageFetchError, extract_tarball, fetch_tarball
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
    name: str, version: str, workdir: Path, *, detonate: bool, analyst: Analyst | None
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

    if detonate:
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

    verdicts = [compute_verdict(d.signals).value for d in dossiers]
    qualifies = False
    if fail_on == "malicious":
        qualifies = "malicious" in verdicts
    elif fail_on == "suspicious":
        qualifies = any(v in ("malicious", "suspicious") for v in verdicts)

    sys.exit(EXIT_FINDINGS if qualifies else EXIT_OK)


@click.group()
def cli() -> None:
    """MalwHunter — hunts malware hiding in your dependencies."""


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--format", "output_format", type=click.Choice(["json", "markdown", "terminal"]), default="json")
@click.option("--out", "out_path", type=click.Path(), default=None, help="Write report to this file instead of stdout.")
@click.option(
    "--no-detonate",
    is_flag=True,
    default=False,
    help="Recon only — skip the sandboxed Detonation pass. No Docker needed, much faster.",
)
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
    path: str, output_format: str, out_path: str | None, no_detonate: bool, fail_on: str, ai: bool
) -> None:
    """Resolve PATH's npm dependencies and hunt for malware in each one."""
    project_dir = Path(path)
    try:
        deps = resolve_dependencies(project_dir)
    except Exception as exc:  # tool/config error — distinct from "findings present"
        click.echo(f"malwhunter: error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if not deps:
        click.echo("malwhunter: no dependencies found (no package.json/package-lock.json?)", err=True)

    analyst = _select_analyst(ai)
    dossiers: list[Dossier] = []
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        workdir = Path(tmp)
        for dep in deps:
            click.echo(f"analyzing {dep.name}@{dep.version}...", err=True)
            dossiers.append(
                _analyze_package(dep.name, dep.version, workdir, detonate=not no_detonate, analyst=analyst)
            )

    _render_and_exit(dossiers, str(project_dir), output_format, out_path, fail_on)


@cli.command()
@click.argument("spec")
@click.option("--format", "output_format", type=click.Choice(["json", "markdown", "terminal"]), default="terminal")
@click.option("--no-detonate", is_flag=True, default=False)
@click.option("--ai/--no-ai", default=True)
def inspect(spec: str, output_format: str, no_detonate: bool, ai: bool) -> None:
    """Deep-dive a single package, e.g. `malwhunter inspect left-pad@1.3.0`."""
    if "@" not in spec.lstrip("@"):
        click.echo("malwhunter: error: expected NAME@VERSION (e.g. left-pad@1.3.0)", err=True)
        sys.exit(EXIT_ERROR)
    name, _, version = spec.rpartition("@")

    analyst = _select_analyst(ai)
    with tempfile.TemporaryDirectory(prefix="malwhunter-") as tmp:
        dossier = _analyze_package(name, version, Path(tmp), detonate=not no_detonate, analyst=analyst)

    _render_and_exit([dossier], f"{name}@{version}", output_format, None, "malicious")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
