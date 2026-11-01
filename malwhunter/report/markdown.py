from __future__ import annotations

from malwhunter.dossier.model import Dossier
from malwhunter.dossier.verdict import dossier_verdict
from malwhunter.report.sanitize import escape_markdown_inline as _md
from malwhunter.report.sanitize import sanitize_text


def _code(text: str) -> str:
    """Text for inside a backtick span: a backtick would close it early."""
    return sanitize_text(text).replace("`", "'").replace("\n", " ")


def _detonation_section(dossiers: list[Dossier]) -> list[str]:
    ran = [d for d in dossiers if d.detonated and d.detonation_summary]
    if not ran:
        return []
    fence = chr(96) * 3
    lines = [f"## Detonation results ({len(ran)} package(s) run in the sandbox)", ""]
    for d in ran:
        sm = d.detonation_summary or {}
        status = "timed out" if sm.get("timed_out") else f"exit code {sm.get('exit_code')}"
        lines.append(
            f"### {_md(d.package)}@{_md(d.version)} — `{dossier_verdict(d).value.upper()}` ({status}, {sm.get('seconds')}s)"
        )
        lines.append("")
        for step, command in (sm.get("scripts_run") or {}).items():
            lines.append(f"- ran `{step}`: `{_code(command)}`")
        https = sm.get("https_hosts") or {}
        http = sm.get("plain_http_hosts") or {}
        expected = sorted(set(https.get("expected", []) + http.get("expected", [])))
        unexpected = sorted(set(https.get("unexpected", []) + http.get("unexpected", [])))
        lines.append(f"- expected hosts contacted: {_md(', '.join(expected)) or 'none'}")
        lines.append(f"- unexpected hosts contacted: {_md(', '.join(unexpected)) or 'none'}")
        if sm.get("blocked_internal_attempts"):
            lines.append(f"- blocked internal-network attempts: {_md(', '.join(sm['blocked_internal_attempts']))}")
        tr = sm.get("tracing") or {}
        if tr.get("enabled"):
            procs = tr.get("processes") or []
            lines.append(f"- processes started: {_md('; '.join(procs[:6])) or 'none'}{' …' if len(procs) > 6 else ''}")
            if tr.get("sensitive_or_persistent_files"):
                lines.append(f"- **sensitive files touched:** {_md(', '.join(tr['sensitive_or_persistent_files']))}")
            if tr.get("direct_connection_attempts"):
                lines.append(f"- direct connections (bypassing the proxy): {_md(', '.join(tr['direct_connection_attempts']))}")
        elif tr.get("note"):
            lines.append(f"- runtime trace: {_md(tr['note'])}")
        leaked = sm.get("canaries_leaked") or []
        if leaked:
            lines.append(f"- **canary secrets leaked: {_md(', '.join(leaked))}**")
        else:
            lines.append(f"- canary secrets leaked: none (of {len(sm.get('canaries_planted', []))} planted)")
        for key in ("stdout_tail", "stderr_tail"):
            if sm.get(key, "").strip():
                body = sanitize_text(sm[key].strip()[-300:]).replace(fence, "'" * 3)
                lines += [f"- {key.split('_')[0]}:", "", f"  {fence}", *("  " + ln for ln in body.splitlines()), f"  {fence}"]
        lines.append("")
    limits = "; ".join(dict.fromkeys(x for d in ran for x in (d.detonation_summary or {}).get("limits", [])))
    lines.append(f"*Limits: {limits}*")
    lines.append("")
    return lines


def dossiers_to_markdown(dossiers: list[Dossier], target: str) -> str:
    active = [d for d in dossiers if not d.ignored]
    ignored = [d for d in dossiers if d.ignored]

    detonated_count = sum(1 for d in dossiers if d.detonated)
    lines = [
        "# MalwHunter Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Packages analyzed:** {len(active)}"
        + (f" ({len(ignored)} ignored via `.MHignore`)" if ignored else ""),
        f"**Detonated:** {detonated_count}/{len(dossiers)} "
        f"({len(dossiers) - detonated_count} skipped — established packages or detonation disabled)",
        "",
    ]

    notable = [d for d in active if dossier_verdict(d).value != "clean"]
    clean_pkgs = [d for d in active if dossier_verdict(d).value == "clean"]
    lines.append(f"**Notable:** {len(notable)} package(s) not clean")
    lines.append("")

    if not notable:
        lines.append("No suspicious or malicious packages found.")
        if ignored:
            lines.append("")
            lines.extend(_ignored_section(ignored))
        det = _detonation_section(dossiers)
        if det:
            lines.append("")
            lines.extend(det)
        if clean_pkgs:
            lines.append("")
            lines.extend(_clean_section(clean_pkgs))
        return "\n".join(lines)

    for d in notable:
        verdict = dossier_verdict(d).value
        lines.append(f"## {_md(d.package)}@{_md(d.version)} — `{verdict.upper()}`")
        lines.append("")
        if d.scan_error:
            lines.append(f"**Not scanned:** {_md(d.scan_error)}")
            lines.append("")
        if d.detonation_decision_reason:
            lines.append(f"*Detonation: {_md(d.detonation_decision_reason)}*")
            lines.append("")
        for i, s in enumerate(d.signals, 1):
            lines.append(f"{i}. **{_md(s.description)}**")
            lines.append(f"   - *technical: {s.category} · {s.severity.value} severity · detected by {s.source.value}*")
            for e in s.evidence:
                loc = f"{e.file}:{e.line}" if e.file and e.line else (e.file or e.detail or "")
                lines.append(f"   - `{_code(loc)}` (in `{_code(d.package)}@{_code(d.version)}`): {_md(e.excerpt)}")
        lines.append("")

    if ignored:
        lines.extend(_ignored_section(ignored))

    lines.extend(_detonation_section(dossiers))

    if clean_pkgs:
        lines.extend(_clean_section(clean_pkgs))

    return "\n".join(lines)


def _ignored_section(ignored: list[Dossier]) -> list[str]:
    lines = [f"## Ignored ({len(ignored)} via `.MHignore` — excluded from `--fail-on`)", ""]
    for d in ignored:
        verdict = dossier_verdict(d).value
        lines.append(f"- **{_md(d.package)}@{_md(d.version)}** (`{verdict.upper()}`) — {_md(d.ignore_reason or '')}")
    lines.append("")
    return lines


def _clean_section(clean: list[Dossier]) -> list[str]:
    lines = [f"## Clean ({len(clean)} package(s))", ""]
    for d in clean:
        lines.append(f"- {_md(d.package)}@{_md(d.version)}")
    lines.append("")
    return lines


def write_markdown_report(dossiers: list[Dossier], target: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dossiers_to_markdown(dossiers, target))
