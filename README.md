# MalwHunter

**MalwHunter** hunts for malware deliberately hidden inside your npm
dependencies — the class of attack behind incidents like event-stream,
ua-parser-js, coa/rc, colors.js, and node-ipc.

Docs: https://imgauravbhosale.github.io/Malwhunter/

## Why another supply-chain scanner

Most existing tools (`npm audit`, Socket.dev, Snyk) are reactive — they
match a dependency against a database of *already-known* bad packages.
That's useful, but it means a brand-new malicious package, published an
hour ago, sails straight through. MalwHunter's bet: combine static
pattern-hunting with an actual sandboxed detonation pass, so it can catch
malicious *behavior*, not just malicious *reputation*.

## How it works

Everything accumulates into one **Dossier** per exact `package@version` —
packages are versioned and shared, so a Dossier is cacheable across
projects, not scoped to a single scan. A Dossier collects **Signals**
(each carrying mandatory evidence — no signal without proof) and resolves
to a **Verdict**: `clean` / `suspicious` / `malicious`.

1. **Recon** (deterministic) — unpacks the tarball and inspects it
   without executing anything: install-lifecycle script abuse
   (`curl ... | sh` in `postinstall`), `eval`/`Function` called with a
   computed argument, sensitive-data reads sitting next to network calls
   in the same file, high-entropy/packed string blobs, typosquat name
   distance.

2. **Analyst** (narrow AI, only for what Recon can't resolve) — a
   high-entropy blob that matches nothing in the catalog gets reviewed by
   two independently-framed AI passes (skeptical vs. suspicious). This
   catches what regex structurally can't: a base64 payload that *decodes*
   to a credential-harvesting shell command is invisible to pattern
   matching until something actually reads what's inside it.

3. **Detonation** (dynamic, sandboxed — needs Docker) — runs the
   package's real install scripts inside a locked-down, single-use
   container. All outbound traffic routes through a local recording
   proxy instead of being cut off, so legitimate installs still complete
   while every destination gets logged. **Canary tripwires** — fake
   secrets with unique per-run values injected as env vars — mean that if
   a tripwire value is ever seen leaving the container, that's a
   near-zero-false-positive "this is actively exfiltrating" signal, with
   no pattern-matching involved at all.

**Verdict combination** is deterministic: any canary exfiltration alone
is enough; a static shape *and* an observed behavior agreeing is enough;
two Analyst passes agreeing is enough. A single signal from just one
source stays `suspicious`, not `malicious` — so one weak signal never
blocks a real build.

## Detonation is smart by default, not all-or-nothing

Docker costs real wall-clock time per package. A typical `scan .` run has
a handful of genuinely new dependencies and a long tail of established
ones already installed by millions of people — Detonating left-pad buys
nothing. By default, MalwHunter only pays Docker's cost on a package
that's actually worth a closer look:

- Recon already found a HIGH/CRITICAL signal → always detonate
- Published more recently than 30 days ago → always detonate (too new to trust)
- Fewer than 1,000 downloads/month → always detonate (too obscure to trust)
- Reputation lookup itself failed → always detonate (fail open, not closed)
- Otherwise → skip Detonation, and say exactly why in the report

This is what makes `scan .` against a real `node_modules` tree practical
to run as a CI gate instead of timing a pipeline out. Live-verified
against the real npm registry: `inspect left-pad@1.3.0` correctly
resolves real reputation data (8.5 years old, ~8.7M downloads/month) and
skips Detonation; `--always-detonate` correctly overrides it.

## Quickstart

```bash
uv sync
uv run malwhunter inspect left-pad@1.3.0
```

```bash
malwhunter scan .                    # resolve your package.json/lockfile, hunt every dependency
malwhunter scan . --no-detonate      # Recon + Analyst only — no Docker needed, fastest possible
malwhunter scan . --always-detonate  # ignore the reputation pre-filter, detonate everything
malwhunter inspect <name>@<version>  # deep-dive one package
```

Tune the pre-filter with `--detonate-age-threshold` (days, default 30)
and `--detonate-downloads-threshold` (default 1000).

The Analyst's default backend is your own authenticated `claude` CLI
session — no separate API key needed. Detonation needs Docker Desktop
running locally.

## Running in CI/CD

Packaged as a GitHub Action ([`action.yml`](action.yml)) — no manual
clone/install step needed in your own workflow:

```yaml
- uses: ImGauravbhosale/Malwhunter@v0.1.0
  with:
    fail-on: malicious   # malicious | suspicious | none
    # detonate: smart    # smart (default) | always | never
    # ai: "false"        # most CI runners have no authenticated `claude` session
```

GitHub-hosted runners already have Docker running, so Detonation works
with zero extra setup — the smart pre-filter (on by default) is what
keeps this fast enough to run on every PR instead of timing out.

## Status

Early, under active development.

**Built and live-verified:** Recon's full catalog, real npm registry
fetch with path-traversal-safe extraction, the Analyst's two-pass second
opinion (proven live against a base64-encoded RCE payload regex alone
can't decode), verdict combination, JSON/Markdown/terminal reporting,
the reputation-based smart Detonation pre-filter (proven live against
the real npm registry).

**Detonation — two real bugs found and fixed by actually running it,
one environment limitation still open:**
- `node:20-slim` (the original sandbox base image) doesn't include
  `curl` or `wget` at all — a `curl | sh` postinstall dropper, one of
  the most common real malware patterns, silently no-ops before ever
  reaching the network. Fixed: a purpose-built sandbox image
  (`chamber/Dockerfile`) adds both, auto-built on first use.
- Even with `curl` installed, it ignored the sandbox's proxy entirely —
  `curl` only honors lowercase `http_proxy` for plain HTTP requests (its
  documented httpoxy-era behavior), and the sandbox was only setting
  uppercase `HTTP_PROXY`. Fixed: both cases are now set.
- The signal-extraction logic also only checked HTTPS CONNECT traffic
  against the host allow-list, never plain HTTP — meaning the exact
  `curl | sh` pattern above would have gone undetected even once it
  reached the network. Fixed, with dedicated tests.
- **Still open:** the full container → host-proxy → tripwire chain
  hasn't been proven inside an actual `docker run` yet. The proxy and
  signal-generation logic are verified correct by testing them directly
  in Python (the exact same code path, same request handling, same
  canary-leak detection — just without the Docker hop), but the last
  hop — a container on this specific development machine reaching back
  to a process on the host via `host.docker.internal` — is blocked by a
  machine-specific Docker Desktop networking issue, confirmed unrelated
  to this project's code (ruled out: the sandbox, `--add-host`,
  `--network host`, and the macOS firewall). Needs verifying on a
  different machine or after further Docker Desktop network
  troubleshooting.

**Not started:** ecosystems beyond npm (PyPI's `setup.py` is a real but
structurally different mechanism), full runtime instrumentation beyond
install-lifecycle scripts, user-configurable verdict policy, a `watch`
mode for CI.

## Contributing

Issues and PRs welcome. See the docs site for the full architecture
writeup before proposing changes to the Dossier model or the Recon/
Detonation/Analyst passes.

## License

[MIT](LICENSE)
