# Security Policy

MalwHunter is a security tool, so its own security matters more than most
projects' — a vulnerability here could mean the thing meant to catch
malicious packages becomes a vector itself (e.g. during the sandboxed
Detonation pass, or in how reports/dependencies are parsed).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security reports.

Instead, use GitHub's
[private vulnerability reporting](https://github.com/ImGauravbhosale/Malwhunter/security/advisories/new)
for this repository. Include:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal package/fixture is ideal, given the project's
  own domain)
- Affected version(s)

## Scope

In scope: the CLI, the GitHub Action, and the Recon/Analyst/Detonation
passes themselves — particularly anything that would let an analyzed
package escape its sandbox, exfiltrate data from the host running
MalwHunter, or produce a false "clean" verdict for a package that is
actually malicious.

## Response

This is an early-stage, actively-developed open-source project maintained
by one person — there's no formal SLA, but security reports get priority
over everything else in the backlog.
