# Security Policy

**English** | [한국어](docs/SECURITY.ko.md)

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

As linpodx is in active development, security updates are applied to the latest version on the `main` branch.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them through [GitHub Security Advisories](https://github.com/kernalix7/linpodx/security/advisories/new).

### What to Include

When reporting a vulnerability, please include:

1. **Description** — A clear description of the vulnerability
2. **Steps to Reproduce** — Detailed steps to reproduce the issue
3. **Impact** — The potential impact of the vulnerability
4. **Affected Components** — Which crate(s) or surface(s) of linpodx are affected (e.g., `linpodx-runtime`, `linpodx-sandbox`, daemon IPC, GUI)
5. **Environment** — OS / kernel version, Podman version, Rust toolchain, GUI display server (Wayland / X11), relevant container/sandbox configuration

### Response Timeline

- **Acknowledgment** — Within 48 hours of the report
- **Initial Assessment** — Within 7 days
- **Fix & Disclosure** — Coordinated with the reporter; typically within 30 days for critical issues

### Scope

The following areas are considered in-scope for security reports:

- Sandbox escape — code running inside an AI-agent or user sandbox affecting the host system
- Approval-gate bypass in the policy engine
- Privilege escalation through the daemon IPC surface
- Capability / seccomp / AppArmor profile holes
- Supply chain — vulnerabilities in pinned dependencies, build / release artifacts
- Secret leakage through logs, audit trails, or IPC responses
- Path traversal / injection in container creation parameters and shell-out invocations
- Authentication / authorization issues on the optional TCP listener
- GUI-side vulnerabilities (Tauri / GTK) leading to host compromise

### Out of Scope

- Bugs that require physical access to the user's machine
- Social engineering attacks
- Issues in third-party dependencies (please report these upstream, but let us know)
- Vulnerabilities in Podman itself (report to the Podman project)

## Security Best Practices

linpodx follows these security practices:

- **Rootless by default** — containers run with user namespace remapping; the daemon does not require root
- **Default-deny sandbox posture** — sandbox profiles whitelist permitted operations
- **Tamper-evident audit log** — append-only with hash-chained entries
- **`#![forbid(unsafe_code)]` default** — `unsafe` requires comment, justification, and review
- **Supply-chain checks** — `cargo audit` and `cargo deny` enforced in CI
- **Capability dropping** — minimum capability set per container, additive only by explicit policy
- **No secrets in logs** — audit entries log facts and metadata, never workspace contents or environment variables

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged (with permission) in our release notes.

---

*This security policy is subject to change as the project matures.*
