# lab-doctor

*Pre-flight checks for a reversing lab.*

---
## What it does

`lab-doctor` runs a set of safety and readiness checks before you touch a sample, then writes a timestamped report to `~/lab_reports/`. The current skeleton implements the **Identity & Context** check (VM detection + root warning) and a Markdown report writer; additional checks are planned (network/netmode, SSH, hardening, storage, tools).&#x20;

Repeatable analysis needs a clean, predictable lab. `lab-doctor` catches the easy-to-miss issues (lax sysctls, broken SSH, missing tools) *before* they waste time or create risk.

---

## Status

* **Version:** `0.0.1` (skeleton)&#x20;
* **Implemented today:**

  * Identity & Context (detect virtualization, warn on root)
  * Report aggregator + Markdown report (`~/lab_reports/lab-doctor-YYYYMMDD-HHMM.md`)&#x20;
* **Planned next:** SSH readiness, hardening guard-rails, storage & snapshots, tools baseline (see Roadmap).

---

## Requirements

* For VM detection, one of:

  * `systemd-detect-virt` (preferred), or
  * `virt-what` (fallback).

---

## Install

Place the script somewhere on your `PATH` and make it executable:

```bash
sudo install -m755 lab-doctor.sh /usr/local/bin/lab-doctor
```

Create the reports directory (first run will also create it):

```bash
mkdir -p ~/lab_reports
```

---

## Usage

```bash
lab-doctor            # full run (skeleton today runs Identity check + writes report)
lab-doctor --fast     # (reserved) faster run
lab-doctor --tools-only
lab-doctor --json     # (reserved) also emit JSON
lab-doctor --fix      # (reserved) apply safe auto-fixes
lab-doctor --help
```

Flags are parsed in `parse_args` and stored in `FLAG_*` variables for later expansion. (In the skeleton, only the standard run path is used.)&#x20;

---

## What it checks

### ✅ Implemented: Identity & Context

* Detects whether you’re inside a VM (prefers `systemd-detect-virt`; falls back to `virt-what`; then DMI/CPU flags).
* **Policy:**

  * **PASS** — VM detected & you’re a non-root user.
  * **WARN** — VM detected but running as root (suggests using a non-root user).
  * **WARN** — No VM detected: proceed on bare metal only if this is intentional and you fully understand the risk/behavior.

### 🔜 Planned (Roadmap)

* **SSH readiness**

  * `sshd` active & listening on `:22`; host forward configured (`127.0.0.1:2222 → :22`).
* **Hardening guard-rails**

  * AppArmor enforcing; sysctls: `kptr_restrict=2`, `dmesg_restrict=1`, `ptrace_scope=2`, `unprivileged_bpf_disabled=1`, `unprivileged_userns_clone=0`; core-dump policy; `noexec` mount for staging.
* **Storage & snapshots**

  * Free space thresholds; `cleanbase` snapshot present; not accidentally running with `-snapshot`.
* **Tools baseline**

  * Presence/versions: compilers (gcc/clang/cmake/meson/ninja), debuggers (gdb/lldb), RE stack (rizin/Cutter/Ghidra + Java ≥17), YARA (+rules path), networking (tcpdump/tshark), perf/bpftrace, Python3/pip.

---

## Output

* Markdown report at: `~/lab_reports/lab-doctor-YYYYMMDD-HHMM.md` (created on each run).
* JSON report path is reserved for a future `--json` flag (`~/lab_reports/lab-doctor-YYYYMMDD-HHMM.json`).&#x20;

---

## Exit codes

Skeleton currently derives an exit code placeholder and will expand as sections are added:

* `0` — OK
* `10` — Identity/context (set)
* `20` — Hardening (planned)
* `30` — Tools (planned)
* `40+` — Multiple/other criticals (planned)&#x20;

---

## Tested on
Debian 12 (bookworm) inside QEMU with user-net (slirp)

---

## BONUS: Security model & good practices

### Threat model (quick view)

| Area        | Assumption                  | Goal                                                                       |
| ----------- | --------------------------- | -------------------------------------------------------------------------- |
| Isolation   | Guest must not impact host  | Run samples only inside a VM with minimal devices                          |
| Egress      | Precise control of outbound | LAB mode = GitHub-only; NORMAL only when needed                            |
| Integrity   | Reproducible analysis       | Snapshots, noexec staging, deterministic tooling                           |
| Attribution | Don’t leak identity         | Prefer IPv4 slirp, optional proxy for browsing, no personal creds in guest |

### QEMU isolation checklist

| Item    | Recommended                                                          | Why                        |
| ------- | -------------------------------------------------------------------- | -------------------------- |
| Devices | `-nodefaults` + only what you need (`virtio-vga`, `e1000`, `tablet`) | Smaller attack surface     |
| Network | user-net (slirp) + host-only SSH forward (`127.0.0.1:2222→22`)       | NAT, no L2 exposure        |
| Display | SDL/VNC bound to `127.0.0.1`                                         | Avoid remote exposure      |
| Sharing | No 9p/virtiofs/USB passthrough                                       | Prevent host/guest bridges |
| Storage | qcow2 with snapshots                                                 | Easy rollback              |

### Guest hardening knobs

| Setting                            |                 Value | Why                    |
| ---------------------------------- | --------------------: | ---------------------- |
| AppArmor                           |             enforcing | Contain processes      |
| `kernel.kptr_restrict`             |                     2 | Hide kernel pointers   |
| `kernel.dmesg_restrict`            |                     1 | Limit dmesg            |
| `kernel.yama.ptrace_scope`         |                     2 | Restrict ptrace        |
| `kernel.unprivileged_bpf_disabled` |                     1 | Block unprivileged BPF |
| `kernel.unprivileged_userns_clone` |                     0 | Reduce namespace abuse |
| Core dumps                         |     disabled (policy) | Avoid sensitive dumps  |
| Transfer mount                     | `nodev,nosuid,noexec` | Safer staging          |

### Sample handling rules

1. Stage to a **noexec** path; never run from `$HOME` or `/tmp`.
2. Treat every file as hostile.
3. Use **throwaway snapshots** for detonation.
4. No host shares; transfer via `scp` or a **read-only ISO**.
5. Keep the host isolated from the sample (no USB passthrough; no clipboard bridges).
6. Log hashes, paths, timestamps, and tool versions.

---

## Development notes

* The script uses strict mode: `set -Eeuo pipefail`.
* Results are stored in parallel arrays (`RESULT_SECTION`, `RESULT_STATUS`, `RESULT_DETAILS`, `RESULT_FIX`) and rendered to Markdown in `write_report_md`. Use `${#ARRAY[@]}` for lengths and guard optional values with `${var:-}`.&#x20;
* `main` currently runs `check_identity`, writes the report, prints a console summary, and exits. This scaffolding is ready for new checks to be added one function at a time.&#x20;

---

## License

MIT. See `LICENSE`.

---

## Credits
Built for repeatable reverse-engineering labs on Debian/QEMU. Contributions welcome!

