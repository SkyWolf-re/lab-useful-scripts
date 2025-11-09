# lab-doctor

*Pre-flight checks for a reversing lab.*

---
## What it does

`lab-doctor` runs a set of safety and readiness checks before you touch a sample, then writes a timestamped report to `~/lab_reports/`. The current skeleton implements the **Identity & Context** check (VM detection + root warning) and a Markdown report writer; additional checks are planned (network/netmode, SSH, hardening, storage, tools).&#x20;

Repeatable analysis needs a clean, predictable lab. `lab-doctor` catches the easy-to-miss issues (lax sysctls, broken SSH, missing tools) *before* they waste time or create risk.

---

## Status

* **Version:** `0.0.4` (skeleton)&#x20;
* **Implemented today:**

  * Identity & Context (detect virtualization, warn on root)
  * SSH & SSHD configuration
  * Disk (HARDENING): Checks free space on /, $HOME, and /var/log
  * Report aggregator + Markdown report (`/var/log/lab-doctor/lab-doctor-YYYYMMDD-HHMM.md`)&#x20;

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

Launch the setup script for automatic reports:

```bash
sudo ./lab-doctor-setup.sh [optional path for reports dir - /var/log/lab-doctor/ by default]
```

---

## Usage

```bash
lab-doctor            # full run (skeleton today runs checks + writes report)
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

### ✅ Implemented: SSH

Checks that `sshd` is ready for remote dev and reasonably configured.

**Policy (what sets the status):**

- **PASS**
  - `sshd` is **active** and **listening** on the effective port (default `:22`);
  - config parses cleanly (`sshd -t`), and:
    - `Subsystem sftp` is present **exactly once**;
    - `AllowTcpForwarding yes`;
    - privilege separation dir `/run/sshd` exists;
    - loopback egress rule found in nftables (if readable with sudo).

- **WARN**
  - `Subsystem sftp` **missing or duplicate**.
  - `AllowTcpForwarding no` (VS Code Remote needs forwarding).
  - Priv-sep dir **missing** (suggest `RuntimeDirectory=sshd`).
  - nftables loopback egress rule **missing** (when `nft list ruleset` is readable).
    - If nft can’t be read without sudo: noted as `nft_lo_egress=unchecked(no_sudo)` (no status change).

- **FAIL**
  - Service **inactive** (`systemctl is-active ssh[ d ]` fails).
  - Not **listening** on the effective port (e.g., `listen=missing(:22)`).
  - Config **error** and daemon not active (e.g., `sshd -t` reports an error and service isn’t running).
  - **No host keys** present (`/etc/ssh/ssh_host_*key` missing).
    - Suggested fix: `sudo ssh-keygen -A && sudo systemctl restart ssh`.

**Notes the report may include (do not affect status):**
- `service=active`, `listen=:22`, `config=ok`.
- `sftp=ok`, `forwarding=yes`, `privsep=/run/sshd`, `nft_lo_egress=ok`.
- `nft_lo_egress=unchecked(no_sudo)` when nftables state can’t be read without sudo.
- Optional hint: `host_forward=127.0.0.1:xxxx->:22` if `LAB_EXPECTED_HOST_SSH` is set.

### ✅ Implemented: Disk (HARDENING)

Checks free space on key local mounts (`/`, `$HOME`, `/var/log`) without sudo, using a single `df` call.

**Policy:**
- **PASS** — all targets have **> 15%** free.
- **WARN** — any target has **≤ 15%** free.
- **FAIL** — any target has **≤ 5%** free.

Notes show only low-space mounts (e.g., `root=12%free(…); varlog=4%free(…)`).  
Thresholds can be tuned via env: `LAB_DISK_WARN_PCT` (default **15**), `LAB_DISK_FAIL_PCT` (default **5**).

### ✅ Implemented: Tools baseline 

Verifies presence/versions of:   
- Compilers (gcc/clang/cmake/meson/ninja)  
- Debuggers (gdb/lldb)  
- RE stack (rizin/Cutter/Ghidra + Java ≥ 17)  
- YARA (+rules path if set)  
- Networking (tcpdump/tshark)  
- perf/bpftrace  
- Python3/pip   

`--tools-only` runs only this check  

### 🔜 Planned (Roadmap)

* **Hardering guard-rails**

  * AppArmor enforcing; sysctls: `kptr_restrict=2`, `dmesg_restrict=1`, `ptrace_scope=2`, `unprivileged_bpf_disabled=1`, `unprivileged_userns_clone=0`; core-dump policy; `noexec` mount for staging.
* **Storage & snapshots**

  * Free space thresholds; `cleanbase` snapshot present; not accidentally running with `-snapshot`.

---

## Output

* Markdown report at: `[lab-doctor-dir]/lab-doctor-YYYYMMDD-HHMM.md` (created on each run).
* JSON report path is reserved for a future `--json` flag (`[lab-doctor-dir]lab-doctor-YYYYMMDD-HHMM.json`).&#x20;

---

## Exit codes

`lab-doctor` returns a **bitmask** exit code so multiple issues can be encoded at once:

| Bit | Value | Meaning                 |
|-----|------:|-------------------------|
| 0   |     1 | At least one **WARN**   |
| 1   |     2 | **IDENTITY** failed     |
| 2   |     4 | **SSH** failed          |
| 3   |     8 | **HARDENING** failed    |

- **0** -> all PASS/INFO  
- **>0** -> combine bits (e.g., `5` = `4+1` = SSH fail + warnings)

**Examples:** `0` OK - `1` warnings only - `2` IDENTITY fail - `4` SSH fail - `12` SSH+HARDENING fail.

**CI usage:** treat any code with bits **other than 1** as failure:  
- pass: `ec == 0`  
- warnings-only: `(ec & ~1) == 0 && (ec & 1)`  
- fail: `(ec & ~1) != 0`

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
* `main` currently runs `check_identity`, `check_ssh`, `check_disk`, writes the report, prints a console summary, and exits. This scaffolding is ready for new checks to be added one function at a time.&#x20;

---

## License

MIT. See `LICENSE`.

---

## Credits
Built for repeatable reverse-engineering labs on Debian/QEMU. Contributions welcome!  
