# 3cx-cert-manager

A single-script bash tool for renewing wildcard SSL certificates across one or many
[3CX](https://www.3cx.com/) v20 PBX servers — run entirely from your local machine,
with nothing to install on the servers.

- Key-based **or** password-based SSH auth, configurable per server
- Accepts keys/certs in any common format (PEM, DER, PKCS#12, PKCS#7) and normalizes them
- **Won't install a cert on a server whose hostname it doesn't cover** (FQDN guard)
- Warns on an **incomplete chain** (leaf without intermediates) before installing
- Idempotent — re-running skips servers already on the new cert
- Archives the cert it replaces, with a one-command **rollback**
- **`verify`** doubles as a health check — flags expired / soon-to-expire / mismatched
  certs and exits non-zero, so it can drive a scheduled alert
- Verbose log file + a brief, readable console

---

## Requirements

Required on your **local machine** only. Nothing is installed on the 3CX servers.

| Tool | Purpose | Install |
|------|---------|---------|
| bash 4.4+ | Script runtime | Ships with Linux; `brew install bash` on macOS; Git for Windows / WSL include it |
| `openssl` | CSR generation, format conversion, validation | Ships with most distros; Git for Windows includes it |
| `ssh` / `scp` | Remote access (deploy/rollback) | Ships with most distros; OpenSSH for Windows |
| `sshpass` | Password-auth servers only | `apt install sshpass` / `brew install hudochenkov/sshpass/sshpass` / Windows: see below |

The script checks `openssl`, `ssh`, `scp`, and the bash version at startup. `sshpass`
is checked as a **preflight** at the start of `deploy` — but only if at least one
server uses password auth — so a missing dependency fails fast with a clear,
platform-specific message before any cert work begins.

### Windows: WSL is recommended (here's why)

The tool runs in **Git Bash** *or* **WSL**. For most Windows users WSL is the
smoother choice, for two concrete reasons:

1. **`sshpass` (password auth).** Git Bash ships no `sshpass`, and it isn't
   `apt`/`brew` installable there — you'd have to install MSYS2 separately and
   hand-copy the binary. In WSL it's one command: `sudo apt install sshpass`.
2. **A Linux-identical toolchain.** WSL gives you the same `bash`, `openssl`, and
   coreutils as the target servers, so behavior matches and there are fewer
   environment-specific edge cases.

**If you use SSH key auth only, Git Bash is perfectly fine** — the WSL
recommendation is really about password auth and toolchain parity. To use Git Bash
with password auth, install `sshpass` via MSYS2 and copy it in:

1. Install MSYS2: https://www.msys2.org
2. In the MSYS2 shell: `pacman -S sshpass`
3. Copy `C:\msys64\usr\bin\sshpass.exe` → `C:\Program Files\Git\usr\bin\`
   (Git Bash already ships the `msys-2.0.dll` it needs.)

**Setup (WSL):**
```bash
sudo apt install -y sshpass openssl openssh-client
cd /mnt/c/Users/<you>/path/to/3cx-cert-manager   # your files, seen from WSL
./3cx_cert_manager.sh ...
```

> One WSL trade-off: a Windows drive mount (`/mnt/c`) can't set Unix file
> permissions, so the tool prints a harmless `WARN: could not chmod …` and
> continues. Files there are protected by Windows ACLs instead. (Running from your
> WSL home directory avoids the warning but puts the files outside the Windows tree.)

---

## Quick start

```bash
# Get the code
git clone https://github.com/MHammett/3cx-cert-manager.git
cd 3cx-cert-manager
chmod +x 3cx_cert_manager.sh          # if the execute bit didn't survive cloning

# Scaffold config, then edit the two files it creates
./3cx_cert_manager.sh setup            # creates cert.conf, servers.txt, .ssh_passwords, dirs
# edit cert.conf   — your wildcard CN, org, and (if needed) remote paths
# edit servers.txt — your server list (CSV or key=value; see Configuration)
```

> On Windows, run these from WSL or Git Bash (see [Requirements](#requirements)).
> No execute bit? Just run it as `bash 3cx_cert_manager.sh …`.

**If you already have the key and the issued cert:**
```bash
./3cx_cert_manager.sh deploy /path/to/issued_chain.pem --key /path/to/private.key
./3cx_cert_manager.sh verify
```

**Starting from scratch:**
```bash
./3cx_cert_manager.sh csr              # generates key + CSR, prints the CSR
# submit the CSR to your CA (Thawte, DigiCert, Sectigo, …); receive issued_chain.pem
./3cx_cert_manager.sh deploy /path/to/issued_chain.pem
./3cx_cert_manager.sh verify
```

Key/cert can be in any supported format — they're normalized automatically. Re-running
`deploy` is always safe: servers already on the new cert are skipped.

---

## How it works

Everything runs on your **local machine** — no agent or daemon on the servers. The
tool is a single script; the per-server install logic is embedded and piped over SSH
at deploy time (nothing is written to the server except the cert and key, in `/tmp`,
which are cleaned up even if the connection drops).

```
Local machine
├── 3cx_cert_manager.sh         ← the only file you need
│   ├── setup     scaffold config files + certs/ and logs/ dirs
│   ├── csr       generate (or import) a key, emit a CSR
│   ├── deploy    normalize → FQDN-guard → upload → install → reload, per server
│   ├── rollback  restore the cert+key that deploy archived
│   └── verify    client-side TLS check against each server's public endpoint
├── certs/                      ← gitignored: your key, CSR, normalized temp files
└── logs/                       ← gitignored: full per-run logs

Remote 3CX server (/var/lib/3cxpbx/Bin/nginx/conf/Instance1/)
    domain_cert_<fqdn>.pem        ← replaced by deploy
    domain_cert_<fqdn>.pem.YYYY   ← previous cert archived here (used by rollback)
    domain_key_<fqdn>.pem         ← replaced by deploy
    domain_key_<fqdn>.pem.YYYY    ← previous key archived here
```

**What `deploy` does:**

1. **Locally, once:** normalizes the key and cert to unencrypted PEM (any passphrase
   is entered once, not per server), confirms the key matches the cert, and warns if
   the chain looks incomplete (only a leaf, no intermediate).
2. **Validates the server list:** removes duplicate hostnames, and skips rows with no
   usable credentials — both with warnings, surfaced again in the final summary.
3. **Per server:**
   - **FQDN guard** — skips the server unless the cert actually covers its hostname
     (CN/SAN, wildcard-aware). Prevents installing, say, a `*.a.com` wildcard on a
     `host.b.com` box. Override with `--force`.
   - Uploads the key + cert to `/tmp`, then runs the install over SSH: it discovers
     the live cert/key by glob, **skips if the cert is already current** (fingerprint
     match), otherwise archives the old pair (`.YYYY`), installs the new one with the
     right owner/permissions, runs `nginx -t`, and reloads nginx.
   - Cleans up the `/tmp` files (via a trap, even on interruption).
4. **Summary:** per-server status (`INSTALLED` / `ALREADY CURRENT` / `SKIPPED (FQDN
   mismatch)` / `FAILED`, plus any `Skipped (incomplete)` for rows with no usable
   credentials), with a loud callout of anything that did **not** get the cert.
5. Runs `verify` automatically at the end.

---

## Configuration

`setup` creates these from the bundled templates; all are gitignored and must never
be committed.

### cert.conf

```bash
CERT_CN="*.pbx.example.com"     # wildcard the cert is for
CERT_O="Your Organization"
CERT_L="City"; CERT_ST="State"; CERT_C="US"
# remote paths, ownership, archive suffix, SSH defaults, VERIFY_PORTS — see the template
```

`VERIFY_PORTS` (default `443 5001`) is the set of ports `verify` checks — 443 (HTTPS)
and 5001 (the legacy 3CX management port, which can't be changed). A server passes if
its cert is confirmed on **at least one** of them. `VERIFY_EXPIRY_WARN_DAYS` (default
30) sets how soon counts as "expiring soon" for the `verify` health check.

### servers.txt

One server per line. Two formats, mixable in one file.

**CSV** — easy to export from a spreadsheet:
```csv
fqdn,username,password,port,keyfile
pbx1.example.com,root,SecretPassword,,
pbx2.example.com,root,AnotherPassword,22,
pbx3.example.com,root,,22,/home/admin/.ssh/id_ed25519
```
Columns after `password` are optional; blank = use the `cert.conf` default. A header
row is auto-detected and ignored. (Passwords containing commas aren't supported in CSV
— use key auth or `.ssh_passwords` for those.)

**key=value** — readable for mixed setups:
```
pbx4.example.com user=root port=22 key=/home/admin/.ssh/id_ed25519   # key auth
pbx5.example.com                                                     # password via .ssh_passwords
```

### .ssh_passwords (password auth, key=value format)

For key=value servers without a `key=`, put the password here (also gitignored):
```
pbx5.example.com=SecretPassword
```
A password given inline in the CSV takes precedence over this file for the same host.

> **Security:** password auth uses `sshpass -e`, which reads the password from an
> environment variable — it is **not** exposed in the process list. Even so, for
> production fleets SSH **key auth is recommended**; then no passwords are stored at all.

---

## Commands

### `setup`
```bash
./3cx_cert_manager.sh setup
```
Creates `certs/` and `logs/`, and scaffolds `cert.conf`, `servers.txt`, and
`.ssh_passwords` if absent. Never overwrites existing files. Idempotent.

### `csr`
```bash
./3cx_cert_manager.sh csr [--key FILE]
```
Generates a CSR in `certs/` and prints it for submission to your CA.
- Without `--key`: generates a new RSA 2048 key, then the CSR.
- With `--key FILE`: builds the CSR from an existing key (any supported format).

### `deploy`
```bash
./3cx_cert_manager.sh deploy <issued_chain.pem> [--key FILE] [--servers FILE] [--parallel] [--force]
```
Normalizes the key/cert, then rolls the cert out across the server list (see
[How it works](#how-it-works)). Skips servers whose FQDN the cert doesn't cover
(`--force` to override) and servers already on the new cert. Verbose detail goes to
the log; the console shows progress + a summary.

To retry only certain servers, point `--servers` at a file containing just those hosts.

### `rollback`
```bash
./3cx_cert_manager.sh rollback [--servers FILE]
```
Restores the cert+key that `deploy` archived (the `.YYYY` copies), reloads nginx, and
reports the restored expiry per server. Use when a deploy installed the wrong cert on
a server — e.g. one the wildcard didn't actually cover. Uses the `ARCHIVE_SUFFIX` from
`cert.conf` (defaults to the current year).

### `verify`
```bash
./3cx_cert_manager.sh verify [--servers FILE]
```
Connects **from this machine** to each server's public FQDN on each `VERIFY_PORTS`
port — the same vantage point as an external SSL checker, no SSH required. For each
port that answers it reports the cert's expiry and flags:

- **EXPIRED** — past its expiry date
- **EXPIRES SOON (<N days)** — within `VERIFY_EXPIRY_WARN_DAYS` (default 30)
- **NAME MISMATCH** — the served cert doesn't actually cover that hostname

A port that doesn't answer is "not serving" (a server may use only 443 or only 5001),
not a failure. `verify` **exits non-zero if any server has a problem** — not confirmed
on any port, expired, expiring soon, or name-mismatched — so you can run it on a
schedule (cron) as a fleet health check and get alerted before a cert lapses.

### `version` / `help`
```bash
./3cx_cert_manager.sh version      # or --version, -V
./3cx_cert_manager.sh help         # or --help, -h
```
`version` prints the tool version; `help` prints usage. Both exit without needing
any config.

---

## Options reference

| Flag | Applies to | Default | Description |
|------|-----------|---------|-------------|
| `--config FILE` | all | `cert.conf` | Config file path |
| `--servers FILE` | deploy, rollback, verify | `servers.txt` | Server list path |
| `--key FILE` | csr, deploy | `certs/wildcard.key` | Private key. csr: use instead of generating one. deploy: use instead of the managed key. |
| `--parallel` | deploy | off | Deploy concurrently. Output interleaves; **serial is recommended** (~6s/server). |
| `--force` | deploy | off | Install even if the cert doesn't cover the server's FQDN |
| `--log FILE` | all | `logs/<action>_<timestamp>.log` | Log file path |
| `--no-log` | all | off | Disable the log file |
| `--no-strict` | deploy, rollback, verify | off | Skip SSH host-key verification — not recommended |

---

## Logging

Every run is logged. For the verbose commands (`deploy`, `rollback`) the **log file
gets full detail** (every step, all SSH/nginx/openssl output) while the **console
shows only** progress (one line per server), the summary, and warnings/errors. The
concise commands (`setup`, `csr`, `verify`) print everything to the console and also
log it. Use `--no-log` to disable, or `--log FILE` to choose the path.

---

## Supported key and cert formats

Inputs are auto-detected and normalized to unencrypted PEM (3CX's nginx requires
unencrypted PEM). Windows CRLF line endings are handled automatically.

**Private keys:** PEM RSA, PEM PKCS#8, PEM EC (encrypted or not — passphrase prompted
once), DER, PKCS#12 (`.p12`/`.pfx`).

**Certs / chains:** PEM (single or full chain), DER, PKCS#7 (`.p7b`), PKCS#12.

---

## Security notes

- **Private key material is owner-only from creation** — the script sets `umask 077`,
  so keys, normalized temp files, and logs are never world-readable.
- **Passwords aren't exposed** — `sshpass -e` keeps them out of the process list.
- **`.gitignore` denies everything by default** and allow-lists only the publishable
  files, so `servers.txt`, `.ssh_passwords`, `cert.conf`, `certs/`, `logs/`, and
  ad-hoc server lists can't be committed by accident.
- Prefer **SSH key auth** for production fleets — then no passwords are stored at all.

---

## Troubleshooting

**`sshpass ... not installed` (preflight).** A server uses password auth but `sshpass`
is missing. Install it (`apt`/`dnf`/`brew install hudochenkov/sshpass/sshpass`; Windows
via MSYS2 — see Requirements) or switch that server to key auth.

**`No credentials for <host> — skipping`.** That server has no key, no inline password,
and no `.ssh_passwords` entry, so it's skipped (and listed in the summary). Add one of
the three, then re-run.

**`SKIPPED (FQDN mismatch)`.** The cert doesn't cover that server's hostname (CN/SAN,
wildcard-aware) — the guard refusing to install the wrong cert. Either that server
needs a different cert, or, if the client-facing name genuinely differs from the name
you connect by, re-run with `--force`.

**`Private key does not match the cert`.** The `--key` file and the cert weren't issued
together. Point `--key` at the key that produced this cert's CSR.

**`No domain_cert_*.pem found in <CERT_DIR>`.** `REMOTE_CERT_DIR` is wrong, or the box
isn't 3CX v20 / uses a non-standard path. SSH in and check
`ls /var/lib/3cxpbx/Bin/nginx/conf/Instance1/`, then adjust `cert.conf`.

**`nginx -t failed`.** The new cert/key was installed but nginx rejected it, so the
reload was skipped and the **previous cert is still live**. SSH in and run `nginx -t`
for the detail (common causes: wrong chain order, key/cert mismatch, truncated file).

**A server got the wrong cert.** Use `rollback` to restore the archived pair.

**`mapfile: command not found` (macOS).** macOS ships bash 3.2. `brew install bash` and
run via `/opt/homebrew/bin/bash 3cx_cert_manager.sh …`.

---

## Development

```bash
shellcheck 3cx_cert_manager.sh tests/test.sh   # lint
bash -n 3cx_cert_manager.sh                     # syntax check
bash tests/test.sh                              # unit + smoke tests
```

`tests/test.sh` sources the script (a `BASH_SOURCE == $0` guard keeps `main` from
running) and asserts the security-critical wildcard matcher and cert-coverage logic,
plus a `version` smoke test. The same three checks run in CI
(`.github/workflows/ci.yml`) on every push and pull request.

## Compatibility

**3CX:** v20 confirmed. v18/v19 likely (may need `REMOTE_CERT_DIR` adjusted). v16 and
older untested.

**Local machine:** Linux (bash 5.x), macOS (bash 5.x via Homebrew), Windows via WSL
(recommended) or Git Bash. Remote servers are Debian-based; the server-side logic uses
only standard bash, openssl, and nginx.

---

## License

[MIT](LICENSE)
