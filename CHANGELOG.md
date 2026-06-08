# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — 2026-06-08

Initial release. A single-script bash tool for renewing wildcard SSL certificates
across one or many 3CX v20 PBX servers, run entirely from the local machine.

### Added

- **Commands:** `setup`, `csr`, `deploy`, `rollback`, `verify`, `version`, `help`
  (`-h`/`--help`, `-V`/`--version`).
- **CSR generation or import** — generate a new RSA 2048 key + CSR, or build a CSR
  from an existing key (`csr --key`).
- **Fleet deploy** over SSH with no software installed on the servers — the install
  logic is embedded and piped over SSH at run time.
- **Per-server auth**, key-based or password-based, via a `servers.txt` list in either
  CSV (`fqdn,username,password,port,keyfile`) or `key=value` format, plus an optional
  `.ssh_passwords` file. Password auth uses `sshpass -e` (password not exposed in the
  process list).
- **Automatic format normalization** of keys and certs to unencrypted PEM — accepts
  PEM (RSA/PKCS#8/EC, encrypted or not), DER, PKCS#12, and PKCS#7; tolerant of Windows
  CRLF line endings and surrounding text.
- **FQDN-match guard** — refuses to install a cert on a server whose hostname it does
  not cover (CN/SAN, wildcard-aware), with a `--force` override.
- **Chain-completeness warning** — flags an issued file that contains only the leaf
  cert (no intermediate) before deploying.
- **Idempotent deploys** — servers already serving the new cert (fingerprint match)
  are skipped.
- **Archive + `rollback`** — the replaced cert/key are archived (`.YYYY`), and
  `rollback` restores them and reloads nginx.
- **Server-list validation** — duplicate hostnames are de-duplicated and rows with no
  usable credentials are skipped, both reported in the summary.
- **Client-side `verify` health check** — checks each server's public endpoint on the
  configured ports (`VERIFY_PORTS`, default `443 5001`); flags certs that are expired,
  expiring within `VERIFY_EXPIRY_WARN_DAYS` (default 30), or don't match the hostname,
  and exits non-zero on any problem so it can run as a scheduled alert. Accommodates
  servers that present TLS on 443 or 5001.
- **Logging** — verbose detail to a per-run log file with a brief console summary for
  `deploy`/`rollback`; `--log FILE` and `--no-log` options.
- **Safety defaults** — `umask 077` so key material is owner-only from creation; a
  deny-by-default `.gitignore` that prevents committing `cert.conf`, `servers.txt`,
  `.ssh_passwords`, certs, logs, or ad-hoc server lists.
- **Tests + CI** — `tests/test.sh` unit-tests the wildcard matcher and cert-coverage
  logic; GitHub Actions runs shellcheck, a syntax check, and the tests on every push.

[Unreleased]: https://github.com/MHammett/3cx-cert-manager/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MHammett/3cx-cert-manager/releases/tag/v1.0.0
