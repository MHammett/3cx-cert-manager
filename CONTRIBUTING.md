# Contributing

## Reporting bugs

Open a GitHub issue with:
- Your OS and bash version (`bash --version`)
- The command you ran (redact any hostnames or credentials)
- The full error output

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `shellcheck 3cx_cert_manager.sh` and `bash -n 3cx_cert_manager.sh` — both clean
4. Test against at least one real 3CX server if the change touches the embedded
   remote logic (`_remote_install_script` / `_remote_rollback_script`)
5. Open a pull request with a clear description of what changed and why

## Development setup

No build step required. The scripts are plain bash.

```bash
git clone https://github.com/MHammett/3cx-cert-manager.git
cd 3cx-cert-manager
cp cert.conf.example cert.conf
cp servers.example.txt servers.txt
```

## Testing locally

Run the lint + test battery (the same checks CI runs):
```bash
shellcheck 3cx_cert_manager.sh tests/test.sh
bash -n 3cx_cert_manager.sh
bash tests/test.sh
```
`tests/test.sh` sources the script (the `BASH_SOURCE == $0` guard keeps `main` from
running) and unit-tests the wildcard matcher (`_host_matches_name`) and
`cert_covers_host`, plus a `version` smoke test. Add assertions there when you touch
that logic.

Test CSR generation without a server:
```bash
./3cx_cert_manager.sh csr
# Should produce certs/wildcard.key and certs/wildcard.csr
```

The per-server logic that runs on the 3CX box is embedded in `3cx_cert_manager.sh`
as single-quoted heredocs — `_remote_install_script` (install) and
`_remote_rollback_script` (rollback) — piped over SSH at run time. There is no
separate installer file. Read those two functions in the source to review what runs
remotely; each is plain bash that takes its inputs via environment variables
(`CERT_DIR`, `CERT_OWNER`, `CERT_PERMS`, `ARCHIVE_SUFFIX`) and arguments, so you can
copy a function's body to a test server and run it directly with those vars set.

## Scope

This tool is intentionally narrow: it manages wildcard cert deployment to 3CX v20
servers. Changes that add support for other PBX systems, ACME/Let's Encrypt automation,
or unrelated infrastructure tooling are out of scope and should live in a separate project.

Changes we welcome:
- Support for additional key/cert formats
- Improved error messages and diagnostics
- Support for 3CX versions other than v20 (with documentation)
- Windows-native runner alternatives (PowerShell wrapper, etc.)
