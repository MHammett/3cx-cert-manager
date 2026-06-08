#!/usr/bin/env bash
# Unit + smoke tests for 3cx-cert-manager.
#
# Sources the main script for its functions; the `BASH_SOURCE == $0` guard in the
# script stops main() from running, so we can exercise functions in isolation.
#
# Run:  bash tests/test.sh    (exit 0 = all passed)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/../3cx_cert_manager.sh"

# shellcheck source=/dev/null
source "${SCRIPT}"
set +e   # the script enables `set -e`; tests probe failure returns, so disable it

pass=0 fail=0
ok() { printf 'ok   - %s\n' "$1"; pass=$((pass + 1)); }
no() { printf 'FAIL - %s\n' "$1"; fail=$((fail + 1)); }

assert_match()   { if _host_matches_name "$1" "$2"; then ok "match:    $1 ~ $2"; else no "expected match:    $1 ~ $2"; fi; }
assert_nomatch() { if _host_matches_name "$1" "$2"; then no "expected NO match: $1 ~ $2"; else ok "no-match: $1 !~ $2"; fi; }

echo "== _host_matches_name (FQDN guard / wildcard logic) =="
assert_match    pbx.example.com        pbx.example.com         # exact
assert_match    host.pbx.example.com   '*.pbx.example.com'     # wildcard, one label
assert_nomatch  pbx.example.com        '*.pbx.example.com'     # wildcard != bare apex
assert_nomatch  a.b.pbx.example.com    '*.pbx.example.com'     # wildcard is one label only
assert_nomatch  host.other.com         '*.pbx.example.com'     # different domain
assert_nomatch  host                   '*.pbx.example.com'     # host with no dot
assert_nomatch  example.com            pbx.example.com         # exact mismatch

echo
echo "== cert_covers_host (end-to-end with a generated cert) =="
tmpd="$(mktemp -d)"
if openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${tmpd}/k.pem" -out "${tmpd}/c.pem" -days 1 \
        -subj "/CN=*.pbx.example.com" \
        -addext "subjectAltName=DNS:*.pbx.example.com,DNS:pbx.example.com" >/dev/null 2>&1; then
    if cert_covers_host "${tmpd}/c.pem" host.pbx.example.com; then ok "cert covers host.pbx.example.com"; else no "cert should cover host.pbx.example.com"; fi
    if cert_covers_host "${tmpd}/c.pem" other.example.org;   then no "cert should NOT cover other.example.org"; else ok "cert does not cover other.example.org"; fi
else
    no "could not generate test cert (openssl -addext unsupported?)"
fi
rm -rf "${tmpd}"

echo
echo "== smoke: version command =="
ver="$(bash "${SCRIPT}" version)"
case "${ver}" in
    "3cx-cert-manager "*) ok "version prints: ${ver}" ;;
    *)                    no "unexpected version output: ${ver}" ;;
esac

echo
echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
