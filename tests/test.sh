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
echo "== --refresh-host-keys list membership =="
# REFRESH_HOST_KEYS/ACCEPT_KEYS are read by the sourced script's functions; export
# them so shellcheck doesn't flag SC2034 (it can't trace use across `source`).
export REFRESH_HOST_KEYS="a.example.com, b.example.com,c.example.com"
if in_refresh_list a.example.com; then ok "in_refresh_list matches first"; else no "should match a.example.com"; fi
if in_refresh_list b.example.com; then ok "in_refresh_list trims spaces"; else no "should match b.example.com (spaced)"; fi
if in_refresh_list z.example.com; then no "should NOT match z.example.com"; else ok "in_refresh_list rejects non-member"; fi
REFRESH_HOST_KEYS=""
if in_refresh_list a.example.com; then no "empty list should match nothing"; else ok "in_refresh_list empty -> no match"; fi

echo
echo "== --accept-key pin lookup =="
export ACCEPT_KEYS="a.example.com=SHA256:AAA,b.example.com=SHA256:BBB"
if [[ "$(pinned_fp_for a.example.com 2>/dev/null)" == "SHA256:AAA" ]]; then ok "pinned_fp_for returns a's fp"; else no "pinned_fp_for a.example.com"; fi
if [[ "$(pinned_fp_for b.example.com 2>/dev/null)" == "SHA256:BBB" ]]; then ok "pinned_fp_for returns b's fp"; else no "pinned_fp_for b.example.com"; fi
if pinned_fp_for c.example.com >/dev/null 2>&1; then no "c has no pin"; else ok "pinned_fp_for rejects unpinned host"; fi
ACCEPT_KEYS=""

echo
echo "== --only subset filter (prepare_server_list) =="
# Fake server list with three hosts; --only should narrow DEPLOY_LINES to the named
# subset while keeping each line's credentials (which come from the list, not the CLI).
onlyd="$(mktemp -d)"
cat > "${onlyd}/servers.txt" <<'EOF'
a.pbx.example.com,root,pw-a
b.pbx.example.com,root,pw-b
c.pbx.example.com,root,pw-c
EOF
# export so shellcheck doesn't flag SC2034 (it can't trace use across `source`)
export SERVERS_FILE="${onlyd}/servers.txt"
export PREPARE_QUIET=true
export ONLY="a.pbx.example.com,c.pbx.example.com"
prepare_server_list 1
if [[ "${#DEPLOY_LINES[@]}" -eq 2 ]]; then ok "--only narrowed 3 -> 2"; else no "--only expected 2 lines, got ${#DEPLOY_LINES[@]}"; fi
case " ${DEPLOY_LINES[*]} " in
    *a.pbx.example.com*) : ;;  *) no "--only dropped a.pbx.example.com" ;;
esac
case " ${DEPLOY_LINES[*]} " in
    *b.pbx.example.com*) no "--only should have dropped b.pbx.example.com" ;;  *) ok "--only excluded b" ;;
esac
case " ${DEPLOY_LINES[*]} " in
    *pw-a*) ok "--only kept credentials from the list" ;;  *) no "--only lost credentials" ;;
esac
ONLY=""
PREPARE_QUIET=false
SERVERS_FILE="servers.txt"
rm -rf "${onlyd}"

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
