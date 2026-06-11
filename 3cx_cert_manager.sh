#!/usr/bin/env bash
# 3cx_cert_manager.sh — Wildcard SSL cert orchestrator for 3CX PBX servers
#
# Generates or imports a CSR/key, then deploys the issued cert to any number of
# remote 3CX servers via SSH/SCP. Supports key-based and password auth,
# configurable per server.
#
# Key/cert formats accepted: PEM (RSA/PKCS#8/EC, encrypted or not), DER, PKCS#12
# All inputs are normalized to unencrypted PEM before deployment.
#
# Usage:
#   ./3cx_cert_manager.sh csr    [--config FILE] [--key FILE]
#   ./3cx_cert_manager.sh deploy <issued_chain.pem> [--config FILE] [--servers FILE] [--key FILE] [--parallel]
#   ./3cx_cert_manager.sh verify [--config FILE] [--servers FILE]
#
# First run:
#   cp cert.conf.example cert.conf   && edit cert.conf
#   cp servers.example.txt servers.txt && edit servers.txt
#
# Requirements: openssl, ssh, scp
# Password auth also requires: sshpass (apt/brew install sshpass)

set -euo pipefail

# This tool handles private key material. Default every file it creates
# (keys, normalized PEMs, temp files, logs) to owner-only from the moment of
# creation — no race window, and no reliance on a post-hoc chmod that fails on
# permission-less mounts like /mnt/c under WSL.
umask 077

VERSION="1.2.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- defaults (all overridable via cert.conf) --------------------------------
CERT_CN="*.pbx.example.com"
CERT_O="Your Organization"
CERT_L="City"
CERT_ST="State"
CERT_C="US"
CSR_FILENAME="wildcard.csr"
KEY_FILENAME="wildcard.key"
OUTPUT_DIR="${SCRIPT_DIR}/certs"

REMOTE_CERT_DIR="/var/lib/3cxpbx/Bin/nginx/conf/Instance1"
REMOTE_CERT_OWNER="phonesystem:phonesystem"
REMOTE_CERT_PERMS="640"
ARCHIVE_SUFFIX=".$(date +%Y)"

SSH_DEFAULT_USER="root"
SSH_DEFAULT_PORT="22"
SSH_DEFAULT_KEY=""
SSH_STRICT="accept-new"   # accept-new | yes | no
VERIFY_PORTS="443 5001"   # space-separated; 443=HTTPS, 5001=legacy 3CX management port

CONFIG_FILE="${SCRIPT_DIR}/cert.conf"
SERVERS_FILE="${SCRIPT_DIR}/servers.txt"
PASSWORDS_FILE="${SCRIPT_DIR}/.ssh_passwords"
LOG_DIR="${SCRIPT_DIR}/logs"
PARALLEL=false
FORCE=false   # --force: install even if the cert doesn't cover the server's FQDN
KEY_FILE=""   # explicit key path; defaults to OUTPUT_DIR/KEY_FILENAME after config loads
LOG_FILE=""   # auto-generated under LOG_DIR if not set; "none" to disable
ONLY=""               # --only: comma-separated hostnames; restrict the run to this subset of the server list
REFRESH_HOST_KEYS=""  # --refresh-host-keys: comma-separated hosts whose changed SSH key to relearn
ACCEPT_KEYS=""        # --accept-key host=SHA256:..  (comma-separated) — relearn only if live key matches
CONSOLE_FD=1  # 1 normally; becomes 3 (saved console) when full output is redirected to a log
PREPARE_QUIET=false  # when true, prepare_server_list suppresses its dup/incomplete warnings

# ---- helpers -----------------------------------------------------------------
# con() prints the brief console view. When output is redirected to a log
# (deploy/rollback), the bulk of stdout goes only to the log; con() additionally
# echoes the line to the saved console (fd 3) so progress + summaries stay visible.
con()  { printf '%s\n' "$*"; [[ "${CONSOLE_FD}" == "3" ]] && printf '%s\n' "$*" >&3; return 0; }
die()  { echo "ERROR: $*" >&2; [[ "${CONSOLE_FD}" == "3" ]] && echo "ERROR: $*" >&3; exit 1; }
warn() { echo "WARN:  $*" >&2; [[ "${CONSOLE_FD}" == "3" ]] && echo "WARN:  $*" >&3; return 0; }
step() { echo; echo "==> $*"; }

# Defensive chmod fallback. Primary protection is the global `umask 077` above,
# which creates files owner-only from the start. This only enforces perms after
# the fact where that's warranted, and warns rather than aborting on
# permission-less mounts (e.g. Windows /mnt/c under WSL).
safe_chmod() {
    chmod "$@" 2>/dev/null \
        || warn "could not chmod ($*) — continuing (expected on /mnt/c under WSL)."
}

# Detect the OS family once, for tailored install instructions.
OS_FAMILY="unknown"
detect_os() {
    case "$(uname -s 2>/dev/null)" in
        Linux*)
            if   [[ -f /etc/debian_version ]]; then OS_FAMILY="debian"
            elif [[ -f /etc/redhat-release ]]; then OS_FAMILY="rhel"
            else OS_FAMILY="linux"; fi ;;
        Darwin*)              OS_FAMILY="macos" ;;
        MINGW*|MSYS*|CYGWIN*) OS_FAMILY="windows" ;;
    esac
}

# Print platform-specific install guidance for a given tool, indented.
install_hint() {
    case "$1" in
        bash)
            echo "  macOS:         brew install bash  (then run with /opt/homebrew/bin/bash)" ;;
        openssl)
            case "${OS_FAMILY}" in
                debian)  echo "  sudo apt install openssl" ;;
                rhel)    echo "  sudo dnf install openssl" ;;
                macos)   echo "  brew install openssl" ;;
                windows) echo "  Ships with Git for Windows — reinstall Git if missing." ;;
                *)       echo "  Install openssl via your package manager." ;;
            esac ;;
        ssh|scp)
            case "${OS_FAMILY}" in
                debian)  echo "  sudo apt install openssh-client" ;;
                rhel)    echo "  sudo dnf install openssh-clients" ;;
                macos)   echo "  Ships with macOS; otherwise: brew install openssh" ;;
                windows) echo "  Settings → Apps → Optional features → OpenSSH Client" ;;
                *)       echo "  Install the OpenSSH client via your package manager." ;;
            esac ;;
        sshpass)
            case "${OS_FAMILY}" in
                debian)  echo "  sudo apt install sshpass" ;;
                rhel)    echo "  sudo dnf install sshpass" ;;
                macos)   echo "  brew install hudochenkov/sshpass/sshpass" ;;
                windows)
                    echo "  Git Bash has no sshpass. Install via MSYS2, then copy the binary:"
                    echo "    1. Install MSYS2:        https://www.msys2.org"
                    echo "    2. In the MSYS2 shell:   pacman -S sshpass"
                    printf '    3. Copy the binary:      %s\n' 'C:\msys64\usr\bin\sshpass.exe'
                    printf '                          -> %s\n' 'C:\Program Files\Git\usr\bin'
                    echo "  Or switch to SSH key auth (add  key=/path/to/key  in servers.txt)." ;;
                *)       echo "  Install sshpass via your package manager, or use SSH key auth." ;;
            esac ;;
    esac
}

# Always-required tools, checked at startup.
check_deps() {
    detect_os
    local fail=0

    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        echo "ERROR: bash 4.4 or newer required (running ${BASH_VERSION})" >&2
        install_hint bash >&2
        fail=1
    fi

    local tool
    for tool in openssl ssh scp; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "ERROR: required tool not found: ${tool}" >&2
            install_hint "${tool}" >&2
            fail=1
        fi
    done

    (( fail == 0 )) || exit 1
}

# sshpass is only required when at least one server uses password auth.
# Called as a preflight from deploy/verify so it fails fast — before any
# normalization, uploads, or connections — rather than mid-run.
require_sshpass_if_needed() {
    local -a lines
    mapfile -t lines < <(read_servers)

    local needs_pw=0 pw_host=""
    local line
    for line in "${lines[@]}"; do
        parse_server_line "${line}"
        if [[ -z "${_KEY}" ]]; then
            needs_pw=1
            pw_host="${_HOST}"
            break
        fi
    done

    if (( needs_pw )) && ! command -v sshpass >/dev/null 2>&1; then
        echo "ERROR: '${pw_host}' (and possibly others) use password auth, but sshpass is not installed." >&2
        echo "       sshpass is required to supply SSH passwords non-interactively." >&2
        install_hint sshpass >&2
        exit 1
    fi
}

load_config() {
    [[ -f "${CONFIG_FILE}" ]] \
        || die "Config not found: ${CONFIG_FILE}
  Run: ./3cx_cert_manager.sh setup"
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
}

# Validate and de-duplicate the server list before any server is touched.
#   - Drops duplicate hostnames (keeps the first occurrence, warns).
#   - Skips rows with no hostname.
#   - With arg "1" (deploy), also skips rows with no usable credentials.
# Incomplete rows are warned about and SKIPPED (the run proceeds with the good
# servers); they are recorded in the global SKIPPED_INCOMPLETE so the caller can
# surface them in the final summary — a skipped server got no cert, which must
# not be silent. Populates the global array DEPLOY_LINES with the usable list.
prepare_server_list() {
    local require_creds="${1:-0}"
    local -a raw
    mapfile -t raw < <(read_servers)

    DEPLOY_LINES=()
    SKIPPED_INCOMPLETE=()
    local -A seen=()
    local -a dups=()
    local line

    for line in "${raw[@]}"; do
        parse_server_line "${line}"

        if [[ -z "${_HOST}" ]]; then
            SKIPPED_INCOMPLETE+=("(no hostname) -> ${line}")
            continue
        fi
        if [[ -n "${seen[${_HOST}]:-}" ]]; then
            dups+=("${_HOST}")
            continue
        fi
        if [[ "${require_creds}" == "1" ]] \
           && [[ -z "${_KEY}" && -z "${_PASSWORD}" ]] \
           && ! get_server_password "${_HOST}" >/dev/null 2>&1; then
            SKIPPED_INCOMPLETE+=("${_HOST} (no key, no password, no .ssh_passwords entry)")
            continue
        fi

        seen["${_HOST}"]=1
        DEPLOY_LINES+=("${line}")
    done

    # --only: restrict to the named subset of the list (credentials still come from
    # the server list, so nothing sensitive is typed on the command line). Hosts named
    # in --only but absent from the list are warned about, not silently ignored.
    if [[ -n "${ONLY}" ]]; then
        local -a want_arr filtered=()
        local -A want=() matched=()
        IFS=',' read -ra want_arr <<< "${ONLY}"
        local w
        for w in "${want_arr[@]}"; do
            w="$(_trim "${w}")"
            [[ -n "${w}" ]] && want["${w}"]=1
        done
        for line in "${DEPLOY_LINES[@]}"; do
            parse_server_line "${line}"
            if [[ -n "${want[${_HOST}]:-}" ]]; then
                filtered+=("${line}")
                matched["${_HOST}"]=1
            fi
        done
        if [[ "${PREPARE_QUIET}" != "true" ]]; then
            local k
            for k in "${!want[@]}"; do
                [[ -z "${matched[${k}]:-}" ]] && warn "--only host not found in ${SERVERS_FILE} (ignored): ${k}"
            done
        fi
        DEPLOY_LINES=("${filtered[@]}")
        (( ${#DEPLOY_LINES[@]} > 0 )) || die "None of the --only hosts matched an entry in ${SERVERS_FILE}."
    fi

    if [[ "${PREPARE_QUIET}" != "true" ]]; then
        if (( ${#dups[@]} > 0 )); then
            warn "Skipping ${#dups[@]} duplicate server entr(ies), keeping first occurrence:"
            local d
            for d in "${dups[@]}"; do echo "         - ${d}" >&2; done
        fi

        if (( ${#SKIPPED_INCOMPLETE[@]} > 0 )); then
            warn "Skipping ${#SKIPPED_INCOMPLETE[@]} server(s) with incomplete config — they will NOT get the cert:"
            local b
            for b in "${SKIPPED_INCOMPLETE[@]}"; do echo "         - ${b}" >&2; done
        fi
    fi

    (( ${#DEPLOY_LINES[@]} > 0 )) || die "No usable servers found in ${SERVERS_FILE}."
}

# Strip leading/trailing whitespace (used when parsing CSV fields)
_trim() { local s="${1}"; s="${s#"${s%%[! ]*}"}"; s="${s%"${s##*[! ]}"}"; printf '%s' "${s}"; }

# Look up password for a host from .ssh_passwords
# Format: hostname=password  (one per line, # comments supported)
# Exact-match the hostname (awk $1==h), not a regex — an FQDN's dots would
# otherwise match any char, and this also tolerates '=' inside the password.
get_server_password() {
    local host="$1"
    [[ -f "${PASSWORDS_FILE}" ]] || return 1
    local pw
    pw=$(awk -F= -v h="${host}" \
        '$1==h { sub(/^[^=]*=/, ""); print; found=1; exit } END { exit !found }' \
        "${PASSWORDS_FILE}" 2>/dev/null) || return 1
    [[ -n "${pw}" ]] && printf '%s' "${pw}" || return 1
}

# Populate global arrays SSH_CMD and SCP_CMD for a given server, plus the global
# _SSH_PW (empty for key auth). Password auth uses `sshpass -e`, which reads the
# password from the SSHPASS environment variable at call time — unlike `-p`, the
# password never appears in the process list. Callers prefix invocations with
# `SSHPASS="${_SSH_PW}"`. Uses _PASSWORD (from parse_server_line) before falling
# back to .ssh_passwords.
make_ssh_cmds() {
    local host="$1" user="$2" port="$3" keyfile="$4"
    # Arrays (not space-strings) so multi-token options expand cleanly and don't
    # rely on word-splitting — robust and shellcheck-clean.
    local -a strict=(-o "StrictHostKeyChecking=${SSH_STRICT}")
    local -a common=(-o ConnectTimeout=15 -o ServerAliveInterval=30)
    _SSH_PW=""

    if [[ -n "${keyfile}" ]]; then
        SSH_CMD=(ssh -i "${keyfile}" -o BatchMode=yes "${strict[@]}" "${common[@]}" -p "${port}" "${user}@${host}")
        SCP_CMD=(scp -i "${keyfile}" -o BatchMode=yes "${strict[@]}" -P "${port}")
    else
        local pw="${_PASSWORD:-}"
        if [[ -z "${pw}" ]]; then
            pw=$(get_server_password "${host}") \
                || { warn "No credentials for ${host} — skipping."; return 1; }
        fi
        if ! command -v sshpass >/dev/null 2>&1; then
            warn "sshpass not installed; cannot use password auth for ${host} — skipping."
            return 1
        fi
        _SSH_PW="${pw}"
        SSH_CMD=(sshpass -e ssh "${strict[@]}" "${common[@]}" -p "${port}" "${user}@${host}")
        SCP_CMD=(sshpass -e scp "${strict[@]}" -P "${port}")
    fi
    return 0
}

# ---- SSH host-key handling ---------------------------------------------------
# Live SHA256 fingerprint(s) the host currently presents (via ssh-keyscan).
# Echoes one fingerprint per line; empty + non-zero if the host is unreachable.
hostkey_live_fps() {
    local host="$1" port="${2:-22}" out
    out=$(ssh-keyscan -T 7 -p "${port}" "${host}" 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
    [[ -n "${out}" ]] || return 1
    printf '%s\n' "${out}" | sort -u
}

# Stored SHA256 fingerprint(s) for the host from known_hosts (empty if none).
hostkey_stored_fps() {
    ssh-keygen -l -F "$1" 2>/dev/null | awk '{print $2}' | grep '^SHA256:' | sort -u
}

# Classify a host's key. Sets globals: _HK_STATE (ok|new|changed|unreachable),
# _HK_OLD (stored fp summary), _HK_NEW (live fp summary).
hostkey_status() {
    local host="$1" port="${2:-22}" live stored
    _HK_STATE="" _HK_OLD="" _HK_NEW=""
    live=$(hostkey_live_fps "${host}" "${port}") || { _HK_STATE="unreachable"; return 0; }
    _HK_NEW=$(paste -sd' ' <<<"${live}")
    stored=$(hostkey_stored_fps "${host}")
    if [[ -z "${stored}" ]]; then _HK_STATE="new"; return 0; fi
    _HK_OLD=$(paste -sd' ' <<<"${stored}")
    # Changed only if NONE of the live fps match a stored fp.
    if comm -12 <(printf '%s\n' "${live}") <(printf '%s\n' "${stored}") | grep -q .; then
        _HK_STATE="ok"
    else
        _HK_STATE="changed"
    fi
    return 0
}

# True if $1 (host) appears in the comma-separated --refresh-host-keys list.
in_refresh_list() {
    local host="$1" item; local -a parts
    [[ -z "${REFRESH_HOST_KEYS}" ]] && return 1
    IFS=',' read -ra parts <<<"${REFRESH_HOST_KEYS}"
    for item in "${parts[@]}"; do [[ "$(_trim "${item}")" == "${host}" ]] && return 0; done
    return 1
}

# If an --accept-key pin exists for $1 (host), echo its expected SHA256 fp; else nothing.
pinned_fp_for() {
    local host="$1" pair k v; local -a parts
    [[ -z "${ACCEPT_KEYS}" ]] && return 1
    IFS=',' read -ra parts <<<"${ACCEPT_KEYS}"
    for pair in "${parts[@]}"; do
        k=$(_trim "${pair%%=*}"); v=$(_trim "${pair#*=}")
        [[ "${k}" == "${host}" ]] && { printf '%s' "${v}"; return 0; }
    done
    return 1
}

# Append a host-key change event to the audit log (best-effort).
audit_hostkey() {  # host  old_fp  new_fp  action
    local f="${LOG_DIR}/host-key-changes.log"
    mkdir -p "${LOG_DIR}" 2>/dev/null || return 0
    printf '%s  user=%s  host=%s  action=%s  old=%s  new=%s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')" "${USER:-unknown}" "$1" "$4" "${2:-none}" "${3:-none}" \
        >> "${f}" 2>/dev/null || true
}

# Remove a host's stale known_hosts entry so accept-new re-learns the current key.
relearn_hostkey() { ssh-keygen -R "$1" >/dev/null 2>&1 || true; }

# Parse one server entry into globals: _HOST _USER _PORT _KEY _PASSWORD
# Accepts two formats:
#   CSV:       fqdn,username,password[,port[,keyfile]]
#   Key=value: hostname [user=x] [port=x] [key=x]   (password via .ssh_passwords)
parse_server_line() {
    _HOST="" _USER="${SSH_DEFAULT_USER}" _PORT="${SSH_DEFAULT_PORT}"
    _KEY="${SSH_DEFAULT_KEY}" _PASSWORD=""

    if [[ "$1" == *,* ]]; then
        # CSV format
        local f1 f2 f3 f4 f5
        IFS=',' read -r f1 f2 f3 f4 f5 <<< "$1"
        _HOST=$(_trim "${f1}")
        [[ -n "$(_trim "${f2}")" ]] && _USER=$(_trim "${f2}")
        _PASSWORD=$(_trim "${f3}")
        [[ -n "$(_trim "${f4}")" ]] && _PORT=$(_trim "${f4}")
        [[ -n "$(_trim "${f5}")" ]] && _KEY=$(_trim "${f5}")
    else
        # Key=value format
        _HOST=$(awk '{print $1}' <<< "$1")
        local field
        while IFS= read -r field; do
            [[ -z "${field}" ]] && continue
            case "${field}" in
                user=*) _USER="${field#user=}" ;;
                port=*) _PORT="${field#port=}" ;;
                key=*)  _KEY="${field#key=}"   ;;
            esac
        done < <(awk '{for(i=2;i<=NF;i++) print $i}' <<< "$1")
    fi
    return 0   # never let a falsy last command trip `set -e` in callers
}

read_servers() {
    [[ -f "${SERVERS_FILE}" ]] \
        || die "Servers file not found: ${SERVERS_FILE}
  Run: cp servers.example.txt servers.txt  and add your hosts."
    grep -v '^\s*#' "${SERVERS_FILE}" \
        | grep -v '^\s*$' \
        | grep -iv '^\s*\(fqdn\|hostname\|host\)[,[:space:]]' \
        | tr -d '\r'
}

# ---- format normalization ----------------------------------------------------
# Convert any supported private key format to unencrypted PEM.
# Supported inputs: RSA PEM (encrypted or not), PKCS#8 PEM (encrypted or not),
#                   EC PEM, DER, PKCS#12 (.p12/.pfx)
normalize_key() {
    local infile="$1" outfile="$2"

    # Detect by scanning for PEM markers anywhere in the file. This tolerates
    # Windows CRLF line endings, a leading BOM, and any preamble text — none of
    # which an exact first-line match would survive. Check the ENCRYPTED PKCS#8
    # marker before the plain one (the strings differ, but order keeps it clear).
    if grep -q -- "-----BEGIN RSA PRIVATE KEY-----" "${infile}" 2>/dev/null; then
        if grep -q "ENCRYPTED" "${infile}"; then
            echo "    RSA key is passphrase-protected. Enter passphrase:"
            openssl rsa -in "${infile}" -out "${outfile}" \
                || die "Failed to decrypt RSA key."
        else
            tr -d '\r' < "${infile}" > "${outfile}"
        fi
    elif grep -q -- "-----BEGIN ENCRYPTED PRIVATE KEY-----" "${infile}" 2>/dev/null; then
        echo "    PKCS#8 key is passphrase-protected. Enter passphrase:"
        openssl pkcs8 -nocrypt -in "${infile}" -out "${outfile}" \
            || die "Failed to decrypt PKCS#8 key."
    elif grep -q -- "-----BEGIN PRIVATE KEY-----" "${infile}" 2>/dev/null; then
        tr -d '\r' < "${infile}" > "${outfile}"   # PKCS#8, nginx-ready
    elif grep -q -- "-----BEGIN EC PRIVATE KEY-----" "${infile}" 2>/dev/null; then
        if grep -q "ENCRYPTED" "${infile}"; then
            echo "    EC key is passphrase-protected. Enter passphrase:"
            openssl ec -in "${infile}" -out "${outfile}" \
                || die "Failed to decrypt EC key."
        else
            tr -d '\r' < "${infile}" > "${outfile}"
        fi
    elif openssl pkcs12 -nocerts -nodes -in "${infile}" -out "${outfile}" 2>/dev/null; then
        echo "    Extracted key from PKCS#12 (passphrase prompt above, if any)."
    elif openssl rsa -inform DER -in "${infile}" -out "${outfile}" 2>/dev/null; then
        echo "    Converted DER key to PEM."
    else
        die "Unrecognized key format: ${infile}
  Supported formats: PEM (RSA/PKCS#8/EC, encrypted or not), DER, PKCS#12 (.p12/.pfx)"
    fi

    # The global umask already creates this 600; this is a belt-and-suspenders
    # guard for the case where a key was copied in and its source perms leaked
    # through. Warns rather than fails on permission-less mounts.
    safe_chmod 600 "${outfile}"
    echo "    Key ready: ${outfile}"
}

# Convert any supported cert/chain format to PEM.
# Supported inputs: PEM (single cert or full chain), DER, PKCS#7 (.p7b), PKCS#12
normalize_cert() {
    local infile="$1" outfile="$2"

    # Detect by scanning for PEM markers anywhere in the file (CRLF/BOM/preamble
    # tolerant). A chain has several BEGIN CERTIFICATE blocks — keep them all.
    if grep -q -- "-----BEGIN CERTIFICATE-----" "${infile}" 2>/dev/null \
       || grep -q -- "-----BEGIN X509 CERTIFICATE-----" "${infile}" 2>/dev/null; then
        tr -d '\r' < "${infile}" > "${outfile}"   # strip CRLF, keep full chain
        openssl x509 -noout -in "${outfile}" >/dev/null 2>&1 \
            || die "File has a PEM certificate marker but failed to parse: ${infile}"
    elif grep -q -- "-----BEGIN PKCS7-----" "${infile}" 2>/dev/null; then
        echo "    Converting PKCS#7 bundle to PEM chain..."
        openssl pkcs7 -print_certs -in "${infile}" -out "${outfile}" \
            || die "Failed to convert PKCS#7 cert."
    elif openssl x509 -inform DER -in "${infile}" -out "${outfile}" 2>/dev/null; then
        echo "    Converted DER cert to PEM."
    elif openssl pkcs12 -nokeys -clcerts -in "${infile}" -out "${outfile}" 2>/dev/null; then
        echo "    Extracted leaf cert from PKCS#12."
        # Append intermediate/root certs from the same P12
        local chain_tmp="${outfile}.chain_tmp"
        if openssl pkcs12 -nokeys -cacerts -in "${infile}" \
                -out "${chain_tmp}" 2>/dev/null && [[ -s "${chain_tmp}" ]]; then
            cat "${chain_tmp}" >> "${outfile}"
        fi
        rm -f "${chain_tmp}"
    else
        die "Unrecognized cert format: ${infile}
  Supported formats: PEM, DER, PKCS#7 (.p7b), PKCS#12 (.p12/.pfx)"
    fi

    echo "    Cert ready: ${outfile}"
}

# Pure name matcher (no openssl) — does a cert name cover a host?
# RFC-6125 wildcard handling: `*.foo.com` matches exactly one label
# (`bar.foo.com`), not `foo.com` or `a.bar.foo.com`. Returns 0 on match.
# Kept dependency-free so it can be unit-tested directly (see tests/).
_host_matches_name() {
    local host="$1" name="$2" suffix
    [[ "${name}" == "${host}" ]] && return 0
    if [[ "${name}" == \*.* ]]; then
        suffix=".${name#\*.}"
        [[ "${host}" == *.* && ".${host#*.}" == "${suffix}" ]] && return 0
    fi
    return 1
}

# Extract every DNS name a cert presents — SAN dNSNames plus the CN.
_cert_names() {
    { openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -n 's/.*DNS:[[:space:]]*//p'
      openssl x509 -in "$1" -noout -subject 2>/dev/null \
        | grep -oE 'CN[[:space:]]*=[[:space:]]*[^,/]+' \
        | sed 's/CN[[:space:]]*=[[:space:]]*//'
    } | sort -u
}

# Does the cert (PEM file) present a name that covers the given host?
# Returns 0 if any SAN/CN name matches, 1 otherwise.
cert_covers_host() {
    local cert="$1" host="$2" name
    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        _host_matches_name "${host}" "${name}" && return 0
    done < <(_cert_names "${cert}")
    return 1
}

# ---- setup command -----------------------------------------------------------
cmd_setup() {
    local created=0

    _dir() {
        if [[ ! -d "$1" ]]; then
            mkdir -p "$1"
            printf "  %-12s %s/\n" "[created]" "$1"
            (( created++ )) || true
        else
            printf "  %-12s %s/\n" "[exists]" "$1"
        fi
    }

    _file() {
        local dest="$1" src="$2" note="${3:-}"
        if [[ ! -f "${dest}" ]]; then
            cp "${src}" "${dest}"
            printf "  %-12s %-45s %s\n" "[created]" "${dest}" "${note}"
            (( created++ )) || true
        else
            printf "  %-12s %s\n" "[exists]" "${dest}  (not overwritten)"
        fi
    }

    _template() {
        local dest="$1" note="$2"
        shift 2
        if [[ ! -f "${dest}" ]]; then
            printf '%s\n' "$@" > "${dest}"
            printf "  %-12s %-45s %s\n" "[created]" "${dest}" "${note}"
            (( created++ )) || true
        else
            printf "  %-12s %s\n" "[exists]" "${dest}  (not overwritten)"
        fi
    }

    echo "Setting up 3cx-cert-manager..."
    echo

    _dir "${OUTPUT_DIR}"
    _dir "${LOG_DIR}"
    _file "${CONFIG_FILE}"   "${SCRIPT_DIR}/cert.conf.example"   "<-- edit: domain, org, SSH defaults"
    _file "${SERVERS_FILE}"  "${SCRIPT_DIR}/servers.example.txt" "<-- edit: add your 3CX servers"
    _template "${PASSWORDS_FILE}" "<-- add passwords for password-auth servers (optional)" \
        "# .ssh_passwords — SSH passwords for servers without key auth" \
        "# Format: hostname=password  (one per line, # comments supported)" \
        "# This file is gitignored and should never be committed." \
        "#" \
        "# Example:" \
        "# pbx1.pbx.example.com=SecretPassword"

    echo
    if (( created > 0 )); then
        echo "Next steps:"
        echo "  1. Edit cert.conf   — set CERT_CN, CERT_O, CERT_L, CERT_ST, CERT_C"
        echo "  2. Edit servers.txt — add your 3CX servers (CSV or key=value format)"
        echo "  3. Add server passwords to .ssh_passwords if using password auth"
        echo
        echo "Then run:"
        echo "  ./3cx_cert_manager.sh csr                       # generate key + CSR"
        echo "  ./3cx_cert_manager.sh deploy <chain.pem>        # deploy issued cert"
        echo "  ./3cx_cert_manager.sh deploy <chain.pem> --key <key>  # existing key"
        echo "  ./3cx_cert_manager.sh verify                    # check cert expiry"
    else
        echo "Everything already in place — no changes made."
    fi
}

# ---- csr command -------------------------------------------------------------
cmd_csr() {
    mkdir -p "${OUTPUT_DIR}"

    local key_path="${OUTPUT_DIR}/${KEY_FILENAME}"
    local csr_path="${OUTPUT_DIR}/${CSR_FILENAME}"

    if [[ -n "${KEY_FILE}" ]]; then
        step "Normalizing provided key -> ${key_path}"
        normalize_key "${KEY_FILE}" "${key_path}"
    else
        step "Generating RSA 2048 private key"
        openssl genrsa -out "${key_path}" 2048   # created 600 via the global umask
        echo "    Saved: ${key_path}"
    fi

    step "Generating CSR"
    openssl req -new \
        -key  "${key_path}" \
        -out  "${csr_path}" \
        -subj "/C=${CERT_C}/ST=${CERT_ST}/L=${CERT_L}/O=${CERT_O}/CN=${CERT_CN}"
    echo "    Saved: ${csr_path}"

    step "CSR content — submit this to your CA:"
    echo "---"
    cat "${csr_path}"
    echo "---"
    echo
    echo "Once the CA issues the cert chain, run:"
    echo "  ./3cx_cert_manager.sh deploy /path/to/issued_chain.pem"
}

# ---- remote install script (piped over SSH — no file left on the server) -----
# Single-quoted heredoc: variables are NOT expanded here; they expand on the server.
_remote_install_script() {
    cat <<'REMOTE_EOF'
set -euo pipefail
ISSUED_CHAIN="${1:-}"
NEW_KEY="${2:-}"
[[ -n "${ISSUED_CHAIN}" ]] || { echo "ERROR: missing arg: issued_chain" >&2; exit 1; }
[[ -n "${NEW_KEY}" ]]      || { echo "ERROR: missing arg: key" >&2; exit 1; }
[[ -f "${ISSUED_CHAIN}" ]] || { echo "ERROR: not found: ${ISSUED_CHAIN}" >&2; exit 1; }
[[ -f "${NEW_KEY}" ]]      || { echo "ERROR: not found: ${NEW_KEY}" >&2; exit 1; }

CERT_DIR="${CERT_DIR:-/var/lib/3cxpbx/Bin/nginx/conf/Instance1}"
CERT_OWNER="${CERT_OWNER:-phonesystem:phonesystem}"
CERT_PERMS="${CERT_PERMS:-640}"
ARCHIVE_SUFFIX="${ARCHIVE_SUFFIX:-.bak}"

[[ -d "${CERT_DIR}" ]] || { echo "ERROR: cert dir not found: ${CERT_DIR}" >&2; exit 1; }

step() { echo "==> $*"; }

shopt -s nullglob
live_certs=("${CERT_DIR}"/domain_cert_*.pem)
live_keys=(  "${CERT_DIR}"/domain_key_*.pem)
shopt -u nullglob

[[ ${#live_certs[@]} -gt 0 ]] || { echo "ERROR: no domain_cert_*.pem in ${CERT_DIR}" >&2; exit 1; }
[[ ${#live_keys[@]} -gt 0 ]]  || { echo "ERROR: no domain_key_*.pem in ${CERT_DIR}" >&2; exit 1; }
[[ ${#live_certs[@]} -eq 1 ]] || echo "WARN: multiple domain_cert_*.pem found; using ${live_certs[0]}"

LIVE_CERT="${live_certs[0]}"
LIVE_KEY="${live_keys[0]}"
step "Live cert: ${LIVE_CERT}"
step "Live key:  ${LIVE_KEY}"

step "Validating cert"
openssl x509 -noout -subject -dates -in "${ISSUED_CHAIN}" \
    || { echo "ERROR: invalid cert PEM" >&2; exit 1; }

step "Checking key/cert match"
cert_pub=$(openssl x509 -noout -pubkey -in "${ISSUED_CHAIN}")
key_pub=$(openssl pkey -pubout -in "${NEW_KEY}" 2>/dev/null) \
    || { echo "ERROR: could not extract public key from ${NEW_KEY}" >&2; exit 1; }
[[ "${cert_pub}" == "${key_pub}" ]] \
    || { echo "ERROR: private key does not match cert" >&2; exit 1; }
echo "    Match confirmed."

step "Current cert"
existing_expiry=$(openssl x509 -noout -enddate -in "${LIVE_CERT}" 2>/dev/null | cut -d= -f2- || echo "unknown")
echo "    Expires: ${existing_expiry}"

step "Checking if cert is already current"
existing_fp=$(openssl x509 -noout -fingerprint -sha256 -in "${LIVE_CERT}" 2>/dev/null)
new_fp=$(openssl x509 -noout -fingerprint -sha256 -in "${ISSUED_CHAIN}" 2>/dev/null)
if [[ -n "${existing_fp}" && "${existing_fp}" == "${new_fp}" ]]; then
    echo "    Fingerprints match — cert already current on $(hostname), skipping."
    exit 2
fi
echo "    Fingerprints differ — proceeding with install."

step "Archiving cert -> ${LIVE_CERT}${ARCHIVE_SUFFIX}"
cp -p "${LIVE_CERT}" "${LIVE_CERT}${ARCHIVE_SUFFIX}"
step "Archiving key  -> ${LIVE_KEY}${ARCHIVE_SUFFIX}"
cp -p "${LIVE_KEY}" "${LIVE_KEY}${ARCHIVE_SUFFIX}"

step "Installing cert"
cp "${ISSUED_CHAIN}" "${LIVE_CERT}"
step "Installing key"
cp "${NEW_KEY}" "${LIVE_KEY}"

step "Setting ownership (${CERT_OWNER}) and permissions (${CERT_PERMS})"
chown "${CERT_OWNER}" "${LIVE_CERT}" "${LIVE_KEY}"
chmod "${CERT_PERMS}" "${LIVE_CERT}" "${LIVE_KEY}"

step "Testing nginx config"
nginx -t || { echo "ERROR: nginx -t failed — cert installed but NOT reloaded" >&2; exit 1; }

step "Reloading nginx"
nginx -s reload
sleep 2
echo "    Reloaded. (Live-cert confirmation runs client-side after deploy.)"

echo
echo "Done on $(hostname). Archived: ${LIVE_CERT}${ARCHIVE_SUFFIX}"
REMOTE_EOF
}

# ---- deploy helpers ----------------------------------------------------------
deploy_one() {
    local line="$1" issued_chain="$2"
    parse_server_line "${line}"
    local tag="[${_HOST}]"
    make_ssh_cmds "${_HOST}" "${_USER}" "${_PORT}" "${_KEY}" \
        || { con "${tag} FAILED: no usable credentials"; return 1; }

    # Guard: don't install a cert that doesn't cover this server's FQDN. This is
    # checked locally (no upload wasted) against the name we connect by. --force
    # overrides for the rare case where the client-facing name differs from it.
    if ! cert_covers_host "${issued_chain}" "${_HOST}"; then
        if [[ "${FORCE}" == "true" ]]; then
            con "${tag} WARN: cert does not cover ${_HOST} — installing anyway (--force)."
        else
            con "${tag} SKIPPED: cert does not cover ${_HOST} (use --force to override)."
            return 3
        fi
    fi

    # Host-key preflight: detect a CHANGED SSH host key (server rebuilt, or worse)
    # and handle it per policy. Default = refuse and report; relearn only when the
    # operator opted in (pin, explicit list, or interactive confirm).
    if in_refresh_list "${_HOST}"; then
        # Explicit operator opt-in: re-learn unconditionally, BEFORE connecting.
        # Deterministic — does not depend on ssh-keyscan detection (which can be
        # flaky). ssh-keygen -R drops the stale entry; accept-new re-adds the
        # current key on the upload below. Harmless if the key hadn't changed.
        con "${tag} re-learning SSH host key (--refresh-host-keys)."
        audit_hostkey "${_HOST}" "(per --refresh-host-keys)" "(re-learned on connect)" "relearn:list"
        relearn_hostkey "${_HOST}"
    else
        # Otherwise detect a CHANGED key and handle per policy (pin / prompt / block).
        hostkey_status "${_HOST}" "${_PORT}"
        if [[ "${_HK_STATE}" == "changed" ]]; then
            local pin=""
            if pin=$(pinned_fp_for "${_HOST}"); then
                if grep -qF "${pin}" <<<"${_HK_NEW}"; then
                    con "${tag} host key changed — re-learning (--accept-key pin matched)."
                    audit_hostkey "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" "relearn:pin"
                    relearn_hostkey "${_HOST}"
                else
                    con "${tag} SKIPPED: host key changed and does NOT match --accept-key pin (now ${_HK_NEW})"
                    audit_hostkey "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" "blocked:pin-mismatch"
                    return 4
                fi
            elif [[ "${PARALLEL}" != "true" ]] && { : >/dev/tty; } 2>/dev/null; then
                printf '\n[%s] SSH HOST KEY CHANGED\n  stored: %s\n  now:    %s\nRe-learn this host and continue? [y/N] ' \
                    "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" >/dev/tty
                local ans=""; read -r ans </dev/tty || true
                if [[ "${ans}" =~ ^[Yy] ]]; then
                    con "${tag} re-learning (operator confirmed)."
                    audit_hostkey "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" "relearn:interactive"
                    relearn_hostkey "${_HOST}"
                else
                    con "${tag} SKIPPED: SSH host key changed (declined)"
                    audit_hostkey "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" "blocked:declined"
                    return 4
                fi
            else
                con "${tag} SKIPPED: SSH host key changed (stored ${_HK_OLD} -> now ${_HK_NEW}); verify, then --refresh-host-keys"
                audit_hostkey "${_HOST}" "${_HK_OLD}" "${_HK_NEW}" "blocked"
                return 4
            fi
        fi
    fi

    local stamp="${BASHPID:-$$}"
    local tmp_cert="/tmp/3cx_chain_${stamp}.pem"
    local tmp_key="/tmp/3cx_key_${stamp}.pem"

    echo "${tag} Uploading cert..."
    SSHPASS="${_SSH_PW}" "${SCP_CMD[@]}" "${issued_chain}" "${_USER}@${_HOST}:${tmp_cert}" \
        || { echo "${tag} FAILED: scp cert"; return 1; }

    echo "${tag} Uploading key..."
    SSHPASS="${_SSH_PW}" "${SCP_CMD[@]}" "${KEY_FILE}" "${_USER}@${_HOST}:${tmp_key}" \
        || { echo "${tag} FAILED: scp key"; return 1; }

    echo "${tag} Installing..."
    # The remote `trap … EXIT` cleans up the uploaded key+cert even if the SSH
    # connection drops mid-install, so the private key is never left in /tmp.
    # The trap comes first (no env prefix); the CERT_* assignments stay on
    # `bash -s` so they're exported into the install script's environment.
    local install_rc=0
    { _remote_install_script | SSHPASS="${_SSH_PW}" "${SSH_CMD[@]}" \
        "trap \"rm -f '${tmp_cert}' '${tmp_key}'\" EXIT; \
         CERT_DIR='${REMOTE_CERT_DIR}' \
         CERT_OWNER='${REMOTE_CERT_OWNER}' \
         CERT_PERMS='${REMOTE_CERT_PERMS}' \
         ARCHIVE_SUFFIX='${ARCHIVE_SUFFIX}' \
         bash -s -- '${tmp_cert}' '${tmp_key}'"; } \
        || install_rc=$?

    case "${install_rc}" in
        0) con "${tag} INSTALLED" ;;
        2) con "${tag} SKIPPED (cert already current)" ; return 2 ;;
        *) con "${tag} FAILED (exit ${install_rc})"   ; return 1 ;;
    esac
}
# deploy_one return codes: 0 installed, 1 failed, 2 already-current,
#                          3 FQDN mismatch, 4 SSH host key changed (blocked)

# ---- deploy command ----------------------------------------------------------
cmd_deploy() {
    local issued_chain="${1:-}"
    [[ -n "${issued_chain}" ]] || die "Usage: $0 deploy <issued_chain.pem> [options]"
    [[ -f "${issued_chain}" ]] || die "File not found: ${issued_chain}"

    # Resolve key path: --key flag overrides cert.conf OUTPUT_DIR/KEY_FILENAME
    [[ -z "${KEY_FILE}" ]] && KEY_FILE="${OUTPUT_DIR}/${KEY_FILENAME}"
    [[ -f "${KEY_FILE}" ]] \
        || die "Private key not found: ${KEY_FILE}
  Either run '$0 csr' to generate one, or pass --key /path/to/existing.key"

    # Fail fast, before any normalization or uploads:
    #   - validate + de-duplicate the server list (populates DEPLOY_LINES)
    #   - confirm sshpass is present if any server uses password auth
    prepare_server_list 1
    require_sshpass_if_needed

    # Normalize key and cert to unencrypted PEM once here, before touching any server.
    # This handles format conversion and passphrase prompts in one place.
    mkdir -p "${OUTPUT_DIR}"
    local norm_key norm_cert
    norm_key=$(mktemp "${OUTPUT_DIR}/deploy_key_XXXXXX.pem")
    norm_cert=$(mktemp "${OUTPUT_DIR}/deploy_cert_XXXXXX.pem")
    # shellcheck disable=SC2064
    trap "rm -f '${norm_key}' '${norm_cert}'" EXIT

    step "Normalizing private key"
    normalize_key "${KEY_FILE}" "${norm_key}"

    step "Normalizing cert chain"
    normalize_cert "${issued_chain}" "${norm_cert}"

    # Point deploy_one at the normalized files
    KEY_FILE="${norm_key}"
    issued_chain="${norm_cert}"

    step "Validating cert"
    openssl x509 -noout -subject -dates -in "${issued_chain}" \
        || die "Cert failed to parse after normalization."

    # Chain-completeness check: a CA-issued server cert normally ships with at
    # least one intermediate. A lone leaf is a classic footgun — it works in
    # browsers (which cache intermediates) but fails for other clients. Warn,
    # don't block (some setups are legitimately single-cert).
    local cert_count
    cert_count=$(grep -c "BEGIN CERTIFICATE" "${issued_chain}" 2>/dev/null) || cert_count=0
    if [[ "${cert_count}" -lt 2 ]]; then
        warn "Cert chain looks incomplete: only ${cert_count} certificate present (no intermediate)."
        warn "  Browsers may accept it, but other clients can fail. Make sure the issued"
        warn "  file is the FULL chain (leaf + intermediate(s)), not just the leaf."
    else
        echo "    Chain contains ${cert_count} certificates (leaf + intermediate(s))."
    fi

    # Compare public keys extracted from cert and private key.
    # Using pkey/pubkey approach works for RSA (traditional and PKCS#8) and EC.
    step "Checking key/cert public key match"
    local cert_pub key_pub
    cert_pub=$(openssl x509 -noout -pubkey -in "${issued_chain}")
    key_pub=$( openssl pkey  -pubout        -in "${norm_key}" 2>/dev/null) \
        || die "Could not extract public key from key file."
    [[ "${cert_pub}" == "${key_pub}" ]] \
        || die "Private key does not match the cert — wrong key file or wrong cert."
    echo "    Match confirmed."

    # Use the validated, de-duplicated list built by prepare_server_list above.
    local -a server_lines=("${DEPLOY_LINES[@]}")
    local total=${#server_lines[@]}
    # Initialize as empty arrays (not just declared) so `${#arr[@]}` and
    # `"${arr[@]}"` are safe under `set -u` even when nothing gets appended.
    local -a installed=() skipped=() mismatched=() hostkey_changed=() failed=()

    con "Deploying to ${total} server(s)..."

    if [[ "${PARALLEL}" == "true" ]]; then
        step "Deploying to ${total} server(s) in parallel"
        local -a pids=() hosts=()

        for line in "${server_lines[@]}"; do
            parse_server_line "${line}"
            hosts+=("${_HOST}")
            deploy_one "${line}" "${issued_chain}" &
            pids+=($!)
        done

        for i in "${!pids[@]}"; do
            local rc=0
            wait "${pids[$i]}" || rc=$?
            case "${rc}" in
                0) installed+=("${hosts[$i]}") ;;
                2) skipped+=("${hosts[$i]}") ;;
                3) mismatched+=("${hosts[$i]}") ;;
                4) hostkey_changed+=("${hosts[$i]}") ;;
                *) failed+=("${hosts[$i]}") ;;
            esac
        done
    else
        step "Deploying to ${total} server(s) serially"
        for line in "${server_lines[@]}"; do
            parse_server_line "${line}"
            local rc=0
            deploy_one "${line}" "${issued_chain}" || rc=$?
            case "${rc}" in
                0) installed+=("${_HOST}") ;;
                2) skipped+=("${_HOST}") ;;
                3) mismatched+=("${_HOST}") ;;
                4) hostkey_changed+=("${_HOST}") ;;
                *) failed+=("${_HOST}"); warn "Continuing to next server..." ;;
            esac
        done
    fi

    con ""
    con "======================================="
    con "Targeted            : ${total}"
    con "Installed           : ${#installed[@]}"
    con "Already current     : ${#skipped[@]}"
    con "Failed              : ${#failed[@]}"
    (( ${#mismatched[@]} > 0 ))         && con "FQDN mismatch (skip) : ${#mismatched[@]}"
    (( ${#hostkey_changed[@]} > 0 ))    && con "Host key changed (skip): ${#hostkey_changed[@]}"
    (( ${#SKIPPED_INCOMPLETE[@]} > 0 )) && con "Skipped (incomplete): ${#SKIPPED_INCOMPLETE[@]}"
    con ""

    con "$(printf '  %-50s %s' 'SERVER' 'STATUS')"
    con "$(printf '  %-50s %s' '------' '------')"
    for h in "${installed[@]}";       do con "$(printf '  %-50s %s' "${h}" 'INSTALLED')"; done
    for h in "${skipped[@]}";         do con "$(printf '  %-50s %s' "${h}" 'ALREADY CURRENT')"; done
    for h in "${mismatched[@]}";      do con "$(printf '  %-50s %s' "${h}" 'SKIPPED (FQDN mismatch)')"; done
    for h in "${hostkey_changed[@]}"; do con "$(printf '  %-50s %s' "${h}" 'SKIPPED (host key changed)')"; done
    for h in "${failed[@]}";          do con "$(printf '  %-50s %s' "${h}" 'FAILED')"; done

    # Servers that got NO cert — make each impossible to overlook.
    if (( ${#mismatched[@]} > 0 )); then
        con ""
        con "WARNING: ${#mismatched[@]} server(s) were SKIPPED because the cert does not cover their FQDN:"
        for h in "${mismatched[@]}"; do con "  - ${h}"; done
        con "  These need a cert that matches their hostname, or re-run with --force if intentional."
    fi

    if (( ${#hostkey_changed[@]} > 0 )); then
        local joined
        printf -v joined '%s,' "${hostkey_changed[@]}"; joined="${joined%,}"
        con ""
        con "WARNING: ${#hostkey_changed[@]} server(s) were SKIPPED because their SSH host key CHANGED:"
        for h in "${hostkey_changed[@]}"; do con "  - ${h}"; done
        con "  Each server's stored vs. current fingerprint was printed above — verify those are"
        con "  legitimate rebuilds (not a man-in-the-middle), then re-learn just these and re-run:"
        con "    $0 deploy <cert> --key <key> --refresh-host-keys ${joined}"
    fi

    if (( ${#SKIPPED_INCOMPLETE[@]} > 0 )); then
        con ""
        con "WARNING: ${#SKIPPED_INCOMPLETE[@]} server(s) were SKIPPED for incomplete config and did NOT receive the cert:"
        for b in "${SKIPPED_INCOMPLETE[@]}"; do con "  - ${b}"; done
        con "  Fix these in servers.txt and re-run (servers already on the new cert are skipped)."
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        con ""
        con "FAILED servers (check the log for details):"
        for h in "${failed[@]}"; do con "  - ${h}"; done
        exit 1
    fi

    # Show current cert state on all servers after deploy. Informational —
    # a probe hiccup must not flip a successful install to a failure exit.
    # PREPARE_QUIET stops the re-validation here from repeating the dup/incomplete
    # warnings already shown at the top of the run.
    if [[ ${#installed[@]} -gt 0 || ${#skipped[@]} -gt 0 ]]; then
        echo
        echo "Current cert state (post-deploy verify):"
        PREPARE_QUIET=true
        cmd_verify || warn "Post-deploy verification reported issues — install itself succeeded; check manually."
    fi
}

# ---- rollback command --------------------------------------------------------
# Restores the archived cert+key (the .<ARCHIVE_SUFFIX> copies that deploy made)
# back into place and reloads nginx. Use when a deploy installed the wrong cert
# on a server — e.g. a server whose FQDN the wildcard didn't actually cover.
_remote_rollback_script() {
    cat <<'REMOTE_EOF'
set -euo pipefail
CERT_DIR="${CERT_DIR:-/var/lib/3cxpbx/Bin/nginx/conf/Instance1}"
CERT_OWNER="${CERT_OWNER:-phonesystem:phonesystem}"
CERT_PERMS="${CERT_PERMS:-640}"
ARCHIVE_SUFFIX="${ARCHIVE_SUFFIX:-}"
[[ -n "${ARCHIVE_SUFFIX}" ]] || { echo "ERROR: no ARCHIVE_SUFFIX given" >&2; exit 1; }
[[ -d "${CERT_DIR}" ]] || { echo "ERROR: cert dir not found: ${CERT_DIR}" >&2; exit 1; }

step() { echo "==> $*"; }

shopt -s nullglob
live_certs=("${CERT_DIR}"/domain_cert_*.pem)
live_keys=(  "${CERT_DIR}"/domain_key_*.pem)
shopt -u nullglob
[[ ${#live_certs[@]} -ge 1 && ${#live_keys[@]} -ge 1 ]] \
    || { echo "ERROR: live cert/key not found in ${CERT_DIR}" >&2; exit 1; }

LIVE_CERT="${live_certs[0]}"; LIVE_KEY="${live_keys[0]}"
ARC_CERT="${LIVE_CERT}${ARCHIVE_SUFFIX}"; ARC_KEY="${LIVE_KEY}${ARCHIVE_SUFFIX}"
[[ -f "${ARC_CERT}" ]] || { echo "ERROR: archive not found: ${ARC_CERT}" >&2; exit 1; }
[[ -f "${ARC_KEY}" ]]  || { echo "ERROR: archive not found: ${ARC_KEY}" >&2; exit 1; }

step "Restoring cert <- ${ARC_CERT}"
cp -p "${ARC_CERT}" "${LIVE_CERT}"
step "Restoring key  <- ${ARC_KEY}"
cp -p "${ARC_KEY}" "${LIVE_KEY}"
chown "${CERT_OWNER}" "${LIVE_CERT}" "${LIVE_KEY}"
chmod "${CERT_PERMS}" "${LIVE_CERT}" "${LIVE_KEY}"

step "Testing nginx config"
nginx -t || { echo "ERROR: nginx -t failed after restore — NOT reloaded" >&2; exit 1; }
step "Reloading nginx"
nginx -s reload
sleep 2
echo "    Rolled back. Restored cert expires: $(openssl x509 -noout -enddate -in "${LIVE_CERT}" | cut -d= -f2-)"
echo "Done on $(hostname)."
REMOTE_EOF
}

rollback_one() {
    local line="$1"
    parse_server_line "${line}"
    local tag="[${_HOST}]"
    make_ssh_cmds "${_HOST}" "${_USER}" "${_PORT}" "${_KEY}" \
        || { con "${tag} FAILED: no usable credentials"; return 1; }

    echo "${tag} Rolling back..."
    _remote_rollback_script | SSHPASS="${_SSH_PW}" "${SSH_CMD[@]}" \
        "CERT_DIR='${REMOTE_CERT_DIR}' \
         CERT_OWNER='${REMOTE_CERT_OWNER}' \
         CERT_PERMS='${REMOTE_CERT_PERMS}' \
         ARCHIVE_SUFFIX='${ARCHIVE_SUFFIX}' \
         bash -s" \
        || { con "${tag} FAILED: rollback"; return 1; }
    con "${tag} ROLLED BACK"
}

cmd_rollback() {
    prepare_server_list 1
    require_sshpass_if_needed
    local -a server_lines=("${DEPLOY_LINES[@]}")
    local total=${#server_lines[@]}
    local -a done_ok=() failed=()

    step "Rolling back ${total} server(s) to archive suffix '${ARCHIVE_SUFFIX}'"
    echo "(Restores the cert+key that deploy archived as *${ARCHIVE_SUFFIX}.)"
    for line in "${server_lines[@]}"; do
        parse_server_line "${line}"
        if rollback_one "${line}"; then
            done_ok+=("${_HOST}")
        else
            failed+=("${_HOST}"); warn "Continuing to next server..."
        fi
    done

    con ""
    con "======================================="
    con "Rolled back : ${#done_ok[@]}/${total}"
    con "Failed      : ${#failed[@]}"
    if (( ${#failed[@]} > 0 )); then
        con ""
        con "FAILED rollbacks (check the log for details):"
        for h in "${failed[@]}"; do con "  - ${h}"; done
        exit 1
    fi
}

# ---- keyscan command ---------------------------------------------------------
# Reports each server's stored vs. currently-presented SSH host-key fingerprint —
# verify keys before a run or after a planned rebuild. No login needed (ssh-keyscan).
cmd_keyscan() {
    prepare_server_list 0
    local -a server_lines=("${DEPLOY_LINES[@]}")
    echo "SSH host-key status for ${#server_lines[@]} server(s):"
    echo
    local -a changed=()
    for line in "${server_lines[@]}"; do
        parse_server_line "${line}"
        hostkey_status "${_HOST}" "${_PORT}"
        case "${_HK_STATE}" in
            ok)          printf '  %-50s OK (matches known_hosts)\n' "${_HOST}" ;;
            new)         printf '  %-50s NEW (not in known_hosts) — now: %s\n' "${_HOST}" "${_HK_NEW}" ;;
            unreachable) printf '  %-50s UNREACHABLE (port %s)\n' "${_HOST}" "${_PORT}" ;;
            changed)     printf '  %-50s CHANGED\n      stored: %s\n      now:    %s\n' "${_HOST}" "${_HK_OLD}" "${_HK_NEW}"
                         changed+=("${_HOST}") ;;
        esac
    done
    echo
    if (( ${#changed[@]} > 0 )); then
        local joined; printf -v joined '%s,' "${changed[@]}"; joined="${joined%,}"
        con "${#changed[@]} host(s) have a CHANGED key. After verifying those are legitimate,"
        con "re-learn them on the next deploy with:  --refresh-host-keys ${joined}"
        return 1
    fi
    con "All reachable hosts match known_hosts (or are new)."
    return 0
}

# ---- verify command ----------------------------------------------------------
# Checks what clients actually see: connects from this machine to each server's
# public FQDN on each configured port (no SSH) — the vantage point of an external
# SSL checker. For each port that answers it reports the cert's expiry and flags:
#   - EXPIRED                  cert is past its notAfter
#   - EXPIRES SOON (<N days)   within VERIFY_EXPIRY_WARN_DAYS (default 30)
#   - NAME MISMATCH            served cert doesn't cover the server's FQDN
# Servers vary (TLS on 443 and/or 5001); a port that doesn't answer is "not
# serving", not a failure. verify exits non-zero if ANY server has a problem
# (not confirmed on any port, expired, expiring soon, or name mismatch) so it
# can be used as a scheduled health check.
cmd_verify() {
    prepare_server_list 0   # de-dup; no credentials needed (client-side)
    local -a server_lines=("${DEPLOY_LINES[@]}")
    local warn_days="${VERIFY_EXPIRY_WARN_DAYS:-30}"
    echo "Checking live certs on ${#server_lines[@]} server(s) — client-side, to public endpoints..."
    echo "(flagging certs that are expired, expire within ${warn_days} days, or don't match the hostname)"
    echo

    local -a problems=()
    local tmp; tmp=$(mktemp "${TMPDIR:-/tmp}/3cx_verify_XXXXXX.pem")
    # shellcheck disable=SC2064
    trap "rm -f '${tmp}'" RETURN

    for line in "${server_lines[@]}"; do
        parse_server_line "${line}"
        echo "${_HOST}"
        local served=0 host_issue=""

        for vport in ${VERIFY_PORTS}; do
            printf "  %-6s " "${vport}:"
            # Capture the leaf cert once, then inspect it locally.
            if ! echo | openssl s_client -connect "${_HOST}:${vport}" \
                    -servername "${_HOST}" 2>/dev/null \
                    | openssl x509 2>/dev/null > "${tmp}" || [[ ! -s "${tmp}" ]]; then
                echo "not serving (port closed or unused on this server)"
                continue
            fi
            served=1

            local enddate labels=()
            enddate=$(openssl x509 -noout -enddate -in "${tmp}" | cut -d= -f2-)
            if ! openssl x509 -noout -checkend 0 -in "${tmp}" >/dev/null 2>&1; then
                labels+=("EXPIRED")
            elif ! openssl x509 -noout -checkend $((warn_days * 86400)) -in "${tmp}" >/dev/null 2>&1; then
                labels+=("EXPIRES SOON (<${warn_days}d)")
            fi
            if ! cert_covers_host "${tmp}" "${_HOST}"; then
                labels+=("NAME MISMATCH")
            fi

            if [[ ${#labels[@]} -eq 0 ]]; then
                echo "expires ${enddate}  [OK]"
            else
                local joined; printf -v joined '%s; ' "${labels[@]}"
                echo "expires ${enddate}  [${joined%; }]"
                host_issue="${labels[*]}"
            fi
        done

        if [[ "${served}" -eq 0 ]]; then
            echo "  -> NOT CONFIRMED on any of: ${VERIFY_PORTS}"
            problems+=("${_HOST} (not serving)")
        elif [[ -n "${host_issue}" ]]; then
            problems+=("${_HOST} (${host_issue})")
        fi
    done

    echo
    if [[ ${#problems[@]} -gt 0 ]]; then
        con "Verification problems (${#problems[@]}):"
        local p
        for p in "${problems[@]}"; do con "  - ${p}"; done
        return 1
    fi
    con "All certs valid, matching, and not expiring within ${warn_days} days."
    return 0
}

# ---- usage -------------------------------------------------------------------
print_usage() {
    cat <<EOF
3cx-cert-manager ${VERSION} — Wildcard SSL cert lifecycle manager for 3CX PBX servers

Usage:
  $0 setup
  $0 csr      [--config FILE] [--key FILE]
  $0 deploy   <issued_chain.pem> [--config FILE] [--servers FILE] [--key FILE] [--parallel] [--force]
                                 [--only h1,h2] [--refresh-host-keys h1,h2] [--accept-key host=SHA256:..]
  $0 rollback [--config FILE] [--servers FILE] [--only h1,h2]
  $0 verify   [--config FILE] [--servers FILE] [--only h1,h2]
  $0 keyscan  [--config FILE] [--servers FILE] [--only h1,h2]
  $0 version
  $0 help

Options:
  --config FILE         Config file       (default: cert.conf)
  --servers FILE        Server list       (default: servers.txt)
  --key FILE            Private key — for csr: use existing key instead of generating one
                                     — for deploy: use instead of OUTPUT_DIR/KEY_FILENAME
  --log FILE            Write full output to FILE (default: logs/<action>_YYYYMMDD_HHMMSS.log)
  --no-log              Disable log file
  --parallel            Deploy to all servers concurrently
  --only h1,h2          Restrict the run to this subset of the server list (creds still
                        come from the list — no credentials on the command line)
  --force               Install even if the cert does not cover the server's FQDN
  --refresh-host-keys L Re-learn the changed SSH host key for the named hosts (comma list)
  --accept-key H=FP     Re-learn host H only if its live key matches fingerprint FP (repeatable)
  --no-strict           Skip SSH host key verification (not recommended)

deploy skips any server whose FQDN the cert does not cover (CN/SAN, wildcard-aware),
so a wildcard for one domain is never installed on a server in another. Override
with --force. rollback restores the cert+key that deploy archived (the .YYYY copies).
verify flags certs that are expired, expiring within VERIFY_EXPIRY_WARN_DAYS, or
don't match the hostname, and exits non-zero if any server has a problem.

If a server's SSH host key has CHANGED (e.g. it was rebuilt), deploy refuses it by
default and prints stored vs. current fingerprints. After verifying, re-learn just
those hosts with --refresh-host-keys (or, in a terminal, confirm the interactive
prompt). keyscan reports stored-vs-current host-key fingerprints without deploying.

Key/cert formats accepted: PEM (RSA/PKCS#8/EC, encrypted or not), DER, PKCS#12 (.p12/.pfx)
Inputs are automatically normalized to unencrypted PEM before deployment.

First time:
  $0 setup   — creates certs/ and logs/ dirs, scaffolds cert.conf, servers.txt, .ssh_passwords

Generate CSR and deploy from scratch:
  1. $0 csr
  2. Submit printed CSR to your CA; receive issued_chain.pem
  3. $0 deploy issued_chain.pem
  4. $0 verify

Already have a key and issued cert — deploy directly:
  $0 deploy issued_chain.pem --key /path/to/existing.key
EOF
}

# Require a value for options that take one; clean error instead of a set -u crash.
need_arg() { [[ $# -ge 2 ]] || die "Option $1 requires a value."; }

# Run the requested action. A function so it can be wrapped in a tee pipeline
# without losing the exit code via PIPESTATUS.
_run() {
    case "${ACTION}" in
        setup)    cmd_setup ;;
        csr)      cmd_csr ;;
        deploy)   cmd_deploy "${POSITIONAL[0]:-}" ;;
        rollback) cmd_rollback ;;
        verify)   cmd_verify ;;
        keyscan)  cmd_keyscan ;;
    esac
}

# ---- entry point -------------------------------------------------------------
# Wrapped in main() and guarded below so the script can be `source`d by the test
# suite (tests/test.sh) to exercise individual functions without running anything.
main() {
    check_deps

    # Pre-scan for --config so it's loaded before other options take effect.
    local _raw=("$@") _i
    for (( _i=0; _i<${#_raw[@]}-1; _i++ )); do
        [[ "${_raw[$_i]}" == "--config" ]] && CONFIG_FILE="${_raw[$((_i+1))]}"
    done

    ACTION="${1:-}"
    shift || true

    case "${ACTION}" in
        version|--version|-V) echo "3cx-cert-manager ${VERSION}"; return 0 ;;
        help|--help|-h)       print_usage; return 0 ;;
    esac

    POSITIONAL=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config)    need_arg "$@"; CONFIG_FILE="$2";  shift 2 ;;
            --servers)   need_arg "$@"; SERVERS_FILE="$2"; shift 2 ;;
            --key)       need_arg "$@"; KEY_FILE="$2";     shift 2 ;;
            --log)       need_arg "$@"; LOG_FILE="$2";     shift 2 ;;
            --no-log)    LOG_FILE="none";   shift   ;;
            --parallel)  PARALLEL=true;     shift   ;;
            --force)     FORCE=true;        shift   ;;
            --only) need_arg "$@"; ONLY="$2"; shift 2 ;;
            --refresh-host-keys) need_arg "$@"; REFRESH_HOST_KEYS="$2"; shift 2 ;;
            --accept-key)        need_arg "$@"; ACCEPT_KEYS="${ACCEPT_KEYS:+${ACCEPT_KEYS},}$2"; shift 2 ;;
            --no-strict) SSH_STRICT="no";   shift   ;;
            --*)         die "Unknown option: $1" ;;
            *)           POSITIONAL+=("$1"); shift  ;;
        esac
    done

    # setup runs before config exists; all other commands require it.
    [[ "${ACTION}" != "setup" ]] && load_config

    # Resolve the log file path once (shared by both logging styles below).
    if [[ "${ACTION}" =~ ^(setup|csr|deploy|rollback|verify|keyscan)$ && "${LOG_FILE}" != "none" ]]; then
        if [[ -z "${LOG_FILE}" ]]; then
            mkdir -p "${LOG_DIR}"
            LOG_FILE="${LOG_DIR}/${ACTION}_$(date +%Y%m%d_%H%M%S).log"
        else
            mkdir -p "$(dirname "${LOG_FILE}")"
        fi
    fi

    case "${ACTION}" in
        deploy|rollback)
            # Verbose to the log, brief to the console: redirect all ordinary
            # output to the log; con()/warn()/die() also echo to the saved
            # console (fd 3).
            if [[ "${LOG_FILE}" != "none" ]]; then
                exec 3>&1
                exec >>"${LOG_FILE}" 2>&1
                CONSOLE_FD=3
                con "Logging full detail to: ${LOG_FILE}"
                con "(console shows progress + summary; see the log for per-server detail)"
                con ""
            fi
            _run
            ;;
        setup|csr|verify|keyscan)
            # Concise commands: show everything on the console, and also record it.
            if [[ "${LOG_FILE}" != "none" ]]; then
                printf 'Logging to: %s\n\n' "${LOG_FILE}" | tee -a "${LOG_FILE}"
                _run 2>&1 | tee -a "${LOG_FILE}"
            else
                _run
            fi
            ;;
        *)
            print_usage >&2
            return 1
            ;;
    esac
}

# Only run when executed directly, not when sourced (e.g. by the test suite).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
