#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# tools/openssl_interop.sh — TCP TLS interoperability between Armor and the
# system OpenSSL, in both directions (audit 2026-11-07 Phase 4 item 4).
#
#   Server side: boots a private onyx-server daemon (temp config, temp PKI,
#   loopback ports — like tools/upgrade_smoke.py) and runs `openssl s_client`
#   against its [tls] listener for every TLS 1.3 cipher suite, every supported
#   group (X25519, secp256r1, X25519MLKEM768 when this OpenSSL has it, plus a
#   HelloRetryRequest case), every enabled TLS 1.2 suite (ECDSA and RSA
#   leaves), 1.3 and 1.2 session resumption (-sess_out / -sess_in), ALPN, and
#   an OCSP status_request (-status). Each handshake must verify the chain
#   (-verify_return_error) and carry IRC application data (NICK/USER -> 001).
#
#   Client side: builds tools/openssl_interop_client.zig (the daemon's real
#   `http_fetch` outbound path: TLS 1.3 client with the hardened TLS 1.2
#   fallback, chain verified against the test CA) and fetches from
#   `openssl s_server -www` pinned to each suite / group / version. The
#   s_server status page names what OpenSSL negotiated, which is asserted.
#
# Requirements: openssl >= 3.0, python3 (free-port probe only), and a real
# Zig 0.17 on PATH when the client helper or daemon must be built. Nothing
# here touches an installed service; everything lives in one mktemp dir.
#
# Usage:
#   tools/openssl_interop.sh [path-to-onyx-server]
# Env:
#   ONYX_BIN            daemon binary (default zig-out/bin/onyx-server; built
#                       with `zig build -Doptimize=ReleaseSafe` when missing)
#   OPENSSL             openssl binary (default: openssl on PATH)
#   INTEROP_KEEP=1      keep the temp dir (logs, PKI) for inspection
#
# Exit 0 = every required case passed. Optional cases (a group this OpenSSL
# lacks) are reported as SKIP and never fail the run.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL="${OPENSSL:-openssl}"
ONYX_BIN="${1:-${ONYX_BIN:-${repo_root}/zig-out/bin/onyx-server}}"

work="$(mktemp -d "${TMPDIR:-/tmp}/onyx-openssl-interop.XXXXXX")"
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]:-}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null && wait "${pid}" 2>/dev/null
  done
  if [[ "${INTEROP_KEEP:-0}" == "1" ]]; then
    echo "[interop] kept ${work}"
  else
    rm -rf "${work}"
  fi
}
trap cleanup EXIT

pass=0
fail=0
skip=0
results=()
record() { # record PASS|FAIL|SKIP "name" "detail"
  results+=("$(printf '%-4s %-46s %s' "$1" "$2" "${3:-}")")
  case "$1" in
    PASS) pass=$((pass + 1)) ;;
    FAIL) fail=$((fail + 1)) ;;
    SKIP) skip=$((skip + 1)) ;;
  esac
  printf '[interop] %-4s %s %s\n' "$1" "$2" "${3:-}"
}

die() {
  echo "[interop] $*" >&2
  exit 2
}

command -v "${OPENSSL}" >/dev/null || die "openssl not found"
command -v python3 >/dev/null || die "python3 not found"
ossl_version="$("${OPENSSL}" version)"
echo "[interop] ${ossl_version}"
case "${ossl_version}" in
  "OpenSSL 3."*) ;;
  *) die "need OpenSSL 3.x (got: ${ossl_version})" ;;
esac

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_port() { # wait_port port seconds
  local port="$1" deadline=$((SECONDS + $2))
  while ((SECONDS < deadline)); do
    if python3 -c 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),0.5); s.close()' "${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# What s_client prints for the negotiated group: classic ECDHE groups show as
# the peer's temporary key, KEM/hybrid groups as "Negotiated TLS1.3 group".
group_evidence() {
  case "$1" in
    x25519) echo "Peer Temp Key: X25519" ;;
    secp256r1) echo "Peer Temp Key: ECDH, prime256v1" ;;
    *) echo "Negotiated TLS1.3 group: $1" ;;
  esac
}

group_supported() { # does this OpenSSL offer TLS group $1?
  "${OPENSSL}" list -tls-groups 2>/dev/null | tr ':' '\n' | grep -qix "$1"
}

# ── Build ────────────────────────────────────────────────────────────────────

if [[ ! -x "${ONYX_BIN}" ]]; then
  echo "[interop] building onyx-server (ReleaseSafe)"
  (cd "${repo_root}" && zig build -Doptimize=ReleaseSafe) || die "daemon build failed"
fi
[[ -x "${ONYX_BIN}" ]] || die "daemon binary not found: ${ONYX_BIN}"

client_bin="${work}/openssl_interop_client"
cat >"${work}/build_info.zig" <<'EOF'
pub const git_commit: []const u8 = "interop";
pub const version: []const u8 = "0.0.0+interop";
pub const windows_rollover_smoke: bool = false;
EOF
echo "[interop] building the http_fetch client helper"
(cd "${repo_root}" && zig build-exe -OReleaseSafe \
  --dep onyx_server -Mroot=tools/openssl_interop_client.zig \
  --dep build_info -Monyx_server=src/root.zig \
  -Mbuild_info="${work}/build_info.zig" \
  --cache-dir "${work}/zig-cache" \
  -femit-bin="${client_bin}") || die "client helper build failed"

# ── PKI: one CA, an ECDSA P-256 leaf and an RSA-2048 leaf for localhost ──────

pki="${work}/pki"
mkdir -p "${pki}"
leaf_ext="${pki}/leaf.ext"
printf '%s\n' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' >"${leaf_ext}"
"${OPENSSL}" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${pki}/ca.key" -out "${pki}/ca.pem" -days 2 -subj /CN=onyx-interop-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  >/dev/null 2>&1 || die "CA generation failed"
make_leaf() { # make_leaf name keygen-args...
  local name="$1"
  shift
  "${OPENSSL}" req -newkey "$@" -nodes -keyout "${pki}/${name}.key" \
    -out "${pki}/${name}.csr" -subj /CN=localhost >/dev/null 2>&1 &&
    "${OPENSSL}" x509 -req -in "${pki}/${name}.csr" -CA "${pki}/ca.pem" \
      -CAkey "${pki}/ca.key" -CAcreateserial -out "${pki}/${name}.pem" -days 2 \
      -extfile "${leaf_ext}" >/dev/null 2>&1 || die "leaf ${name} generation failed"
  # PKCS#8 PEM, the form tls_certs.loadFromDisk documents.
  "${OPENSSL}" pkcs8 -topk8 -nocrypt -in "${pki}/${name}.key" -out "${pki}/${name}.p8" ||
    die "leaf ${name} key conversion failed"
}
make_leaf ecdsa ec -pkeyopt ec_paramgen_curve:P-256
make_leaf rsa rsa:2048
ca_der_b64="$("${OPENSSL}" x509 -in "${pki}/ca.pem" -outform DER | base64 -w0)"

# ── Daemon ───────────────────────────────────────────────────────────────────

daemon_tls_port=""
start_daemon() { # start_daemon leaf-name
  local name="$1" dir="${work}/daemon-$1"
  mkdir -p "${dir}"
  local irc_port tls_port
  irc_port="$(free_port)"
  tls_port="$(free_port)"
  cat >"${dir}/onyx.toml" <<EOF
[node]
id = 1
[limits]
num_shards = 1
[listen]
irc = ${irc_port}
[tls]
enabled = true
port = ${tls_port}
cert_path = "${pki}/${name}.pem"
key_path = "${pki}/${name}.p8"
dns_name = "localhost"
enable_tls12 = true
enable_resumption = true
alpn = ["irc"]
EOF
  (
    cd "${dir}" || exit 1
    # A Debug daemon with [tls] enabled needs a large stack (upgrade_smoke.py).
    ulimit -s unlimited 2>/dev/null || ulimit -s 524288 2>/dev/null || true
    umask 077
    exec "${ONYX_BIN}" "${dir}/onyx.toml"
  ) >"${dir}/daemon.log" 2>&1 &
  pids+=("$!")
  if ! wait_port "${tls_port}" 20; then
    tail -20 "${dir}/daemon.log" >&2
    die "daemon (${name} leaf) did not open its TLS port"
  fi
  daemon_tls_port="${tls_port}"
  echo "[interop] daemon (${name} leaf) tls=127.0.0.1:${tls_port} log=${dir}/daemon.log"
}

stop_last_daemon() {
  local last=$((${#pids[@]} - 1))
  kill "${pids[${last}]}" 2>/dev/null
  wait "${pids[${last}]}" 2>/dev/null
  unset "pids[${last}]"
  pids=("${pids[@]}")
}

# s_client wrapper: runs one IRC registration over TLS and captures both the
# handshake summary (stderr with -brief, plus -sess_out etc.) and app data.
s_client_irc() { # s_client_irc outfile s_client-args...
  local out="$1"
  shift
  {
    printf 'NICK interop%s\r\nUSER interop 0 * :openssl interop\r\n' "$RANDOM"
    sleep 1.5
    printf 'QUIT :done\r\n'
    sleep 0.5
  } | timeout 20 "${OPENSSL}" s_client -connect "127.0.0.1:${daemon_tls_port}" \
    -servername localhost -CAfile "${pki}/ca.pem" -verify_return_error \
    -verify_hostname localhost "$@" >"${out}" 2>&1
}

# Assert helpers over one s_client transcript.
expect_in() { grep -qF -- "$2" "$1"; }

server_case() { # server_case name expect-substring s_client-args...
  local name="$1" want="$2"
  shift 2
  local out="${work}/s_client.$(echo "${name}" | tr -c 'A-Za-z0-9' '_').log"
  s_client_irc "${out}" "$@"
  if ! expect_in "${out}" "Verify return code: 0 (ok)" && ! expect_in "${out}" "Verification: OK"; then
    record FAIL "${name}" "chain did not verify ($(grep -m1 -iE 'error|alert' "${out}" | tr -d '\r'))"
  elif ! expect_in "${out}" "${want}"; then
    record FAIL "${name}" "missing '${want}' ($(grep -m1 -iE 'error|alert' "${out}" | tr -d '\r'))"
  elif ! grep -qE '^:[^ ]+ 001 ' "${out}"; then
    record FAIL "${name}" "handshake ok but no IRC 001 over TLS"
  else
    record PASS "${name}" "${want}"
  fi
}

run_server_side() {
  start_daemon ecdsa

  local suite
  for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    server_case "s_client tls1.3 ${suite}" "Ciphersuite: ${suite}" \
      -tls1_3 -ciphersuites "${suite}" -brief
  done

  local group
  for group in x25519 secp256r1 X25519MLKEM768; do
    if ! group_supported "${group}"; then
      record SKIP "s_client tls1.3 group ${group}" "not in this OpenSSL"
      continue
    fi
    server_case "s_client tls1.3 group ${group}" "$(group_evidence "${group}")" \
      -tls1_3 -groups "${group}"
  done
  # With an explicit list OpenSSL sends a key share only for the first group;
  # secp384r1 is unsupported, so completing on X25519 requires the server's
  # HelloRetryRequest (RFC 8446 §4.1.4) — the -msg trace must show two
  # ServerHello-type messages (HRR is encoded as a ServerHello).
  server_case "s_client tls1.3 HRR secp384r1->x25519" "$(group_evidence x25519)" \
    -tls1_3 -groups secp384r1:x25519 -msg
  local hrr_log="${work}/s_client.s_client_tls1_3_HRR_secp384r1__x25519_.log"
  if [[ -f "${hrr_log}" ]] && (($(grep -c 'Handshake.*ServerHello' "${hrr_log}") < 2)); then
    record FAIL "s_client tls1.3 HRR round trip" "expected HelloRetryRequest + ServerHello in the -msg trace"
  elif [[ -f "${hrr_log}" ]]; then
    record PASS "s_client tls1.3 HRR round trip" "HelloRetryRequest observed"
  fi

  for suite in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    server_case "s_client tls1.2 ${suite}" "Ciphersuite: ${suite}" \
      -tls1_2 -cipher "${suite}" -brief
  done

  # Resumption: first connection saves the session (TLS 1.3 tickets arrive
  # after the handshake, which the 2 s IRC exchange gives time to read).
  local v
  for v in tls1_3 tls1_2; do
    local sess="${work}/sess.${v}.pem"
    local out1="${work}/s_client.resume1.${v}.log" out2="${work}/s_client.resume2.${v}.log"
    s_client_irc "${out1}" "-${v}" -sess_out "${sess}"
    if [[ ! -s "${sess}" ]]; then
      record FAIL "s_client ${v} resumption" "no session saved ($(grep -m1 -iE 'error|alert' "${out1}" | tr -d '\r'))"
      continue
    fi
    s_client_irc "${out2}" "-${v}" -sess_in "${sess}"
    if expect_in "${out2}" "Reused, TLSv1"; then
      record PASS "s_client ${v} resumption" "$(grep -m1 -F 'Reused, TLSv1' "${out2}" | tr -d '\r')"
    else
      record FAIL "s_client ${v} resumption" "second connection was not resumed ($(grep -m1 -E '^(New|Reused), ' "${out2}" | tr -d '\r'))"
    fi
  done

  # (-brief omits the ALPN line, so these use the full summary.)
  server_case "s_client tls1.3 ALPN irc" "ALPN protocol: irc" -tls1_3 -alpn irc
  server_case "s_client tls1.2 ALPN irc" "ALPN protocol: irc" -tls1_2 -alpn irc
  # RFC 7301 §3.2: no overlap ⇒ the server either ignores ALPN (no protocol
  # selected) or aborts with no_application_protocol. Record which.
  local alpn_out="${work}/s_client.alpn_mismatch.log"
  s_client_irc "${alpn_out}" -tls1_3 -alpn h2
  if expect_in "${alpn_out}" "no application protocol"; then
    record PASS "s_client tls1.3 ALPN mismatch" "no_application_protocol alert"
  elif expect_in "${alpn_out}" "ALPN protocol:"; then
    record FAIL "s_client tls1.3 ALPN mismatch" "server selected an unoffered protocol"
  elif grep -qE '^:[^ ]+ 001 ' "${alpn_out}"; then
    record PASS "s_client tls1.3 ALPN mismatch" "no protocol selected; connection proceeds"
  else
    record FAIL "s_client tls1.3 ALPN mismatch" "$(grep -m1 -iE 'error|alert' "${alpn_out}" | tr -d '\r')"
  fi

  # OCSP status_request: no responder is configured for the test CA, so the
  # server must simply not staple (RFC 6066 §8) and the handshake proceeds.
  server_case "s_client tls1.3 status_request" "OCSP response: no response sent" -tls1_3 -status
  server_case "s_client tls1.2 status_request" "OCSP response: no response sent" -tls1_2 -status

  stop_last_daemon
  start_daemon rsa
  server_case "s_client tls1.3 RSA leaf (rsa_pss_rsae)" "Ciphersuite: TLS_AES_128_GCM_SHA256" \
    -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -brief
  for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    server_case "s_client tls1.2 ${suite}" "Ciphersuite: ${suite}" \
      -tls1_2 -cipher "${suite}" -brief
  done
  stop_last_daemon
}

# ── Client side: http_fetch against openssl s_server -www ───────────────────

client_case() { # client_case name expect-substring leaf s_server-args...
  local name="$1" want="$2" leaf="$3"
  shift 3
  local port log out
  port="$(free_port)"
  log="${work}/s_server.$(echo "${name}" | tr -c 'A-Za-z0-9' '_').log"
  out="${log%.log}.body"
  "${OPENSSL}" s_server -accept "127.0.0.1:${port}" -www -naccept 2 \
    -cert "${pki}/${leaf}.pem" -key "${pki}/${leaf}.key" "$@" >"${log}" 2>&1 &
  local spid=$!
  pids+=("${spid}")
  # s_server prints ACCEPT once it listens (a TCP probe would consume an
  # accept slot). Two slots: a TLS-1.2-only server rejects http_fetch's first
  # (TLS 1.3) ClientHello, and the client retries with its 1.2 fallback.
  local deadline=$((SECONDS + 10))
  while ! grep -q '^ACCEPT' "${log}" 2>/dev/null; do
    if ((SECONDS >= deadline)) || ! kill -0 "${spid}" 2>/dev/null; then
      record FAIL "${name}" "s_server did not start ($(head -1 "${log}"))"
      return
    fi
    sleep 0.1
  done
  if timeout 20 "${client_bin}" "${port}" "${ca_der_b64}" localhost >"${out}" 2>&1; then
    if grep -qF -- "${want}" "${out}"; then
      record PASS "${name}" "${want}"
    else
      record FAIL "${name}" "response lacks '${want}': $(grep -m1 -E '^(New|Reused), ' "${out}" | tr -d '\r')"
    fi
  else
    record FAIL "${name}" "$(tail -1 "${out}" | tr -d '\r'); s_server: $(grep -m1 -iE 'error' "${log}" | tr -d '\r')"
  fi
  kill "${spid}" 2>/dev/null
  wait "${spid}" 2>/dev/null
}

run_client_side() {
  local suite
  for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    client_case "http_fetch tls1.3 ${suite}" "New, TLSv1.3, Cipher is ${suite}" ecdsa \
      -tls1_3 -ciphersuites "${suite}"
  done
  local group
  for group in x25519 secp256r1 X25519MLKEM768; do
    if ! group_supported "${group}"; then
      record SKIP "http_fetch tls1.3 group ${group}" "not in this OpenSSL"
      continue
    fi
    # s_server limited to one group: success means that group was negotiated
    # (directly or via HelloRetryRequest).
    client_case "http_fetch tls1.3 group ${group}" "New, TLSv1.3, Cipher is" ecdsa \
      -tls1_3 -groups "${group}"
  done
  client_case "http_fetch tls1.3 RSA leaf" "New, TLSv1.3, Cipher is" rsa -tls1_3
  for suite in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    client_case "http_fetch tls1.2 ${suite}" "New, TLSv1.2, Cipher is ${suite}" ecdsa \
      -tls1_2 -cipher "${suite}"
  done
  for suite in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    client_case "http_fetch tls1.2 ${suite}" "New, TLSv1.2, Cipher is ${suite}" rsa \
      -tls1_2 -cipher "${suite}"
  done
}

run_server_side
run_client_side

echo
echo "[interop] ===== summary (${ossl_version}) ====="
printf '%s\n' "${results[@]}"
echo "[interop] ${pass} passed; ${fail} failed; ${skip} skipped"
((fail == 0 && pass > 0))
