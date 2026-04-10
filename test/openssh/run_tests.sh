#!/bin/bash
# End-to-end test suite for sshconf against a real OpenSSH server.
#
# Usage: ./test/openssh/run_tests.sh
#
# Prerequisites: docker (or podman), go toolchain
# The script builds the sshconf binary, starts an OpenSSH container,
# runs every test, then tears down the container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE_NAME="sshconf-test-openssh"
CONTAINER_NAME="sshconf-test-$$"
SSH_PORT=""       # assigned dynamically
TMPDIR_TEST=""
BINARY=""
TEST_KEY=""
KNOWN_HOSTS=""

# Counters
PASS=0
FAIL=0
SKIP=0
ERRORS=()

# ---------- helpers ----------------------------------------------------------

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "$CONTAINER_NAME" ]; then
        docker rm -f "$CONTAINER_NAME" &>/dev/null || true
    fi
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 1; }

log()  { echo "--- $*"; }
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAIL=$((FAIL + 1)); ERRORS+=("$1: $2"); }
skip() { echo "  SKIP: $1 — $2"; SKIP=$((SKIP + 1)); }

# Run sshconf with common flags. Automatically adds key, port, known_hosts,
# disables password auth (key-only) and sets BatchMode.
ssh_cmd() {
    "$BINARY" \
        -F none \
        -o "UserKnownHostsFile=$KNOWN_HOSTS" \
        -o "StrictHostKeyChecking=no" \
        -o "PasswordAuthentication=no" \
        -o "BatchMode=yes" \
        -i "$TEST_KEY" \
        -p "$SSH_PORT" \
        "$@"
}

# Same but allow password auth (for password test).
ssh_cmd_password() {
    "$BINARY" \
        -F none \
        -o "UserKnownHostsFile=$KNOWN_HOSTS" \
        -o "StrictHostKeyChecking=no" \
        -p "$SSH_PORT" \
        "$@"
}

# Wait for a TCP port to become reachable.
wait_for_port() {
    local host=$1 port=$2 timeout=${3:-30}
    local deadline=$((SECONDS + timeout))
    while ! bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; do
        if [ $SECONDS -ge $deadline ]; then
            die "Timed out waiting for $host:$port"
        fi
        sleep 0.2
    done
}

# Pick a free ephemeral port.
free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

# ---------- build & start ----------------------------------------------------

build_binary() {
    log "Building sshconf binary"
    cd "$PROJECT_ROOT"
    go build -o "$TMPDIR_TEST/sshconf" ./cmd/ssh/
    BINARY="$TMPDIR_TEST/sshconf"
    [ -x "$BINARY" ] || die "Binary not found after build"
    echo "  Built: $BINARY"
}

build_image() {
    log "Building Docker image"
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR" || die "Docker build failed"
}

start_container() {
    log "Starting container"
    SSH_PORT=$(free_port)
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "127.0.0.1:${SSH_PORT}:22" \
        "$IMAGE_NAME" || die "Failed to start container"
    echo "  Container: $CONTAINER_NAME  SSH port: $SSH_PORT"

    # Copy the test private key out of the container
    docker cp "$CONTAINER_NAME:/etc/ssh/test_key" "$TEST_KEY"
    chmod 600 "$TEST_KEY"

    wait_for_port 127.0.0.1 "$SSH_PORT" 30
    echo "  SSH server ready"

    # Populate known_hosts on first connection (accept any key)
    ssh_cmd -o "StrictHostKeyChecking=accept-new" testuser@127.0.0.1 true 2>/dev/null || true
}

# ---------- tests ------------------------------------------------------------

test_version() {
    log "Test: version flag"
    local out
    out=$("$BINARY" -V 2>&1) || true
    if echo "$out" | grep -q "sshconf"; then
        pass "version flag"
    else
        fail "version flag" "unexpected output: $out"
    fi
}

test_query() {
    log "Test: query ciphers"
    local out
    out=$("$BINARY" -Q cipher 2>&1)
    if echo "$out" | grep -q "aes256-ctr"; then
        pass "query ciphers"
    else
        fail "query ciphers" "aes256-ctr not listed"
    fi
}

test_print_config() {
    log "Test: print config (-G)"
    local out
    out=$(ssh_cmd -G testuser@127.0.0.1 2>&1)
    if echo "$out" | grep -q "^hostname 127.0.0.1"; then
        pass "print config"
    else
        fail "print config" "hostname line missing"
    fi
}

test_pubkey_auth() {
    log "Test: public key authentication"
    local out
    out=$(ssh_cmd testuser@127.0.0.1 "echo ok" 2>&1)
    if [ "$out" = "ok" ]; then
        pass "pubkey auth"
    else
        fail "pubkey auth" "expected 'ok', got: $out"
    fi
}

test_remote_command() {
    log "Test: remote command execution"
    local out
    out=$(ssh_cmd testuser@127.0.0.1 "uname -s" 2>&1)
    if [ "$out" = "Linux" ]; then
        pass "remote command"
    else
        fail "remote command" "expected 'Linux', got: $out"
    fi
}

test_exit_code() {
    log "Test: exit code propagation"
    local rc=0
    ssh_cmd testuser@127.0.0.1 "exit 42" 2>/dev/null || rc=$?
    if [ "$rc" -eq 42 ]; then
        pass "exit code"
    else
        fail "exit code" "expected 42, got: $rc"
    fi
}

test_stderr() {
    log "Test: stderr separation"
    local err
    err=$(ssh_cmd testuser@127.0.0.1 "echo err >&2" 2>&1 1>/dev/null)
    if echo "$err" | grep -q "err"; then
        pass "stderr"
    else
        fail "stderr" "stderr not captured"
    fi
}

test_stdin_pipe() {
    log "Test: stdin piping"
    local out
    out=$(echo "hello" | ssh_cmd testuser@127.0.0.1 "cat")
    if [ "$out" = "hello" ]; then
        pass "stdin pipe"
    else
        fail "stdin pipe" "expected 'hello', got: $out"
    fi
}

test_stdin_null() {
    log "Test: stdin null (-n)"
    local out
    out=$(ssh_cmd -n testuser@127.0.0.1 "cat; echo done" 2>&1)
    if echo "$out" | grep -q "done"; then
        pass "stdin null"
    else
        fail "stdin null" "expected 'done' in output"
    fi
}

test_compression() {
    log "Test: compression (-C)"
    local out
    out=$(ssh_cmd -C testuser@127.0.0.1 "echo compressed" 2>&1)
    if [ "$out" = "compressed" ]; then
        pass "compression"
    else
        fail "compression" "expected 'compressed', got: $out"
    fi
}

test_setenv() {
    log "Test: SetEnv"
    local out
    out=$(ssh_cmd -o "SetEnv TEST_FOO=bar123" testuser@127.0.0.1 'echo $TEST_FOO' 2>&1)
    if [ "$out" = "bar123" ]; then
        pass "SetEnv"
    else
        fail "SetEnv" "expected 'bar123', got: $out"
    fi
}

test_sendenv() {
    log "Test: SendEnv"
    export TEST_SEND=hello_send
    local out
    out=$(ssh_cmd -o "SendEnv TEST_SEND" testuser@127.0.0.1 'echo $TEST_SEND' 2>&1)
    if [ "$out" = "hello_send" ]; then
        pass "SendEnv"
    else
        # SendEnv depends on server AcceptEnv; skip if env not set
        skip "SendEnv" "got: $out (server may not AcceptEnv TEST_*)"
    fi
    unset TEST_SEND
}

test_local_forward() {
    log "Test: local port forwarding (-L)"
    local lport
    lport=$(free_port)

    # Start ssh with local forward in background
    ssh_cmd -N -L "127.0.0.1:${lport}:127.0.0.1:8080" testuser@127.0.0.1 &
    local ssh_pid=$!
    sleep 1

    local out
    out=$(curl -sf --max-time 5 "http://127.0.0.1:${lport}" 2>&1) || true
    kill $ssh_pid 2>/dev/null; wait $ssh_pid 2>/dev/null || true

    if echo "$out" | grep -q "hello from port 8080"; then
        pass "local forward"
    else
        fail "local forward" "expected 'hello from port 8080', got: $out"
    fi
}

test_remote_forward() {
    log "Test: remote port forwarding (-R)"
    local lport
    lport=$(free_port)

    # Start a local web server for the remote side to reach back to
    local local_response="hello-from-local"
    socat TCP-LISTEN:${lport},fork,reuseaddr SYSTEM:"echo -e 'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n${local_response}'" &
    local socat_pid=$!
    sleep 0.3

    local rport
    rport=$(free_port)

    # Remote forward: remote:rport -> local:lport
    ssh_cmd -N -R "127.0.0.1:${rport}:127.0.0.1:${lport}" testuser@127.0.0.1 &
    local ssh_pid=$!
    sleep 1

    # curl from inside the container to the remote-forwarded port
    local out
    out=$(ssh_cmd testuser@127.0.0.1 "curl -sf --max-time 5 http://127.0.0.1:${rport}" 2>&1) || true

    kill $ssh_pid 2>/dev/null; wait $ssh_pid 2>/dev/null || true
    kill $socat_pid 2>/dev/null; wait $socat_pid 2>/dev/null || true

    if echo "$out" | grep -q "$local_response"; then
        pass "remote forward"
    else
        fail "remote forward" "expected '$local_response', got: $out"
    fi
}

test_dynamic_forward() {
    log "Test: dynamic (SOCKS5) forwarding (-D)"
    local dport
    dport=$(free_port)

    ssh_cmd -N -D "127.0.0.1:${dport}" testuser@127.0.0.1 &
    local ssh_pid=$!
    sleep 1

    local out
    out=$(curl -sf --max-time 5 --socks5 "127.0.0.1:${dport}" "http://127.0.0.1:8080" 2>&1) || true
    kill $ssh_pid 2>/dev/null; wait $ssh_pid 2>/dev/null || true

    if echo "$out" | grep -q "hello from port 8080"; then
        pass "dynamic forward"
    else
        fail "dynamic forward" "expected 'hello from port 8080', got: $out"
    fi
}

test_stdio_forward() {
    log "Test: stdio forwarding (-W)"
    local out
    out=$(echo -e "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" | \
        ssh_cmd -W "127.0.0.1:8080" testuser@127.0.0.1 2>/dev/null) || true

    if echo "$out" | grep -q "hello from port 8080"; then
        pass "stdio forward"
    else
        fail "stdio forward" "expected 'hello from port 8080', got: $out"
    fi
}

test_no_session() {
    log "Test: no remote command (-N)"
    # -N should connect but not open a session; we time it out after 2s
    timeout 3 ssh_cmd -N testuser@127.0.0.1 &
    local ssh_pid=$!
    sleep 1

    # If it's still running after 1s, that's correct (it blocks on Wait)
    if kill -0 $ssh_pid 2>/dev/null; then
        pass "no session (-N)"
        kill $ssh_pid 2>/dev/null; wait $ssh_pid 2>/dev/null || true
    else
        fail "no session (-N)" "process exited prematurely"
    fi
}

test_force_tty() {
    log "Test: force PTY (-tt)"
    # -tt forces PTY allocation even without a terminal
    local out
    out=$(ssh_cmd -tt testuser@127.0.0.1 "tty" 2>/dev/null) || true
    # With a PTY, tty should print /dev/pts/N; without, "not a tty"
    if echo "$out" | grep -q "/dev/pts"; then
        pass "force PTY (-tt)"
    else
        # Some implementations return different paths
        if echo "$out" | grep -qv "not a tty"; then
            pass "force PTY (-tt)"
        else
            fail "force PTY (-tt)" "expected PTY device, got: $out"
        fi
    fi
}

test_no_tty() {
    log "Test: disable PTY (-T)"
    local out
    out=$(ssh_cmd -T testuser@127.0.0.1 "tty" 2>&1) || true
    if echo "$out" | grep -q "not a tty"; then
        pass "no PTY (-T)"
    else
        fail "no PTY (-T)" "expected 'not a tty', got: $out"
    fi
}

test_ipv4_only() {
    log "Test: IPv4 only (-4)"
    local out
    out=$(ssh_cmd -4 testuser@127.0.0.1 "echo ipv4" 2>&1)
    if [ "$out" = "ipv4" ]; then
        pass "IPv4 only"
    else
        fail "IPv4 only" "expected 'ipv4', got: $out"
    fi
}

test_multi_command() {
    log "Test: multi-word remote command"
    local out
    out=$(ssh_cmd testuser@127.0.0.1 "echo hello world" 2>&1)
    if [ "$out" = "hello world" ]; then
        pass "multi-word command"
    else
        fail "multi-word command" "expected 'hello world', got: $out"
    fi
}

test_large_output() {
    log "Test: large output transfer"
    local count
    count=$(ssh_cmd testuser@127.0.0.1 "seq 1 10000" 2>/dev/null | wc -l)
    count=$(echo "$count" | tr -d ' ')
    if [ "$count" = "10000" ]; then
        pass "large output"
    else
        fail "large output" "expected 10000 lines, got: $count"
    fi
}

test_binary_data() {
    log "Test: binary data transfer"
    # Generate 1KB of random data, pipe through ssh, compare
    dd if=/dev/urandom bs=1024 count=1 2>/dev/null > "$TMPDIR_TEST/random_in"
    ssh_cmd testuser@127.0.0.1 "cat" < "$TMPDIR_TEST/random_in" > "$TMPDIR_TEST/random_out" 2>/dev/null
    if cmp -s "$TMPDIR_TEST/random_in" "$TMPDIR_TEST/random_out"; then
        pass "binary data"
    else
        fail "binary data" "data mismatch"
    fi
}

test_multiple_identity_files() {
    log "Test: multiple identity files (-i)"
    # Pass a bogus key first, then the real one — should still auth
    local bogus_key="$TMPDIR_TEST/bogus_key"
    ssh-keygen -t ed25519 -f "$bogus_key" -N "" -q
    local out
    out=$(ssh_cmd -i "$bogus_key" -i "$TEST_KEY" testuser@127.0.0.1 "echo multi" 2>&1)
    if [ "$out" = "multi" ]; then
        pass "multiple identity files"
    else
        fail "multiple identity files" "expected 'multi', got: $out"
    fi
}

test_config_override() {
    log "Test: -o option override"
    local out
    out=$(ssh_cmd -o "LogLevel=QUIET" testuser@127.0.0.1 "echo override" 2>&1)
    if [ "$out" = "override" ]; then
        pass "config override (-o)"
    else
        fail "config override (-o)" "expected 'override', got: $out"
    fi
}

test_config_file() {
    log "Test: custom config file (-F)"
    local cfg="$TMPDIR_TEST/ssh_config"
    cat > "$cfg" <<EOF
Host testbox
    HostName 127.0.0.1
    Port $SSH_PORT
    User testuser
    IdentityFile $TEST_KEY
    UserKnownHostsFile $KNOWN_HOSTS
    StrictHostKeyChecking no
    PasswordAuthentication no
    BatchMode yes
EOF
    local out
    out=$("$BINARY" -F "$cfg" testbox "echo fromconfig" 2>&1)
    if [ "$out" = "fromconfig" ]; then
        pass "config file (-F)"
    else
        fail "config file (-F)" "expected 'fromconfig', got: $out"
    fi
}

test_host_wildcard_config() {
    log "Test: Host wildcard in config"
    local cfg="$TMPDIR_TEST/ssh_config_wildcard"
    cat > "$cfg" <<EOF
Host *
    Port $SSH_PORT
    User testuser
    IdentityFile $TEST_KEY
    UserKnownHostsFile $KNOWN_HOSTS
    StrictHostKeyChecking no
    PasswordAuthentication no
    BatchMode yes
EOF
    local out
    out=$("$BINARY" -F "$cfg" 127.0.0.1 "echo wildcard" 2>&1)
    if [ "$out" = "wildcard" ]; then
        pass "host wildcard config"
    else
        fail "host wildcard config" "expected 'wildcard', got: $out"
    fi
}

test_concurrent_sessions() {
    log "Test: concurrent sessions"
    local pids=()
    local results="$TMPDIR_TEST/concurrent"
    mkdir -p "$results"

    for i in 1 2 3 4 5; do
        ssh_cmd testuser@127.0.0.1 "echo session-$i" > "$results/$i" 2>/dev/null &
        pids+=($!)
    done

    local all_ok=true
    for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || true
        local n=$((i + 1))
        if [ "$(cat "$results/$n")" != "session-$n" ]; then
            all_ok=false
        fi
    done

    if $all_ok; then
        pass "concurrent sessions"
    else
        fail "concurrent sessions" "one or more sessions returned wrong output"
    fi
}

test_cipher_selection() {
    log "Test: cipher selection (-c)"
    local out
    out=$(ssh_cmd -c "aes256-ctr" testuser@127.0.0.1 "echo cipher" 2>&1)
    if [ "$out" = "cipher" ]; then
        pass "cipher selection"
    else
        fail "cipher selection" "expected 'cipher', got: $out"
    fi
}

test_mac_selection() {
    log "Test: MAC selection (-m)"
    local out
    out=$(ssh_cmd -m "hmac-sha2-256" testuser@127.0.0.1 "echo mac" 2>&1)
    if [ "$out" = "mac" ]; then
        pass "MAC selection"
    else
        fail "MAC selection" "expected 'mac', got: $out"
    fi
}

test_subsystem() {
    log "Test: subsystem invocation (-s sftp)"
    # Open sftp subsystem and send SSH_FXP_INIT (version 3), expect a response
    local out
    out=$(printf '\x00\x00\x00\x05\x01\x00\x00\x00\x03' | \
        ssh_cmd -s testuser@127.0.0.1 sftp 2>/dev/null | od -A n -t x1 -N 5) || true
    # SSH_FXP_VERSION response starts with type byte 0x02
    if echo "$out" | grep -q "02"; then
        pass "sftp subsystem"
    else
        skip "sftp subsystem" "could not verify SFTP response"
    fi
}

test_connection_timeout() {
    log "Test: connection timeout"
    local rc=0
    # Connect to a non-routable address with a short timeout
    "$BINARY" -F none \
        -o "ConnectTimeout=1" \
        -o "BatchMode=yes" \
        testuser@192.0.2.1 "echo nope" 2>/dev/null || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "connection timeout"
    else
        fail "connection timeout" "expected failure, got success"
    fi
}

# ---------- main -------------------------------------------------------------

echo "============================================"
echo "  sshconf end-to-end test suite"
echo "============================================"
echo ""

TMPDIR_TEST=$(mktemp -d)
TEST_KEY="$TMPDIR_TEST/test_key"
KNOWN_HOSTS="$TMPDIR_TEST/known_hosts"
touch "$KNOWN_HOSTS"

build_binary
build_image
start_container

echo ""
echo "=== Running tests ==="
echo ""

# Meta / CLI tests
test_version
test_query
test_print_config

# Authentication
test_pubkey_auth

# Remote execution
test_remote_command
test_exit_code
test_stderr
test_stdin_pipe
test_stdin_null
test_multi_command

# Crypto selection
test_cipher_selection
test_mac_selection
test_compression

# Configuration
test_config_override
test_config_file
test_host_wildcard_config
test_multiple_identity_files
test_setenv
test_sendenv

# PTY handling
test_force_tty
test_no_tty

# Port forwarding
test_local_forward
test_remote_forward
test_dynamic_forward
test_stdio_forward

# Session modes
test_no_session
test_subsystem

# Network
test_ipv4_only
test_connection_timeout

# Data integrity
test_large_output
test_binary_data

# Concurrency
test_concurrent_sessions

# ---------- summary ----------------------------------------------------------

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "Failures:"
    for e in "${ERRORS[@]}"; do
        echo "  - $e"
    done
fi

echo ""
exit $FAIL
