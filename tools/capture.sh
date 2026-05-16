#!/usr/bin/env bash
#
# tools/capture.sh - automated PyTCP example capture helper.
#
# Brings up a chosen example scenario on a TAP interface, waits until
# the stack is actually ready (no hand-timing), drives the client
# exchange, captures the wire with tshark, and prints a clean
# README-ready transcript: filtered stack log + tshark decode (+ the
# client output for echo scenarios). All processes are torn down on
# exit via a trap, so nothing is left running.
#
# Run as root on a host where the TAP/bridge is already set up
# (`make tap7 && make bridge`) and the venv is built (`make venv`).
#
# Usage:
#   sudo tools/capture.sh <scenario>
#
# Scenarios:
#   boot   - full startup: IPv6 LLA/SLAAC DAD, MLDv2, RS/RA, IPv4 ACD
#   arp    - RFC 5227 ARP Probe / Announcement
#   icmp   - host pings the stack (ARP resolution + ICMP Echo)
#   tcp    - TCP echo, client sends 'malpi' (the ASCII monkeys)
#   udp    - UDP echo, client sends 'malpi' (the ASCII monkeys)
#
# Environment overrides:
#   IFACE (tap7)  IP4 (192.168.1.77/24)  GW4 (192.168.1.1)
#   PORT (7)      PEER (192.168.1.10 - the host side, for icmp)
#
set -euo pipefail

IFACE="${IFACE:-tap7}"
IP4="${IP4:-192.168.1.77/24}"
GW4="${GW4:-192.168.1.1}"
PORT="${PORT:-7}"
PEER="${PEER:-}"
IP4_ADDR="${IP4%%/*}"

# Readiness waits. A static address is not owned until RFC 5227 ACD
# (and any IPv6 SLAAC) completes, then the service rebinds on its
# next 0.5 s retry; on a busy bridged LAN this can take well over
# 30 s, so the defaults are generous and env-tunable.
CLAIM_TIMEOUT="${CLAIM_TIMEOUT:-60}"
BIND_TIMEOUT="${BIND_TIMEOUT:-90}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PY:-$ROOT/venv/bin/python}"

TMP="$(mktemp -d)"
PCAP="$TMP/cap.pcap"
LOG="$TMP/stack.log"
OUT="$TMP/client.out"
SVC_PID=""
CAP_PID=""

cleanup() {
    [ -n "$SVC_PID" ] && kill -INT "$SVC_PID" 2>/dev/null || true
    sleep 1
    [ -n "$SVC_PID" ] && kill -9 "$SVC_PID" 2>/dev/null || true
    [ -n "$CAP_PID" ] && { kill -TERM "$CAP_PID" 2>/dev/null; sleep 1; kill -9 "$CAP_PID" 2>/dev/null; } || true
    pkill -9 -f 'examples\.' 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (packet capture + TAP need it)"
[ -x "$PY" ] || die "venv python not found at $PY (run: make venv)"
command -v tshark >/dev/null || die "tshark not installed"
ip link show "$IFACE" >/dev/null 2>&1 || die "interface $IFACE missing (run: make tap7)"

strip() { sed -r 's/\x1b\[[0-9;]*m//g'; }

# wait_for <grep-pattern> <timeout-seconds>
wait_for() {
    local pat="$1" t="${2:-40}" i=0
    while [ "$i" -lt "$t" ]; do
        grep -aq -- "$pat" "$LOG" 2>/dev/null && return 0
        sleep 1
        i=$((i + 1))
    done
    die "timed out after ${t}s waiting for: $pat"
}

start_capture() { # <bpf-filter>
    # tshark (already required for decoding) doubles as the
    # capture engine, so there is no tcpdump dependency. It writes
    # the savefile incrementally; a graceful SIGTERM on stop flushes
    # and closes it cleanly.
    tshark -i "$IFACE" -f "$1" -w "$PCAP" >/dev/null 2>&1 &
    CAP_PID=$!
    disown "$CAP_PID" 2>/dev/null || true
    sleep 1
}

start_example() { # <module> [args...]
    # shellcheck disable=SC2068
    PYTHONPATH="$ROOT" "$PY" -u -m "$@" >"$LOG" 2>&1 &
    SVC_PID=$!
    disown "$SVC_PID" 2>/dev/null || true
}

stop_example() {
    kill -INT "$SVC_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$SVC_PID" 2>/dev/null || true
    SVC_PID=""
    # SIGTERM (not KILL) so tshark flushes and closes the pcap.
    kill -TERM "$CAP_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$CAP_PID" 2>/dev/null || true
    CAP_PID=""
}

log_highlights() { # <grep-pattern> [max-lines]
    echo "=== stack log ==="
    strip <"$LOG" | grep -aE -- "$1" | grep -avE 'RX-RING|TX-RING|^ *[0-9.]+ \| ETHER' | head -"${2:-18}" || true
}

wire() { # tshark args
    echo
    echo "=== wire capture ($IFACE) ==="
    local out
    out="$(tshark -r "$PCAP" "$@" 2>/dev/null || true)"
    if [ -z "$out" ]; then
        # Field/filter mismatch or empty pcap - fall back to the
        # default packet summary so the block is never silently
        # blank, and surface tshark's own error.
        out="$(tshark -r "$PCAP" 2>&1 || true)"
    fi
    [ -n "$out" ] && echo "$out" || echo "(no packets captured)"
}

scenario="${1:-}"
case "$scenario" in
boot)
    start_capture "ip6 or arp"
    start_example examples.stack --stack-interface "$IFACE" \
        --stack-ip4-address "$IP4" --stack-ip4-gateway "$GW4"
    wait_for "Successfully claimed IPv4 address ${IP4_ADDR}" "$CLAIM_TIMEOUT"
    sleep 2
    stop_example
    log_highlights 'ICMPv6 ND DAD - (Starting|No duplicate)|Successfully claimed|Sent out ICMPv6 ND Router Solicitation|Sent out ARP Announcement|Multicast Listener Report .HBH' 16
    wire -Y 'eth.src==02:00:00:77:77:77' -T fields \
        -e frame.time_relative -e _ws.col.Protocol -e _ws.col.Info
    ;;
arp)
    start_capture arp
    start_example examples.stack --stack-interface "$IFACE" \
        --stack-ip4-address "$IP4" --stack-ip4-gateway "$GW4" --stack-no-ip6
    wait_for "Successfully claimed IPv4 address ${IP4_ADDR}" "$CLAIM_TIMEOUT"
    sleep 1
    stop_example
    log_highlights 'Sent out ARP Probe|Sent out ARP Announcement|Successfully claimed IPv4' 10
    wire -Y arp -T fields -e frame.time_relative -e _ws.col.Info
    ;;
icmp)
    [ -n "$PEER" ] || PEER="$(ip -4 -o addr show 2>/dev/null \
        | awk '$2!="lo"{sub(/\/.*/,"",$4);print $4;exit}')"
    start_capture "arp or icmp"
    start_example examples.stack --stack-interface "$IFACE" \
        --stack-ip4-address "$IP4" --stack-ip4-gateway "$GW4" --stack-no-ip6
    wait_for "Successfully claimed IPv4 address ${IP4_ADDR}" "$CLAIM_TIMEOUT"
    sleep 1
    ping -c 3 -W 1 "$IP4_ADDR" >"$OUT" 2>&1 || true
    sleep 1
    stop_example
    echo "=== host ping ($PEER -> $IP4_ADDR) ==="
    tail -2 "$OUT"
    wire -Y 'arp || icmp' -T fields \
        -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info
    ;;
tcp | udp)
    if [ "$scenario" = tcp ]; then
        mod=examples.service__tcp_echo
    else
        mod=examples.service__udp_echo
    fi
    start_capture "(${scenario} port ${PORT}) or arp"
    start_example "$mod" --local-port "$PORT" --stack-interface "$IFACE" \
        --stack-ip4-address "$IP4" --stack-ip4-gateway "$GW4" --stack-no-ip6
    wait_for "Socket created, bound to ${IP4_ADDR}, port ${PORT}" "$BIND_TIMEOUT"
    # Only TCP transitions to listening; a bound UDP socket is
    # immediately ready to recvfrom (no listen()).
    [ "$scenario" = tcp ] && wait_for "Socket set to listening mode" 10
    sleep 1
    if [ "$scenario" = tcp ]; then
        printf 'malpi\nquit\n' | timeout 8 nc -w5 "$IP4_ADDR" "$PORT" >"$OUT" 2>&1 || true
    else
        printf 'malpi\n' | timeout 8 nc -u -w3 "$IP4_ADDR" "$PORT" >"$OUT" 2>&1 || true
    fi
    sleep 2
    stop_example
    echo "=== client output (banner + echoed 'malpi' monkeys) ==="
    cat "$OUT"
    # TCP payload length is 'tcp.len'; UDP's is 'udp.length'.
    if [ "$scenario" = tcp ]; then
        len_field=tcp.len
    else
        len_field=udp.length
    fi
    wire -Y "${scenario}.port==${PORT} || arp" -T fields \
        -e frame.time_relative -e ip.src -e ip.dst \
        -e tcp.flags.str -e "$len_field" -e _ws.col.Info
    ;;
*)
    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
