#!/bin/sh
# Redirect clear-text HTTP and TLS traffic to ubproxy with netfilter.
#
#   ./ubproxy-redirect.sh up            # gateway mode: filter the LAN behind us
#   MODE=local ./ubproxy-redirect.sh up # filter this machine's own traffic
#   ./ubproxy-redirect.sh down
#
# Everything lives in a dedicated UBPROXY chain, so "down" removes exactly what
# "up" added and nothing else.
set -eu

HTTP_PORT="${HTTP_PORT:-8080}"
TLS_PORT="${TLS_PORT:-8443}"
LAN_IF="${LAN_IF:-eth1}"
MODE="${MODE:-gateway}"          # gateway | local
PROXY_USER="${PROXY_USER:-ubproxy}"
IPTABLES="${IPTABLES:-iptables}"

chain_exists() {
    $IPTABLES -t nat -n -L UBPROXY >/dev/null 2>&1
}

up() {
    chain_exists || $IPTABLES -t nat -N UBPROXY
    $IPTABLES -t nat -F UBPROXY

    # Never touch traffic aimed at the machine itself or at private services.
    $IPTABLES -t nat -A UBPROXY -d 127.0.0.0/8 -j RETURN
    $IPTABLES -t nat -A UBPROXY -d 10.0.0.0/8 -j RETURN
    $IPTABLES -t nat -A UBPROXY -d 172.16.0.0/12 -j RETURN
    $IPTABLES -t nat -A UBPROXY -d 192.168.0.0/16 -j RETURN
    $IPTABLES -t nat -A UBPROXY -d 169.254.0.0/16 -j RETURN

    $IPTABLES -t nat -A UBPROXY -p tcp --dport 80 -j REDIRECT --to-ports "$HTTP_PORT"
    $IPTABLES -t nat -A UBPROXY -p tcp --dport 443 -j REDIRECT --to-ports "$TLS_PORT"

    if [ "$MODE" = "local" ]; then
        # Skip the proxy's own connections, otherwise they loop back into it.
        $IPTABLES -t nat -C OUTPUT -p tcp -m owner --uid-owner "$PROXY_USER" -j RETURN 2>/dev/null ||
            $IPTABLES -t nat -I OUTPUT 1 -p tcp -m owner --uid-owner "$PROXY_USER" -j RETURN
        $IPTABLES -t nat -C OUTPUT -p tcp -j UBPROXY 2>/dev/null ||
            $IPTABLES -t nat -A OUTPUT -p tcp -j UBPROXY
    else
        $IPTABLES -t nat -C PREROUTING -i "$LAN_IF" -p tcp -j UBPROXY 2>/dev/null ||
            $IPTABLES -t nat -A PREROUTING -i "$LAN_IF" -p tcp -j UBPROXY
    fi

    # HTTP/3 travels over UDP/443 and would bypass the proxy entirely; rejecting
    # it makes browsers fall back to TLS over TCP, which we do see.
    if [ "$MODE" = "gateway" ]; then
        $IPTABLES -C FORWARD -i "$LAN_IF" -p udp --dport 443 -j REJECT 2>/dev/null ||
            $IPTABLES -A FORWARD -i "$LAN_IF" -p udp --dport 443 -j REJECT
    else
        $IPTABLES -C OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null ||
            $IPTABLES -A OUTPUT -p udp --dport 443 -j REJECT
    fi

    echo "ubproxy redirection enabled (mode=$MODE, http=$HTTP_PORT, tls=$TLS_PORT)"
}

down() {
    $IPTABLES -t nat -D PREROUTING -i "$LAN_IF" -p tcp -j UBPROXY 2>/dev/null || true
    $IPTABLES -t nat -D OUTPUT -p tcp -j UBPROXY 2>/dev/null || true
    $IPTABLES -t nat -D OUTPUT -p tcp -m owner --uid-owner "$PROXY_USER" -j RETURN 2>/dev/null || true
    $IPTABLES -A FORWARD -i "$LAN_IF" -p udp --dport 443 -j REJECT 2>/dev/null && \
        $IPTABLES -D FORWARD -i "$LAN_IF" -p udp --dport 443 -j REJECT 2>/dev/null || true
    $IPTABLES -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null || true
    if chain_exists; then
        $IPTABLES -t nat -F UBPROXY
        $IPTABLES -t nat -X UBPROXY
    fi
    echo "ubproxy redirection removed"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
