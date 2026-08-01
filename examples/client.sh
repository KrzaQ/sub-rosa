#!/bin/sh
# Fetch a secret from a running rosa agent. Requires socat and jq.
# usage: client.sh NAME
#
# socat's -t is how long it stays connected after stdin closes; it must
# outlive the agent's request_timeout_secs or an unanswered approval
# prompt kills the wait early.
set -eu

name=$1
sock=${ROSA_SOCK:-${XDG_CONFIG_HOME:-$HOME/.config}/rosa/rosa.sock}

reply=$(printf '{"op":"get","name":"%s"}\n' "$name" | socat -t 120 - "UNIX-CONNECT:$sock")

if [ "$(printf '%s' "$reply" | jq -r .ok)" = "true" ]; then
    printf '%s' "$(printf '%s' "$reply" | jq -r .value)"
else
    echo "rosa: $(printf '%s' "$reply" | jq -r .error)" >&2
    exit 1
fi
