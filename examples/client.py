#!/usr/bin/env python3
"""Fetch a secret from a running rosa agent.

Import rosa_get() into your script, or run: client.py NAME
"""
import json
import os
import socket
import sys


def rosa_get(name: str) -> str:
    sock_path = os.environ.get("ROSA_SOCK") or os.path.join(
        os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"), "rosa.sock"
    )
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(sock_path)
        s.sendall(json.dumps({"op": "get", "name": name}).encode() + b"\n")
        # A confirm-gated secret blocks here until the human decides.
        reply = json.loads(s.makefile().readline())
    if not reply.get("ok"):
        raise RuntimeError(f"rosa: {reply.get('error', 'unknown error')}")
    return reply["value"]


if __name__ == "__main__":
    try:
        print(rosa_get(sys.argv[1]), end="")
    except (RuntimeError, OSError) as e:
        sys.exit(str(e))
