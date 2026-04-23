#!/bin/sh
set -eu
if [ -n "${FLAG:-}" ]; then
  printf '%s\n' "$FLAG" > /app/flag.txt
  chmod 444 /app/flag.txt || true
fi
exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./ld-linux-x86-64.so.2 --library-path . ./cider_vault",stderr
