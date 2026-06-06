# ICMP Data Transfer Secure (IDTS)

`IDTS` means **ICMP Data Transfer Secure**.

It is a secure, reliable, unordered transport derived from the `USTP-Secure` design, but using **ICMP instead of UDP**.

Architecture:
- server: `FFmpeg -> IDTS sender -> ICMP`
- client: `ICMP -> IDTS receiver -> local TCP/UDP output`

Status: **Beta**

## What IDTS is
- ICMP-based transport
- AEAD mandatory
- X25519 per-client key exchange
- multi-client server support
- selective retransmission
- unordered transport behavior
- NAT traversal strategy based on client keepalive and endpoint learning

## Security model
- no plaintext mode
- supported AEAD ciphers:
  - `chacha20`
  - `aes-256-gcm`
  - `aes-128-gcm`
- each client negotiates its own ephemeral session key
- server host key is persistent by default
- TOFU is enabled on the client

Default files:
- server host key: `~/.idts_host_key`
- client TOFU database: `~/.idts_known_hosts.json`

## Transport model
- IDTS stays **unordered** at the transport layer
- later packets are accepted even if earlier packets are missing
- retransmission is selective, not Go-Back-N
- `seq` is used for reliability
- `stream_pos` is used by the application if it wants ordered reconstruction

## NAT traversal
IDTS uses client-originated ICMP keepalive traffic so the server can:
- learn the client's current public endpoint
- keep sending back through the same NAT mapping
- migrate sessions when the source endpoint changes

Practical note:
- ICMP NAT behavior is much less predictable than UDP
- some NATs, CGNATs, routers, and firewalls treat ICMP very differently
- some environments simply will not carry this reliably

## Very important ICMP warning
Many ISPs, CGNATs, Wi-Fi networks, VPS providers, and enterprise networks **rate-limit ICMP**.

Because of that, `IDTS` can be:
- much slower than `USTPS`
- unstable under heavier traffic
- sometimes **absurdly slow** if the network heavily shapes ICMP

If the network rate-limits ICMP aggressively, speeds can become extremely low even when the same path performs well with UDP.

## ICMP tuning defaults
The current defaults are intentionally conservative to reduce ICMP burstiness:
- client keepalive is slower than the UDP-based USTPS defaults
- sender pacing is enabled
- send bursts are smaller
- outbound queues are bounded more aggressively

This is not because ICMP is inherently better at low speed, but because many real networks penalize bursty ICMP much more aggressively than bursty UDP.

## IDTS vs USTPS
- `USTPS`:
  - transport: UDP
  - generally better throughput
  - usually better for streaming in real networks
  - less likely to be heavily rate-limited by ISPs
- `IDTS`:
  - transport: ICMP
  - useful when experimenting with ICMP-based transport behavior
  - may cross some paths differently than UDP
  - can become extremely slow on networks that shape or rate-limit ICMP

Short version:
- if you want real throughput, `USTPS` is usually the better choice
- if you specifically want ICMP transport semantics, use `IDTS`

## Root requirement
IDTS uses raw ICMP sockets.

That means:
- root is required on Linux/Android environments
- raw socket support must be available

## Server example
```bash
python3 server.py \
  --bind-ip 0.0.0.0 \
  --bind-id 0 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --cipher chacha20
```

## Custom ffmpeg parameters
Without `--video-parameters`, the server uses:
- `-c copy -mpegts_flags +resend_headers`

If you want custom ffmpeg parameters instead:
```bash
python3 server.py \
  --bind-ip 0.0.0.0 \
  --bind-id 0 \
  --video "<HLS_URL_OR_LOCAL_FILE>" \
  --video-parameters "-c:v libx264 -preset veryfast -b:v 2500k -c:a aac -b:a 128k -mpegts_flags +resend_headers" \
  --cipher chacha20
```

## Client example
```bash
python3 client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --bind-ip 0.0.0.0 \
  --bind-id 0 \
  --output-mode tcp \
  --tcp-host 127.0.0.1 \
  --tcp-port 1238 \
  --cipher chacha20
```

VLC:
```text
tcp://127.0.0.1:1238
```

## Notes
- default local playout delay is `350ms`
- `--udp-unordered-live` is still dangerous for generic players
- for strict ordered byte-stream applications, ordering still has to happen above the transport
- this repository is focused on streaming over IDTS
