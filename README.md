# N4 — Port Knocking Client/Server

Covert access to a hidden port via a pre-defined knock sequence. The default
`listen` transport is plain TCP over localhost (unprivileged, deterministic);
a raw-socket SYN watcher is available behind `--live` for real interfaces.

## Overview

This project implements a port knocking system that grants access to a secret
port only after receiving the correct sequence of TCP connection attempts. It
is intended for authorized own-lab testing of network access control design.

**Two server transports:**
- `listen` (default): real TCP listeners on the knock ports and the secret
  port. Works end-to-end over 127.0.0.1 with no privileges — this is what the
  selftest and unit tests exercise.
- `raw` (`--live`): raw-socket SYN watcher on a real interface (root only).

## What Works

- **Sequence state machine** (`KnockGate`) — per-source-IP validation with
  attempts counter and grant timeout; shared by both transports.
- **Listener server** (`ListenerKnockServer`) — grants the secret port
  (banner `OK-AUTH`) only after the full knock sequence; answers `DENIED`
  before it. Acks each knock so the client never races the server.
- **Real localhost end-to-end** (`selftest`) — client knocks via genuine TCP
  connects against 127.0.0.1 and proves the secret port was gated, then opened.
- **Raw live watcher** (`RawKnockWatcher`, `--live`) — parses real SYN packets.

## Usage

```bash
# Deterministic localhost end-to-end selftest (no privileges)
python3 knock_server.py selftest

# Run a listen-mode server explicitly
python3 knock_server.py server --sequence 7000,8000,9000 --port 8443

# Knock from a client, then probe the secret port
python3 knock_client.py 127.0.0.1 --sequence 7000,8000,9000 --secret-port 8443

# Live raw-socket SYN watcher (root): explicit --live required
sudo python3 knock_server.py server --live --transport raw \
      --sequence 7000,8000,9000
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, 00:11:22:33:44:55).

1. Run `python3 knock_server.py server --sequence 7000,8000,9000 --port 22` on the
   lab target (or `server --live --transport raw` for a real SYN watcher).
2. From the lab client run `python3 knock_client.py 192.0.2.10 --sequence 7000,8000,9000 --secret-port 22`.
3. Confirm the server logs `[AUTH]` and the client receives `OK-AUTH`.
4. Probe the secret port **before** knocking and confirm the answer is `DENIED`.
5. Drive a wrong-sequence client and confirm `[BLOCK]`-style behaviour (attempt
   counter increments, no grant).

## Metrics

Core offline harness (localhost, no privileges) is deterministic and unit-tested:

- Sequence state machine (correct/wrong order/unknown port/timeout): PASS (5 tests)
- End-to-end: denied before knock, `OK-AUTH` after knock over real TCP: PASS
- Wrong sequence keeps the port closed: PASS
- Grant window expiry re-closes the port: PASS (9 tests total)
- Exit code: `0` on successful selftest, `1` on failure

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT