# N4 — Port Knocking Client/Server

Covert port access via SYN knock sequences for authorized security testing.

## Overview

This project implements a port knocking system that provides covert access to hidden services. Port knocking is a security mechanism where a closed port is opened after receiving a pre-defined sequence of connection attempts (knocks) to specific ports.

**Use cases:**
- Hidden SSH/TCP service access
- Covert channel establishment
- Network access control research
- Security hardening validation

## Features

- **SYN Knock Sequence**: Sends TCP SYN packets to pre-defined ports
- **HMAC Authentication**: Optional HMAC-based sequence verification
- **Timing Stealth**: Random delays between knocks
- **Client/Server Architecture**: Complete client and server implementations
- **Statistics Tracking**: Monitor knock attempts and successes

## Architecture

```
Client                    Server
  |                         |
  |-- SYN:7000 ----------->|
  |-- SYN:8000 ----------->|
  |-- SYN:9000 ----------->|
  |<-- [Port 8080 Opens] --|
  |<-- Connection OK ------|
```

## Installation

```bash
# Clone and install
git clone https://github.com/yourorg/n4-port-knock.git
cd n4-port-knock/firmware
pip install -r requirements.txt

# Or install directly
pip install pycryptodome
```

### Dependencies

```bash
pip install pycryptodome
```

## Usage

### Server

```bash
# Start knock server on all interfaces
sudo python3 knock_server.py server --port 8080

# Custom knock sequence
sudo python3 knock_server.py server --sequence 1000,2000,3000

# With authentication timeout
sudo python3 knock_server.py server --timeout 15 --max-attempts 5
```

### Client

```bash
# Basic knock
python3 knock_client.py 192.168.1.100

# Custom sequence
python3 knock_client.py 192.168.1.100 --sequence 1000,2000,3000

# With secret port probe
python3 knock_client.py 192.168.1.100 --secret-port 8080

# With verbose output
python3 knock_client.py 192.168.1.100 -v
```

### Example Output

```
=== N4 — Port Knocking Client ===
Target: 192.168.1.100
Sequence: [7000, 8000, 9000]
Delay: 0.5s
[SENT] Port 7000 (1/3)
[SENT] Port 8000 (2/3)
[SENT] Port 9000 (3/3)
[DONE] 3 knocks sent
[ACCESS] Connection attempt result: Connection refused
```

## Command Reference

### `server` Command
| Flag | Description | Default |
|------|-------------|---------|
| `--interface` | Bind address | 0.0.0.0 |
| `--port` | Secret port | 8080 |
| `--sequence` | Knock sequence | 7000,8000,9000 |
| `--timeout` | Auth timeout (s) | 10 |
| `--max-attempts` | Max failed attempts | 3 |

### `client` Command
| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target IP | (required) |
| `--sequence` | Knock sequence | 7000,8000,9000 |
| `--delay` | Inter-knock delay (s) | 0.5 |
| `--secret-port` | Port to probe | (none) |
| `--retries` | Connection retries | 3 |

## How It Works

1. **Knock Phase**: Client sends SYN packets to each port in sequence
2. **Validation**: Server tracks incoming SYNs and validates sequence
3. **Access Grant**: Upon valid sequence, server opens secret port
4. **Connection**: Client connects to newly opened port
5. **Session Expiry**: Access expires after timeout period

## Security Considerations

- SYN packets can be logged by IDS/IPS systems
- Timing analysis may detect knock sequences
- Use HMAC-verified sequences for stronger authentication
- Consider rate limiting on server side

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
