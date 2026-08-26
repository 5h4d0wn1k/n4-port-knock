#!/usr/bin/env python3
"""
N4 — Port Knocking Utility Library
Shared utilities for knock client/server.
"""

import hashlib
import hmac
import os
import secrets
import struct
import time
from typing import List, Optional


class KnockSequence:
    """Represents a validated knock sequence."""

    def __init__(self, ports: List[int], secret: Optional[bytes] = None):
        self.ports = ports
        self.secret = secret or os.urandom(32)
        self._nonce = secrets.token_bytes(8)

    @property
    def expected(self) -> List[int]:
        return self.ports

    def generate(self) -> List[int]:
        """Generate a fresh knock sequence with HMAC verification."""
        nonce_int = int.from_bytes(self._nonce, 'big')
        result = []
        for port in self.ports:
            data = struct.pack('!QI', nonce_int, port)
            h = hmac.new(self.secret, data, hashlib.sha256).digest()
            obfuscated = port ^ int.from_bytes(h[:2], 'big')
            result.append(obfuscated % 65535 + 1)
        return result

    def validate(self, received: List[int], expected: List[int]) -> bool:
        """Validate received sequence matches expected."""
        if len(received) != len(expected):
            return False
        return all(r == e for r, e in zip(received, expected))


class KnockTimer:
    """Timing utilities for knock sequences."""

    def __init__(self):
        self.start_time = None
        self.events = []

    def start(self):
        self.start_time = time.monotonic()
        self.events = []

    def event(self, name: str):
        if self.start_time:
            elapsed = time.monotonic() - self.start_time
            self.events.append((name, elapsed))

    def elapsed(self) -> float:
        if self.start_time:
            return time.monotonic() - self.start_time
        return 0.0

    def summary(self) -> str:
        lines = ["Timing Summary:"]
        for name, t in self.events:
            lines.append(f"  {name}: {t*1000:.2f}ms")
        return '\n'.join(lines)


def random_sequence(length: int = 3,
                    min_port: int = 1024,
                    max_port: int = 65535) -> List[int]:
    """Generate a random knock sequence."""
    return sorted(secrets.randbelow(max_port - min_port) + min_port
                  for _ in range(length))


def stealth_delay() -> float:
    """Calculate a random stealth delay between knocks."""
    return secrets.randbelow(500) / 1000.0 + 0.1
