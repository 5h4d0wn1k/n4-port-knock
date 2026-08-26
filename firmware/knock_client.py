#!/usr/bin/env python3
"""
N4 — Port Knocking Client
Sends covert SYN knock sequences to open hidden services.
"""

import argparse
import logging
import socket
import struct
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('knock-client')


class KnockClient:
    def __init__(self, target, sequence=None, delay=0.5,
                 secret_port=None, retries=3):
        self.target = target
        self.sequence = sequence or [7000, 8000, 9000]
        self.delay = delay
        self.secret_port = secret_port
        self.retries = retries
        self.stats = {
            'knocks_sent': 0,
            'connections_attempted': 0,
            'connections_successful': 0
        }

    def _send_syn(self, port):
        """Send a single SYN packet."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            sock.close()
            self.stats['knocks_sent'] += 1
            return True
        except Exception as e:
            log.debug(f"SYN to {port} failed: {e}")
            return False

    def send_sequence(self):
        """Send the full knock sequence."""
        log.info(f"Target: {self.target}")
        log.info(f"Sequence: {self.sequence}")
        log.info(f"Delay: {self.delay}s")

        for i, port in enumerate(self.sequence):
            success = self._send_syn(port)
            status = "SENT" if success else "FAIL"
            log.info(
                f"[{status}] Port {port} "
                f"({i + 1}/{len(self.sequence)})"
            )
            if i < len(self.sequence) - 1:
                time.sleep(self.delay)

        log.info(f"[DONE] {self.stats['knocks_sent']} knocks sent")

    def probe_secret(self):
        """Attempt to connect to the secret port after knocking."""
        if not self.secret_port:
            return False

        log.info(f"Probing secret port {self.secret_port}...")
        for attempt in range(self.retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target, self.secret_port))
                log.info("[CONNECTED] Secret port is open!")
                sock.close()
                self.stats['connections_successful'] += 1
                return True
            except (ConnectionRefusedError, socket.timeout) as e:
                log.info(
                    f"[ATTEMPT {attempt + 1}] "
                    f"Connection refused: {e}"
                )
                self.stats['connections_attempted'] += 1
                time.sleep(1)

        log.info("[FAILED] Could not connect to secret port")
        return False

    def print_stats(self):
        log.info("\n=== Statistics ===")
        log.info(f"Knocks sent:     {self.stats['knocks_sent']}")
        log.info(f"Probes attempted: {self.stats['connections_attempted']}")
        log.info(f"Probes succeeded: {self.stats['connections_successful']}")


def main():
    parser = argparse.ArgumentParser(
        description='N4 — Port Knocking Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.100 --sequence 1000,2000,3000
  %(prog)s 192.168.1.100 --secret-port 8080 --delay 1.0
        """
    )

    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--sequence', default='7000,8000,9000',
                        help='Comma-separated knock sequence (default: 7000,8000,9000)')
    parser.add_argument('--delay', type=float, default=0.5,
                        help='Delay between knocks in seconds (default: 0.5)')
    parser.add_argument('--secret-port', type=int, default=None,
                        help='Secret port to probe after knocking')
    parser.add_argument('--retries', type=int, default=3,
                        help='Connection retry count (default: 3)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable debug output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sequence = [int(p.strip()) for p in args.sequence.split(',')]

    client = KnockClient(
        target=args.target,
        sequence=sequence,
        delay=args.delay,
        secret_port=args.secret_port,
        retries=args.retries
    )

    log.info("=== N4 — Port Knocking Client ===")
    client.send_sequence()

    if args.secret_port:
        client.probe_secret()

    client.print_stats()


if __name__ == '__main__':
    main()
