#!/usr/bin/env python3
"""
N4 — Port Knocking Server
Covert port access via SYN knock sequences.
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('knock-server')


class KnockServer:
    def __init__(self, interface='0.0.0.0', secret_port=8080,
                 knock_sequence=None, timeout=10, max_attempts=3):
        self.interface = interface
        self.secret_port = secret_port
        self.knock_sequence = knock_sequence or [7000, 8000, 9000]
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.authenticated_hosts = {}
        self.knock_log = []
        self._lock = threading.Lock()
        self._running = False
        self.stats = {
            'total_knocks': 0,
            'successful': 0,
            'failed': 0,
            'active_sessions': 0
        }

    def _validate_knock(self, src_ip, ports):
        """Validate knock sequence from a host."""
        with self._lock:
            if src_ip not in self.authenticated_hosts:
                self.authenticated_hosts[src_ip] = {
                    'ports': [],
                    'attempts': 0,
                    'timestamp': None,
                    'authenticated': False
                }

            entry = self.authenticated_hosts[src_ip]

            if entry['authenticated']:
                if time.time() - entry['timestamp'] < self.timeout:
                    return True
                entry['authenticated'] = False
                entry['ports'] = []

            for port in ports:
                if len(entry['ports']) < len(self.knock_sequence):
                    expected = self.knock_sequence[len(entry['ports'])]
                    if port == expected:
                        entry['ports'].append(port)
                        entry['timestamp'] = time.time()
                        log.info(
                            f"[KNOCK] {src_ip} -> port {port} "
                            f"({len(entry['ports'])}/{len(self.knock_sequence)})"
                        )
                    else:
                        entry['ports'] = []
                        entry['attempts'] += 1
                        if entry['attempts'] >= self.max_attempts:
                            log.warning(
                                f"[BLOCK] {src_ip} exceeded max attempts"
                            )
                        return False

            if entry['ports'] == self.knock_sequence:
                entry['authenticated'] = True
                entry['attempts'] = 0
                self.stats['successful'] += 1
                log.info(f"[AUTH] {src_ip} authenticated")
                self._log_event(src_ip, 'SUCCESS')
                return True

        return False

    def _log_event(self, src_ip, event):
        self.knock_log.append({
            'timestamp': time.time(),
            'src_ip': src_ip,
            'event': event
        })

    def _handle_syn(self, packet):
        """Process incoming SYN packet."""
        try:
            src_ip = packet[0][0]
            dst_port = packet[0][1]
            self.stats['total_knocks'] += 1

            if dst_port == self.secret_port:
                return

            if dst_port in self.knock_sequence:
                authenticated = self._validate_knock(src_ip, [dst_port])
                if authenticated:
                    log.info(
                        f"[OPEN] Granting access to {src_ip} "
                        f"on port {self.secret_port}"
                    )
        except Exception as e:
            log.debug(f"Packet parse error: {e}")

    def start(self):
        """Start the knock server using raw sockets."""
        self._running = True
        log.info("=== N4 — Port Knocking Server ===")
        log.info(f"Knock sequence: {self.knock_sequence}")
        log.info(f"Secret port: {self.secret_port}")
        log.info(f"Timeout: {self.timeout}s")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
            sock.settimeout(1.0)
        except PermissionError:
            log.error("Requires root privileges (raw sockets)")
            sys.exit(1)

        log.info("Listening for knock packets...")

        try:
            while self._running:
                try:
                    data, addr = sock.recvfrom(65535)
                    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
                    protocol = ip_header[6]

                    if protocol == 6:
                        tcp_header = struct.unpack(
                            '!HHLLBBHHH',
                            data[20:40]
                        )
                        src_port = tcp_header[0]
                        dst_port = tcp_header[1]
                        flags = tcp_header[5]
                        src_ip = socket.inet_ntoa(ip_header[8])

                        if flags & 0x02:
                            self._handle_syn(
                                ((src_ip, dst_port),)
                            )
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    break
        finally:
            sock.close()
            self._running = False
            self._print_stats()

    def stop(self):
        self._running = False

    def _print_stats(self):
        log.info("\n=== Statistics ===")
        log.info(f"Total knocks:    {self.stats['total_knocks']}")
        log.info(f"Successful auth: {self.stats['successful']}")
        log.info(f"Failed attempts: {self.stats['failed']}")


class KnockClient:
    def __init__(self, target, sequence=None, delay=0.5):
        self.target = target
        self.sequence = sequence or [7000, 8000, 9000]
        self.delay = delay

    def send_knock(self):
        """Send SYN knock sequence to target."""
        log.info(f"=== N4 — Port Knocking Client ===")
        log.info(f"Target: {self.target}")
        log.info(f"Sequence: {self.sequence}")

        for i, port in enumerate(self.sequence):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                log.info(
                    f"[KNOCK] Sent SYN to port {port} "
                    f"({i + 1}/{len(self.sequence)})"
                )
            except Exception as e:
                log.debug(f"Knock to {port}: {e}")

            if i < len(self.sequence) - 1:
                time.sleep(self.delay)

        log.info("[DONE] Knock sequence sent")
        time.sleep(1)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.sequence[-1] + 1))
            log.info("[ACCESS] Connection established")
            sock.close()
            return True
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            log.info(f"[ACCESS] Connection attempt result: {e}")
            return False


def cmd_server(args):
    server = KnockServer(
        interface=args.interface,
        secret_port=args.port,
        knock_sequence=[int(p) for p in args.sequence.split(',')],
        timeout=args.timeout,
        max_attempts=args.max_attempts
    )
    server.start()


def cmd_client(args):
    client = KnockClient(
        target=args.target,
        sequence=[int(p) for p in args.sequence.split(',')],
        delay=args.delay
    )
    client.send_knock()


def main():
    parser = argparse.ArgumentParser(
        description='N4 — Port Knocking Client/Server',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Command')

    srv = subparsers.add_parser('server', help='Start knock server')
    srv.add_argument('--interface', default='0.0.0.0',
                     help='Bind address (default: 0.0.0.0)')
    srv.add_argument('--port', type=int, default=8080,
                     help='Secret port (default: 8080)')
    srv.add_argument('--sequence', default='7000,8000,9000',
                     help='Knock sequence (default: 7000,8000,9000)')
    srv.add_argument('--timeout', type=int, default=10,
                     help='Auth timeout in seconds (default: 10)')
    srv.add_argument('--max-attempts', type=int, default=3,
                     help='Max failed attempts (default: 3)')
    srv.set_defaults(func=cmd_server)

    cli = subparsers.add_parser('client', help='Send knock sequence')
    cli.add_argument('target', help='Target IP address')
    cli.add_argument('--sequence', default='7000,8000,9000',
                     help='Knock sequence (default: 7000,8000,9000)')
    cli.add_argument('--delay', type=float, default=0.5,
                     help='Delay between knocks (default: 0.5)')
    cli.set_defaults(func=cmd_client)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == '__main__':
    main()
