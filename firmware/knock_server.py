#!/usr/bin/env python3
"""
N4 - Port Knocking Client/Server
Covert port access via knock sequences.

Two transports for the server:
  - `listen` (DEFAULT): plain TCP listeners on the knock ports and the secret
    port. Client knocks open an actual TCP connection on each knock port; the
    server only grants the secret port after the full sequence. Runs
    unprivileged and deterministically over localhost - this is the path used
    by the offline harness and the unit tests.
  - `raw` (gated behind --live): real raw-socket SYN watcher on a network
    interface. Requires root and a genuine packet path.

The state machine (KnockGate) is shared by both transports, so the offline
harness exercises exactly the same core code as live mode.
"""
import argparse
import logging
import select
import socket
import struct
import sys
import threading
import time

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger('knock-server')


class KnockGate:
    """Per-source-IP knock sequence state machine."""

    def __init__(self, knock_sequence=None, timeout=10, max_attempts=3):
        self.knock_sequence = list(knock_sequence or [7000, 8000, 9000])
        self.timeout = timeout
        self.max_attempts = max_attempts
        self._state = {}          # src_ip -> dict
        self._lock = threading.Lock()
        self.stats = {'total_knocks': 0, 'successful': 0, 'failed': 0}

    def _entry(self, src_ip):
        if src_ip not in self._state:
            self._state[src_ip] = {
                'ports': [], 'attempts': 0, 'timestamp': None,
                'authenticated': False,
            }
        return self._state[src_ip]

    def handle(self, src_ip, port):
        """Record a knock event; returns True when the full sequence matched.

        Ports must arrive in the configured order; any mismatch resets the
        pending sequence for that source.
        """
        with self._lock:
            self.stats['total_knocks'] += 1
            if port == self.knock_sequence[-1] + 1:
                # Secret port is not a knock port; ignore knocks aimed at it.
                return self.is_authenticated(src_ip)
            if port not in self.knock_sequence:
                entry = self._entry(src_ip)
                entry['ports'] = []
                entry['attempts'] += 1
                self.stats['failed'] += 1
                return False
            entry = self._entry(src_ip)

            if entry['authenticated']:
                if time.time() - (entry['timestamp'] or 0) < self.timeout:
                    return True
                entry['authenticated'] = False
                entry['ports'] = []

            expected = self.knock_sequence[len(entry['ports'])]
            if port != expected:
                entry['ports'] = []
                entry['attempts'] += 1
                self.stats['failed'] += 1
                return False

            entry['ports'].append(port)
            entry['timestamp'] = time.time()
            log.info('[KNOCK] %s -> port %s (%s/%s)', src_ip, port,
                     len(entry['ports']), len(self.knock_sequence))

            if entry['ports'] == self.knock_sequence:
                entry['authenticated'] = True
                entry['attempts'] = 0
                self.stats['successful'] += 1
                log.info('[AUTH] %s authenticated', src_ip)
                return True
            return False

    def is_authenticated(self, src_ip):
        with self._lock:
            entry = self._entry(src_ip)
            if not entry['authenticated']:
                return False
            if time.time() - (entry['timestamp'] or 0) >= self.timeout:
                entry['authenticated'] = False
                entry['ports'] = []
                return False
            return True

    def reset(self):
        with self._lock:
            self._state.clear()
            self.stats = {'total_knocks': 0, 'successful': 0, 'failed': 0}


class ListenerKnockServer:
    """Plain-TCP knock server for unprivileged localhost demos/tests.

    Listens on each knock port: an inbound connect() is the knock. Listens on
    the secret port too: connections are answered DENIED until the sequence
    completes, then OK-AUTH.
    """

    def __init__(self, host='127.0.0.1', secret_port=0, knock_sequence=None,
                 timeout=10, max_attempts=3, banner=b'OK-AUTH\n',
                 denied=b'DENIED\n'):
        self.host = host
        self.secret_port = secret_port
        self.knock_sequence = list(knock_sequence or [7000, 8000, 9000])
        self.banner = banner
        self.denied = denied
        self.gate = KnockGate(self.knock_sequence, timeout, max_attempts)
        self._socks = []
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self.knock_ports = []
        self.granted = 0
        self.denied_count = 0

    def start(self):
        """Bind all knock ports + the secret port; return bound ports."""
        secret = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secret.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        secret.bind((self.host, self.secret_port))
        secret.listen(64)
        self.secret_port = secret.getsockname()[1]
        self._socks.append((None, secret))

        for port in self.knock_sequence:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, port))
            s.listen(64)
            self._socks.append((port, s))
        self.knock_ports = [s.getsockname()[1] for _, s in self._socks
                            if _ is not None]
        return self.knock_ports, self.secret_port

    def serve(self):
        """Accept-loop until stop(); run in a thread."""
        self._running = True
        while self._running:
            try:
                ready, _, _ = select.select([s for _, s in self._socks],
                                            [], [], 0.2)
                for s in ready:
                    conn, addr = s.accept()
                    with self._lock:
                        port = s.getsockname()[1]
                        if port == self.secret_port:
                            if self.gate.is_authenticated(addr[0]):
                                self.granted += 1
                                conn.sendall(self.banner)
                            else:
                                self.denied_count += 1
                                conn.sendall(self.denied)
                        else:
                            self.gate.handle(addr[0], port)
                            # Ack the knock so the client knows it was
                            # processed before moving to the next port.
                            conn.sendall(b'K')
                    conn.close()
            except OSError:
                break
            except socket.error:
                break

    def start_background(self):
        self._thread = threading.Thread(target=self.serve, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._running = False
        for _, s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)


class RawKnockWatcher:
    """Live raw-socket SYN watcher (root only). Gated behind --live."""

    def __init__(self, knock_sequence=None, timeout=10, max_attempts=3):
        self.gate = KnockGate(knock_sequence, timeout, max_attempts)
        self._running = False

    def run(self):
        self._running = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
            sock.settimeout(1.0)
        except PermissionError:
            log.error('ERROR: live raw-socket mode requires root.')
            return 1
        log.info('Listening for knock packets (raw)...')
        try:
            while self._running:
                try:
                    data, _ = sock.recvfrom(65535)
                    if len(data) < 40:
                        continue
                    ip_fields = struct.unpack('!BBHHHBBH4s4s', data[:20])
                    if ip_fields[6] != 6:  # TCP
                        continue
                    tcp_fields = struct.unpack('!HHLLBBHHH', data[20:40])
                    if not (tcp_fields[5] & 0x02):  # SYN flag
                        continue
                    src_ip = socket.inet_ntoa(ip_fields[8])
                    dst_port = tcp_fields[1]
                    self.gate.handle(src_ip, dst_port)
                except socket.timeout:
                    continue
        finally:
            sock.close()
        return 0

    def stop(self):
        self._running = False


def run_selftest(host='127.0.0.1', delay=0.0):
    """Deterministic localhost end-to-end: knock -> secret port opens."""
    import knock_client
    server = ListenerKnockServer(host=host, secret_port=0,
                                 knock_sequence=[7001, 8001, 9001],
                                 timeout=10)
    server.start()
    server.start_background()
    try:
        client = knock_client.KnockClient(host, delay=delay)
        print('=== N4 Port Knock: localhost end-to-end selftest ===')

        # 1. Secret port must be denied BEFORE the sequence.
        before = client.probe_secret(server.secret_port)
        print(f'[gated before knock] banner={before!r} '
              f'(expect DENIED)')
        denied_ok = before is not None and b'DENIED' in before

        # 2. Knock the sequence (real TCP connects on localhost).
        client.send_sequence_to(server.knock_ports)

        # 3. Secret port now answers with the AUTH banner.
        after = client.probe_secret(server.secret_port)
        print(f'[opened after knock] banner={after!r} '
              f'(expect OK-AUTH)')
        opened_ok = after is not None and b'OK-AUTH' in after

        print('\n=== Stats ===')
        print(f'  knocks observed: {server.gate.stats["total_knocks"]}')
        print(f'  auths granted:   {server.gate.stats["successful"]}')
        print(f'  grants served:   {server.granted}')

        ok = denied_ok and opened_ok and server.granted >= 1
        print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
        return 0 if ok else 1
    finally:
        server.stop()


def cmd_server(args):
    if args.transport == 'raw':
        watcher = RawKnockWatcher(
            [int(p) for p in args.sequence.split(',')],
            timeout=args.timeout, max_attempts=args.max_attempts)
        sys.exit(watcher.run())
    server = ListenerKnockServer(
        host=args.interface, secret_port=args.port,
        knock_sequence=[int(p) for p in args.sequence.split(',')],
        timeout=args.timeout, max_attempts=args.max_attempts)
    server.start()
    print(f'=== N4 Port Knock server (listen) ===')
    print(f'  host:    {server.host}')
    print(f'  knocks:  {server.knock_ports}')
    print(f'  secret:  {server.secret_port}')
    server.serve()


def cmd_client(args):
    import knock_client
    client = knock_client.KnockClient(
        args.target, sequence=[int(p) for p in args.sequence.split(',')],
        delay=args.delay)
    client.send_sequence()
    if args.secret_port:
        res = client.probe_secret(args.secret_port)
        print(f'[probe] {res!r}')
    client.print_stats()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='N4 — Port Knocking Client/Server',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command')

    srv = sub.add_parser('server', help='Start knock server')
    srv.add_argument('--transport', choices=['listen', 'raw'], default='listen',
                     help='listen=plain TCP (default, unprivileged); '
                          'raw=raw-socket SYNs (--live, root)')
    srv.add_argument('--live', action='store_true',
                     help='Enable the raw-socket transport (requires root)')
    srv.add_argument('--interface', default='127.0.0.1',
                     help='Bind address (default: 127.0.0.1)')
    srv.add_argument('--iface', dest='interface',
                     help='Alias for --interface')
    srv.add_argument('--port', type=int, default=0,
                     help='Secret port (default: ephemeral)')
    srv.add_argument('--sequence', default='7000,8000,9000',
                     help='Knock sequence (default: 7000,8000,9000)')
    srv.add_argument('--timeout', type=int, default=10)
    srv.add_argument('--max-attempts', type=int, default=3)

    cli = sub.add_parser('client', help='Send knock sequence')
    cli.add_argument('target', help='Target IP address')
    cli.add_argument('--sequence', default='7000,8000,9000',
                     help='Knock sequence (default: 7000,8000,9000)')
    cli.add_argument('--secret-port', type=int, default=None,
                     help='Probe this secret port after knocking')
    cli.add_argument('--delay', type=float, default=0.2)

    st = sub.add_parser('selftest', help='Localhost end-to-end test')
    st.add_argument('--host', default='127.0.0.1')

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    if args.command == 'selftest':
        return run_selftest(host=args.host)

    if args.command == 'server':
        if args.transport == 'listen':
            return cmd_server(args)
        if not args.live:
            print('ERROR: raw transport requires --live (root). '
                  'Use listen transport for localhost demos.')
            return 1
        return cmd_server(args)
    if args.command == 'client':
        cmd_client(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())