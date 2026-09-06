#!/usr/bin/env python3
"""N4 Port Knock: real localhost end-to-end test + state-machine unit tests.

The end-to-end test runs real TCP connects over 127.0.0.1 and asserts the
secret port is denied before the sequence and opens after it - no privileges.
"""
import os
import sys
import unittest
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

import knock_client  # noqa: E402
import knock_server  # noqa: E402


class TestKnockGate(unittest.TestCase):
    def setUp(self):
        self.gate = knock_server.KnockGate([7001, 7002, 7003], timeout=10)

    def test_correct_sequence_authenticates(self):
        self.assertFalse(self.gate.handle('192.0.2.10', 7001))
        self.assertFalse(self.gate.handle('192.0.2.10', 7002))
        self.assertTrue(self.gate.handle('192.0.2.10', 7003))
        self.assertTrue(self.gate.is_authenticated('192.0.2.10'))

    def test_wrong_order_resets(self):
        self.assertFalse(self.gate.handle('192.0.2.10', 7001))
        self.assertFalse(self.gate.handle('192.0.2.10', 7003))  # mismatch
        self.assertFalse(self.gate.handle('192.0.2.10', 7001))
        self.assertFalse(self.gate.handle('192.0.2.10', 7002))
        self.assertFalse(self.gate.is_authenticated('192.0.2.10'))

    def test_wrong_first_port_never_authenticates(self):
        for _ in range(3):
            self.gate.handle('192.0.2.10', 9999)
        self.assertFalse(self.gate.is_authenticated('192.0.2.10'))
        self.assertGreaterEqual(self.gate.stats['failed'], 1)

    def test_timeout_expires_auth(self):
        gate = knock_server.KnockGate([7001], timeout=1)
        gate.handle('192.0.2.10', 7001)
        self.assertTrue(gate.is_authenticated('192.0.2.10'))
        gate._state['192.0.2.10']['timestamp'] = time.time() - 5
        self.assertFalse(gate.is_authenticated('192.0.2.10'))

    def test_stats_counts(self):
        self.gate.handle('192.0.2.10', 7001)
        self.gate.handle('192.0.2.10', 7002)
        self.gate.handle('192.0.2.10', 7003)
        self.assertEqual(self.gate.stats['total_knocks'], 3)
        self.assertEqual(self.gate.stats['successful'], 1)


class TestEndToEndLocalhost(unittest.TestCase):
    """Real sockets on 127.0.0.1: knock then open the secret port."""

    SEQ = [7010, 7011, 7012]

    def setUp(self):
        self.server = knock_server.ListenerKnockServer(
            host='127.0.0.1', secret_port=0,
            knock_sequence=list(self.SEQ), timeout=10)
        self.knock_ports, self.secret_port = self.server.start()
        self.server.start_background()

    def tearDown(self):
        self.server.stop()

    def test_secret_denied_before_knock(self):
        client = knock_client.KnockClient('127.0.0.1', delay=0)
        banner = client.probe_secret(self.secret_port)
        self.assertIsNotNone(banner)
        self.assertIn(b'DENIED', banner)

    def test_knock_then_open_secret_port(self):
        client = knock_client.KnockClient('127.0.0.1', delay=0)
        sent = client.send_sequence_to(self.knock_ports)
        self.assertEqual(sent, len(self.knock_ports))
        banner = client.probe_secret(self.secret_port)
        self.assertIsNotNone(banner)
        self.assertIn(b'OK-AUTH', banner)
        self.assertGreaterEqual(self.server.granted, 1)

    def test_wrong_sequence_leaves_port_closed(self):
        client = knock_client.KnockClient('127.0.0.1', delay=0)
        client.send_sequence_to([self.knock_ports[0], self.knock_ports[2],
                                 self.knock_ports[1]])
        banner = client.probe_secret(self.secret_port)
        self.assertIsNotNone(banner)
        self.assertIn(b'DENIED', banner)

    def test_auth_expires_then_denied(self):
        knocker = knock_client.KnockClient('127.0.0.1', delay=0)
        knocker.send_sequence_to(self.knock_ports)
        self.assertIn(b'OK-AUTH', knocker.probe_secret(self.secret_port))
        # Expire the grant window; the secret port must close again.
        self.server.gate._state['127.0.0.1']['timestamp'] = time.time() - 30
        banner = knocker.probe_secret(self.secret_port)
        self.assertIsNotNone(banner)
        self.assertIn(b'DENIED', banner)


if __name__ == '__main__':
    unittest.main()