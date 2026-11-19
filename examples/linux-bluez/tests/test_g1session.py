#!/usr/bin/env python3
"""G1 server and client sessions talking to each other (no Bluetooth)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from vscp_ble import Event, G1Status  # noqa: E402
from vscp_ble.g1session import AUTH_EVENT, AttError, G1Client, G1Server  # noqa: E402

GUID = bytes(range(16))


class Link:
    """A server and a client connected back to back at an ATT MTU."""

    def __init__(self, mtu=23, max_data=487):
        self.now = 0.0
        self.received = []
        self.delivered = []
        self.server = G1Server(GUID, self.indicate, self.notify, self.on_event, max_data, clock=lambda: self.now)
        self.client = G1Client(self.server.write_control, self.server.write_event_rx, mtu)
        self.server.mtu = mtu
        self.server.authorization = AUTH_EVENT
        self.server.control_indicate = True
        self.server.event_notify = True
        self.controls = []

    def indicate(self, value):
        self.controls.append(self.client.on_control(value))

    def notify(self, value):
        ev = self.client.on_event_tx(value)
        if ev is not None:
            self.received.append(ev)

    def on_event(self, ev, tid):
        self.delivered.append(ev)
        return G1Status.OK


class Session(unittest.TestCase):
    def test_round_trip_at_mtus(self):
        for mtu in (23, 100, 247, 517):
            link = Link(mtu)
            link.client.hello()
            self.assertEqual((487, 521), link.client.negotiated)
            for n in (0, 1, 12, 13, 487):
                ev = Event(GUID, 10, 6, bytes(range(256)) * 2 if n == 487 else bytes(n))
                ev.data = ev.data[:n]
                tid = link.client.send_event(ev)
                self.assertEqual((0x82, tid, 0), link.controls[-1])
                self.assertEqual(ev, link.delivered[-1])
                self.assertTrue(link.server.send_event(ev))
                self.assertEqual(ev, link.received[-1])

    def test_negotiation_limits(self):
        link = Link(23, max_data=100)
        link.client.hello(487, 521)
        self.assertEqual((100, 134), link.client.negotiated)
        link.client.send_event(Event(GUID, 10, 6, bytes(101)))
        self.assertEqual(G1Status.TOO_LARGE, link.controls[-1][2])
        self.assertEqual([], link.delivered)

    def test_not_ready_and_authorization(self):
        link = Link()
        link.client.negotiated = (487, 521)  # Client skipped HELLO
        tid = link.client.send_event(Event(GUID, 10, 6, b"x"))
        self.assertEqual((0x82, tid, G1Status.NOT_READY), link.controls[-1])
        link.server.authorization = 0
        with self.assertRaises(AttError):
            link.client.hello()

    def test_timeout(self):
        link = Link()
        link.client.hello()
        frags = []
        link.client.write_event_rx = frags.append
        link.client.send_event(Event(GUID, 10, 6, bytes(40)))
        link.server.write_event_rx(frags[0])
        link.now = 5.0
        link.server.tick()
        self.assertEqual(G1Status.TIMEOUT, link.controls[-1][2])
        n = len(link.controls)
        for f in frags[1:]:
            link.server.write_event_rx(f)  # Ignored: transaction already failed
        self.assertEqual(n, len(link.controls))
        self.assertEqual([], link.delivered)


if __name__ == "__main__":
    unittest.main()
