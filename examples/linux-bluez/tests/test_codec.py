#!/usr/bin/env python3
"""Tests of the Python codec against the shared vectors (no Bluetooth needed).

  python3 -m unittest discover -s examples/linux-bluez/tests
"""

import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
VECTORS = json.loads((HERE.parent.parent.parent / "tests" / "vectors" / "vectors.json").read_text())

from vscp_ble import (A2Key, A2Receiver, Event, F1Reassembler, G1Reassembler, SequenceCounter,  # noqa: E402
                      VscpBleError, a2_encode, e1_decode, e1_decode_dataset, e1_encode, f1_fragment,
                      g1_control_decode, g1_fragments, g1_record_decode, g1_record_encode, l0_decode, l0_guid)

GUID = bytes.fromhex(VECTORS["guid"])
KEY = bytes.fromhex(VECTORS["a2_key"])
PREFIX = bytes.fromhex(VECTORS["a2_nonce_prefix"])


def ev_of(v):
    return Event(GUID, v["vscp_class"], v["vscp_type"], bytes.fromhex(v["data"]), v["head"])


class E1(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["e1"]:
            frame = bytes.fromhex(v["frame"])
            self.assertEqual(frame, e1_encode(ev_of(v), v["sequence"]))
            ev, seq = e1_decode(frame)
            self.assertEqual((ev, seq), (ev_of(v), v["sequence"]))

    def test_negative(self):
        f = bytearray.fromhex(VECTORS["e1"][1]["frame"])
        for i, val, code in ((4, 2, "version"), (5, 1, "flags"), (5, 0x80, "flags"), (0, 0x24, "length"),
                             (33, 3, "length"), (1, 0x16, "type")):
            g = bytearray(f)
            g[i] = val
            with self.assertRaises(VscpBleError) as cm:
                e1_decode(g)
            self.assertEqual(code, cm.exception.code)
        g = bytearray(f)
        g[10:26] = bytes(16)
        self.assertRaises(VscpBleError, e1_decode, g)
        self.assertRaises(VscpBleError, e1_encode, Event(GUID, 0, 0, bytes(223)), 0)
        with self.assertRaises(VscpBleError) as cm:
            e1_decode_dataset(bytes(f) + bytes(f))
        self.assertEqual("ambiguous", cm.exception.code)
        with self.assertRaises(VscpBleError) as cm:
            e1_decode_dataset(bytes(f)[:-1])
        self.assertEqual("truncated", cm.exception.code)


class L0(unittest.TestCase):
    def test_vector(self):
        d = l0_decode(bytes.fromhex(VECTORS["l0"][0]["frame"]))
        self.assertEqual(0x1234, d["node_id"])
        self.assertEqual(b"\xaa\xbb", d["data"])
        self.assertEqual(bytes.fromhex("fffffffffffffff8c01122334455" "1234"),
                         l0_guid(bytes.fromhex("c01122334455"), 0x1234))


class A2(unittest.TestCase):
    def setUp(self):
        self.keys = {(0xFFFF, kid): A2Key(0xFFFF, kid, GUID, KEY, PREFIX) for kid in (1, 0x0102)}
        self.saved = []
        self.rx = A2Receiver(self.keys, persist=lambda rec: self.saved.append(rec.last))

    def test_vectors(self):
        for v in VECTORS["a2"]:
            frame = bytes.fromhex(v["frame"])
            self.assertEqual(frame, a2_encode(ev_of(v), v["key_id"], v["epoch"], v["sequence"], KEY, PREFIX))
            self.keys[(0xFFFF, v["key_id"])].last = None  # Independent vectors
            ev, rec = self.rx.receive(frame)
            self.assertEqual(ev_of(v), ev)
        self.assertEqual(len(VECTORS["a2"]), len(self.saved))

    def test_tamper_every_octet(self):
        frame = bytes.fromhex(VECTORS["a2"][0]["frame"])
        for i in range(len(frame)):
            g = bytearray(frame)
            g[i] ^= 1
            self.assertRaises(VscpBleError, self.rx.receive, bytes(g))
        self.assertEqual([], self.saved)

    def test_replay(self):
        enc = lambda e, s: a2_encode(Event(GUID, 10, 6, b"x"), 1, e, s, KEY, PREFIX)  # noqa: E731
        self.rx.receive(enc(5, 10))
        for e, s in ((5, 10), (5, 9), (4, 99)):
            with self.assertRaises(VscpBleError) as cm:
                self.rx.receive(enc(e, s))
            self.assertEqual("replay", cm.exception.code)
        self.rx.receive(enc(6, 0))

    def test_keys(self):
        enc = a2_encode(Event(GUID, 10, 6, b"x"), 7, 0, 0, KEY, PREFIX)
        self.assertRaises(VscpBleError, self.rx.receive, enc)
        self.keys[(0xFFFF, 1)].revoked = True
        self.assertRaises(VscpBleError, self.rx.receive, a2_encode(Event(GUID, 10, 6), 1, 0, 0, KEY, PREFIX))

    def test_persist_failure(self):
        def fail(rec):
            raise OSError("disk full")
        rx = A2Receiver(self.keys, persist=fail)
        with self.assertRaises(VscpBleError) as cm:
            rx.receive(bytes.fromhex(VECTORS["a2"][0]["frame"]))
        self.assertEqual("persist", cm.exception.code)
        self.assertIsNone(self.keys[(0xFFFF, 1)].last)


class F1(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["f1"]:
            frags = [bytes.fromhex(f) for f in v["fragments"]]
            self.assertEqual(frags, f1_fragment(ev_of(v), v["message_id"]))
            r = F1Reassembler()
            out = [r.feed(f, 0.0) for f in reversed(frags)]
            self.assertEqual([None] * (len(frags) - 1), out[:-1])
            self.assertEqual(ev_of(v), out[-1])
            self.assertIsNone(r.feed(frags[0], 0.1))  # Delivered once
        self.assertEqual([0xFD, 0x34], [bytes.fromhex(f)[0] for f in VECTORS["f1"][0]["fragments"]])

    def test_limits(self):
        r = F1Reassembler()
        mk = lambda mid: f1_fragment(Event(GUID, 10, 6, bytes(300)), mid)  # noqa: E731
        r.feed(mk(1)[0], 0)
        r.feed(mk(2)[0], 0)
        with self.assertRaises(VscpBleError):
            r.feed(mk(3)[0], 0)
        self.assertIsNone(r.feed(mk(3)[0], 3.0))  # Deadline frees the slots
        changed = bytearray(mk(3)[0])
        changed[-1] ^= 1
        with self.assertRaises(VscpBleError) as cm:
            r.feed(bytes(changed), 3.0)
        self.assertEqual("conflict", cm.exception.code)


class G1(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS["g1"]:
            rec = bytes.fromhex(v["record"])
            self.assertEqual(rec, g1_record_encode(ev_of(v), v["tid"]))
            self.assertEqual((ev_of(v), v["tid"]), g1_record_decode(rec))
            for mtu, frags in v["fragments"].items():
                frags = [bytes.fromhex(f) for f in frags]
                self.assertEqual(frags, g1_fragments(rec, int(mtu)))
                r = G1Reassembler()
                self.assertEqual([None] * (len(frags) - 1) + [rec], [r.feed(f) for f in frags])

    def test_reassembly_errors(self):
        frags = g1_fragments(g1_record_encode(Event(GUID, 10, 6, bytes(40)), 3), 23)
        r = G1Reassembler()
        r.feed(frags[0])
        with self.assertRaises(VscpBleError) as cm:
            r.feed(frags[2])
        self.assertEqual(0x04, cm.exception.status)
        r.feed(frags[0], 0.0)
        with self.assertRaises(VscpBleError):
            r.feed(frags[1], 5.0)  # Timed out, needs a new FIRST

    def test_control(self):
        op, tid, status, payload = g1_control_decode(bytes.fromhex(VECTORS["g1_hello"]))
        self.assertEqual((1, 0, 0, bytes.fromhex("01e702090000")), (op, tid, status, payload))


class Counter(unittest.TestCase):
    def test_restart_and_epoch(self):
        store = {"v": (0, 0xFFFFFFF0)}
        load = lambda: store["v"]  # noqa: E731
        save = lambda e, u: store.__setitem__("v", (e, u))  # noqa: E731
        c = SequenceCounter(load, save, block=8)
        seen = [c.take() for _ in range(20)]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual((1, 0), seen[16])
        c2 = SequenceCounter(load, save, block=8)
        self.assertGreater(c2.take(), seen[-1])
        e1 = SequenceCounter(lambda: (0, 0xFFFFFFFF), save, use_epoch=False)
        self.assertEqual((0, 0xFFFFFFFF), e1.take())
        self.assertRaises(VscpBleError, e1.take)


if __name__ == "__main__":
    unittest.main()
