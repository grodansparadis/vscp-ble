"""G1 server and client session logic (transport independent).

The BlueZ programs connect these to D-Bus; tests drive them directly.

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import struct
import time

from .codec import (G1_MAX_DATA, G1_RECORD_HEADER, G1Op, G1Reassembler, G1Status, VscpBleError, g1_control_decode,
                    g1_control_encode, g1_fragments, g1_record_decode, g1_record_encode)

# Standard ATT error codes for refused requests
ATT_INSUFFICIENT_AUTHORIZATION = 0x08
ATT_REQUEST_NOT_SUPPORTED = 0x06
ATT_VALUE_NOT_ALLOWED = 0x13
ATT_CCCD_IMPROPER = 0xFD

AUTH_NONE, AUTH_EVENT, AUTH_ADMIN = 0, 1, 2


class AttError(Exception):
    def __init__(self, code):
        super().__init__("ATT error 0x%02x" % code)
        self.code = code


def limits_payload(max_data, max_record):
    return struct.pack(">HHH", max_data, max_record, 0)


class G1Server:
    """One connection of a G1 server.

    indicate(value) / notify(value) send Control indications and Event TX
    notifications. on_event(event, tid) admits an Event RX event and returns
    a G1Status. Link security is enforced by the GATT stack (BlueZ flags
    encrypt-authenticated-*); authorization is this object's .authorization.
    """

    def __init__(self, guid, indicate, notify, on_event, max_event_data=G1_MAX_DATA, clock=time.monotonic):
        self.guid = bytes(guid)
        self.indicate = indicate
        self.notify = notify
        self.on_event = on_event
        self.local = (max_event_data, G1_RECORD_HEADER + max_event_data)
        self.clock = clock
        self.disconnected()

    # Connection state ----------------------------------------------------

    def disconnected(self):
        self.mtu = 23
        self.authorization = AUTH_NONE
        self.control_indicate = False
        self.event_notify = False
        self.negotiated = None
        self.rx = G1Reassembler(self.local[1])
        self.failed_tid = None
        self.next_tid = 1

    connected = disconnected

    # Reads ---------------------------------------------------------------

    def capabilities(self):
        d, r = self.negotiated or self.local
        return struct.pack(">BBHHHHH", 1, 0, d, r, self.mtu - 11, 0, 0)

    def security_status(self, paired):
        return bytes([1, 1 if paired else 0, self.authorization if paired else 0, 0])

    @staticmethod
    def configuration():
        return b"\x01\x00"

    # Writes --------------------------------------------------------------

    def _check(self):
        if self.authorization < AUTH_EVENT:
            raise AttError(ATT_INSUFFICIENT_AUTHORIZATION)
        if not self.control_indicate:
            raise AttError(ATT_CCCD_IMPROPER)

    def _result(self, opcode, tid, status, payload=b""):
        self.indicate(g1_control_encode(opcode, tid, status, payload))

    def write_control(self, value):
        self._check()
        value = bytes(value)
        if len(value) >= 1 and value[0] != 1:
            self._result(G1Op.HELLO_RESULT, 0, G1Status.UNSUPPORTED_VERSION)
            return
        try:
            op, tid, status, payload = g1_control_decode(value)
        except VscpBleError:
            raise AttError(ATT_VALUE_NOT_ALLOWED) from None
        if op == G1Op.HELLO:
            if len(payload) != 6 or status:
                self.negotiated = None
                return self._result(G1Op.HELLO_RESULT, tid, G1Status.BAD_LENGTH)
            d, r, features = struct.unpack(">HHH", payload)
            if d > G1_MAX_DATA or not G1_RECORD_HEADER <= r <= G1_RECORD_HEADER + G1_MAX_DATA:
                self.negotiated = None
                return self._result(G1Op.HELLO_RESULT, tid, G1Status.BAD_LENGTH)
            if features:
                self.negotiated = None
                return self._result(G1Op.HELLO_RESULT, tid, G1Status.BAD_FLAGS)
            r = min(r, self.local[1])
            d = min(d, self.local[0], r - G1_RECORD_HEADER)
            self.negotiated = (d, G1_RECORD_HEADER + d)
            self.rx = G1Reassembler(self.negotiated[1])
            return self._result(G1Op.HELLO_RESULT, tid, G1Status.OK, limits_payload(*self.negotiated))
        if op == G1Op.RESET and not payload:
            self.rx.reset()
            return
        raise AttError(ATT_VALUE_NOT_ALLOWED)

    def write_event_rx(self, value):
        self._check()
        value = bytes(value)
        if len(value) < 8 or len(value) > self.mtu - 3:
            raise AttError(ATT_VALUE_NOT_ALLOWED)
        (tid,) = struct.unpack(">I", value[2:6])
        if self.negotiated is None:
            return self._result(G1Op.EVENT_RESULT, tid, G1Status.NOT_READY)
        if not value[1] & 1 and self.rx.tid is None and tid == self.failed_tid:
            return  # Rest of a transaction that already got its error
        try:
            rec = self.rx.feed(value, self.clock())
        except VscpBleError as e:
            if e.code != "busy":
                self.failed_tid = tid
            return self._result(G1Op.EVENT_RESULT, tid, e.status)
        if rec is None:
            return
        self.failed_tid = None
        try:
            ev, tid = g1_record_decode(rec, self.negotiated[0])
        except VscpBleError as e:
            status = G1Status.TOO_LARGE if e.code == "too_large" else G1Status.BAD_LENGTH
            return self._result(G1Op.EVENT_RESULT, tid, status)
        try:
            status = self.on_event(ev, tid)
        except Exception:
            status = G1Status.INTERNAL_ERROR
        self._result(G1Op.EVENT_RESULT, tid, status)

    def write_configuration(self, value):
        if self.authorization < AUTH_ADMIN:
            raise AttError(ATT_INSUFFICIENT_AUTHORIZATION)
        raise AttError(ATT_REQUEST_NOT_SUPPORTED)  # No writable TLVs in version 1

    def tick(self):
        """Call about once a second: expires a stalled Event RX record."""
        if self.rx.tid is not None and self.clock() - self.rx.last >= G1Reassembler.TIMEOUT:
            tid = self.rx.tid
            self.rx.reset()
            self.failed_tid = tid
            self._result(G1Op.EVENT_RESULT, tid, G1Status.TIMEOUT)

    # Sending -------------------------------------------------------------

    def send_event(self, ev):
        """Notify an event to the client. Returns False if not possible now."""
        if self.negotiated is None or not self.event_notify or self.authorization < AUTH_EVENT:
            return False
        if len(ev.data) > self.negotiated[0]:
            raise VscpBleError("too_large")
        tid = self.next_tid
        self.next_tid = self.next_tid % 0xFFFFFFFF + 1
        try:
            for frag in g1_fragments(g1_record_encode(ev, tid), self.mtu):
                self.notify(frag)
        except Exception:
            self._result(G1Op.TX_RESULT, tid, G1Status.INTERNAL_ERROR)
            return False
        self._result(G1Op.TX_RESULT, tid, G1Status.OK)
        return True


class G1Client:
    """Client side: builds Control/Event RX values, decodes notifications.

    write_control(value) and write_event_rx(value) do the ATT writes.
    """

    def __init__(self, write_control, write_event_rx, mtu=23):
        self.write_control = write_control
        self.write_event_rx = write_event_rx
        self.mtu = mtu
        self.negotiated = None
        self.rx = G1Reassembler()
        self.next_tid = 1
        self.results = {}

    def hello(self, max_data=G1_MAX_DATA, max_record=G1_RECORD_HEADER + G1_MAX_DATA):
        self.write_control(g1_control_encode(G1Op.HELLO, 0, 0, limits_payload(max_data, max_record)))

    def send_event(self, ev):
        """Write an event (wait for its EVENT_RESULT before the next one)."""
        if self.negotiated is None:
            raise VscpBleError("not_ready")
        tid = self.next_tid
        self.next_tid = self.next_tid % 0xFFFFFFFF + 1
        for frag in g1_fragments(g1_record_encode(ev, tid), self.mtu):
            self.write_event_rx(frag)
        return tid

    def on_control(self, value):
        """Handle a Control indication. Returns (opcode, tid, status)."""
        op, tid, status, payload = g1_control_decode(value)
        if op == G1Op.HELLO_RESULT:
            self.negotiated = struct.unpack(">HH", payload[:4]) if status == G1Status.OK else None
            self.rx = G1Reassembler(self.negotiated[1] if self.negotiated else G1_RECORD_HEADER)
        else:
            self.results[tid] = (op, status)
        return op, tid, status

    def on_event_tx(self, value):
        """Handle an Event TX notification. Returns the Event when complete."""
        rec = self.rx.feed(value, time.monotonic())
        if rec is None:
            return None
        return g1_record_decode(rec, self.negotiated[0] if self.negotiated else G1_MAX_DATA)[0]
