"""VSCP over Bluetooth LE: frame codecs (no Bluetooth stack needed).

All multi-octet integers are big-endian except the Bluetooth Company
Identifier, which is little-endian. Frames are complete AD structures
(starting with the AD Length octet).

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import math
import struct
from dataclasses import dataclass, field

__all__ = [
    "TEST_COMPANY_ID", "VscpBleError", "Event",
    "ad_structures", "find_frame",
    "e1_encode", "e1_decode", "e1_decode_dataset",
    "l0_encode", "l0_decode", "l0_guid",
    "a2_encode", "a2_decode", "A2Key", "A2Receiver",
    "f1_fragment", "F1Reassembler",
    "G1_UUID", "g1_record_encode", "g1_record_decode", "g1_fragments", "G1Reassembler",
    "g1_control_encode", "g1_control_decode", "G1Op", "G1Status",
    "SequenceCounter",
]

TEST_COMPANY_ID = 0xFFFF  # Test only, never in production
AD_TYPE_MANUFACTURER = 0xFF

VERSION_E1 = 1
VERSION_A2 = 2
VERSION_F1 = 3


class VscpBleError(ValueError):
    """A frame was rejected. .code is a short reason ("length", "guid" ...)."""

    def __init__(self, code, message=None):
        super().__init__(message or code)
        self.code = code


@dataclass
class Event:
    guid: bytes
    vscp_class: int
    vscp_type: int
    data: bytes = b""
    head: int = 0

    def __post_init__(self):
        self.guid = bytes(self.guid)
        self.data = bytes(self.data)
        if len(self.guid) != 16:
            raise ValueError("GUID must be 16 octets")


def _company_le(company):
    return struct.pack("<H", company)


def _check_guid(guid):
    if not any(guid):
        raise VscpBleError("guid", "all-zero GUID")


# ---------------------------------------------------------------------------
#                       Advertising data structures
# ---------------------------------------------------------------------------

def ad_structures(data):
    """Yield complete AD structures (with Length octet). A zero Length ends
    the significant part. Raises VscpBleError("truncated") on overrun."""
    data = bytes(data)
    pos = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return
        if pos + 1 + length > len(data):
            raise VscpBleError("truncated", "AD structure overruns the data")
        yield data[pos:pos + 1 + length]
        pos += 1 + length


def find_frame(data, company, version):
    """The single candidate VSCP frame of a version in an advertising data set."""
    found = []
    for ad in ad_structures(data):
        if (len(ad) >= 5 and ad[1] == AD_TYPE_MANUFACTURER and ad[2:4] == _company_le(company)
                and ad[4] == version):
            found.append(ad)
    if not found:
        raise VscpBleError("not_found")
    if len(found) > 1:
        raise VscpBleError("ambiguous", "more than one candidate frame")
    return found[0]


def _frame_header(ad, company, version, minimum, maximum=256):
    ad = bytes(ad)
    if not minimum <= len(ad) <= maximum or ad[0] + 1 != len(ad):
        raise VscpBleError("length")
    if ad[1] != AD_TYPE_MANUFACTURER:
        raise VscpBleError("type")
    if ad[2:4] != _company_le(company):
        raise VscpBleError("company")
    if ad[4] != version:
        raise VscpBleError("version")
    return ad


# ---------------------------------------------------------------------------
#                                   E1
# ---------------------------------------------------------------------------

E1_MAX_DATA = 222


def e1_encode(ev, sequence, company=TEST_COMPANY_ID):
    n = len(ev.data)
    if n > E1_MAX_DATA:
        raise VscpBleError("too_large")
    _check_guid(ev.guid)
    if not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("sequence out of range")
    return (bytes([33 + n, AD_TYPE_MANUFACTURER]) + _company_le(company) + bytes([VERSION_E1, 0])
            + struct.pack(">I", sequence) + ev.guid
            + struct.pack(">HHHH", ev.head, ev.vscp_class, ev.vscp_type, n) + ev.data)


def e1_decode(ad, company=TEST_COMPANY_ID):
    """Returns (event, sequence)."""
    ad = _frame_header(ad, company, VERSION_E1, 34)
    if ad[5] != 0:
        raise VscpBleError("flags")
    (n,) = struct.unpack(">H", ad[32:34])
    if n > E1_MAX_DATA or len(ad) != 34 + n:
        raise VscpBleError("length")
    _check_guid(ad[10:26])
    (seq,) = struct.unpack(">I", ad[6:10])
    head, cls, typ = struct.unpack(">HHH", ad[26:32])
    return Event(ad[10:26], cls, typ, ad[34:], head), seq


def e1_decode_dataset(data, company=TEST_COMPANY_ID):
    return e1_decode(find_frame(data, company, VERSION_E1), company)


# ---------------------------------------------------------------------------
#                                 L0 (legacy)
# ---------------------------------------------------------------------------

def l0_encode(node_id, head, vscp_class, vscp_type, data=b"", company=TEST_COMPANY_ID):
    data = bytes(data)
    if len(data) > 8:
        raise VscpBleError("too_large")
    return (bytes([0x14, AD_TYPE_MANUFACTURER]) + _company_le(company) + b"\x00"
            + struct.pack(">HBHHB", node_id, head & 0xFF, vscp_class, vscp_type, len(data))
            + data.ljust(8, b"\x00"))


def l0_decode(ad, company=TEST_COMPANY_ID):
    """Returns dict(node_id, head, vscp_class, vscp_type, data). Encrypted
    (historic AES-ECB) frames are rejected."""
    ad = bytes(ad)
    if len(ad) != 21 or ad[0] != 0x14:
        raise VscpBleError("length")
    if ad[1] != AD_TYPE_MANUFACTURER:
        raise VscpBleError("type")
    if ad[2:4] != _company_le(company):
        raise VscpBleError("company")
    if ad[4] & 0x0F:
        raise VscpBleError("version")
    if ad[4] & 0xF0:
        raise VscpBleError("flags")
    node_id, head, cls, typ, n = struct.unpack(">HBHHB", ad[5:13])
    if n > 8:
        raise VscpBleError("length")
    return dict(node_id=node_id, head=head, vscp_class=cls, vscp_type=typ, data=ad[13:13 + n])


def l0_guid(addr, node_id):
    """FF:FF:FF:FF:FF:FF:FF:F8:<BLE address, MSB first>:<node id>."""
    addr = bytes(addr)
    if len(addr) != 6:
        raise ValueError("BLE address must be 6 octets")
    return b"\xff" * 7 + b"\xf8" + addr + struct.pack(">H", node_id)


# ---------------------------------------------------------------------------
#                                   A2
# ---------------------------------------------------------------------------

A2_MAX_DATA = 200
A2_DOMAIN = b"VSCP-BLE-A2"


def _aesccm(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM  # python3-cryptography
    return AESCCM(bytes(key), tag_length=16)


def a2_encode(ev, key_id, epoch, sequence, key, nonce_prefix, company=TEST_COMPANY_ID):
    n = len(ev.data)
    if n > A2_MAX_DATA:
        raise VscpBleError("too_large")
    _check_guid(ev.guid)
    if not 1 <= key_id <= 0xFFFF or len(nonce_prefix) != 5:
        raise ValueError("bad key id or nonce prefix")
    header = (_company_le(company) + bytes([VERSION_A2, 0x01]) + struct.pack(">HII", key_id, epoch, sequence)
              + ev.guid + struct.pack(">HHHH", ev.head, ev.vscp_class, ev.vscp_type, n))
    nonce = bytes(nonce_prefix) + struct.pack(">II", epoch, sequence)
    sealed = _aesccm(key).encrypt(nonce, ev.data, A2_DOMAIN + header)  # ciphertext || tag
    return bytes([55 + n, AD_TYPE_MANUFACTURER]) + header + sealed


@dataclass
class A2Key:
    """A provisioned receiver key record (with its replay state)."""
    company: int
    key_id: int
    guid: bytes
    key: bytes
    nonce_prefix: bytes
    min_epoch: int = 0
    max_epoch: int = 0xFFFFFFFF
    revoked: bool = False
    last: tuple = None  # (epoch, sequence) of the last accepted frame


def a2_decode(ad, rec, company=TEST_COMPANY_ID):
    """Framing, key/GUID match, epoch range and tag check against one key
    record. Replay checking is A2Receiver's job. Returns (event, epoch, seq)."""
    ad = _frame_header(ad, company, VERSION_A2, 56)
    if ad[5] != 0x01:
        raise VscpBleError("flags")
    (n,) = struct.unpack(">H", ad[38:40])
    if n > A2_MAX_DATA or len(ad) != 56 + n:
        raise VscpBleError("length")
    guid = ad[16:32]
    _check_guid(guid)
    key_id, epoch, seq = struct.unpack(">HII", ad[6:16])
    if (key_id == 0 or rec is None or rec.revoked or rec.company != company or rec.key_id != key_id
            or rec.guid != guid):
        raise VscpBleError("key")
    if not rec.min_epoch <= epoch <= rec.max_epoch:
        raise VscpBleError("replay", "epoch outside the provisioned range")
    from cryptography.exceptions import InvalidTag
    nonce = bytes(rec.nonce_prefix) + struct.pack(">II", epoch, seq)
    try:
        plain = _aesccm(rec.key).decrypt(nonce, ad[40:], A2_DOMAIN + ad[2:40])
    except InvalidTag:
        raise VscpBleError("auth", "tag verification failed") from None
    head, cls, typ = struct.unpack(">HHH", ad[32:38])
    return Event(guid, cls, typ, plain, head), epoch, seq


class A2Receiver:
    """Receiver with replay protection (spec 7.6).

    keys: dict {(company, key_id): A2Key}. persist(rec) is called with the
    new replay state before an event is accepted; it must make it durable
    or raise (the event is then rejected).
    """

    def __init__(self, keys, company=TEST_COMPANY_ID, persist=None):
        self.keys = keys
        self.company = company
        self.persist = persist

    def receive(self, ad):
        ad = bytes(ad)
        key_id = struct.unpack(">H", ad[6:8])[0] if len(ad) >= 8 else 0
        rec = self.keys.get((self.company, key_id))
        ev, epoch, seq = a2_decode(ad, rec, self.company)
        if rec.last is not None and (epoch, seq) <= rec.last:
            raise VscpBleError("replay")
        old = rec.last
        rec.last = (epoch, seq)
        if self.persist is not None:
            try:
                self.persist(rec)
            except Exception:
                rec.last = old
                raise VscpBleError("persist") from None
        return ev, rec

    def receive_dataset(self, data):
        return self.receive(find_frame(data, self.company, VERSION_A2))


# ---------------------------------------------------------------------------
#                                   F1
# ---------------------------------------------------------------------------

F1_CHUNK = 212
F1_MIN_DATA = 223
F1_MAX_DATA = 1024
F1_SLOTS = 2
F1_DEADLINE = 3.0


def f1_fragment(ev, message_id, company=TEST_COMPANY_ID):
    """The canonical F1 fragments (AD structures) of an event."""
    t = len(ev.data)
    if not F1_MIN_DATA <= t <= F1_MAX_DATA:
        raise VscpBleError("too_large")
    if not 1 <= message_id <= 0xFFFFFFFF:
        raise ValueError("message id must be nonzero")
    _check_guid(ev.guid)
    k = math.ceil(t / F1_CHUNK)
    out = []
    for i in range(k):
        off = i * F1_CHUNK
        chunk = ev.data[off:off + F1_CHUNK]
        flags = (1 if i == 0 else 0) | (2 if i == k - 1 else 0)
        out.append(bytes([41 + len(chunk), AD_TYPE_MANUFACTURER]) + _company_le(company)
                   + bytes([VERSION_F1, flags]) + struct.pack(">I", message_id) + ev.guid
                   + struct.pack(">HHHHBBHH", ev.head, ev.vscp_class, ev.vscp_type, t, i, k, off, len(chunk))
                   + b"\x00\x00" + chunk)
    return out


class F1Reassembler:
    """Bounded F1 reassembly: two concurrent messages, 3 s absolute deadline,
    completion cache. feed() returns the Event once complete, else None."""

    def __init__(self, company=TEST_COMPANY_ID, cache_size=8):
        self.company = company
        self.slots = {}
        self.done = {}
        self.cache_size = cache_size

    def expire(self, now):
        for key in [k for k, s in self.slots.items() if now - s["start"] >= F1_DEADLINE]:
            del self.slots[key]
        for key in [k for k, t in self.done.items() if now - t >= 2 * F1_DEADLINE]:
            del self.done[key]

    def feed(self, ad, now):
        self.expire(now)
        ad = _frame_header(ad, self.company, VERSION_F1, 43)
        flags = ad[5]
        (mid,) = struct.unpack(">I", ad[6:10])
        guid = ad[10:26]
        head, cls, typ, t, i, k, off, c = struct.unpack(">HHHHBBHH", ad[26:40])
        if ad[40:42] != b"\x00\x00" or flags & 0xFC:
            raise VscpBleError("flags")
        if mid == 0 or not any(guid):
            raise VscpBleError("guid")
        if not F1_MIN_DATA <= t <= F1_MAX_DATA or k != math.ceil(t / F1_CHUNK) or i >= k:
            raise VscpBleError("length")
        if off != i * F1_CHUNK or c != min(F1_CHUNK, t - off) or len(ad) != 42 + c:
            raise VscpBleError("sequence")
        if flags != ((1 if i == 0 else 0) | (2 if i == k - 1 else 0)):
            raise VscpBleError("flags")
        key = (guid, mid)
        if key in self.done:
            return None  # Already delivered
        slot = self.slots.get(key)
        if slot is None:
            if len(self.slots) >= F1_SLOTS:
                raise VscpBleError("busy")
            slot = self.slots[key] = dict(meta=(head, cls, typ, t, k), start=now, parts={})
        if slot["meta"] != (head, cls, typ, t, k):
            del self.slots[key]
            raise VscpBleError("conflict")
        chunk = ad[42:]
        if i in slot["parts"]:
            if slot["parts"][i] != chunk:
                del self.slots[key]
                raise VscpBleError("conflict")
            return None
        slot["parts"][i] = chunk
        if len(slot["parts"]) < k:
            return None
        del self.slots[key]
        if len(self.done) >= self.cache_size:
            del self.done[min(self.done, key=self.done.get)]
        self.done[key] = now
        return Event(guid, cls, typ, b"".join(slot["parts"][j] for j in range(k)), head)


# ---------------------------------------------------------------------------
#                                   G1
# ---------------------------------------------------------------------------

def G1_UUID(n):
    """UUID string of G1 attribute n (0 = service, 1-7 characteristics)."""
    return "9b7a%04x-6e44-4b8a-9d64-565343502001" % n


G1_MAX_DATA = 487
G1_RECORD_HEADER = 34


class G1Op:
    HELLO = 0x01
    RESET = 0x02
    HELLO_RESULT = 0x81
    EVENT_RESULT = 0x82
    TX_RESULT = 0x83


class G1Status:
    OK = 0x00
    UNSUPPORTED_VERSION = 0x01
    BAD_LENGTH = 0x02
    BAD_FLAGS = 0x03
    BAD_SEQUENCE = 0x04
    BUSY = 0x05
    NOT_AUTHORIZED = 0x06
    TOO_LARGE = 0x07
    TIMEOUT = 0x08
    INVALID_EVENT = 0x09
    NOT_READY = 0x0A
    INTERNAL_ERROR = 0x0B


def g1_record_encode(ev, tid):
    n = len(ev.data)
    if n > G1_MAX_DATA:
        raise VscpBleError("too_large")
    if not 1 <= tid <= 0xFFFFFFFF:
        raise ValueError("transaction id must be nonzero")
    _check_guid(ev.guid)
    # L = 22 + N as in the draft's record table (total record = L + 12)
    return (bytes([1, 1, 0, 0]) + struct.pack(">IH", tid, 22 + n) + ev.guid
            + struct.pack(">HHHH", ev.head, ev.vscp_class, ev.vscp_type, n) + ev.data)


def g1_record_decode(rec, max_data=G1_MAX_DATA):
    """Returns (event, tid)."""
    rec = bytes(rec)
    if len(rec) < G1_RECORD_HEADER:
        raise VscpBleError("length")
    if rec[0] != 1:
        raise VscpBleError("version")
    if rec[1] != 1:
        raise VscpBleError("type")
    if rec[2] or rec[3]:
        raise VscpBleError("flags")
    tid, l = struct.unpack(">IH", rec[4:10])
    (n,) = struct.unpack(">H", rec[32:34])
    if tid == 0 or l < 22 or l + 12 != len(rec) or 34 + n != len(rec) or n > G1_MAX_DATA:
        raise VscpBleError("length")
    if n > max_data:
        raise VscpBleError("too_large")
    _check_guid(rec[10:26])
    head, cls, typ = struct.unpack(">HHH", rec[26:32])
    return Event(rec[10:26], cls, typ, rec[34:], head), tid


def g1_fragments(record, att_mtu=23):
    """Split a record into ATT values (one per notification/write)."""
    record = bytes(record)
    if att_mtu < 23:
        raise ValueError("ATT_MTU must be at least 23")
    cap = att_mtu - 11
    tid = record[4:8]
    out = []
    for off in range(0, len(record), cap):
        chunk = record[off:off + cap]
        flags = (1 if off == 0 else 0) | (2 if off + len(chunk) == len(record) else 0)
        out.append(bytes([1, flags]) + tid + struct.pack(">H", off) + chunk)
    return out


class G1Reassembler:
    """One record per direction. feed() returns the record when complete,
    None while incomplete; raises VscpBleError (with .status) on errors."""

    TIMEOUT = 5.0

    def __init__(self, max_record=G1_RECORD_HEADER + G1_MAX_DATA):
        self.max_record = max_record
        self.reset()

    def reset(self):
        self.tid = None
        self.buf = bytearray()
        self.total = 0
        self.last = 0.0

    def _fail(self, code, status):
        self.reset()
        err = VscpBleError(code)
        err.status = status
        raise err

    def feed(self, frag, now=0.0):
        frag = bytes(frag)
        if self.tid is not None and now - self.last >= self.TIMEOUT:
            self.reset()
        if len(frag) < 9:
            self._fail("length", G1Status.BAD_LENGTH)
        if frag[0] != 1:
            self._fail("version", G1Status.UNSUPPORTED_VERSION)
        flags = frag[1]
        tid, off = struct.unpack(">IH", frag[2:8])
        chunk = frag[8:]
        if flags & 0xFC:
            self._fail("flags", G1Status.BAD_FLAGS)
        if tid == 0:
            self._fail("sequence", G1Status.BAD_SEQUENCE)
        if flags & 1:
            if self.tid is not None:
                err = VscpBleError("busy")
                err.status = G1Status.BUSY
                raise err
            if off != 0 or len(chunk) < 10:
                self._fail("sequence", G1Status.BAD_SEQUENCE)
            if chunk[0] != 1:
                self._fail("version", G1Status.UNSUPPORTED_VERSION)
            if chunk[2] or chunk[3]:
                self._fail("flags", G1Status.BAD_FLAGS)
            rtid, l = struct.unpack(">IH", chunk[4:10])
            if chunk[1] != 1 or l < 22 or l - 22 > G1_MAX_DATA:
                self._fail("length", G1Status.BAD_LENGTH)
            if l + 12 > self.max_record:
                self._fail("too_large", G1Status.TOO_LARGE)
            if rtid != tid:
                self._fail("sequence", G1Status.BAD_SEQUENCE)
            self.tid, self.total = tid, l + 12
        else:
            if self.tid is None:
                self._fail("sequence", G1Status.BAD_SEQUENCE)
            if tid != self.tid:
                err = VscpBleError("busy")
                err.status = G1Status.BUSY
                raise err
            if off != len(self.buf):
                self._fail("sequence", G1Status.BAD_SEQUENCE)
        end = len(self.buf) + len(chunk)
        if end > self.total or bool(flags & 2) != (end == self.total):
            self._fail("length", G1Status.BAD_LENGTH)
        self.buf += chunk
        self.last = now
        if not flags & 2:
            return None
        rec = bytes(self.buf)
        self.reset()
        return rec


def g1_control_encode(opcode, tid=0, status=0, payload=b""):
    payload = bytes(payload)
    return bytes([1, opcode]) + struct.pack(">I", tid) + bytes([status, len(payload)]) + payload


def g1_control_decode(value):
    """Returns (opcode, tid, status, payload)."""
    value = bytes(value)
    if len(value) < 8 or len(value) != 8 + value[7]:
        raise VscpBleError("length")
    if value[0] != 1:
        raise VscpBleError("version")
    if value[1] not in (1, 2, 0x81, 0x82, 0x83):
        raise VscpBleError("type")
    if value[6] > G1Status.INTERNAL_ERROR:
        raise VscpBleError("status")
    (tid,) = struct.unpack(">I", value[2:6])
    return value[1], tid, value[6], value[8:]


# ---------------------------------------------------------------------------
#                       Persistent sender counter
# ---------------------------------------------------------------------------

@dataclass
class SequenceCounter:
    """Never-reused (epoch, sequence) with block reservation.

    load() -> (epoch, reserved_until) and save(epoch, reserved_until) are
    the persistence functions; save must be durable when it returns.
    use_epoch=False (E1): stop at 0xFFFFFFFF. True (A2): advance the epoch.
    """
    load: object
    save: object
    block: int = 256
    use_epoch: bool = True
    epoch: int = field(init=False)
    next: int = field(init=False)
    reserved: int = field(init=False)

    def __post_init__(self):
        self.epoch, self.reserved = self.load()
        self.next = self.reserved

    def take(self):
        if self.next > 0xFFFFFFFF:
            if not self.use_epoch or self.epoch >= 0xFFFFFFFF:
                raise VscpBleError("exhausted")
            self.epoch += 1
            self.next = self.reserved = 0
        if self.next >= self.reserved:
            until = min(self.next + self.block, 0x100000000)
            self.save(self.epoch, until)
            self.reserved = until
        seq = self.next
        self.next += 1
        return self.epoch, seq
