#!/usr/bin/env python3
"""Write fuzz seeds from the interoperability vectors (selector octet first)."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
v = json.loads((root / "vectors" / "vectors.json").read_text())
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)


def seq(frames):
    return b"".join(bytes([min(len(f), 255)]) + f[:255] for f in frames)


seeds = {}
for e in v["e1"]:
    seeds["e1_" + e["name"]] = b"\x00\x02\x01\x06" + bytes.fromhex(e["frame"])
for e in v["l0"]:
    seeds["l0"] = b"\x01" + bytes.fromhex(e["frame"])
for e in v["a2"]:
    seeds["a2_" + e["name"]] = b"\x02" + seq([bytes.fromhex(e["frame"])] * 2)
for e in v["f1"]:
    seeds["f1_" + e["name"]] = b"\x03" + seq(bytes.fromhex(f) for f in e["fragments"])
for e in v["g1"]:
    for mtu, frags in e["fragments"].items():
        seeds["g1_%s_%s" % (e["name"], mtu)] = b"\x04" + seq(bytes.fromhex(f) for f in frags)
        hello = bytes.fromhex(v["g1_hello"])
        seeds["srv_%s_%s" % (e["name"], mtu)] = b"\x46" + seq([b"\x01" + hello] + [b"\x00" + bytes.fromhex(f) for f in frags])
seeds["ctl"] = b"\x05" + bytes.fromhex(v["g1_hello"])
for name, data in seeds.items():
    (out / name).write_bytes(data)
