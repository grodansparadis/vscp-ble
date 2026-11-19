"""VSCP over Bluetooth LE - Python reference codec and BlueZ helpers.

An implementation of the draft VSCP BLE transport (E1, A2, F1, G1, L0)
that is independent of the C library in src/. Both are tested against the
same vectors (tests/vectors/vectors.json).
"""

from .codec import *  # noqa: F401,F403
