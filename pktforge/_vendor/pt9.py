"""Minimal stand-in for the `pt9` module that lab_api imports.

The original pt9 needs libgcrypt; pktforge uses the pure-Python codec in
pkt_core instead, so only the three calls lab_api makes are provided.
"""
from pathlib import Path

from pkt_core import decode_bytes as _decode_bytes
from pkt_core import encode_bytes as _encode_bytes


def decode_bytes(raw, fmt="pkt", verify_tag=True):
    return _decode_bytes(raw, fmt, verify_tag=verify_tag).xml


def decode(path, fmt="pkt", verify_tag=True):
    return decode_bytes(Path(path).read_bytes(), fmt, verify_tag)


def encode(path, xml, fmt="pkt"):
    Path(path).write_bytes(_encode_bytes(xml, fmt))
