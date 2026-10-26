"""RSA keys for SSH (LESSONS L22).

Packet Tracer cannot make a key from a replayed config: its `crypto key generate rsa` has no `modulus` keyword, the
modulus prompt is skipped on replay (so the key is always 512 bits and `ip ssh version 2` is refused), and the key
lives in the router's <SECURITY> block, not in the config text. So pktforge takes the key-generation lines out of the
config and writes a key Packet Tracer itself saved (data/ssh_keys.json, scripts/harvest_ssh_keys.py) into that block.
The keys only exist inside the simulator and are shared by every lab pktforge builds.
"""
import json
import os
import re

import pktforge

DEFAULT_BITS = 512            # what IOS offers at the modulus prompt
_KEYGEN = re.compile(r"^\s*crypto key generate rsa(?:\s+general-keys)?(?:\s+modulus\s+(\d+))?\s*$", re.I)
_ANSWER = re.compile(r"^\s*(\d{3,4})\s*$")                  # the manual's answer to the modulus prompt
_DOMAIN = re.compile(r"^\s*ip domain-name\s+(\S+)\s*$", re.I)
_cache = {}


def keys():
    if "k" not in _cache:
        with open(os.path.join(pktforge.DATA_DIR, "ssh_keys.json"), encoding="utf-8") as fh:
            _cache["k"] = {int(b): k for b, k in json.load(fh).items()}
    return _cache["k"]


def split_config(lines):
    """-> (lines without key generation, requested modulus or None, domain name or None)."""
    kept, bits, domain, i = [], None, None, 0
    lines = list(lines)
    while i < len(lines):
        line = lines[i]
        m = _KEYGEN.match(line)
        if m:
            bits = int(m.group(1)) if m.group(1) else None
            if bits is None and i + 1 < len(lines) and _ANSWER.match(lines[i + 1]):
                i += 1
                bits = int(lines[i])
            bits = bits or DEFAULT_BITS
        else:
            kept.append(line)
            d = _DOMAIN.match(line)
            if d:
                domain = d.group(1)
        i += 1
    return kept, bits, domain


def interactive(lines):
    """For a CLI paste: `crypto key generate rsa modulus N` as Packet Tracer wants it, the command then the answer."""
    out = []
    for line in lines:
        m = _KEYGEN.match(line)
        out += ["crypto key generate rsa", m.group(1)] if m and m.group(1) else [line]
    return out


def pick(bits):
    """The shipped key size to use for a requested modulus: the smallest one that is big enough, else the largest."""
    sizes = sorted(keys())
    return next((s for s in sizes if s >= bits), sizes[-1])


def apply(engine, hostname, domain, bits):
    """Write the key into a device's <SECURITY> block, named the way Packet Tracer names it."""
    sec = engine.find("SECURITY")
    if sec is None:
        sec = engine.makeelement("SECURITY", {})
        engine.append(sec)
    key = keys()[bits]
    name = "%s.%s" % (hostname, domain)
    values = {"KEY_NAME": name, "TEMP_KEY_NAME": name + ".server", "RSA_KEY": key["RSA_KEY"],
              "TEMP_RSA_KEY": key["TEMP_RSA_KEY"], "TIME_DATE": key["TIME_DATE"], "ENABLED": "1",
              "MODULUS_BITS": str(bits)}
    for tag, text in values.items():
        el = sec.find(tag)
        if el is None:
            el = sec.makeelement(tag, {})
            sec.append(el)
        el.text = text
