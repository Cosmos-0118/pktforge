"""Take the RSA key blocks Packet Tracer stored in saved labs and keep them as pktforge's SSH keys.

    python scripts/harvest_ssh_keys.py SAVE.pkt [SAVE.pkt ...]

Packet Tracer cannot make a key from a replayed config (LESSONS L17), but it does save one in the router's
<SECURITY> block. In Packet Tracer: give a router `ip domain-name x`, run `crypto key generate rsa`, answer the
modulus prompt (512, 768 or 1024), save the lab, and run this on the file. Each save adds or replaces the entry for
its modulus in pktforge/data/ssh_keys.json.
"""
import json
import os
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pktforge  # noqa: E402  (puts the vendored modules on sys.path)
import pkt_core  # noqa: E402

KEYS = os.path.join(pktforge.DATA_DIR, "ssh_keys.json")
_FIELDS = ("RSA_KEY", "TEMP_RSA_KEY", "TIME_DATE")


def harvest(path):
    with open(path, "rb") as fh:
        root = ET.fromstring(pkt_core.decode_bytes(fh.read(), "pkt").xml)
    for sec in root.iter("SECURITY"):
        if sec.findtext("ENABLED") == "1" and (sec.findtext("RSA_KEY") or "").strip():
            return int(sec.findtext("MODULUS_BITS")), {f: sec.findtext(f) for f in _FIELDS}
    return None, None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    data = {}
    if os.path.exists(KEYS):
        with open(KEYS) as fh:
            data = json.load(fh)
    rc = 0
    for path in sys.argv[1:]:
        bits, key = harvest(path)
        if bits is None:
            print("no RSA key in " + path)
            rc = 1
            continue
        print("%s %d-bit key from %s" % ("replaced" if str(bits) in data else "added   ", bits, os.path.basename(path)))
        data[str(bits)] = key
    with open(KEYS, "w") as fh:
        json.dump(dict(sorted(data.items(), key=lambda kv: int(kv[0]))), fh, indent=1)
        fh.write("\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
