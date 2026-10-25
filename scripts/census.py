"""Build a census lab: one device of every model whose port names are known, with the first and last port of each
Ethernet family cabled to a bank of 2960 collector switches.

Open the result in Packet Tracer, save it under a new name, then compare:

    python scripts/census.py out/census.json
    pktforge build out/census.json -o out
    (open out/census.pkt in Packet Tracer, File > Save As census_saved.pkt)
    python scripts/census.py --compare out/census.json out/census_saved.pkt

Packet Tracer drops a cable whose port name does not exist, so every missing link is a wrong name in pktforge.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pktforge  # noqa: E402,F401
from pktforge import build, ports  # noqa: E402
import lab_api  # noqa: E402
import pkt_core  # noqa: E402

KINDS = ("router", "switch", "multilayer-switch", "firewall", "pc", "laptop", "server", "access-point", "sniffer")


def families(names):
    """{prefix: [names...]} for Ethernet-style ports; serial is left out (needs a paired DCE cable)."""
    out = {}
    for n in names:
        m = re.match(r"([A-Za-z]+)", n)
        if m and m.group(1) != "Serial":
            out.setdefault(m.group(1), []).append(n)
    return out


def make_spec(only=None):
    models, _ = build._templates()
    devices, links, skipped = [], [], []
    cols = []
    slots = []   # (collector name, port)

    def new_collector():
        name = "COL%d" % (len(cols) + 1)
        cols.append(name)
        devices.append({"name": name, "model": "2960-24TT", "at": [100 + 330 * (len(cols) - 1), 1000]})
        slots.extend((name, "Fa0/%d" % i) for i in range(1, 25))
        slots.extend((name, "Gi0/%d" % i) for i in range(1, 3))

    grid = 0
    for model in sorted(models):
        kind = lab_api.kind_for_model(model)
        if kind not in KINDS or (only and model not in only):
            continue
        names = build.model_ports(model)
        fam = families(names)
        if not fam:
            skipped.append(model)
            continue
        dev = "T-%s" % model
        devices.append({"name": dev, "model": model, "at": [90 + 170 * (grid % 8), 100 + 190 * (grid // 8)]})
        grid += 1
        for prefix, lst in fam.items():
            for port in dict.fromkeys([lst[0], lst[-1]]):
                if not slots:
                    new_collector()
                col, cport = slots.pop(0)
                links.append(["%s:%s" % (dev, port), "%s:%s" % (col, cport)])
        if len(slots) < 8:
            new_collector()
    return {"name": "census", "labels": False, "devices": devices, "links": links}, skipped


def link_set_from_pkt(path):
    root = ET.fromstring(pkt_core.decode_bytes(open(path, "rb").read(), "pkt").xml)
    names = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME") for d in root.findall("NETWORK/DEVICES/DEVICE")}
    out = set()
    for l in root.findall("NETWORK/LINKS/LINK"):
        c = l.find("CABLE")
        p = [x.text for x in c.findall("PORT")]
        out.add(frozenset([(names.get(c.findtext("FROM")), ports.canon_port(p[0])),
                           (names.get(c.findtext("TO")), ports.canon_port(p[1]))]))
    return out, names


def compare(spec_path, saved_path):
    spec = json.load(open(spec_path))
    want = set()
    for a, b in spec["links"]:
        (da, pa), (db, pb) = a.split(":"), b.split(":")
        want.add(frozenset([(da, ports.canon_port(pa)), (db, ports.canon_port(pb))]))
    have, names = link_set_from_pkt(saved_path)
    missing = want - have
    print("devices in saved file: %d (spec %d)" % (len(names), len(spec["devices"])))
    print("links wanted %d, kept by Packet Tracer %d, missing %d" % (len(want), len(want & have), len(missing)))
    for m in sorted(missing, key=lambda s: sorted(map(str, s))):
        print("  MISSING:", " <-> ".join("%s:%s" % t for t in sorted(m)))
    extra = have - want
    for m in sorted(extra, key=lambda s: sorted(map(str, s))):
        print("  PT-ONLY:", " <-> ".join("%s:%s" % t for t in sorted(m)))
    return 0 if not missing else 1


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--compare":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
    out = sys.argv[1] if len(sys.argv) > 1 else "census.json"
    only = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None      # optional: model1,model2,...
    spec, skipped = make_spec(only)
    if only:
        spec["name"] = "census_" + re.sub(r"[^A-Za-z0-9]+", "_", os.path.splitext(os.path.basename(out))[0])
    json.dump(spec, open(out, "w"), indent=1)
    print("wrote %s: %d devices, %d links; no known ports (skipped): %s" % (
        out, len(spec["devices"]), len(spec["links"]), ", ".join(skipped) or "-"))
