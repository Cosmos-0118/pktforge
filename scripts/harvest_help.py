"""Read Packet Tracer's own help pages and record which modules each device accepts.

    python scripts/harvest_help.py ["C:/Program Files/Cisco Packet Tracer 9.0.1"]

Writes pktforge/data/pt_help.json. Only device and module *names* are kept (facts); the help text itself is
Cisco's and is not copied. Modules are limited to the ones pktforge has templates for.
"""
import html
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pktforge  # noqa: E402,F401
from pktforge import build  # noqa: E402

PT = sys.argv[1] if len(sys.argv) > 1 else r"C:\Program Files\Cisco Packet Tracer 9.0.1"
PAGES = {"routers": "router", "switches": "switch", "endDevices": "end", "others": "other"}


def text(page):
    p = os.path.join(PT, "help", "default", "devicesAndModules_%s.htm" % page)
    t = open(p, encoding="utf-8", errors="replace").read()
    t = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", "", t)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    return re.sub(r"\s+", " ", t)


def main():
    _models, modules = build._templates()
    mods = sorted(modules, key=len, reverse=True)
    out = {"packet_tracer": os.path.basename(PT.rstrip("/\\")), "devices": {}}
    for page, group in PAGES.items():
        t = text(page)
        if group in ("router", "switch"):
            parts = re.split(r"(?:^|\s)(?:Router|Switch): ", t)[1:]
            names = [re.match(r"(\S+)", p).group(1) for p in parts]
        else:
            # "<NAME> The <NAME> provides ..." introduces each device on these pages
            heads = list(re.finditer(r"(\S+) (?:The|This) \1 ", t))
            parts = [t[m.start(): heads[i + 1].start() if i + 1 < len(heads) else len(t)] for i, m in enumerate(heads)]
            names = [m.group(1) for m in heads]
        for name, body in zip(names, parts):
            if "-NM-" in name:                  # a module that happens to match the heading pattern
                continue
            found = [m for m in mods if re.search(r"(?<![A-Za-z0-9-])%s(?![A-Za-z0-9-])" % re.escape(m), body)]
            out["devices"][name] = {"group": group, "modules": sorted(found)}
    path = os.path.join(ROOT, "pktforge", "data", "pt_help.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("wrote %s: %d devices" % (path, len(out["devices"])))
    for n, d in sorted(out["devices"].items()):
        print("  %-22s %-7s %s" % (n, d["group"], ",".join(d["modules"])))


if __name__ == "__main__":
    main()
