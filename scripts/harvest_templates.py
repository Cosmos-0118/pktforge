"""Replace device templates with copies saved by the installed Packet Tracer.

    python scripts/harvest_templates.py SAVE.pkt MODEL [MODEL ...]      (or --all)

Open Packet Tracer, drag the devices into an empty lab, save it, and run this on the file. Each named model's
<DEVICE> block is taken from that save (power normalised on, like lab_api.harvest_models) and written over the
template in pktforge/data/device_templates.json. Use it when Packet Tracer refuses a shipped template (LESSONS L11):
the template was harvested from an older version, a fresh save from the user's own version loads by definition.
"""
import argparse
import base64
import gzip
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pktforge  # noqa: E402,F401  (vendored modules on sys.path)
import lab_api  # noqa: E402

TEMPLATES = os.path.join(pktforge.DATA_DIR, "device_templates.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("save")
    ap.add_argument("models", nargs="*")
    ap.add_argument("--all", action="store_true", help="take every model found in the save")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="pktforge-harvest-")
    try:
        shutil.copy(args.save, os.path.join(tmp, "save.pkt"))
        found = lab_api.harvest_models(tmp, None if args.all else set(args.models))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    with open(TEMPLATES) as fh:
        data = json.load(fh)
    if not data.get("gz"):
        sys.exit("unexpected template file format (no gz flag)")
    wanted = sorted(found) if args.all else args.models
    missing = [m for m in wanted if m not in found]
    for model in wanted:
        if model in found:
            old = model in data["models"]
            data["models"][model] = base64.b64encode(gzip.compress(found[model], 9, mtime=0)).decode("ascii")
            print("%s %s (%d bytes)" % ("replaced" if old else "added   ", model, len(found[model])))
    for model in missing:
        print("not in save: " + model)
    data["models"] = dict(sorted(data["models"].items()))
    with open(TEMPLATES, "w") as fh:
        json.dump(data, fh, separators=(",", ":"))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
