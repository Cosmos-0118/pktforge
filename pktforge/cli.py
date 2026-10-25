"""pktforge command line."""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

import pktforge
from pktforge import build, lint, ports, spec as specmod
from pktforge.issues import ERROR, INFO, WARNING, Issue, SpecError, has_errors

import pkt_core

EXIT_OK, EXIT_PROBLEMS, EXIT_USAGE = 0, 1, 2


# --------------------------------------------------------------------------- #
def _out(args, payload, text_lines):
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for line in text_lines:
            print(line)


def _issues_text(issues):
    return [str(i) for i in sorted(issues, key=lambda i: {ERROR: 0, WARNING: 1, INFO: 2}[i.severity])]


def check_spec(sp):
    """All spec-level checks: ports against the model catalogue, then network logic."""
    build.normalize_ports(sp)
    net = lint.net_from_spec(sp)
    cats = {}
    models = set(build.model_names())
    for d in sp.devices:
        if d.model in models:
            cats[d.name] = (build.port_catalog(d.model, d.modules), d.model in ports.VERIFIED_MODELS)
    return build.device_checks(sp) + lint.check_net(net, cats)


def _load_any(path):
    """Return (kind, payload): ('spec', Spec) | ('xml', Element)."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pkt":
        with open(path, "rb") as fh:
            xml = pkt_core.decode_bytes(fh.read(), "pkt").xml
        return "xml", ET.fromstring(xml)
    if ext == ".xml":
        return "xml", ET.parse(path).getroot()
    return "spec", specmod.load(path)


# --------------------------------------------------------------------------- #
def cmd_build(args):
    sp = specmod.load(args.spec)
    issues = list(sp.notes) + check_spec(sp)
    ok = not has_errors(issues)
    if not ok and not args.force:
        _out(args, {"ok": False, "built": False, "issues": [i.as_dict() for i in issues]},
             _issues_text(issues) + ["", "Not built: fix the errors above (or pass --force to build anyway)."])
        return EXIT_PROBLEMS
    outdir = args.output or os.path.join(os.getcwd(), "out")
    paths, bissues, manual, post = build.build_files(sp, outdir, want_pkt=not args.no_pkt, want_xml=not args.no_xml)
    issues += bissues + post
    ok = not has_errors(issues)
    text = _issues_text(issues) if issues else []
    text += ["", "Built %d devices, %d cables." % (len(sp.devices), len(sp.links))]
    text += ["  %-4s %s" % (k, v) for k, v in paths.items()]
    if "pkt" in paths:
        text.append("Open the .pkt directly in Packet Tracer - no converter site needed.")
    text += ["", "Do these by hand (cannot be expressed in the file):"] + ["  - " + m for m in manual]
    _out(args, {"ok": ok, "built": True, "files": paths, "issues": [i.as_dict() for i in issues],
                "manual_steps": manual}, text)
    return EXIT_OK if ok else EXIT_PROBLEMS


def cmd_check(args):
    kind, obj = _load_any(args.file)
    if kind == "spec":
        issues = list(obj.notes) + check_spec(obj)
    else:
        issues = lint.check_xml(obj) + lint.check_net(lint.net_from_xml(obj))
    ok = not has_errors(issues)
    text = _issues_text(issues) or ["No problems found."]
    text.append("")
    text.append("%d error(s), %d warning(s)." % (sum(i.severity == ERROR for i in issues),
                                                  sum(i.severity == WARNING for i in issues)))
    _out(args, {"ok": ok, "issues": [i.as_dict() for i in issues]}, text)
    return EXIT_OK if ok and not (args.strict and issues and any(i.severity == WARNING for i in issues)) \
        else EXIT_PROBLEMS


def cmd_init(args):
    name = args.name
    src = os.path.join(pktforge.DATA_DIR, "examples", "%s.json" % args.template)
    if not os.path.exists(src):
        print("unknown template %r (use: %s)" % (args.template, ", ".join(sorted(
            f[:-5] for f in os.listdir(os.path.join(pktforge.DATA_DIR, "examples")) if f.endswith(".json")))),
              file=sys.stderr)
        return EXIT_USAGE
    dest = name if name.lower().endswith((".json", ".toml")) else name + ".json"
    if os.path.exists(dest) and not args.force:
        print("%s already exists (use --force to overwrite)" % dest, file=sys.stderr)
        return EXIT_USAGE
    with open(src, encoding="utf-8") as fh:
        data = fh.read()
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(data)
    print("Wrote %s (template: %s). Edit it, then run: pktforge build %s" % (dest, args.template, dest))
    return EXIT_OK


def cmd_models(args):
    models, modules = build._templates()
    import lab_api
    if args.modules:
        names = sorted(modules)
        _out(args, {"modules": names}, names)
        return EXIT_OK
    rows = []
    for m in sorted(models):
        k = lab_api.kind_for_model(m)
        if args.kind and k != args.kind:
            continue
        rows.append({"model": m, "kind": k, "verified": m in ports.VERIFIED_MODELS})
    text = ["%-28s %-18s %s" % (r["model"], r["kind"], "verified in PT 9.0.1" if r["verified"] else "") for r in rows]
    text += ["", "%d models. Only the 'verified' ones have been opened and pinged in Packet Tracer; others build "
                 "but their port names are inferred." % len(rows)]
    _out(args, {"models": rows}, text)
    return EXIT_OK


def cmd_ports(args):
    if args.model not in build.model_names():
        print("unknown model %r - run `pktforge models`" % args.model, file=sys.stderr)
        return EXIT_USAGE
    names = sorted(build.port_catalog(args.model, args.module or []),
                   key=lambda n: [int(t) if t.isdigit() else t for t in __import__("re").split(r"(\d+)", n)])
    _out(args, {"model": args.model, "ports": names}, names)
    return EXIT_OK


def cmd_decode(args):
    with open(args.file, "rb") as fh:
        xml = pkt_core.decode_bytes(fh.read(), "pkt").xml
    dest = args.output or os.path.splitext(args.file)[0] + ".xml"
    with open(dest, "wb") as fh:
        fh.write(xml)
    print("wrote %s (%d bytes)" % (dest, len(xml)))
    return EXIT_OK


def cmd_encode(args):
    with open(args.file, "rb") as fh:
        xml = fh.read()
    try:
        ET.fromstring(xml)
    except ET.ParseError as exc:
        print("not well-formed XML: %s" % exc, file=sys.stderr)
        return EXIT_PROBLEMS
    dest = args.output or os.path.splitext(args.file)[0] + ".pkt"
    with open(dest, "wb") as fh:
        fh.write(pkt_core.encode_bytes(xml, "pkt"))
    print("wrote %s" % dest)
    return EXIT_OK


def cmd_cli_backup(args):
    sp = specmod.load(args.spec)
    print(build.cli_backup(sp))
    return EXIT_OK


def cmd_schema(args):
    print(json.dumps(specmod.SCHEMA, indent=2))
    return EXIT_OK


def _print_data(name):
    with open(os.path.join(pktforge.DATA_DIR, name), encoding="utf-8") as fh:
        sys.stdout.write(fh.read())


def cmd_catalog(args):
    from pktforge import catalog
    if args.md:
        print(catalog.markdown())
        return EXIT_OK
    rows = [e for e in catalog.entries() if (not args.kind or e["kind"] == args.kind)
            and (not args.status or e["status"] == args.status)]
    text = ["%-24s %-17s %-16s %s" % (e["model"], e["kind"], e["status"], ", ".join(catalog.compress(e["ports"]))[:70])
            for e in rows]
    _out(args, {"models": rows}, text)
    return EXIT_OK


def cmd_guide(args):
    if args.topic == "devices":
        from pktforge import catalog
        print(catalog.markdown())
        return EXIT_OK
    _print_data("LESSONS.md" if args.topic == "lessons" else "GUIDE.md")
    return EXIT_OK


def cmd_doctor(args):
    checks = []

    def rec(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    rec("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    try:
        models, modules = build._templates()
        rec("device templates", len(models) > 100, "%d models, %d modules" % (len(models), len(modules)))
    except Exception as exc:
        rec("device templates", False, str(exc))
    try:
        data = pkt_core.encode_bytes(b"<PACKETTRACER5></PACKETTRACER5>", "pkt")
        rec("codec round-trip", pkt_core.decode_bytes(data, "pkt").xml == b"<PACKETTRACER5></PACKETTRACER5>",
            "pure-Python Twofish/EAX")
    except Exception as exc:
        rec("codec round-trip", False, str(exc))
    try:
        example = os.path.join(pktforge.DATA_DIR, "examples", "minimal.json")
        sp = specmod.load(example)
        lab, _i, _m = build.build_lab(sp)
        build._cleanup_seed()
        rec("build example lab", len(lab.devs.findall("DEVICE")) == len(sp.devices), "%d devices" % len(sp.devices))
    except Exception as exc:
        rec("build example lab", False, str(exc))
    ok = all(c["ok"] for c in checks)
    _out(args, {"ok": ok, "version": pktforge.__version__, "checks": checks},
         ["%-22s %s  %s" % (c["check"], "ok" if c["ok"] else "FAIL", c["detail"]) for c in checks]
         + ["", "pktforge %s: %s" % (pktforge.__version__, "ready" if ok else "NOT ready")])
    return EXIT_OK if ok else EXIT_PROBLEMS


# --------------------------------------------------------------------------- #
def make_parser():
    p = argparse.ArgumentParser(
        prog="pktforge",
        description="Build Cisco Packet Tracer 9 labs (.pkt) from a text spec. Start with: pktforge guide",
        epilog="Agents: run `pktforge guide`, then `pktforge schema`; every command accepts --json.")
    p.add_argument("--version", action="version", version="pktforge " + pktforge.__version__)
    sub = p.add_subparsers(dest="cmd", metavar="command")

    def add(name, fn, help, json_flag=True):
        sp = sub.add_parser(name, help=help, description=help)
        sp.set_defaults(fn=fn)
        if json_flag:
            sp.add_argument("--json", action="store_true", help="machine-readable output")
        return sp

    s = add("build", cmd_build, "spec -> .pkt (+ .xml, + CLI backup). Lints first.")
    s.add_argument("spec")
    s.add_argument("-o", "--output", help="output directory (default ./out)")
    s.add_argument("--no-pkt", action="store_true")
    s.add_argument("--no-xml", action="store_true")
    s.add_argument("--force", action="store_true", help="build even if the linter found errors")

    s = add("check", cmd_check, "lint a spec, or audit an existing .pkt/.xml")
    s.add_argument("file")
    s.add_argument("--strict", action="store_true", help="warnings also give a non-zero exit code")

    s = add("init", cmd_init, "write a starter spec", json_flag=False)
    s.add_argument("name", nargs="?", default="lab")
    s.add_argument("-t", "--template", default="minimal", help="minimal | bank-cs5 | campus-vlan | ha-campus | wifi-campus | wan-ospf-areas | "
                   "two-wan-modules | model-mix | hub-spoke-43")
    s.add_argument("--force", action="store_true")

    s = add("models", cmd_models, "list available device models")
    s.add_argument("--kind", help="router, switch, pc, server, ...")
    s.add_argument("--modules", action="store_true", help="list installable modules instead")

    s = add("ports", cmd_ports, "list valid port names for a model")
    s.add_argument("model")
    s.add_argument("--module", action="append", help="installed module, repeatable (e.g. HWIC-2T)")

    s = add("decode", cmd_decode, ".pkt -> XML", json_flag=False)
    s.add_argument("file")
    s.add_argument("-o", "--output")

    s = add("encode", cmd_encode, "XML -> .pkt (replaces the pt-convert website)", json_flag=False)
    s.add_argument("file")
    s.add_argument("-o", "--output")

    s = add("cli-backup", cmd_cli_backup, "print paste-able config blocks per device", json_flag=False)
    s.add_argument("spec")

    add("schema", cmd_schema, "print the spec's JSON Schema", json_flag=False)

    s = add("catalog", cmd_catalog, "every model with its status, valid ports and modules")
    s.add_argument("--kind", help="router, switch, pc, server, ...")
    s.add_argument("--status", choices=["traffic-verified", "ports-verified", "untested", "rejected"])
    s.add_argument("--md", action="store_true", help="print the full Markdown report (DEVICES.md)")

    s = add("guide", cmd_guide, "print the usage guide, `lessons`, or `devices`", json_flag=False)
    s.add_argument("topic", nargs="?", default="usage", choices=["usage", "lessons", "devices"])

    add("doctor", cmd_doctor, "self-test the installation")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    parser = make_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return EXIT_USAGE
    if getattr(args, "json", False) is None:
        args.json = False
    try:
        return args.fn(args)
    except SpecError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "issues": [i.as_dict() for i in exc.issues]}, indent=2))
        else:
            for line in _issues_text(exc.issues):
                print(line, file=sys.stderr)
        return EXIT_PROBLEMS
    except FileNotFoundError as exc:
        print("file not found: %s" % exc.filename, file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:        # pkt_core errors: not a Packet Tracer file, etc.
        if os.environ.get("PKTFORGE_DEBUG"):
            raise
        print("error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
