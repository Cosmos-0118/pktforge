"""Load and normalise a pktforge spec (JSON, TOML or - if PyYAML exists - YAML)."""
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field

from pktforge.issues import ERROR, INFO, Issue, SpecError
from pktforge.ports import canon_port

# commands that mean "I typed this at a prompt", not "this is part of a config"
_PROMPT_ONLY = re.compile(
    r"^(enable|en|configure terminal|conf t|configure t|end|exit\s*all|disable|"
    r"copy\s+running-config\s+startup-config|copy\s+run\s+start|write(\s+memory)?|wr)$", re.I)


@dataclass
class Dev:
    name: str
    model: str
    at: tuple = None
    modules: list = field(default_factory=list)
    config: list = field(default_factory=list)
    ip: str = None
    mask: str = None
    gateway: str = None
    dns: str = None
    dhcp: bool = False
    services: dict = field(default_factory=dict)
    dhcp_pools: list = field(default_factory=list)   # servers: [{name, network, mask, gateway, dns, start, max_users, tftp}]
    wireless: dict = field(default_factory=dict)     # {"ssid": "LAB"}: APs/routers broadcast it, clients join it
    power: bool = True
    stripped: list = field(default_factory=list)


@dataclass
class Link:
    a: str
    a_port: str
    b: str
    b_port: str
    type: str = "auto"      # auto | straight | cross | serial
    dce: str = None
    clock: int = 64000
    index: int = 0


@dataclass
class Spec:
    name: str
    devices: list
    links: list
    labels: object = "auto"   # "auto" | False | [ {text, at} ]
    notes: list = field(default_factory=list)
    base_dir: str = "."


def load_file(path):
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        if ext == ".toml":
            import tomllib
            return tomllib.loads(raw.decode("utf-8"))
        if ext in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError:
                raise SpecError(Issue("S001", ERROR, "YAML spec needs PyYAML, which is not installed",
                                      path, "use a .json or .toml spec, or: pip install pyyaml"))
            return yaml.safe_load(raw)
        return json.loads(raw.decode("utf-8-sig"))
    except SpecError:
        raise
    except Exception as exc:
        raise SpecError(Issue("S002", ERROR, "cannot parse spec: %s" % exc, path,
                              "check commas/quotes; run `pktforge schema` for the expected shape"))


def _split_endpoint(text, where):
    if not isinstance(text, str) or ":" not in text:
        raise SpecError(Issue("S010", ERROR, "link endpoint %r is not 'Device:Port'" % (text,), where,
                              "write it like \"R1:Gi0/0\""))
    dev, port = text.rsplit(":", 1)
    return dev.strip(), canon_port(port)


def _clean_config(raw, where):
    if raw is None:
        return [], []
    if isinstance(raw, str):
        raw = raw.splitlines()
    kept, stripped = [], []
    for line in raw:
        line = str(line).rstrip()
        if _PROMPT_ONLY.match(line.strip()):
            stripped.append(line.strip())
            continue
        kept.append(line)
    # trailing blank lines carry no meaning
    while kept and not kept[-1].strip():
        kept.pop()
    return kept, stripped


def _parse_ip(dev, d, where):
    ip = d.get("ip")
    if not ip:
        return
    mask = d.get("mask")
    try:
        if "/" in ip:
            iface = ipaddress.ip_interface(ip)
            dev.ip, dev.mask = str(iface.ip), str(iface.netmask)
        else:
            if not mask:
                raise ValueError("no mask")
            ipaddress.ip_interface("%s/%s" % (ip, mask))
            dev.ip, dev.mask = ip, mask
    except ValueError:
        raise SpecError(Issue("S020", ERROR, "bad IP address %r (mask %r)" % (ip, mask), where,
                              "use \"10.0.0.5/24\" or ip + mask"))


def _parse_pools(raw, where):
    """Server DHCP pools: {"network": "10.0.10.0/24", "gateway", "dns", "start", "max_users", "name", "tftp"}."""
    pools = []
    for n, p in enumerate(raw or []):
        try:
            if not isinstance(p, dict) or not p.get("network"):
                raise ValueError("needs a `network`, e.g. \"10.0.10.0/24\"")
            if "/" in str(p["network"]):
                net = ipaddress.ip_network(p["network"], strict=False)
            elif p.get("mask"):
                net = ipaddress.ip_network("%s/%s" % (p["network"], p["mask"]), strict=False)
            else:
                raise ValueError("network %r needs a /prefix or a `mask`" % p["network"])
            if net.version != 4 or net.prefixlen > 30:
                raise ValueError("pool network must be an IPv4 network of /30 or larger")
            hosts = list(net.hosts())
            start = ipaddress.ip_address(p["start"]) if p.get("start") else hosts[0]
            for key in ("gateway", "dns", "tftp"):
                if p.get(key):
                    ipaddress.ip_address(p[key])
            max_users = int(p.get("max_users", max(1, len(hosts) - (hosts.index(start) if start in hosts else 0))))
            pools.append({"name": str(p.get("name") or ("serverPool" if n == 0 else "pool%d" % n)),
                          "network": net, "start": start, "max_users": max_users,
                          "gateway": p.get("gateway"), "dns": p.get("dns"), "tftp": p.get("tftp")})
        except (ValueError, TypeError) as exc:
            raise SpecError(Issue("S050", ERROR, "dhcp_pools[%d]: %s" % (n, exc), where,
                                  "e.g. {\"network\": \"10.0.10.0/24\", \"gateway\": \"10.0.10.1\", \"dns\": \"10.0.99.2\"}"))
    return pools


def parse(data, base_dir="."):
    """Turn a decoded spec dict into a Spec, raising SpecError on malformed input."""
    if not isinstance(data, dict):
        raise SpecError(Issue("S003", ERROR, "spec must be an object at the top level"))
    problems = []
    devices, seen = [], set()
    for i, d in enumerate(data.get("devices") or []):
        where = "devices[%d]" % i
        if not isinstance(d, dict) or not d.get("name") or not d.get("model"):
            problems.append(Issue("S004", ERROR, "every device needs a name and a model", where,
                                  "e.g. {\"name\": \"R1\", \"model\": \"2911\"}"))
            continue
        name = str(d["name"])
        where = "device %s" % name
        if name in seen:
            problems.append(Issue("S005", ERROR, "duplicate device name %r" % name, where,
                                  "device names must be unique"))
            continue
        seen.add(name)
        dev = Dev(name=name, model=str(d["model"]))
        at = d.get("at")
        if at is not None:
            if not (isinstance(at, (list, tuple)) and len(at) == 2):
                problems.append(Issue("S006", ERROR, "'at' must be [x, y]", where))
            else:
                dev.at = (int(at[0]), int(at[1]))
        dev.modules = list(d.get("modules") or [])
        cfg = d.get("config")
        if d.get("config_file"):
            p = os.path.join(base_dir, d["config_file"])
            try:
                with open(p, encoding="utf-8") as fh:
                    cfg = fh.read()
            except OSError as exc:
                problems.append(Issue("S007", ERROR, "cannot read config_file: %s" % exc, where))
        dev.config, dev.stripped = _clean_config(cfg, where)
        try:
            _parse_ip(dev, d, where)
        except SpecError as exc:
            problems.extend(exc.issues)
        dev.gateway = d.get("gateway")
        dev.dns = d.get("dns")
        dev.dhcp = bool(d.get("dhcp", False))
        dev.services = dict(d.get("services") or {})
        w = d.get("wireless")
        if w is not None:
            if isinstance(w, str):
                w = {"ssid": w}
            if not isinstance(w, dict) or not str(w.get("ssid", "")).strip():
                problems.append(Issue("S060", ERROR, "`wireless` needs an ssid, e.g. {\"ssid\": \"LAB\"}", where,
                                      "open (no password) networks only; WPA is not supported yet"))
            else:
                dev.wireless = {"ssid": str(w["ssid"])}
        try:
            dev.dhcp_pools = _parse_pools(d.get("dhcp_pools"), where)
        except SpecError as exc:
            problems.extend(exc.issues)
        dev.power = bool(d.get("power", True))
        if dev.stripped:
            problems.append(Issue("S030", INFO, "removed prompt-only lines from config: %s"
                                  % ", ".join(sorted(set(dev.stripped))), where,
                                  "harmless - the file is loaded as a ready-made config"))
        devices.append(dev)

    links = []
    for i, l in enumerate(data.get("links") or []):
        where = "links[%d]" % i
        try:
            if isinstance(l, (list, tuple)):
                if len(l) != 2:
                    raise SpecError(Issue("S011", ERROR, "list-form link needs exactly 2 endpoints", where))
                a, b, extra = l[0], l[1], {}
            elif isinstance(l, dict):
                a, b, extra = l.get("a"), l.get("b"), l
            else:
                raise SpecError(Issue("S011", ERROR, "link must be [\"A:port\", \"B:port\"] or an object", where))
            ad, ap = _split_endpoint(a, where)
            bd, bp = _split_endpoint(b, where)
        except SpecError as exc:
            problems.extend(exc.issues)
            continue
        ltype = str(extra.get("type", "auto")).lower()
        if ltype not in ("auto", "straight", "cross", "serial", "console", "fiber"):
            problems.append(Issue("S012", ERROR, "link type %r unknown" % ltype, where,
                                  "use auto, straight, cross, serial, console or fiber"))
            continue
        links.append(Link(ad, ap, bd, bp, ltype, extra.get("dce"), int(extra.get("clock", 64000)), i))

    labels = data.get("labels", "auto")
    if isinstance(labels, list):
        for lab in labels:
            if not (isinstance(lab, dict) and lab.get("text") and isinstance(lab.get("at"), (list, tuple))):
                problems.append(Issue("S040", ERROR, "each label needs text and at:[x,y]", "labels"))
                break
    if any(p.severity == ERROR for p in problems):
        raise SpecError(problems)
    spec = Spec(name=str(data.get("name") or "lab"), devices=devices, links=links, labels=labels,
                base_dir=base_dir)
    spec.notes = problems     # carry the INFO items forward
    return spec


def load(path):
    data = load_file(path)
    return parse(data, os.path.dirname(os.path.abspath(path)))


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "pktforge spec",
    "type": "object",
    "required": ["devices"],
    "properties": {
        "name": {"type": "string", "description": "lab name; used for output file names"},
        "devices": {"type": "array", "items": {"type": "object", "required": ["name", "model"], "properties": {
            "name": {"type": "string"},
            "model": {"type": "string", "description": "see `pktforge models` (e.g. 2911, 2960-24TT, PC-PT, Server-PT)"},
            "at": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2,
                   "description": "canvas position [x, y]; omit for auto-layout"},
            "modules": {"type": "array", "items": {"type": "string"}, "description": "e.g. [\"HWIC-2T\"] for serial ports"},
            "config": {"description": "IOS lines (array or one string), exactly as typed in config mode",
                       "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
            "config_file": {"type": "string", "description": "path (relative to the spec) of a file with IOS lines"},
            "ip": {"type": "string", "description": "end devices: \"10.0.0.5/24\", or ip with separate mask"},
            "mask": {"type": "string"},
            "gateway": {"type": "string"},
            "dns": {"type": "string"},
            "dhcp": {"type": "boolean"},
            "services": {"type": "object", "description": "servers: {\"http\": true}"},
            "wireless": {"description": "{\"ssid\": \"LAB\"}: an access point / wireless router broadcasts it, a laptop, "
                         "PC or phone joins it (a wireless NIC is fitted automatically; open networks only, and the "
                         "client must sit within the AP's coverage - auto-layout takes care of that)",
                         "anyOf": [{"type": "string"}, {"type": "object", "properties": {"ssid": {"type": "string"}}}]},
            "dhcp_pools": {"type": "array", "description": "Server-PT: DHCP pools the server hands out (turns the DHCP "
                           "service on). Routers need `ip helper-address <server ip>` to reach it from other subnets",
                           "items": {"type": "object", "required": ["network"], "properties": {
                               "network": {"type": "string", "description": "\"10.0.10.0/24\""},
                               "gateway": {"type": "string"}, "dns": {"type": "string"}, "tftp": {"type": "string"},
                               "start": {"type": "string", "description": "first address handed out (default: first host)"},
                               "max_users": {"type": "integer"}, "name": {"type": "string"}}}},
            "power": {"type": "boolean", "default": True},
        }}},
        "links": {"type": "array", "items": {"anyOf": [
            {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2,
             "description": "[\"R1:Gi0/0\", \"SW1:Gi0/1\"]; cable type is chosen automatically"},
            {"type": "object", "required": ["a", "b"], "properties": {
                "a": {"type": "string"}, "b": {"type": "string"},
                "type": {"enum": ["auto", "straight", "cross", "serial", "console", "fiber"],
                         "description": "auto picks serial/console/fibre/straight/crossover from the ports and models"},
                "dce": {"type": "string", "description": "serial only: device that provides the clock (default: a)"},
                "clock": {"type": "integer", "default": 64000}}}]}},
        "labels": {"anyOf": [{"enum": ["auto", False]},
                             {"type": "array", "items": {"type": "object", "required": ["text", "at"],
                                                        "properties": {"text": {"type": "string"},
                                                                       "at": {"type": "array", "items": {"type": "integer"}}}}}],
                   "description": "canvas labels. 'auto' = one short subnet label per network (default)"},
    },
}
