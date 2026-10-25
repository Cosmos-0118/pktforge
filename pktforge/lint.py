"""Static checks that catch, before Packet Tracer opens the file, the mistakes
that make a lab *look* right but pass no traffic.

Every rule here exists because it bit a real build (see docs/LESSONS.md).
The checks run on a small network model built either from a spec or from the
XML inside a .pkt, so a hand-edited or third-party file can be audited too.
"""
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import pktforge  # noqa: F401  (puts the vendored modules on sys.path)
import lab_api

from pktforge.issues import ERROR, INFO, WARNING, Issue
from pktforge.ports import ENDPOINT_KINDS, IOS_KINDS, canon_port, is_switch_like

# global commands that end an `interface` block in CLI-style (unindented) configs
_GLOBAL = re.compile(r"^(router|line|ip route|ip nat|ip dhcp|ip domain|ip classless|access-list|hostname|"
                     r"enable|username|vlan|spanning-tree|service|banner|no ip domain|crypto|ipv6 unicast|"
                     r"logging|snmp-server|ntp|end|exit|!)\b", re.I)
_IP_ADDR = re.compile(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*$", re.I)


@dataclass
class Iface:
    name: str
    ip: str = None
    mask: str = None
    shutdown: bool = None

    @property
    def network(self):
        if not self.ip:
            return None
        try:
            return ipaddress.ip_interface("%s/%s" % (self.ip, self.mask)).network
        except ValueError:
            return None


@dataclass
class NDev:
    name: str
    model: str
    kind: str
    ifaces: dict = field(default_factory=dict)
    config: list = field(default_factory=list)
    gateway: str = None
    has_ip_cfg: bool = True

    @property
    def is_end(self):
        return self.kind in ENDPOINT_KINDS


@dataclass
class NLink:
    a: str
    a_port: str
    b: str
    b_port: str
    cable: str = None       # eStraightThrough | eCrossOver | eSerial
    dce: str = None
    where: str = ""


@dataclass
class Net:
    devs: dict = field(default_factory=dict)
    links: list = field(default_factory=list)


def parse_ios(lines):
    """Extract interfaces and their IPs from IOS lines (CLI or running-config style)."""
    ifaces, cur = {}, None
    for raw in lines:
        s = raw.strip()
        m = re.match(r"^interface\s+(\S+)$", s, re.I)
        if m:
            cur = ifaces.setdefault(canon_port(m.group(1)), Iface(canon_port(m.group(1))))
            continue
        if cur is not None:
            if not raw.startswith(" ") and _GLOBAL.match(s) and not s.lower().startswith(("no shutdown", "shutdown")):
                cur = None
                continue
            ma = _IP_ADDR.match(raw)
            if ma:
                cur.ip, cur.mask = ma.group(1), ma.group(2)
            elif s.lower() == "no ip address":
                cur.ip = cur.mask = None
            elif s.lower() == "shutdown":
                cur.shutdown = True
            elif s.lower() == "no shutdown":
                cur.shutdown = False
    return ifaces


def static_routes(lines):
    out = []
    for raw in lines:
        m = re.match(r"^\s*ip route\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s*$", raw, re.I)
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def ospf_networks(lines):
    out = []
    for raw in lines:
        m = re.match(r"^\s*network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)\s*$", raw, re.I)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# --------------------------------------------------------------------------- #
# model construction
# --------------------------------------------------------------------------- #
def net_from_spec(spec):
    net = Net()
    for d in spec.devices:
        kind = lab_api.kind_for_model(d.model)
        nd = NDev(d.name, d.model, kind, config=list(d.config))
        if kind in IOS_KINDS:
            nd.ifaces = parse_ios(d.config)
        else:
            nd.ifaces = {"": Iface("", d.ip, d.mask)}
            nd.gateway = d.gateway
            nd.has_ip_cfg = bool(d.ip) or d.dhcp
        net.devs[d.name] = nd
    for l in spec.links:
        cable = "eSerial" if l.type == "serial" else None
        net.links.append(NLink(l.a, l.a_port, l.b, l.b_port, cable, l.dce, "links[%d]" % l.index))
    return net


def net_from_xml(root):
    net = Net()
    ids = {}
    for d in root.findall("NETWORK/DEVICES/DEVICE"):
        eng = d.find("ENGINE")
        name = eng.findtext("NAME") or ""
        model = eng.find("TYPE").get("model", "") if eng.find("TYPE") is not None else ""
        kind = lab_api.kind_for_model(model)
        lines = [l.text or "" for l in eng.findall("RUNNINGCONFIG/LINE")]
        nd = NDev(name, model, kind, config=lines)
        if kind in IOS_KINDS:
            nd.ifaces = parse_ios(lines)
        else:
            p = d.find(".//PORT")
            ip = p.findtext("IP") if p is not None else None
            mask = p.findtext("SUBNET") if p is not None else None
            nd.ifaces = {"": Iface("", ip or None, mask or None)}
            nd.gateway = (p.findtext("PORT_GATEWAY") if p is not None else None) or None
            nd.has_ip_cfg = bool(ip) or (p is not None and p.findtext("PORT_DHCP_ENABLE") == "true")
        ids[eng.findtext("SAVE_REF_ID")] = name
        net.devs[name] = nd
    for L in root.findall("NETWORK/LINKS/LINK"):
        c = L.find("CABLE")
        if c is None:
            continue
        ports = [p.text or "" for p in c.findall("PORT")]
        if len(ports) < 2:
            continue
        a, b = ids.get(c.findtext("FROM")), ids.get(c.findtext("TO"))
        dce = ids.get(c.findtext("DCEDEV")) if c.findtext("DCEDEV") else None
        ctype = "eSerial" if L.findtext("TYPE") == "eSerial" else c.findtext("TYPE")
        net.links.append(NLink(a, canon_port(ports[0]), b, canon_port(ports[1]), ctype, dce))
    return net


# --------------------------------------------------------------------------- #
# the rules
# --------------------------------------------------------------------------- #
def _l3(dev):
    return [i for i in dev.ifaces.values() if i.ip and i.network is not None]


def check_net(net, verified_ports=None):
    """verified_ports: {device name: (set of valid names, model_is_verified)} - optional."""
    out = []

    # --- links reference real devices; ports valid and unique
    used = Counter()
    for l in net.links:
        for end, port in ((l.a, l.a_port), (l.b, l.b_port)):
            if end not in net.devs:
                out.append(Issue("E003", ERROR, "link names unknown device %r" % end, l.where,
                                 "add it to `devices`, or fix the spelling (names are case-sensitive)"))
                continue
            used[(end, port)] += 1
            if verified_ports and end in verified_ports:
                valid, firm = verified_ports[end]
                if valid and port not in valid:
                    sev = ERROR if firm else WARNING
                    sample = ", ".join(sorted(valid)[:6])
                    out.append(Issue("E004", sev, "%s has no port %s%s" % (
                        end, port, "" if firm else " (port names for this model are inferred, not verified)"),
                        l.where, "valid ports include: %s ..." % sample))
        if l.a == l.b:
            out.append(Issue("E007", ERROR, "link connects %s to itself" % l.a, l.where))
    for (end, port), n in used.items():
        if n > 1:
            out.append(Issue("E005", ERROR, "%s %s is used by %d cables" % (end, port, n), "",
                             "one cable per port"))

    # --- serial links
    for l in net.links:
        if l.cable == "eSerial":
            if l.dce and l.dce not in (l.a, l.b):
                out.append(Issue("E006", ERROR, "serial DCE %r is not an end of this link" % l.dce, l.where))
            for end, port in ((l.a, l.a_port), (l.b, l.b_port)):
                if end in net.devs and not port.startswith("Serial"):
                    out.append(Issue("E008", ERROR, "%s %s is not a serial port" % (end, port), l.where,
                                     "serial links need Serial ports (add modules: [\"HWIC-2T\"])"))

    # --- per device: overlapping subnets (the bug that silently blanked R1's LAN port)
    for dev in net.devs.values():
        nets = [(i, i.network) for i in _l3(dev)]
        for x in range(len(nets)):
            for y in range(x + 1, len(nets)):
                (ia, na), (ib, nb) = nets[x], nets[y]
                if na.overlaps(nb):
                    out.append(Issue("E010", ERROR, "%s: %s (%s) overlaps %s (%s)" % (
                        dev.name, ia.name, na, ib.name, nb), dev.name,
                        "Packet Tracer rejects the second `ip address` when it replays the config, so that "
                        "interface comes up with no address. Give each interface its own subnet"))

    # --- duplicate IPs
    seen = {}
    for dev in net.devs.values():
        for i in _l3(dev):
            key = i.ip
            if key in seen:
                out.append(Issue("E011", ERROR, "IP %s is on both %s and %s" % (key, seen[key], dev.name),
                                 dev.name, "every interface needs a unique address"))
            else:
                seen[key] = dev.name

    # --- stale/missing end-device addressing
    for dev in net.devs.values():
        if dev.is_end:
            i = dev.ifaces[""]
            if not dev.has_ip_cfg and any(dev.name in (l.a, l.b) for l in net.links):
                out.append(Issue("W012", WARNING, "%s is cabled but has no IP address" % dev.name, dev.name,
                                 "set ip (and gateway), or dhcp: true"))
            if i.ip and dev.gateway:
                try:
                    gw = ipaddress.ip_address(dev.gateway)
                    if i.network is not None and gw not in i.network:
                        out.append(Issue("E013", ERROR, "%s: gateway %s is outside its subnet %s" % (
                            dev.name, dev.gateway, i.network), dev.name,
                            "the default gateway must be on the same subnet as the host"))
                except ValueError:
                    out.append(Issue("E013", ERROR, "%s: gateway %r is not an IP address" % (dev.name, dev.gateway),
                                     dev.name))

    # --- broadcast domains: switches/hubs merge their neighbours; routers and hosts do not
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    # a node is (device) for switches, (device, port) for L3 devices
    def node(devname, port):
        d = net.devs[devname]
        return ("sw", devname) if is_switch_like(d.kind, d.model) else (devname, port)

    for l in net.links:
        if l.a in net.devs and l.b in net.devs:
            union(node(l.a, l.a_port), node(l.b, l.b_port))
    domains = defaultdict(list)
    for dev in net.devs.values():
        if is_switch_like(dev.kind, dev.model):
            continue
        for l in net.links:
            for end, port in ((l.a, l.a_port), (l.b, l.b_port)):
                if end == dev.name:
                    iface = dev.ifaces.get(port if not dev.is_end else "")
                    domains[find((dev.name, port))].append((dev, port, iface))
    for members in domains.values():
        nets_here = {}
        for dev, port, iface in members:
            if iface is not None and iface.network is not None:
                nets_here.setdefault(iface.network, []).append("%s %s" % (dev.name, port or ""))
        if len(nets_here) > 1:
            desc = "; ".join("%s = %s" % (n, ", ".join(v)) for n, v in nets_here.items())
            out.append(Issue("E014", ERROR, "devices on the same cable segment are in different subnets: " + desc,
                             "", "put both ends of a link (and everything on one switch) in one subnet - "
                                 "this is why pings fail even though the diagram looks right"))
        ips_here = {str(i.ip) for _d, _p, i in members if i is not None and i.ip}
        for dev, port, iface in members:
            if dev.is_end and dev.gateway and ips_here and dev.gateway not in ips_here:
                routers = [d for d, _p, i in members if not d.is_end]
                if routers:
                    out.append(Issue("E015", ERROR, "%s: gateway %s is not an address of any device on its LAN "
                                     "(found: %s)" % (dev.name, dev.gateway, ", ".join(sorted(ips_here))),
                                     dev.name, "set gateway to the router interface that faces this LAN"))

    # --- routing sanity
    for dev in net.devs.values():
        if dev.kind not in IOS_KINDS:
            continue
        mine = [i.network for i in _l3(dev)]
        for net_addr, mask, nh in static_routes(dev.config):
            try:
                n = ipaddress.ip_address(nh)
            except ValueError:
                continue
            if mine and not any(n in m for m in mine):
                out.append(Issue("W030", WARNING, "%s: static route next hop %s is not on any directly connected "
                                 "network" % (dev.name, nh), dev.name,
                                 "the route will never be installed; check the next-hop address"))
        for addr, wild in ospf_networks(dev.config):
            try:
                w = ipaddress.ip_network("%s/%s" % (addr, ".".join(str(255 - int(o)) for o in wild.split("."))),
                                         strict=False)
            except ValueError:
                continue
            if mine and not any(m.overlaps(w) for m in mine):
                out.append(Issue("W031", WARNING, "%s: OSPF network %s %s matches none of its interfaces"
                                 % (dev.name, addr, wild), dev.name,
                                 "check the wildcard mask (it is the inverse of the subnet mask)"))

    # --- cable choice
    for l in net.links:
        if l.cable in ("eStraightThrough", "eCrossOver") and l.a in net.devs and l.b in net.devs:
            a, b = net.devs[l.a], net.devs[l.b]
            same = is_switch_like(a.kind, a.model) == is_switch_like(b.kind, b.model)
            want = "eCrossOver" if same else "eStraightThrough"
            if l.cable != want:
                out.append(Issue("W040", WARNING, "%s <-> %s uses %s; %s is expected" % (l.a, l.b, l.cable, want),
                                 l.where, "PT may leave the link down with the wrong copper cable type"))
    return out


# --------------------------------------------------------------------------- #
# XML-only structural checks
# --------------------------------------------------------------------------- #
def check_xml(root):
    out = []
    if root.tag != "PACKETTRACER5":
        out.append(Issue("X001", ERROR, "root element is %s, not PACKETTRACER5" % root.tag))
        return out
    devs = root.findall("NETWORK/DEVICES/DEVICE")
    ids = Counter(d.findtext("ENGINE/SAVE_REF_ID") for d in devs)
    for sid, n in ids.items():
        if n > 1:
            out.append(Issue("X002", ERROR, "duplicate SAVE_REF_ID %s" % sid))
    leaves = {n.findtext("UUID_STR") for n in root.iter("NODE")}
    for d in devs:
        name = d.findtext("ENGINE/NAME")
        leaf = (d.findtext("WORKSPACE/PHYSICAL") or "").split(",")[-1]
        if leaf not in leaves:
            out.append(Issue("X003", ERROR, "%s has no matching physical-workspace leaf (file will be reported "
                             "corrupt)" % name, name))
        if d.findtext("ENGINE/POWER") != "true":
            out.append(Issue("X004", WARNING, "%s is powered off" % name, name))
        model = d.find("ENGINE/TYPE").get("model", "") if d.find("ENGINE/TYPE") is not None else ""
        kind = lab_api.kind_for_model(model)
        if kind in IOS_KINDS:
            stale = [p for p in d.iter("PORT") if (p.findtext("IP") or "").strip()]
            if stale:
                out.append(Issue("X005", ERROR, "%s: %d port(s) carry a stale port-level IP (%s) - Packet Tracer "
                                 "will reject overlapping addresses from the config" % (
                                     name, len(stale), stale[0].findtext("IP")), name,
                                 "clear <IP>/<SUBNET> on IOS devices; addresses belong in the config"))
            off = [p for p in d.iter("PORT") if p.findtext("POWER") == "false"]
            if off:
                out.append(Issue("X006", INFO, "%s: %d port(s) are administratively off" % (name, len(off)), name))
        elif kind in ENDPOINT_KINDS:
            eg = d.findtext("ENGINE/GATEWAY") or ""
            pg = d.findtext(".//PORT/PORT_GATEWAY") or ""
            if eg and pg and eg != pg:
                out.append(Issue("X007", WARNING, "%s: engine gateway %s differs from NIC gateway %s" % (
                    name, eg, pg), name))
    macs = Counter(m.text for m in root.iter("MACADDRESS") if m.text)
    dup = [m for m, c in macs.items() if c > 1]
    if dup:
        out.append(Issue("X008", ERROR, "duplicate MAC addresses: %s" % ", ".join(dup[:3])))
    return out
