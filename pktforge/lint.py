"""Static checks that catch, before Packet Tracer opens the file, the mistakes
that make a lab *look* right but pass no traffic.

Every rule here exists because it bit a real build (see pktforge/data/LESSONS.md).
The checks run on a small network model built either from a spec or from the
XML inside a .pkt, so a hand-edited or third-party file can be audited too.
"""
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import pktforge  # noqa: F401  (puts the vendored modules on sys.path)
import lab_api

from pktforge import iosparse
from pktforge.iosparse import Iface
from pktforge.issues import ERROR, INFO, WARNING, Issue
from pktforge.ports import ENDPOINT_KINDS, IOS_KINDS, canon_port, is_switch_like


@dataclass
class NDev:
    name: str
    model: str
    kind: str
    ifaces: dict = field(default_factory=dict)
    config: list = field(default_factory=list)
    cfg: iosparse.Cfg = None
    gateway: str = None
    dhcp: bool = False
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
    """Interfaces of an IOS config (kept for callers that only need addresses)."""
    return iosparse.parse(lines).ifaces


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
def _ios_dev(name, model, kind, lines):
    nd = NDev(name, model, kind, config=list(lines))
    nd.cfg = iosparse.parse(lines)
    nd.ifaces = nd.cfg.ifaces
    return nd


def net_from_spec(spec):
    net = Net()
    for d in spec.devices:
        kind = lab_api.kind_for_model(d.model)
        if kind in IOS_KINDS:
            nd = _ios_dev(d.name, d.model, kind, d.config)
        else:
            nd = NDev(d.name, d.model, kind, config=list(d.config))
            nd.ifaces = {"": Iface("", d.ip, d.mask)}
            nd.gateway = d.gateway
            nd.dhcp = d.dhcp
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
        if kind in IOS_KINDS:
            nd = _ios_dev(name, model, kind, lines)
        else:
            nd = NDev(name, model, kind, config=lines)
            p = d.find(".//PORT")
            ip = p.findtext("IP") if p is not None else None
            mask = p.findtext("SUBNET") if p is not None else None
            nd.ifaces = {"": Iface("", ip or None, mask or None)}
            nd.gateway = (p.findtext("PORT_GATEWAY") if p is not None else None) or None
            nd.dhcp = p is not None and p.findtext("PORT_DHCP_ENABLE") == "true"
            nd.has_ip_cfg = bool(ip) or nd.dhcp
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
# layer-2 segments (VLAN aware)
# --------------------------------------------------------------------------- #
def segments(net):
    """Group layer-3 interfaces into broadcast segments.

    A segment is one VLAN on one connected set of switches (trunks carry many VLANs; an access port carries one),
    a router-on-a-stick sub-interface joins the VLAN its `encapsulation dot1Q` names, and a direct cable between
    two layer-3 devices is its own segment. Returns a list of [(device, port, Iface), ...].
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    all_vlans = {1}
    for d in net.devs.values():
        if d.cfg is not None:
            all_vlans |= d.cfg.vlans
            for i in d.cfg.ifaces.values():
                all_vlans.add(i.access_vlan)
                if i.vlan:
                    all_vlans.add(i.vlan)

    def sw(d):
        return is_switch_like(d.kind, d.model)

    def swport(d, port):
        return d.ifaces.get(port) or Iface(port)

    for l in net.links:
        if l.a not in net.devs or l.b not in net.devs:
            continue
        A, B = net.devs[l.a], net.devs[l.b]
        if not sw(A) and not sw(B):
            union(("l3", A.name, l.a_port), ("l3", B.name, l.b_port))
        elif sw(A) and sw(B):
            ia, ib = swport(A, l.a_port), swport(B, l.b_port)
            if "trunk" in (ia.mode, ib.mode):
                allowed = all_vlans
                for i in (ia, ib):
                    if i.trunk_vlans is not None:
                        allowed = allowed & i.trunk_vlans
                for v in allowed:
                    union(("vlan", A.name, v), ("vlan", B.name, v))
            else:
                union(("vlan", A.name, ia.access_vlan), ("vlan", B.name, ib.access_vlan))
        else:
            S, sp, O, op = (A, l.a_port, B, l.b_port) if sw(A) else (B, l.b_port, A, l.a_port)
            i = swport(S, sp)
            if i.mode == "trunk":
                for sub in O.ifaces.values():
                    if sub.vlan and sub.name.split(".")[0] == op and (i.trunk_vlans is None or sub.vlan in i.trunk_vlans):
                        union(("vlan", S.name, sub.vlan), ("l3", O.name, sub.name))
                union(("vlan", S.name, i.native), ("l3", O.name, op))
            else:
                union(("vlan", S.name, i.access_vlan), ("l3", O.name, op))

    groups = defaultdict(list)
    for d in net.devs.values():
        if sw(d):
            continue
        if d.is_end or d.kind not in IOS_KINDS:
            ports = {l.a_port for l in net.links if l.a == d.name} | {l.b_port for l in net.links if l.b == d.name}
            iface = d.ifaces.get("")
            for p in ports:
                groups[find(("l3", d.name, p))].append((d, p, iface))
        else:
            for name, iface in d.ifaces.items():
                groups[find(("l3", d.name, name))].append((d, name, iface))
    return list(groups.values())


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

    # --- order-dependent commands Packet Tracer rejects on replay
    for dev in net.devs.values():
        if dev.cfg is None:
            continue
        for i in dev.cfg.ifaces.values():
            if i.ip and "." in i.name and (i.vlan is None or i.ip_before_encap):
                out.append(Issue("E016", ERROR, "%s %s: `ip address` before (or without) `encapsulation dot1Q N`" % (
                    dev.name, i.name), dev.name,
                    "put `encapsulation dot1Q <vlan>` first; IOS refuses an address on a sub-interface that has no VLAN"))
            for name, _dir in i.acls:
                if name not in dev.cfg.acls:
                    out.append(Issue("W060", WARNING, "%s %s applies ACL %s, which is never defined" % (
                        dev.name, i.name, name), dev.name, "define it with `ip access-list` / `access-list`"))
        for pool, rule in dev.cfg.nat_bad_pool:
            out.append(Issue("E017", ERROR, "%s: `%s` uses NAT pool %s before it is defined" % (dev.name, rule, pool),
                             dev.name, "write `ip nat pool %s ...` earlier in the config" % pool))

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

    # --- end-device addressing
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

    # --- layer-2 segments
    for members in segments(net):
        nets_here = {}
        for dev, port, iface in members:
            if iface is not None and iface.network is not None:
                nets_here.setdefault(iface.network, []).append("%s %s" % (dev.name, port or ""))
        if len(nets_here) > 1:
            desc = "; ".join("%s = %s" % (n, ", ".join(v)) for n, v in nets_here.items())
            out.append(Issue("E014", ERROR, "devices in one broadcast segment are in different subnets: " + desc,
                             "", "put both ends of a link (and everything in one VLAN) in one subnet - "
                                 "this is why pings fail even though the diagram looks right"))
        ips_here = {str(i.ip) for _d, _p, i in members if i is not None and i.ip}
        for dev, port, iface in members:
            if dev.is_end and dev.gateway and dev.gateway not in ips_here:
                out.append(Issue("E015", ERROR, "%s: gateway %s is not an address of any device in its VLAN/LAN "
                                 "(found: %s)" % (dev.name, dev.gateway, ", ".join(sorted(ips_here)) or "none"),
                                 dev.name, "give the router the gateway address on the interface or sub-interface "
                                           "that faces this VLAN, and check trunk/access VLAN numbers"))
            if dev.is_end and dev.dhcp:
                subnets = [i.network for _d, _p, i in members if i is not None and i.ip and not _d.is_end]
                served = False
                for d2, _p, i2 in members:
                    if d2.is_end or d2.cfg is None:
                        continue
                    if i2 is not None and i2.helpers:
                        served = True
                    for pool in d2.cfg.dhcp_pools:
                        if pool["network"] is not None and pool["network"] in subnets:
                            served = True
                if not served:
                    out.append(Issue("W070", WARNING, "%s uses DHCP but nothing in its segment offers it" % dev.name,
                                     dev.name, "add an `ip dhcp pool` for this VLAN's subnet on the router "
                                               "(or `ip helper-address` on its interface)"))

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
        if kind in IOS_KINDS and is_switch_like(kind, model):
            cfg = iosparse.parse([l.text or "" for l in d.findall("ENGINE/RUNNINGCONFIG/LINE")])
            present = {int(v.get("number")) for v in d.findall("ENGINE/VLANS/VLAN")}
            missing = sorted({i.access_vlan for i in cfg.ifaces.values()} | cfg.vlans) if present else []
            missing = [v for v in missing if v not in present and 1 <= v <= 1001]
            if missing:
                out.append(Issue("X009", ERROR, "%s: VLAN(s) %s are used in the config but missing from the VLAN "
                                 "database, so those ports will not forward" % (name, ", ".join(map(str, missing))),
                                 name, "Packet Tracer ignores `vlan N` in a replayed config; add <VLAN number=..> "
                                       "under <ENGINE><VLANS> (pktforge build does this for you)"))
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
