"""Spec -> Packet Tracer XML / .pkt.

Everything in `_sanitise` and `_finish_*` is a fix for something the raw
templates get wrong; each one links to its entry in docs/LESSONS.md.
"""
import gzip
import ipaddress
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET

import pktforge
from pktforge import iosparse, lint, ports, sshkeys
from pktforge.issues import ERROR, INFO, WARNING, Issue, SpecError

import lab_api
import pkt_core

_SERVICE_TAGS = {"http": "HTTP_SERVER", "https": "HTTPS_SERVER", "dns": "DNS_SERVER", "tftp": "TFTP_SERVER",
                 "ftp": "FTP_SERVER", "ntp": "NTP_SERVER", "syslog": "SYSLOG_SERVER", "email": "EMAIL_SERVER"}

_TIER_Y = {"endpoint": 60, "switch": 220, "router": 380}

_cache = {}


def _templates():
    if "t" not in _cache:
        _cache["t"] = lab_api.load_templates(os.path.join(pktforge.DATA_DIR, "device_templates.json"))
    return _cache["t"]


def model_names():
    return sorted(_templates()[0])


def module_names():
    return sorted(_templates()[1])


_NOT_PHYSICAL = re.compile(r"^(Vlan|Loopback|Tunnel|Cellular|Dot11|Bluetooth|wlan|VirtualPortGroup|BDI)", re.I)
_SERIAL_MODULES = ("HWIC-2T", "WIC-2T", "NIM-2T")


def model_ports(model, modules=()):
    """Ordered physical port names of a model, as Packet Tracer itself names them.

    IOS devices carry an `interface X` block per port in their template config, which is Packet Tracer's own
    spelling (Gi0/0/0 on an ISR4321, Gi1/0/1 on a 3650, Fa1/0 on a Router-PT ...). Devices without a config
    (PCs, servers, hubs) fall back to the port types, numbered from 0.
    """
    models, _ = _templates()
    if model in ports.PORT_NAMES:                  # read off Packet Tracer's cable menu (names may contain spaces)
        return list(ports.PORT_NAMES[model])
    el = ET.fromstring(models[model].decode("utf-8", "replace"))
    renames = ports.PORT_RENAMES.get(model, {})
    names = []
    for l in el.findall("ENGINE/RUNNINGCONFIG/LINE"):
        m = re.match(r"interface\s+(\S+)$", (l.text or "").strip())
        if m and not _NOT_PHYSICAL.match(m.group(1)):
            name = ports.canon_port(m.group(1))
            names.append(renames.get(name, name))
    if not names:
        count = {}
        for p in el.iter("PORT"):
            prefix = {"eCopperFastEthernet": "FastEthernet", "eCopperGigabitEthernet": "GigabitEthernet",
                      "eCopperEthernet": "Ethernet"}.get(p.findtext("TYPE"))
            if prefix:
                n = count.get(prefix, 0)
                count[prefix] = n + 1
                names.append("%s%d" % (prefix, n))
    serial_mods = sum(1 for m in modules if m.upper().replace("_", "-") in _SERIAL_MODULES)
    have = sum(1 for n in names if n.startswith("Serial"))
    for i in range(2 * serial_mods):
        names.append("Serial0/%d/%d" % ((have + i) // 2, (have + i) % 2))
    return names


def port_catalog(model, modules=()):
    return set(model_ports(model, modules))


def normalize_ports(spec):
    """Rewrite link ports to the exact spelling Packet Tracer uses ('Gi3' -> 'GigabitEthernet 3' on a Meraki).

    Idempotent. A port that matches nothing is left alone for the linter to report.
    """
    by_name = {d.name: d for d in spec.devices}
    cache = {}
    for l in spec.links:
        for end, attr in ((l.a, "a_port"), (l.b, "b_port")):
            dev = by_name.get(end)
            port = getattr(l, attr)
            if dev is None or ports.is_console_port(port) or dev.model not in _templates()[0]:
                continue
            key = (dev.model, tuple(dev.modules))
            if key not in cache:
                cache[key] = {ports.squash(n): n for n in model_ports(dev.model, dev.modules)}
            exact = cache[key].get(ports.squash(port))
            if exact:
                setattr(l, attr, exact)
    return spec


def _seed_path():
    if "seed" not in _cache:
        with gzip.open(os.path.join(pktforge.DATA_DIR, "network_seed.xml.gz"), "rb") as fh:
            data = fh.read()
        fd, path = tempfile.mkstemp(suffix=".xml", prefix="pktforge-seed-")
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        _cache["seed"] = path
    return _cache["seed"]


def _cleanup_seed():
    path = _cache.pop("seed", None)
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
def _tree_layout(spec):
    """Whole-diagram layout for specs that give no positions: a tidy tree grown from the best-connected router.

    Breadth-first from the root, each device sits one row below its parent; leaves take the next free column and
    parents are centred over their children, so LANs hang under their routers instead of lining up in one row.
    """
    names = [d.name for d in spec.devices]
    kinds = {d.name: lab_api.kind_for_model(d.model) for d in spec.devices}
    adj = {n: [] for n in names}
    for l in spec.links:
        if l.a in adj and l.b in adj and l.b not in adj[l.a]:
            adj[l.a].append(l.b)
            adj[l.b].append(l.a)
    pos, col, seen = {}, [0], set()
    colw, rowh = 120, 170

    def root_of(pool):
        routers = [n for n in pool if kinds[n] in ("router", "firewall")] or pool
        return max(routers, key=lambda n: (len(adj[n]), -names.index(n)))

    def grow(root):
        depth, parent, order = {root: 0}, {root: None}, [root]
        for n in order:
            for m in adj[n]:
                if m not in depth:
                    depth[m], parent[m] = depth[n] + 1, n
                    order.append(m)
        kids = {n: [m for m in order if parent[m] == n] for n in order}

        def place(n):
            if not kids[n]:
                x = col[0] * colw
                col[0] += 1
            else:
                xs = [place(k) for k in kids[n]]
                x = sum(xs) / len(xs)
            pos[n] = (int(60 + x), 60 + depth[n] * rowh)
            return x

        place(root)
        seen.update(order)
        col[0] += 1                      # gap before the next disconnected piece

    while len(seen) < len(names):
        grow(root_of([n for n in names if n not in seen]))
    return pos


def _auto_positions(spec):
    """Positions for devices without `at`.

    No `at` anywhere -> a tidy tree (_tree_layout). A mix -> keep the given ones and drop the rest into tiered
    rows, never closer than 90 units to anything placed.
    """
    if spec.devices and not any(d.at for d in spec.devices):
        return _tree_layout(spec)
    pos = {d.name: d.at for d in spec.devices if d.at}
    taken = list(pos.values())
    counters = {}
    for d in spec.devices:
        if d.name in pos:
            continue
        kind = lab_api.kind_for_model(d.model)
        tier = "router" if kind in ("router", "firewall") else "switch" if ports.is_switch_like(kind, d.model) \
            else "endpoint"
        k = counters.get(tier, 0)
        while True:
            x, y = 100 + 200 * k, _TIER_Y[tier]
            k += 1
            if all(abs(x - tx) > 90 or abs(y - ty) > 90 for tx, ty in taken):
                break
        counters[tier] = k
        pos[d.name] = (x, y)
        taken.append((x, y))
    return pos


def _ios_document(dev, extra_lines):
    c = ["!", "version 15.1", "no service timestamps log datetime msec",
         "no service timestamps debug datetime msec", "no service password-encryption", "!",
         "hostname " + dev.name, "!"]
    c += [l for l in sshkeys.split_config(dev.config)[0] if not re.match(r"^\s*hostname\s", l, re.I)]
    c += extra_lines
    c += ["!", "end"]
    return c


def _restore_domain(el, hostname, domain):
    """lab_api.ensure_ios_hostname drops `ip domain-name` from the running config; SSH needs it back, under the hostname."""
    config = el.find("ENGINE/RUNNINGCONFIG")
    for i, line in enumerate(config.findall("LINE")):
        if (line.text or "").strip() == "hostname " + hostname:
            new = ET.Element("LINE")
            new.text = "ip domain-name " + domain
            config.insert(i + 1, new)
            return


def _put_config(el, lines):
    eng = el.find("ENGINE")
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):    # startup == running, as after `copy run start`
        e = eng.find(tag)
        if e is None:
            e = ET.SubElement(eng, tag)
        for c in list(e):
            e.remove(c)
        for l in lines:
            ET.SubElement(e, "LINE").text = l


def _pt_help():
    if "help" not in _cache:
        with open(os.path.join(pktforge.DATA_DIR, "pt_help.json"), encoding="utf-8") as fh:
            _cache["help"] = json.load(fh)["devices"]
    return _cache["help"]


def device_checks(spec):
    """Per-model findings from what was learned by opening models in Packet Tracer (data/census.json)."""
    out, models, seen = [], set(model_names()), set()
    by_name = {d.name: d for d in spec.devices}
    help_ = _pt_help()
    for d in spec.devices:
        where = "device " + d.name
        if d.model in ports.REJECTED:
            out.append(Issue("E018", ERROR, "Packet Tracer 9.0.1 refuses to open files that contain a %s (%s)" % (
                d.model, ports.REJECTED[d.model]), where,
                "pick another model; `pktforge catalog` lists what loads. Add this one by hand in Packet Tracer"))
        elif d.model in models and d.model not in ports.VERIFIED_MODELS and d.model not in seen:
            seen.add(d.model)
            out.append(Issue("S050", INFO, "model %s was never opened in Packet Tracer 9.0.1 by pktforge's census; "
                             "its port names are unverified" % d.model, where,
                             "open the built file and check the cables, or use a verified model"))
        known = set(help_.get(d.model, {}).get("modules", []))
        for m in d.modules:
            if known and m not in known:
                out.append(Issue("W002", WARNING, "module %s is not listed as compatible with %s in Packet Tracer's "
                                 "help (it lists: %s)" % (m, d.model, ", ".join(sorted(known))), where,
                                 "Packet Tracer may refuse to power the device"))
    broadcast = {d.wireless["ssid"] for d in spec.devices
                 if d.wireless and d.model in models and _wireless_role(d.model) == "server"}
    for d in spec.devices:
        if not d.wireless or d.model not in models:
            continue
        role, where = _wireless_role(d.model), "device " + d.name
        if role is None:
            out.append(Issue("E032", ERROR, "%s (%s) has no wireless radio, so `wireless` does nothing" % (d.name, d.model),
                             where, "use an access point or wireless router (`pktforge catalog --kind access-point`) "
                                    "to broadcast, or a laptop/phone/tablet to join"))
        elif role == "client":
            if not _has_wireless_nic(d.model, d.modules) and not _wireless_nic_for(d.model):
                out.append(Issue("W093", WARNING, "%s (%s) has no wireless NIC and none can be fitted" % (d.name, d.model),
                                 where, "use Laptop-PT, SMARTPHONE-PT or TabletPC-PT"))
            if d.wireless["ssid"] not in broadcast:
                out.append(Issue("W090", WARNING, "%s joins SSID %r but no access point or wireless router in the lab "
                                 "broadcasts it" % (d.name, d.wireless["ssid"]), where,
                                 "give an access point the same `wireless` ssid (names are case-sensitive)"))
    for l in spec.links:
        ends = ((l.a, l.a_port), (l.b, l.b_port))
        fibre =[bool(by_name.get(e)) and p in ports.FIBER_PORTS.get(by_name[e].model, ()) for e, p in ends]
        as_fibre = l.type == "fiber" or (l.type == "auto" and all(fibre))
        for (end, port), is_fibre in zip(ends, fibre):
            if l.type == "console" or ports.is_console_port(port):
                continue
            if as_fibre and not is_fibre:
                out.append(Issue("E029", ERROR, "%s %s is a copper port; Packet Tracer refuses a fibre cable there" % (
                    end, port), "links[%d]" % l.index,
                    "use a fibre port (`pktforge ports %s`) or a copper cable" % by_name[end].model))
            elif is_fibre and not as_fibre:
                out.append(Issue("E009", ERROR, "%s %s is a fibre port; Packet Tracer drops copper cables there" % (
                    end, port), "links[%d]" % l.index,
                    "cable a fibre port to a fibre port (`\"type\": \"fiber\"`), or use one of the copper ports "
                    "(`pktforge ports %s`)" % by_name[end].model))
    return out


def _sync_vlans(el, d):
    """Create the VLANs a switch config declares.

    Packet Tracer keeps the VLAN database in <ENGINE><VLANS>, not in the replayed config: a `vlan 10` line is
    accepted but creates nothing, so access ports end up in a VLAN that does not exist and never forward.
    """
    cfg = iosparse.parse(d.config)
    vlans = el.find("ENGINE/VLANS")
    wanted = set(cfg.vlans) | {i.access_vlan for i in cfg.ifaces.values()}   # real IOS also auto-creates these
    if vlans is None or not wanted - {1}:
        return
    have = {int(v.get("number")): v for v in vlans.findall("VLAN")}
    sample = next(iter(have.values()), None)
    for num in sorted(wanted):
        if num in have or not 1 <= num <= 1001:
            continue
        v = ET.Element("VLAN")
        v.set("number", str(num))
        if sample is not None and sample.get("rspan") is not None:
            v.set("rspan", "0")
        v.set("name", cfg.vlan_names.get(num, "VLAN%04d" % num))
        vlans.append(v)
    ordered = sorted(vlans.findall("VLAN"), key=lambda v: int(v.get("number")))
    for v in list(vlans):
        vlans.remove(v)
    for v in ordered:
        vlans.append(v)


def _has_clock(lines, iface):
    cur = None
    for raw in lines:
        m = re.match(r"^\s*interface\s+(\S+)", raw, re.I)
        if m:
            cur = ports.canon_port(m.group(1))
        elif cur == iface and re.match(r"^\s*clock rate\s+\d+", raw, re.I):
            return True
    return False


def build_lab(spec):
    """Return (lab, issues, manual_steps). Raises SpecError for problems that stop the build."""
    issues = []
    models, modules = _templates()
    problems = []
    normalize_ports(spec)
    for d in spec.devices:
        if d.model not in models:
            near = [m for m in models if d.model.lower() in m.lower()][:5]
            problems.append(Issue("E001", ERROR, "unknown model %r" % d.model, "device " + d.name,
                                  "run `pktforge models`" + (" - did you mean: %s?" % ", ".join(near) if near else "")))
        for m in d.modules:
            if m not in modules:
                problems.append(Issue("E002", ERROR, "unknown module %r" % m, "device " + d.name,
                                      "run `pktforge models --modules`"))
    if problems:
        raise SpecError(problems)

    lab = lab_api.Lab(_seed_path(), models, modules, annotate_links=False)
    lab.prune_seed_devices()
    pos = _auto_positions(spec)
    _place_wireless(spec, pos)
    ids, kinds, roles = {}, {}, {}
    for d in spec.devices:
        kind = lab_api.kind_for_model(d.model)
        kinds[d.name] = kind
        x, y = pos[d.name]
        pc_ip = (d.ip, d.mask, d.gateway or "") if d.ip else None
        mods = list(d.modules)
        if d.wireless:
            roles[d.name] = _wireless_role(d.model)
            if roles[d.name] == "client" and not _has_wireless_nic(d.model, mods) and _wireless_nic_for(d.model):
                mods.append(_wireless_nic_for(d.model))
                issues.append(Issue("S061", INFO, "fitted wireless NIC %s to %s (it ships with a wired card)" % (
                    mods[-1], d.name), "device " + d.name))
        sid = lab.add_device(d.model, d.name, x, y, power=d.power, pc_ip=pc_ip,
                             install=mods[0] if mods else None)
        for extra in mods[1:]:
            lab.install_module(sid, extra)
        ids[d.name] = sid
        el = lab._els[sid]
        if kind in ports.ENDPOINT_KINDS or kind not in ports.IOS_KINDS:
            _prepare_endpoint(el, d)
        if d.wireless and roles[d.name]:
            _set_ssid(el, roles[d.name], d.wireless["ssid"], d)
    for d in spec.devices:                                    # a client outside every matching AP's circle never joins
        if d.wireless and roles.get(d.name) == "client":
            near = [(pos[d.name][0] - pos[s.name][0]) ** 2 + (pos[d.name][1] - pos[s.name][1]) ** 2 <= _coverage(s.model) ** 2
                    for s in spec.devices if s.wireless and roles.get(s.name) == "server"
                    and s.wireless["ssid"] == d.wireless["ssid"]]
            if near and not any(near):
                issues.append(Issue("W092", WARNING, "%s is outside the coverage of every access point broadcasting "
                                    "%r, so it will not associate" % (d.name, d.wireless["ssid"]), "device " + d.name,
                                    "move it within ~140 units of the AP (or drop its `at` for automatic placement)"))

    # ---- cables
    for l in spec.links:
        problems = []
        for end in (l.a, l.b):
            if end not in ids:
                problems.append(Issue("E003", ERROR, "link names unknown device %r" % end, "links[%d]" % l.index,
                                      "add it to `devices`, or fix the spelling (names are case-sensitive)"))
        if problems:
            raise SpecError(problems)
        ka, kb = kinds[l.a], kinds[l.b]
        ma = next(d.model for d in spec.devices if d.name == l.a)
        mb = next(d.model for d in spec.devices if d.name == l.b)
        ltype = l.type
        if ltype == "auto":
            if l.a_port.startswith("Serial") and l.b_port.startswith("Serial"):
                ltype = "serial"
            elif ports.is_console_port(l.a_port) or ports.is_console_port(l.b_port):
                ltype = "console"
            elif l.a_port in ports.FIBER_PORTS.get(ma, ()) and l.b_port in ports.FIBER_PORTS.get(mb, ()):
                ltype = "fiber"
            else:
                ltype = "straight" if ports.cable_type(ka, ma, kb, mb) == "eStraightThrough" else "cross"
        if ltype == "serial":
            dce = l.dce or l.a
            if dce not in ids:
                raise SpecError(Issue("E006", ERROR, "serial dce %r is not a device" % dce, "links[%d]" % l.index))
            lab.link(ids[l.a], l.a_port, ids[l.b], l.b_port, kind="serial", dce=ids[dce], clock=l.clock)
        else:
            lab.link(ids[l.a], l.a_port, ids[l.b], l.b_port)
            link = lab.net.find("LINKS").findall("LINK")[-1]
            if ltype == "cross":
                link.find("CABLE/TYPE").text = "eCrossOver"
            elif ltype in ("console", "fiber"):
                _retype_link(link, ltype)

    # ---- IOS configs (written after links: lab.link() appends to RUNNINGCONFIG)
    for d in spec.devices:
        if kinds[d.name] not in ports.IOS_KINDS:
            continue
        extra = []
        for l in spec.links:
            if ltype_is_serial(l) and (l.dce or l.a) == d.name:
                port = l.a_port if (l.dce or l.a) == l.a else l.b_port
                if not _has_clock(d.config, port):
                    extra += ["interface " + port, " clock rate %d" % l.clock, " exit"]
                    issues.append(Issue("S031", INFO, "added `clock rate %d` on %s %s (DCE end of a serial link)"
                                        % (l.clock, d.name, port), "device " + d.name))
        _put_config(lab._els[ids[d.name]], _ios_document(d, extra))
        _sync_vlans(lab._els[ids[d.name]], d)

    # ---- sanitise (LESSONS L1-L3)
    for device in lab.devs.findall("DEVICE"):
        model = device.find("ENGINE/TYPE").get("model", "")
        kind = lab_api.kind_for_model(model)
        if device.findtext("ENGINE/POWER") == "true":
            for p in device.iter("PORT"):
                pw = p.find("POWER")
                if pw is not None:
                    pw.text = "true"                       # L2: template ports ship powered off
        if kind in ports.IOS_KINDS:
            for p in device.iter("PORT"):
                for tag in ("IP", "SUBNET"):               # L1: stale 10.0.0.1/8 rejects real addresses
                    e = p.find(tag)
                    if e is not None:
                        e.text = None
        lab_api.ensure_ios_hostname(device)

    # ---- SSH (LESSONS L22): ensure_ios_hostname dropped `ip domain-name`, and a key is not config text
    for d in spec.devices:
        if kinds[d.name] not in ports.IOS_KINDS:
            continue
        _, wanted, domain = sshkeys.split_config(d.config)
        if domain is None:
            continue
        el = lab._els[ids[d.name]]
        _restore_domain(el, d.name, domain)
        if wanted:
            size = sshkeys.pick(wanted)
            sshkeys.apply(el.find("ENGINE"), d.name, domain, size)
            issues.append(Issue("S062", INFO, "%s: gave the router a %d-bit RSA key%s (Packet Tracer cannot create one "
                                "from a config)" % (d.name, size, "" if size == wanted else " for the requested %d" % wanted),
                                "device " + d.name))

    _add_labels(lab, spec, pos)
    manual = [
        "Open the file in Packet Tracer and run `show ip interface brief` on each router before trusting it; "
        "pktforge has verified the file structure, not the running simulation.",
    ]
    return lab, issues, manual


def _retype_link(link, ltype):
    """Console and fibre cables, in the exact shape Packet Tracer 9.0.1 itself saves them (data/LESSONS L16)."""
    cable = link.find("CABLE")
    if ltype == "console":                    # a roll-over cable is still an <eCopper> link
        cable.find("TYPE").text = "eRollOver"
        cable.find("GEO_VIEW_COLOR").text = "#1e59a5"
    else:
        link.find("TYPE").text = "eFiber"
        cable.find("TYPE").text = "eMultiMode"
        cable.find("GEO_VIEW_COLOR").text = "#ff0000"
        ET.SubElement(cable, "OVERWITE_MISMATCH_FIBER").text = "false"      # sic: Packet Tracer's own spelling


def ltype_is_serial(l):
    return l.type == "serial" or (l.type == "auto" and l.a_port.startswith("Serial") and l.b_port.startswith("Serial"))


def _prepare_endpoint(el, d):
    eng = el.find("ENGINE")
    g = eng.find("GATEWAY")
    if g is not None:                                      # L3: engine-level gateway is stale in the template
        g.text = d.gateway or None
    port = el.find(".//PORT")
    if port is not None:
        if d.ip:                                           # a NIC swap (wireless card) replaces the port: set again
            for tag, val in (("IP", d.ip), ("SUBNET", d.mask), ("PORT_GATEWAY", d.gateway)):
                e = port.find(tag)
                if e is None:
                    e = ET.SubElement(port, tag)
                e.text = val or None
        if not d.ip:
            for tag in ("IP", "SUBNET", "PORT_GATEWAY"):
                e = port.find(tag)
                if e is not None:
                    e.text = None
        dh = port.find("PORT_DHCP_ENABLE")
        if dh is not None:
            dh.text = "true" if d.dhcp else "false"
    for dns in el.iter("PORT_DNS"):
        dns.text = d.dns or None
    # L4: server template ships an enabled DHCP pool from another lab
    aps = eng.find("DHCP_SERVERS/ASSOCIATED_PORTS")
    if aps is not None:
        for ap in list(aps.findall("ASSOCIATED_PORT")):
            if any(p.findtext("NETWORK") != "0.0.0.0" for p in ap.findall("DHCP_SERVER/POOLS/POOL")):
                aps.remove(ap)
        if d.dhcp_pools:
            _put_dhcp_pools(aps, d.dhcp_pools)
    for svc, on in d.services.items():
        tag = _SERVICE_TAGS.get(str(svc).lower())
        node = eng.find("%s/ENABLED" % tag) if tag else None
        if node is not None:
            node.text = "1" if on else "0"


_WIRELESS_NICS = {"ePtLaptopModule": "PT-LAPTOP-NM-1W", "ePtHostModule": "PT-HOST-NM-1W"}
_CLIENT_SPOTS = ((0, 95), (-85, 70), (85, 70), (-120, 0), (120, 0), (-40, 120), (40, 120), (-110, -50), (110, -50),
                 (0, -95))       # all inside a 140-unit access-point coverage circle


def _wireless_role(model):
    """'server' (access point, wireless router), 'client' (laptop, phone, PC) or None, from the template."""
    el = ET.fromstring(_templates()[0][model].decode("utf-8", "replace"))
    if el.find("ENGINE/WIRELESS_SERVER") is not None:
        return "server"
    return "client" if el.find("ENGINE/WIRELESS_CLIENT") is not None else None


def _has_wireless_nic(model, modules):
    models, mods = _templates()
    texts = [models[model].decode("utf-8", "replace")] + [mods[m] for m in modules if m in mods]
    return any("Wireless" in (p.findtext("TYPE") or "")
               for t in texts for p in ET.fromstring(t).iter("PORT"))


def _wireless_nic_for(model):
    el = ET.fromstring(_templates()[0][model].decode("utf-8", "replace"))
    for sl in el.iter("SLOT"):
        if sl.findtext("TYPE") in _WIRELESS_NICS:
            return _WIRELESS_NICS[sl.findtext("TYPE")]
    return None


def _coverage(model):
    el = ET.fromstring(_templates()[0][model].decode("utf-8", "replace"))
    vals = [int(p.findtext("COVERAGERANGE") or 0) for p in el.iter("PORT") if "Wireless" in (p.findtext("TYPE") or "")]
    return max(vals or [0])


def _set_ssid(el, role, ssid, dev):
    eng = el.find("ENGINE")
    if role == "server":
        eng.find("WIRELESS_SERVER/WIRELESS_COMMON/SSID").text = ssid
        return
    eng.find("WIRELESS_CLIENT/WIRELESS_COMMON/SSID").text = ssid
    for prof in eng.findall("WIRELESS_CLIENT/PROFILES/WIRELESS_PROFILE") + \
            eng.findall("WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE"):
        prof.find("NAME").text = ssid
        prof.find("SSID").text = ssid
        if dev.ip:                                         # static addressing lives in the profile too
            for tag, val in (("DHCP_ENABLED", "0"), ("IP_ADDRESS", dev.ip), ("SUBNET_MASK", dev.mask),
                             ("DEFAULT_GATEWAY", dev.gateway or "")):
                prof.find(tag).text = val or None


def _place_wireless(spec, pos):
    """Put each wireless client inside the coverage of the first access point that broadcasts its SSID."""
    servers = {}
    for d in spec.devices:
        if d.wireless and d.model in _templates()[0] and _wireless_role(d.model) == "server":
            servers.setdefault(d.wireless["ssid"], d.name)
    used = {}
    for d in spec.devices:
        if not d.wireless or d.at or d.name in servers.values() or d.wireless["ssid"] not in servers:
            continue
        ap = servers[d.wireless["ssid"]]
        k = used.get(ap, 0)
        used[ap] = k + 1
        dx, dy = _CLIENT_SPOTS[k % len(_CLIENT_SPOTS)]
        pos[d.name] = (pos[ap][0] + dx, pos[ap][1] + dy)


def _put_dhcp_pools(aps, pools):
    """Turn the server's DHCP service on with these pools (replaces the template's empty `serverPool`)."""
    ap = aps.find("ASSOCIATED_PORT")
    if ap is None:
        return
    server = ap.find("DHCP_SERVER")
    server.find("ENABLED").text = "1"
    el = server.find("POOLS")
    for p in list(el):
        el.remove(p)
    for p in pools:
        net = p["network"]
        end = min(p["start"] + p["max_users"], net.broadcast_address)   # PT stores end = start + max users
        pool = ET.SubElement(el, "POOL")
        for tag, val in (("NAME", p["name"]), ("NETWORK", net.network_address), ("MASK", net.netmask),
                         ("DEFAULT_ROUTER", p["gateway"] or "0.0.0.0"), ("TFTP_ADDRESS", p["tftp"] or "0.0.0.0"),
                         ("START_IP", p["start"]), ("END_IP", end), ("DNS_SERVER", p["dns"] or "0.0.0.0"),
                         ("MAX_USERS", p["max_users"])):
            ET.SubElement(pool, tag).text = str(val)
        ET.SubElement(pool, "DHCP_POOL_LEASES")


def _add_labels(lab, spec, pos):
    labels = spec.labels
    if labels is False:
        return
    items = []
    if isinstance(labels, list):
        items = [(l["text"], int(l["at"][0]), int(l["at"][1])) for l in labels]
    else:
        net = lint.net_from_spec(spec)
        best = {}       # subnet -> (priority, link); one short label per network
        for l in spec.links:
            a, b = net.devs.get(l.a), net.devs.get(l.b)
            if a is None or b is None:
                continue
            subnet = None
            for dev, port in ((a, l.a_port), (b, l.b_port)):
                if ports.is_switch_like(dev.kind, dev.model):
                    continue                  # a switch port has no address; use the other end's
                i = dev.ifaces.get("" if dev.is_end else port)
                if i is not None and i.network is not None:
                    subnet = i.network
                    break
            if subnet is None:
                continue
            # a LAN is labelled on its switch<->router uplink, not on a host cable
            prio = 0 if not a.is_end and not b.is_end else 1
            if subnet not in best or prio < best[subnet][0]:
                best[subnet] = (prio, l)
        for subnet, (_prio, l) in best.items():
            (ax, ay), (bx, by) = pos[l.a], pos[l.b]
            text = str(subnet)
            w = int(6.6 * len(text))
            mx, my = (ax + bx) // 2, (ay + by) // 2
            if abs(bx - ax) >= abs(by - ay):
                items.append((text, mx - w // 2, my - 28))
            else:
                items.append((text, mx - w - 14, my - 8))
    notes_el = lab._pw.find("NOTES")
    if notes_el is None:
        notes_el = ET.SubElement(lab._pw, "NOTES")
    for i, (text, x, y) in enumerate(items):
        note = ET.SubElement(notes_el, "NOTE", {"uuid": "{%s}" % lab_api._det_uuid("label", i, text)})
        for tag, value in (("X", x), ("Y", y), ("Z", 40000 + i), ("TEXT", text), ("NOTECLUSTERID", "1-1")):
            ET.SubElement(note, tag).text = str(value)


# --------------------------------------------------------------------------- #
def to_xml(lab):
    return ET.tostring(lab.base, encoding="unicode")


def to_pkt(xml_text):
    return pkt_core.encode_bytes(xml_text.encode("utf-8"), "pkt")


def cli_backup(spec):
    """Paste-able blocks, one per IOS device (use if a device ever opens unconfigured)."""
    out = ["%s - CLI BACKUP" % spec.name,
           "Only needed if a device opens unconfigured. Open its CLI tab, answer `no` to the setup dialog, paste the block.",
           ""]
    for d in spec.devices:
        if lab_api.kind_for_model(d.model) not in ports.IOS_KINDS or not d.config:
            continue
        out += ["================ %s ================" % d.name, "enable", "configure terminal"]
        out += [l for l in sshkeys.interactive(d.config) if l.strip() and l.strip() != "!"]
        out += ["end", "copy running-config startup-config", ""]
    return "\n".join(out)


def build_files(spec, outdir, want_pkt=True, want_xml=True):
    """Build and write files. Returns (paths dict, issues, manual steps, post-build issues)."""
    try:
        lab, issues, manual = build_lab(spec)
        xml_text = to_xml(lab)
    finally:
        _cleanup_seed()
    root = ET.fromstring(xml_text)
    post = lint.check_xml(root)
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", spec.name) or "lab"
    if want_xml:
        p = os.path.join(outdir, base + ".xml")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(xml_text)
        paths["xml"] = p
    if want_pkt:
        data = to_pkt(xml_text)
        back = pkt_core.decode_bytes(data, "pkt").xml
        if back != xml_text.encode("utf-8"):
            raise SpecError(Issue("B001", ERROR, "internal error: .pkt did not round-trip to the same XML"))
        p = os.path.join(outdir, base + ".pkt")
        with open(p, "wb") as fh:
            fh.write(data)
        paths["pkt"] = p
    p = os.path.join(outdir, base + "_cli.txt")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cli_backup(spec))
    paths["cli"] = p
    return paths, issues, manual, post
