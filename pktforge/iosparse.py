"""A deliberately small IOS config reader.

It extracts only what the linter needs (interface addresses, VLAN/trunk settings, ACL / NAT pool / DHCP pool
definitions) and remembers the *order* things were written, because Packet Tracer replays the saved config line
by line and rejects commands whose prerequisites come later.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from pktforge.ports import canon_port

# column-0 commands that end an interface/pool block when a config is written flat (no indentation)
_GLOBAL = re.compile(
    r"^(router|line|ip route|ip nat pool|ip nat inside source|ip dhcp|ip domain|ip classless|ip access-list|"
    r"access-list|hostname|enable|username|vlan|spanning-tree|service|banner|no ip domain|crypto|ipv6 unicast|"
    r"logging|snmp-server|ntp|end|exit|!)\b", re.I)

_IP_ADDR = re.compile(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*$", re.I)


@dataclass
class Iface:
    name: str
    ip: str = None
    mask: str = None
    shutdown: bool = None
    vlan: int = None                 # dot1Q tag of a subinterface
    ip_before_encap: bool = False    # subinterface got `ip address` before `encapsulation`
    mode: str = None                 # access | trunk | None (default)
    access_vlan: int = 1
    trunk_vlans: set = None          # None = all
    native: int = 1
    helpers: list = field(default_factory=list)
    acls: list = field(default_factory=list)     # [(name, 'in'|'out')]
    channel: int = None              # `channel-group N mode X`
    channel_mode: str = None
    standby: dict = field(default_factory=dict)  # HSRP: group -> {"ip", "priority", "preempt"}
    port_security: bool = False
    ps_before_mode: bool = False     # `switchport port-security` written before `switchport mode access`
    ps_max: int = None

    @property
    def network(self):
        if not self.ip:
            return None
        try:
            return ipaddress.ip_interface("%s/%s" % (self.ip, self.mask)).network
        except ValueError:
            return None


@dataclass
class Cfg:
    ifaces: dict = field(default_factory=dict)
    vlans: set = field(default_factory=set)
    vlan_names: dict = field(default_factory=dict)
    acls: set = field(default_factory=set)
    pools: set = field(default_factory=set)
    nat_bad_pool: list = field(default_factory=list)     # [(pool name, rule text)] pool used before defined
    dhcp_pools: list = field(default_factory=list)       # [{"name", "network"}]
    stp_priorities: list = field(default_factory=list)   # [(vlan list text, priority)]
    lines: list = field(default_factory=list)


def expand_range(text):
    """`interface range Fa0/1 - 4, Gi0/1` -> ['FastEthernet0/1', ..., 'FastEthernet0/4', 'GigabitEthernet0/1']."""
    names = []
    for item in re.split(r"\s*,\s*", text.strip()):
        item = re.sub(r"(?<=\d)\s*-\s*(?=[A-Za-z]*\s*\d)", "-", item.strip())
        m = re.match(r"^([A-Za-z]+)\s*(\d+(?:/\d+)*?/)?(\d+)-(?:[A-Za-z]+\s*(?:\d+(?:/\d+)*?/)?)?(\d+)$", item)
        if m:
            kind, prefix, lo, hi = m.group(1), m.group(2) or "", int(m.group(3)), int(m.group(4))
            names += [canon_port("%s%s%d" % (kind, prefix, n)) for n in range(lo, hi + 1)]
        elif item:
            names.append(canon_port(item))
    return names


def _vlan_list(text):
    out = set()
    for part in text.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            out.update(range(lo, min(hi, 4094) + 1))
    return out


def parse(lines):
    cfg = Cfg(lines=list(lines))
    indented = any(l.startswith(" ") for l in lines)
    ctx = None                      # ("if", Iface) | ("pool", dict)
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        col0 = not raw.startswith(" ")
        if col0 and ctx is not None and (indented or _GLOBAL.match(s)):
            ctx = None          # an unindented line starts a new top-level command
        if s.lower() in ("exit", "!"):
            ctx = None
            continue

        m = re.match(r"^interface\s+range\s+(.+)$", s, re.I)
        if m:
            ctx = ("if", [cfg.ifaces.setdefault(n, Iface(n)) for n in expand_range(m.group(1))])
            continue
        m = re.match(r"^interface\s+(\S+)$", s, re.I)
        if m:
            name = canon_port(m.group(1))
            ctx = ("if", [cfg.ifaces.setdefault(name, Iface(name))])
            continue
        m = re.match(r"^spanning-tree vlan\s+(\S+)\s+priority\s+(\d+)", s, re.I)
        if m:
            cfg.stp_priorities.append((m.group(1), int(m.group(2))))
            continue
        m = re.match(r"^vlan\s+(\d+)$", s, re.I)
        if m and col0:
            cfg.vlans.add(int(m.group(1)))
            ctx = ("vlan", int(m.group(1)))
            continue
        m = re.match(r"^ip access-list\s+(?:standard|extended)\s+(\S+)", s, re.I)
        if m:
            cfg.acls.add(m.group(1))
            ctx = None
            continue
        m = re.match(r"^access-list\s+(\S+)\s", s, re.I)
        if m:
            cfg.acls.add(m.group(1))
            continue
        m = re.match(r"^ip nat pool\s+(\S+)", s, re.I)
        if m:
            cfg.pools.add(m.group(1))
            continue
        m = re.match(r"^ip nat inside source list\s+\S+\s+pool\s+(\S+)", s, re.I)
        if m:
            if m.group(1) not in cfg.pools:
                cfg.nat_bad_pool.append((m.group(1), s))
            continue
        m = re.match(r"^ip dhcp pool\s+(\S+)", s, re.I)
        if m:
            pool = {"name": m.group(1), "network": None}
            cfg.dhcp_pools.append(pool)
            ctx = ("pool", pool)
            continue

        if ctx is None:
            continue
        kind, obj = ctx
        if kind == "vlan":
            m = re.match(r"^name\s+(\S+)$", s, re.I)
            if m:
                cfg.vlan_names[obj] = m.group(1)
            continue
        if kind == "pool":
            m = re.match(r"^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", s, re.I)
            if m:
                try:
                    obj["network"] = ipaddress.ip_network("%s/%s" % (m.group(1), m.group(2)), strict=False)
                except ValueError:
                    pass
            continue

        for i in obj:
            _apply(i, raw, s)
    return cfg


def _apply(i, raw, s):
    """One line of an `interface` block applied to one interface."""
    ma = _IP_ADDR.match(raw)
    if ma:
        i.ip, i.mask = ma.group(1), ma.group(2)
        if "." in i.name and i.vlan is None:
            i.ip_before_encap = True
    elif s.lower() == "no ip address":
        i.ip = i.mask = None
    elif s.lower() == "shutdown":
        i.shutdown = True
    elif s.lower() == "no shutdown":
        i.shutdown = False
    elif re.match(r"^encapsulation\s+dot1q\s+(\d+)", s, re.I):
        i.vlan = int(re.match(r"^encapsulation\s+dot1q\s+(\d+)", s, re.I).group(1))
    elif re.match(r"^switchport mode\s+(access|trunk)", s, re.I):
        i.mode = re.match(r"^switchport mode\s+(access|trunk)", s, re.I).group(1).lower()
    elif re.match(r"^switchport access vlan\s+(\d+)", s, re.I):
        i.access_vlan = int(re.match(r"^switchport access vlan\s+(\d+)", s, re.I).group(1))
    elif re.match(r"^switchport trunk native vlan\s+(\d+)", s, re.I):
        i.native = int(re.match(r"^switchport trunk native vlan\s+(\d+)", s, re.I).group(1))
    elif re.match(r"^switchport trunk allowed vlan\s+(.+)$", s, re.I):
        arg = re.match(r"^switchport trunk allowed vlan\s+(.+)$", s, re.I).group(1).strip()
        if arg.lower() == "all":
            i.trunk_vlans = None
        elif arg.lower().startswith("add "):
            i.trunk_vlans = (i.trunk_vlans or set()) | _vlan_list(arg[4:])
        elif arg.lower().startswith("none"):
            i.trunk_vlans = set()
        else:
            i.trunk_vlans = _vlan_list(arg)
    elif re.match(r"^ip helper-address\s+(\S+)", s, re.I):
        i.helpers.append(re.match(r"^ip helper-address\s+(\S+)", s, re.I).group(1))
    elif re.match(r"^ip access-group\s+(\S+)\s+(in|out)", s, re.I):
        mm = re.match(r"^ip access-group\s+(\S+)\s+(in|out)", s, re.I)
        i.acls.append((mm.group(1), mm.group(2).lower()))
    elif re.match(r"^channel-group\s+(\d+)(?:\s+mode\s+(\S+))?", s, re.I):
        mm = re.match(r"^channel-group\s+(\d+)(?:\s+mode\s+(\S+))?", s, re.I)
        i.channel, i.channel_mode = int(mm.group(1)), (mm.group(2) or "").lower() or None
    elif re.match(r"^standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", s, re.I):
        mm = re.match(r"^standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", s, re.I)
        i.standby.setdefault(int(mm.group(1)), {})["ip"] = mm.group(2)
    elif re.match(r"^standby\s+(\d+)\s+priority\s+(\d+)", s, re.I):
        mm = re.match(r"^standby\s+(\d+)\s+priority\s+(\d+)", s, re.I)
        i.standby.setdefault(int(mm.group(1)), {})["priority"] = int(mm.group(2))
    elif re.match(r"^standby\s+(\d+)\s+preempt", s, re.I):
        i.standby.setdefault(int(re.match(r"^standby\s+(\d+)", s, re.I).group(1)), {})["preempt"] = True
    elif re.match(r"^switchport port-security$", s, re.I):
        i.port_security = True
        i.ps_before_mode = i.mode is None
    elif re.match(r"^switchport port-security maximum\s+(\d+)", s, re.I):
        i.ps_max = int(re.match(r"^switchport port-security maximum\s+(\d+)", s, re.I).group(1))
