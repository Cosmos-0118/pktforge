"""Port naming, device classes and cable-type rules.

Packet Tracer's XML never stores port names; they are implied by the order and
type of the <PORT> elements. Names come from each template's own saved config.
pktforge/data/census.json records which models were then opened in Packet Tracer
9.0.1 and kept their cables (VERIFIED_MODELS), which only had traffic passed
through them (TRAFFIC_VERIFIED), and which Packet Tracer refuses outright
(REJECTED). For unverified models a bad port name is a warning, not an error.
"""
import json
import os
import re

import pktforge


def _census():
    with open(os.path.join(pktforge.DATA_DIR, "census.json"), encoding="utf-8") as fh:
        return json.load(fh)


_C = _census()
VERIFIED_MODELS = set(_C["ports_verified"])
TRAFFIC_VERIFIED = set(_C["traffic_verified"])
REJECTED = dict(_C["rejected"])
PORT_RENAMES = {m: dict(r) for m, r in _C["port_renames"].items()}
FIBER_PORTS = {m: list(p) for m, p in _C["fiber_ports"].items()}

_PREFIXES = (
    (re.compile(r"^(fa|fast\w*)$", re.I), "FastEthernet"),
    (re.compile(r"^(gi|gig\w*|g)$", re.I), "GigabitEthernet"),
    (re.compile(r"^(se|ser\w*|s)$", re.I), "Serial"),
    (re.compile(r"^(eth\w*|e)$", re.I), "Ethernet"),
    (re.compile(r"^(lo|loop\w*)$", re.I), "Loopback"),
)

_PORT_RE = re.compile(r"^([A-Za-z]+)\s*(\d[\d/]*(?:\.\d+)?)$")     # optional .N = dot1Q subinterface


def canon_port(name):
    """'Gi0/0' -> 'GigabitEthernet0/0'. Unknown prefixes are returned unchanged."""
    m = _PORT_RE.match(name.strip())
    if not m:
        return name.strip()
    for rx, full in _PREFIXES:
        if rx.match(m.group(1)):
            return full + m.group(2)
    return name.strip()


def short_port(name):
    """'GigabitEthernet0/0' -> 'Gi0/0' (for compact messages)."""
    return (canon_port(name).replace("GigabitEthernet", "Gi").replace("FastEthernet", "Fa")
            .replace("Serial", "Se"))


# --------------------------------------------------------------------------- #
# device classes
# --------------------------------------------------------------------------- #
ENDPOINT_KINDS = {"pc", "laptop", "server", "iot", "sniffer"}
IOS_KINDS = {"router", "switch", "multilayer-switch", "firewall"}
SWITCH_KINDS = {"switch", "multilayer-switch"}


def is_switch_like(kind, model=""):
    return kind in SWITCH_KINDS or model.lower().startswith("hub")


def cable_type(kind_a, model_a, kind_b, model_b):
    """Pick the copper cable PT expects.

    Hosts (PC, server, router, firewall, access point) are 'DTE'; switches and
    hubs are 'DCE'. Like with like needs a crossover, unlike needs a straight.
    """
    a = is_switch_like(kind_a, model_a)
    b = is_switch_like(kind_b, model_b)
    return "eStraightThrough" if a != b else "eCrossOver"

