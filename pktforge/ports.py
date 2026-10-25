"""Port naming, device classes and cable-type rules.

Packet Tracer's XML never stores port names; they are implied by the order and
type of the <PORT> elements. This module reproduces the naming for the models
that were opened and tested in Packet Tracer 9.0.1 (VERIFIED_MODELS) and infers
it for the rest, where a wrong guess is reported as a warning, not an error.
"""
import re

VERIFIED_MODELS = {"2911", "2960-24TT", "PC-PT", "Server-PT"}

_PREFIXES = (
    (re.compile(r"^(fa|fast\w*)$", re.I), "FastEthernet"),
    (re.compile(r"^(gi|gig\w*|g)$", re.I), "GigabitEthernet"),
    (re.compile(r"^(se|ser\w*|s)$", re.I), "Serial"),
    (re.compile(r"^(eth\w*|e)$", re.I), "Ethernet"),
    (re.compile(r"^(lo|loop\w*)$", re.I), "Loopback"),
)

_PORT_RE = re.compile(r"^([A-Za-z]+)\s*(\d[\d/]*)$")


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


# --------------------------------------------------------------------------- #
# port catalogue
# --------------------------------------------------------------------------- #
def catalog(kind, counts, serial_modules=0):
    """Return the set of canonical port names a device offers.

    counts: {'eCopperFastEthernet': n, 'eCopperGigabitEthernet': n, 'eSmartSerial': n}
    serial_modules: number of installed 2-port serial cards (HWIC-2T).
    """
    fa = counts.get("eCopperFastEthernet", 0)
    gi = counts.get("eCopperGigabitEthernet", 0)
    se = counts.get("eSmartSerial", 0)
    names = set()
    if kind in ("router", "firewall"):
        names |= {"FastEthernet0/%d" % i for i in range(fa)}
        names |= {"GigabitEthernet0/%d" % i for i in range(gi)}
        total_se = se + 2 * serial_modules
        names |= {"Serial0/%d/%d" % (i // 2, i % 2) for i in range(total_se)}
    elif kind in SWITCH_KINDS:
        names |= {"FastEthernet0/%d" % i for i in range(1, fa + 1)}
        names |= {"GigabitEthernet0/%d" % i for i in range(1, gi + 1)}
    else:
        names |= {"FastEthernet%d" % i for i in range(fa)}
        names |= {"GigabitEthernet%d" % i for i in range(gi)}
    return names
