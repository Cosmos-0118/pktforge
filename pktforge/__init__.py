"""pktforge - build Cisco Packet Tracer 9 labs from a plain-text spec.

Zero third-party dependencies. The codec and lab builder are vendored from
packet-tracer-pkt-format (GPL-3.0-or-later); see NOTICE.md.
"""
import os
import sys

__version__ = "0.3.0"

_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor")
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
