# Notice

pktforge is licensed under the **GNU General Public License v3.0 or later** (see `LICENSE`).

It bundles code and data from **packet-tracer-pkt-format** by aacanadaa
(<https://github.com/aacanadaa/packet-tracer-pkt-format>), GPL-3.0-or-later:

* `pktforge/_vendor/pkt_core/` - the pure-Python `.pkt` codec (Twofish/EAX container, qCompress framing), unmodified
  apart from omitting the unused CLI/model modules.
* `pktforge/_vendor/lab_api.py` - the lab builder (unmodified).
* `pktforge/data/network_seed.xml.gz` and `pktforge/data/device_templates.json` - the seed workspace and the device
  templates harvested from real Packet Tracer saves.

`pktforge/_vendor/pt9.py` is a small shim written for this project so the vendored builder runs without libgcrypt.

Cisco and Packet Tracer are trademarks of Cisco Systems, Inc. This project is not affiliated with or endorsed by
Cisco. It writes files that Packet Tracer opens; it does not contain Packet Tracer.
