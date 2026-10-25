# pktforge

**Write your network as text. Get a Cisco Packet Tracer `.pkt` that already pings.**

pktforge builds Packet Tracer 9 labs from a short JSON spec: devices, cables, IP addresses, and full router and
switch configs. It writes the `.pkt` itself (no converter website, no GUI), and it lints the result for the
mistakes that make a lab *look* right while passing no traffic. Those mistakes cost a lot of hours to find by
hand; they are written down in [`pktforge/data/LESSONS.md`](pktforge/data/LESSONS.md).

* Zero dependencies. Python 3.10+ only. Works on Windows, macOS and Linux.
* Built for people **and AI agents**: every command has `--json`, stable exit codes, and findings that say how to
  fix them. See [`AGENTS.md`](AGENTS.md).
* Verified end to end in Packet Tracer 9.0.1, on eight labs that were each built from one spec and then opened and
  pinged: a bank WAN (OSPF, NAT, serial), a VLAN campus (trunks, router-on-a-stick, DHCP, ACL), a 7-router
  multi-area OSPF network (MD5, PAT, serial), a 44-device hub-and-spoke with no positions given, a high-availability
  campus (HSRP, LACP EtherChannel, RSTP, port security, DHCP server with relay), a wireless campus (AP, DHCP and
  static laptops), a router with two WAN cards, and a 14-device network of 10 different router and switch models.
* Knows what Packet Tracer will and won't load: a device catalogue built by opening device models in Packet
  Tracer ([`DEVICES.md`](DEVICES.md)): 17 models have carried traffic, about 30 more keep their cables.

## Install

macOS / Linux / WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.ps1 | iex
```

Both put a `pktforge` command on your PATH under `~/.pktforge`, need only Python 3.10+, and run a self-test at
the end. Add `-s -- --with-skill` (sh) or set `$env:PKTFORGE_SKILL = "1"` first (PowerShell) to also install the
Claude skill. Uninstall: `... | sh -s -- --uninstall` or `$env:PKTFORGE_UNINSTALL = "1"`.

From a checkout instead: `python -m pktforge doctor`.

## 60 seconds

```bash
pktforge init lab               # writes lab.json (two LANs and a router)
pktforge check lab.json         # lint: "No problems found."
pktforge build lab.json -o out  # out/lab.pkt  <- open this in Packet Tracer
```

Bigger starting points: `pktforge init x -t bank-cs5 | campus-vlan | ha-campus | wifi-campus | wan-ospf-areas | two-wan-modules | model-mix | hub-spoke-43`.
Not sure which model or port name to use? `pktforge catalog`, or read [`DEVICES.md`](DEVICES.md).

A spec is just this:

```json
{
  "devices": [
    {"name": "PC1", "model": "PC-PT", "ip": "192.168.1.10/24", "gateway": "192.168.1.1"},
    {"name": "SW1", "model": "2960-24TT"},
    {"name": "R1",  "model": "2911", "config": [
      "interface GigabitEthernet0/0", " ip address 192.168.1.1 255.255.255.0", " no shutdown"]}
  ],
  "links": [["PC1:Fa0", "SW1:Fa0/1"], ["SW1:Gi0/1", "R1:Gi0/0"]]
}
```

Everything else (cable types, serial clocking, positions, subnet labels, powering ports, clearing the template's
stale addresses) is handled for you. Full reference: `pktforge guide`.

## What the linter catches

Overlapping subnets on one router (the silent killer), a host whose gateway is not on its LAN or VLAN, two ends of
a link in different subnets, duplicate IPs, ports that do not exist, are fibre, or are used twice, models Packet
Tracer refuses to open, sub-interface and NAT-pool ordering mistakes, DHCP clients with no DHCP server, undefined
ACLs, static routes whose next hop is unreachable, OSPF wildcard slips, wrong cable types, VLANs the switch
database never received, EtherChannel modes that never bundle (and `channel-group` lines Packet Tracer silently
drops), HSRP groups with two virtual IPs, port security in the wrong order, DHCP relays pointing nowhere, and wireless
clients on an SSID nobody broadcasts or outside the AP's range. `pktforge check` also audits any existing
`.pkt`/`.xml`, including ones you did not make.

## Commands

`build` `check` `init` `catalog` `models` `ports` `decode` `encode` `cli-backup` `schema` `guide` `doctor`. Run
`pktforge --help`.

## Honest limits

Traffic has been passed through 17 models (routers 2911, 1941, 2901, 2811, 1841, ISR4321, ISR4331; switches
2960-24TT, 2950-24, 2950T-24, 3560-24PS, 3650-24PS, Switch-PT; PC-PT, Laptop-PT, Server-PT, AccessPoint-PT). About 30
more models were opened and kept their cables but never carried traffic, and the rest are templates nobody has
opened (`pktforge catalog` says which). Config that was proven to replay: VLANs, trunks, router-on-a-stick, router
and server DHCP, ACLs, OSPF, PAT, serial on two WAN cards, HSRP, LACP EtherChannel, RSTP, port security. Console and
multimode-fibre cables and open-SSID wireless work too.

Not supported: WPA/WEP wireless and wireless controllers, single-mode fibre, coaxial/phone/USB cables, `.pka`
activities, and PAgP, sticky-MAC, BPDU guard and IPv6 are linted but were never run in Packet Tracer.
pktforge proves a file is consistent, not that traffic flows: open it in Packet Tracer and read
`show ip interface brief`. Details in `pktforge guide`.

## Development

```bash
python -m unittest discover -s tests   # ~2 s, stdlib only
python scripts/make_release.py         # dist/pktforge-<version>.zip / .tar.gz
```

## License

GPL-3.0-or-later. Bundles the codec and device templates of
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format) (see [`NOTICE.md`](NOTICE.md)).
Not affiliated with Cisco.
