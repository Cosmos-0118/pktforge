# pktforge

**Write your network as text. Get a Cisco Packet Tracer `.pkt` that already pings.**

pktforge builds Packet Tracer 9 labs from a short JSON spec: devices, cables, IP addresses, and full router and
switch configs. It writes the `.pkt` itself (no converter website, no GUI), and it lints the result for the
mistakes that make a lab *look* right while passing no traffic. Those mistakes cost a lot of hours to find by
hand; they are written down in [`pktforge/data/LESSONS.md`](pktforge/data/LESSONS.md).

* Zero dependencies. Python 3.10+ only. Works on Windows, macOS and Linux.
* Built for people **and AI agents**: every command has `--json`, stable exit codes, and findings that say how to
  fix them. See [`AGENTS.md`](AGENTS.md).
* Verified end to end in Packet Tracer 9.0.1, on four labs that were each built from one spec and then opened and
  pinged: a bank WAN (OSPF, NAT, serial), a VLAN campus (trunks, router-on-a-stick, DHCP, ACL), a 7-router
  multi-area OSPF network (MD5, PAT, serial) and a 44-device hub-and-spoke with no positions given.
* Knows what Packet Tracer will and won't load: a device catalogue built by opening 44 device models in Packet
  Tracer ([`DEVICES.md`](DEVICES.md)): 36 cable-verified, 8 that Packet Tracer refuses outright.

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

Bigger starting points: `pktforge init x -t bank-cs5 | campus-vlan | wan-ospf-areas | hub-spoke-43`.
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
ACLs, static routes whose next hop is unreachable, OSPF wildcard slips, wrong cable types, and VLANs the switch
database never received. `pktforge check` also audits any existing
`.pkt`/`.xml`, including ones you did not make.

## Commands

`build` `check` `init` `catalog` `models` `ports` `decode` `encode` `cli-backup` `schema` `guide` `doctor`. Run
`pktforge --help`.

## Honest limits

Traffic has been passed through the 2911 router, 2960-24TT switch, PC-PT and Server-PT. 32 more models were
opened in Packet Tracer and kept their cables but never carried traffic; 93 templates were never opened; 8 are
refused by Packet Tracer 9.0.1 (including every access point). One WAN module per router; no fibre cables, console
cables, wireless, server DHCP pools or `.pka` activities. pktforge proves a file is consistent, not that traffic flows: open it in
Packet Tracer and read `show ip interface brief`. Details in `pktforge guide`.

## Development

```bash
python -m unittest discover -s tests   # ~2 s, stdlib only
python scripts/make_release.py         # dist/pktforge-<version>.zip / .tar.gz
```

## License

GPL-3.0-or-later. Bundles the codec and device templates of
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format) (see [`NOTICE.md`](NOTICE.md)).
Not affiliated with Cisco.
