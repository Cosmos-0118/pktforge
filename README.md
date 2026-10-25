# pktforge

**Write your network as text. Get a Cisco Packet Tracer `.pkt` that already pings.**

pktforge builds Packet Tracer 9 labs from a short JSON spec: devices, cables, IP addresses, and full router and
switch configs. It writes the `.pkt` itself (no converter website, no GUI), and it lints the result for the
mistakes that make a lab *look* right while passing no traffic. Those mistakes cost a lot of hours to find by
hand; they are written down in [`pktforge/data/LESSONS.md`](pktforge/data/LESSONS.md).

* Zero dependencies. Python 3.10+ only. Works on Windows, macOS and Linux.
* Built for people **and AI agents**: every command has `--json`, stable exit codes, and findings that say how to
  fix them. See [`AGENTS.md`](AGENTS.md).
* Verified end to end in Packet Tracer 9.0.1: a 13-device lab with OSPF, NAT, serial WAN and an ISP builds from
  one spec and pings across all of it.

## Install

macOS / Linux / WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/pktforge/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/OWNER/pktforge/main/install.ps1 | iex
```

Both put a `pktforge` command on your PATH under `~/.pktforge`, need only Python 3.10+, and run a self-test at
the end. Add `-s -- --with-skill` (sh) or set `$env:PKTFORGE_SKILL = "1"` first (PowerShell) to also install the
Claude skill. Uninstall: `... | sh -s -- --uninstall` or `$env:PKTFORGE_UNINSTALL = "1"`.

From a checkout instead: `python -m pktforge doctor`.

> The commands above use the placeholder `OWNER/pktforge`. After you push the repo to GitHub run
> `python scripts/set_repo.py yourname/pktforge` once to fill in your name.

## 60 seconds

```bash
pktforge init lab               # writes lab.json (two LANs and a router)
pktforge check lab.json         # lint: "No problems found."
pktforge build lab.json -o out  # out/lab.pkt  <- open this in Packet Tracer
```

Or start from the bigger example: `pktforge init mybank -t bank-cs5`.

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

Overlapping subnets on one router (the silent killer), a host whose gateway is not on its LAN, two ends of a
link in different subnets, duplicate IPs, ports that do not exist or are used twice, static routes whose next hop
is unreachable, OSPF wildcard slips, wrong cable types. `pktforge check` also audits any existing
`.pkt`/`.xml`, including ones you did not make.

## Commands

`build` `check` `init` `models` `ports` `decode` `encode` `cli-backup` `schema` `guide` `doctor`. Run
`pktforge --help`.

## Honest limits

Only the 2911 router, 2960-24TT switch, PC-PT and Server-PT have been opened and pinged in Packet Tracer; other
models build from real templates but are unverified. One WAN module per router; no console cables, wireless,
server DHCP pools or `.pka` activities. pktforge proves a file is consistent, not that traffic flows: open it in
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
