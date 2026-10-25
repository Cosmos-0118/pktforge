# pktforge: usage guide (for people and agents)

pktforge turns a short text spec into a **Cisco Packet Tracer 9 `.pkt`** that opens with every device, cable, IP and
router config already in place. No converter website, no GUI, no dependencies beyond Python 3.10+.

```
spec.json --pktforge check--> findings --pktforge build--> lab.pkt  (+ lab.xml, lab_cli.txt)
```

## Workflow

1. **Read the source material** (a lab sheet, a guide, a diagram). List devices, cables, addresses, configs.
2. **Write the spec** (`pktforge init lab` gives a starter; `pktforge schema` prints the full schema).
3. **`pktforge check lab.json --json`**. Fix every `error`; read every `warning`. Exit code 0 = clean.
4. **`pktforge build lab.json -o out`**. Writes `out/lab.pkt`, `out/lab.xml`, `out/lab_cli.txt`.
5. **Tell the user the manual steps** printed by `build` (console cables etc.) and what you did *not* verify.
6. If you can drive Packet Tracer, open the `.pkt`, wait ~70 s of simulated time, then follow
   "Testing in Packet Tracer" in `pktforge guide lessons`.

Never claim a lab "works" from `check`/`build` alone. They prove the file is well-formed and the addressing is
consistent; only opening it in Packet Tracer proves traffic flows.

## Choosing devices (read this before writing a spec)

`pktforge catalog` lists every model with a **status**; `pktforge guide devices` (or `DEVICES.md` in the repo) is
the full map: valid port names per model, compatible modules, and how Packet Tracer's palette labels ("4331",
"PT-Switch", "2960") translate to `model` names.

| status | what it means |
|---|---|
| `traffic-verified` | `2911`, `2960-24TT`, `PC-PT`, `Server-PT`: pings, OSPF, NAT, VLANs, DHCP, ACLs were proven in Packet Tracer 9.0.1. Use these by default. |
| `ports-verified` | Opens in Packet Tracer and keeps its cables under the listed port names (32 models: ISR4321/4331, 1841, 1941, 2811, 2901, 3560, 3650, IE switches, 5505, ...). No traffic test yet. |
| `untested` | Template exists, never opened by pktforge's census. Open the result and look. |
| `rejected` | Packet Tracer 9.0.1 refuses any file containing it. Add it by hand. |

Always copy port names from `pktforge ports MODEL`; they differ per model (`Gi0/0`, `Gi0/0/0`, `Gi1/0/1`, `Fa0/1`...).

## Spec in one screen

```json
{
  "name": "demo",
  "devices": [
    {"name": "PC1", "model": "PC-PT", "at": [100, 60], "ip": "10.0.1.10/24", "gateway": "10.0.1.1"},
    {"name": "SRV", "model": "Server-PT", "at": [400, 60], "ip": "10.0.2.10/24", "gateway": "10.0.2.1",
     "services": {"http": true}},
    {"name": "SW1", "model": "2960-24TT", "at": [100, 200]},
    {"name": "R1", "model": "2911", "at": [250, 340], "modules": ["HWIC-2T"],
     "config": [
       "hostname R1",
       "interface GigabitEthernet0/0",
       " ip address 10.0.1.1 255.255.255.0",
       " no shutdown",
       "interface Serial0/0/0",
       " ip address 10.0.9.1 255.255.255.252",
       " no shutdown"
     ]}
  ],
  "links": [
    ["PC1:Fa0", "SW1:Fa0/1"],
    ["SW1:Gi0/1", "R1:Gi0/0"],
    {"a": "R1:Se0/0/0", "b": "R2:Se0/0/0", "dce": "R1", "clock": 64000}
  ],
  "labels": "auto"
}
```

| field | notes |
|---|---|
| `devices[].model` | `pktforge models`. Verified in PT 9.0.1: `2911`, `2960-24TT`, `PC-PT`, `Server-PT`. |
| `devices[].at` | `[x, y]` canvas position. **Omit it on every device** for a tidy-tree layout (each LAN hangs under its router; 44 devices came out readable). Mix explicit and omitted and the omitted ones fall into plain rows. About 150-200 units apart reads well by hand. |
| `devices[].modules` | `["HWIC-2T"]` adds `Serial0/0/0-1` to a router. |
| `devices[].config` | IOS lines exactly as typed in config mode (array, or one string). Or `config_file`. |
| `devices[].ip`, `gateway`, `dns`, `dhcp` | End devices. `ip` is `"a.b.c.d/nn"` or ip + `mask`. |
| `devices[].services` | Servers: `http https dns tftp ftp ntp syslog email` set to `true`/`false`. |
| `links[]` | `["Dev:Port", "Dev:Port"]`, or an object with `type` (`auto` `straight` `cross` `serial`), `dce`, `clock`. |
| port names | `Gi0/0`, `Fa0`, `Se0/0/0` abbreviations are accepted. `pktforge ports MODEL` lists them. |
| `labels` | `"auto"` (default, one short subnet label per network), `false`, or `[{"text": "...", "at": [x, y]}]`. |

Config rules:

* Write config the way a guide tells you to type it. `enable`, `configure terminal`, `end`, `copy run start` and
  `write memory` are dropped for you (info `S030`).
* Order matters as it does on a real router: define an ACL and a NAT pool before the `ip nat inside source` that
  uses them; `interface` before its sub-commands.
* Indent sub-commands and close each sub-mode with `exit`, as in `pktforge init -t bank-cs5`. That style was
  verified to replay correctly in Packet Tracer 9.0.1; flat, unindented configs are untested.
* Put addresses **in the config**, never in anything else. pktforge deliberately blanks port-level addresses.
* On a serial link give the DCE end a `clock rate`, or let pktforge add it.

## Commands

| command | what it does |
|---|---|
| `pktforge build SPEC [-o DIR] [--no-pkt] [--no-xml] [--force]` | lint, then write `.pkt`, `.xml`, `_cli.txt` |
| `pktforge check FILE [--strict]` | lint a spec, or audit any existing `.pkt` / `.xml` (also useful on files you did not make) |
| `pktforge init [NAME] [-t TEMPLATE]` | starter spec. Templates: `minimal`, `bank-cs5` (3 routers, OSPF, NAT), `campus-vlan` (trunks, router-on-a-stick, DHCP, ACL), `wan-ospf-areas` (7 routers, 4 OSPF areas, MD5, serial, PAT), `hub-spoke-43` (44 devices, no positions) |
| `pktforge catalog [--kind K] [--status S] [--md]` | every model: status, ports, modules (`--md` = full report) |
| `pktforge models [--kind K] [--modules]` | plain list of what you can place |
| `pktforge ports MODEL [--module HWIC-2T]` | valid port names |
| `pktforge decode FILE.pkt` / `encode FILE.xml` | convert between `.pkt` and XML |
| `pktforge cli-backup SPEC` | paste-able per-device config (fallback if a device opens blank) |
| `pktforge schema` | JSON Schema of the spec |
| `pktforge guide [lessons\|devices]` | this guide / the lessons learned / the device map |
| `pktforge doctor` | self-test the install |

Every command except `init`, `decode`, `encode`, `cli-backup`, `schema` and `guide` takes `--json`.

## Machine contract

* Exit codes: `0` success, `1` problems found (lint errors, or `--strict` warnings), `2` bad usage or unreadable file.
* `--json` output is one JSON document on stdout. Findings look like
  `{"code": "E014", "severity": "error", "message": "...", "where": "links[3]", "fix": "..."}`.
  `severity` is `error`, `warning` or `info`. `build --json` adds `files` and `manual_steps`.
* `build` refuses to write files when errors exist, unless `--force`.
* Builds are deterministic: the same spec gives the same bytes.
* Nothing is sent over the network by any command. Set `PKTFORGE_DEBUG=1` for a full Python traceback.

## Known limits (be honest about these)

* Only 2911, 2960-24TT, PC-PT, Server-PT have had traffic pass; 32 more models are cable-verified; 8 models are
  refused by Packet Tracer 9.0.1 (see the catalogue). Wireless/access points are among the refused ones.
* One WAN module per router (`Serial0/0/*`). A second HWIC is not supported. No fibre cables.
* VLANs, 802.1Q trunks, router-on-a-stick, DHCP pools on routers, extended ACLs, OSPF (multi-area, MD5), PAT and
  serial links are verified. Not yet: EtherChannel, port security, HSRP, STP tuning, DHCP pools on servers, console
  cables, wireless association, activity (`.pka`) scoring.
* The `.pkt` targets Packet Tracer 9.0.x. Older versions have a different schema.
