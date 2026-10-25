---
name: pktforge
description: Build a Cisco Packet Tracer 9 (.pkt) lab from a text spec - devices, cables, IPs and router/switch configs - and lint it for the mistakes that make a lab look right but pass no traffic. Use when asked to create, generate, convert or fix a Packet Tracer file from a lab sheet, guide or topology.
---

# pktforge

Install (Python 3.10+ only): `curl -fsSL https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.sh | sh`
or on Windows `irm https://raw.githubusercontent.com/Cosmos-0118/pktforge/main/install.ps1 | iex`.

Then run `pktforge guide` and follow it. Short version:

1. `pktforge init lab` -> edit `lab.json` from the user's lab sheet.
2. `pktforge check lab.json --json` until `ok` is true (findings include a `fix`).
3. `pktforge build lab.json -o out` -> `out/lab.pkt` opens directly in Packet Tracer 9.
4. Tell the user the printed manual steps and what you did not verify. Passing `check` does not prove traffic
   flows; opening the file in Packet Tracer and reading `show ip interface brief` does.

`pktforge guide lessons` explains every trap (stale port IPs, gateways, DCE clocks, cable types) - read it
before debugging a lab that "looks right but doesn't ping".
