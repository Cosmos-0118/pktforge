# Lessons: why a Packet Tracer file can look right and pass no traffic

These come from building a 13-device lab (3 routers, ISP, 3 switches, 4 PCs, 2 servers; OSPF, NAT, serial WAN)
and opening it in Packet Tracer 9.0.1. The first build drew perfectly and passed **zero** packets. Everything
below was found by opening the file and reading `show ip interface brief`, not by reading the XML.
pktforge applies L1-L5 automatically and `pktforge check` flags the rest.

## The file

| | |
|---|---|
| **A `.pkt` is an encrypted container around XML.** | Root `<PACKETTRACER5>`. Fixed key and IV, so encoding is deterministic. pktforge writes `.pkt` itself; the pt-convert website is not needed. `pktforge decode/encode` convert either way. |
| **Starting from scratch fails.** | The XML is large (about 1 MB for 13 devices) and strict. pktforge clones device templates harvested from real saves and edits them. |
| **Physical-workspace leaves must match.** | Every device needs a `<NODE>` leaf in the rack, referenced by a *braced* `{uuid}` in `<PHYSICAL>`. A missing or orphaned leaf gives "corrupted Physical Workspace data". |
| **Rebuilds are byte-identical.** | UUIDs are derived from stable inputs. If two builds of the same spec differ, something is wrong. |

## The traps (L1-L5 are fixed automatically)

**L1. Stale port-level IP on routers and switches. This is what silently broke traffic.**
Templates carry `<IP>10.0.0.1</IP><SUBNET>255.0.0.0</SUBNET>` on a router's first serial port. Packet Tracer
*replays the saved config on load*, and an `ip address` that overlaps an existing address is rejected. So
`10.10.10.1/24` on Gi0/0 overlapped the stale `10.0.0.0/8`, was refused, and the LAN port came up
`unassigned`. The diagram, the link lights and the config text all looked correct.
*Symptom:* `show ip interface brief` shows `unassigned` on a port you configured; pings die at the router.
*Fix:* blank `<IP>/<SUBNET>` on every port of IOS devices; addresses belong in the config. (`X005`)

**L2. Template router ports ship powered off.** In Packet Tracer, port power is the admin state. pktforge powers
every port of a powered device. This was not the cause of L1 but is needed so `no shutdown` is never required to
get a link up. Consequence: unused router ports are up, not shut.

**L3. End-device gateway lives in two places.** `<ENGINE><GATEWAY>` and the NIC's `<PORT_GATEWAY>`. The PC template
has a stale engine value (`1.1.1.2`). pktforge sets both. (`X007`)

**L4. Server template carries another lab's DHCP pool** (192.168.10.0). Pools with a real network are removed;
set services explicitly (`"services": {"http": true}`).

**L5. Template switches carry stale config** (Vlan1 `1.1.1.2`). pktforge replaces the whole running and startup
config of every IOS device (startup == running, as after `copy run start`).

**L6. Serial links need a DCE end with a clock.** One end must have `clock rate 64000` in config *and*
`CLOCKRATE` on the port; both ends need `POWER=true` and `CLOCKRATEFLAG=true`. Without it the line stays down.
pktforge sets all of it and adds the config line if you forgot (`S031`). Serial cables draw as red zig-zags;
that is normal. Serial interface names are `Serial0/0/0`, `0/0/1` for a first HWIC-2T. Only one WAN module per
router is verified.

**L7. Cable types matter.** Host-to-switch is straight-through. Router-router, router-PC/server and
switch-switch are crossover (`eCrossOver`). pktforge picks automatically; a wrong choice is `W040`.

**L8. Port names are not in the XML.** They are implied by port order and type. Verified in Packet Tracer:
2911 (`GigabitEthernet0/0-2`, `Serial0/0/0-1` with HWIC-2T), 2960-24TT (`FastEthernet0/1-24`,
`GigabitEthernet0/1-2`), PC-PT and Server-PT (`FastEthernet0`). Other models build, but their port names are
inferred, so a bad name there is only a warning. `pktforge ports MODEL` lists names.

**L9. Short canvas labels only.** Per-cable notes such as `PC-CSD FastEthernet0 SW-A Fa0/1 10.10.10.0/24`
overlap into an unreadable smear. One short subnet label per network, placed beside the cable
(`10.0.12.0/30`), reads cleanly. A label's X is its left edge. pktforge's `"labels": "auto"` does this.

## Rules the linter enforces (each one is a way to get "looks right, doesn't work")

| code | meaning |
|---|---|
| E010 | two interfaces on one device overlap (see L1) |
| E011 | duplicate IP anywhere |
| E013 / E015 | host gateway outside its subnet / not an address on its own LAN |
| E014 | two ends of one link (or devices on one switch) sit in different subnets |
| E004 / E005 | no such port / one port used by two cables |
| W030 | static route next hop is not on a connected network (route never installs) |
| W031 | OSPF `network` statement matches no interface (usually a wildcard-mask slip) |

## Testing in Packet Tracer

* Wait about 30 s of simulated time. Switch ports show amber until spanning tree finishes, then OSPF needs a
  further 40 s. The first ping of any pair times out (ARP); read the *later* replies.
* TTL tells you the path: 126 from a PC across two routers, 125 across three.
* Useful on a router: `show ip interface brief`, `show ip route`, `show ip ospf neighbor`,
  `show ip nat translations`. Start with `show ip interface brief`; `unassigned` on a port you configured
  means L1.
* A device window only opens after the device has been *selected* by a first click, then double-clicked.
* When driving Packet Tracer through computer-use, text typed via the clipboard does not reach the CLI; send
  one key per action. The `|` character cannot be sent that way, so page with the space bar instead of piping.

## What a file cannot hold

* Console cables (PC templates have no RS-232 port): use the device's CLI tab.
* Anything depending on the simulator's state (ARP caches, DHCP leases, a typed-in password prompt).
* Models whose port names are inferred: open the result and look before relying on it.

## Dev-machine gotchas (if you rebuild the vendored codec)

The upstream `pt9` module needs libgcrypt, so pktforge uses the pure-Python codec instead. On Windows the
`python` command may be a Store stub: install Python 3.10+ first. Very long working-directory paths broke Python
tooling: build in a short folder.
