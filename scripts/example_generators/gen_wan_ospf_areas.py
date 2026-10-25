import json, sys

def ifc(name, ip, mask, extra=()):
    return ["interface " + name, " ip address %s %s" % (ip, mask)] + [" " + e for e in extra] + [" no shutdown", " exit"]

def ospf(rid, nets, passive=(), extra=()):
    c = ["router ospf 1", " router-id " + rid]
    c += [" " + e for e in extra]
    c += [" passive-interface " + p for p in passive]
    c += [" network %s %s area %s" % n for n in nets]
    return c + [" exit"]

MD5 = ["ip ospf message-digest-key 1 md5 OSPFkey2026"]
AUTH0 = [" area 0 authentication message-digest"]

devs, links = [], []
def dev(name, model, at, **kw):
    d = {"name": name, "model": model, "at": at}
    d.update(kw)
    devs.append(d)

dev("R1", "2911", [420, 120], config=["hostname R1", "no ip domain-lookup"]
    + ifc("GigabitEthernet0/0", "10.0.12.1", "255.255.255.252", MD5 + ["ip nat inside"])
    + ifc("GigabitEthernet0/1", "10.0.13.1", "255.255.255.252", MD5 + ["ip nat inside"])
    + ifc("GigabitEthernet0/2", "203.0.113.1", "255.255.255.252", ["ip nat outside"])
    + ["access-list 1 permit 10.0.0.0 0.255.255.255",
       "ip nat inside source list 1 interface GigabitEthernet0/2 overload",
       "ip route 0.0.0.0 0.0.0.0 203.0.113.2"]
    + ospf("1.1.1.1", [("10.0.12.0", "0.0.0.3", 0), ("10.0.13.0", "0.0.0.3", 0)],
           extra=["default-information originate"] + AUTH0))

dev("R2", "2911", [240, 330], modules=["HWIC-2T"], config=["hostname R2", "no ip domain-lookup"]
    + ifc("GigabitEthernet0/0", "10.0.12.2", "255.255.255.252", MD5)
    + ifc("GigabitEthernet0/1", "10.0.23.1", "255.255.255.252", MD5)
    + ifc("GigabitEthernet0/2", "10.1.24.1", "255.255.255.252")
    + ifc("Serial0/0/0", "10.3.26.1", "255.255.255.252", ["clock rate 64000"])
    + ospf("2.2.2.2", [("10.0.12.0", "0.0.0.3", 0), ("10.0.23.0", "0.0.0.3", 0),
                       ("10.1.24.0", "0.0.0.3", 1), ("10.3.26.0", "0.0.0.3", 3)],
           extra=AUTH0 + [" area 1 range 10.1.0.0 255.255.0.0", " area 3 range 10.3.0.0 255.255.0.0"]))

dev("R3", "2911", [600, 330], config=["hostname R3", "no ip domain-lookup"]
    + ifc("GigabitEthernet0/0", "10.0.23.2", "255.255.255.252", MD5)
    + ifc("GigabitEthernet0/1", "10.0.13.2", "255.255.255.252", MD5)
    + ifc("GigabitEthernet0/2", "10.2.35.1", "255.255.255.252")
    + ospf("3.3.3.3", [("10.0.23.0", "0.0.0.3", 0), ("10.0.13.0", "0.0.0.3", 0), ("10.2.35.0", "0.0.0.3", 2)],
           extra=AUTH0 + [" area 2 range 10.2.0.0 255.255.0.0"]))

def branch(n, rid, x, uplink, up_peer_ip_net, area, lan_net, serial=False):
    name = "R%d" % n
    lan_ip = lan_net + ".1"
    if serial:
        up = ifc("Serial0/0/0", uplink[0], "255.255.255.252")
    else:
        up = ifc("GigabitEthernet0/0", uplink[0], "255.255.255.252")
    lan_if = "GigabitEthernet0/0" if serial else "GigabitEthernet0/1"
    dev(name, "2911", [x, 520], modules=["HWIC-2T"] if serial else [],
        config=["hostname " + name, "no ip domain-lookup"] + up + ifc(lan_if, lan_ip, "255.255.255.0")
        + ospf(rid, [(up_peer_ip_net, "0.0.0.3", area), (lan_net + ".0", "0.0.0.255", area)], passive=[lan_if]))
    dev("SW%d" % n, "2960-24TT", [x, 660])
    dev("PC%d" % n, "PC-PT", [x, 790], ip="%s.10/24" % lan_net, gateway=lan_ip)
    links.append(["PC%d:Fa0" % n, "SW%d:Fa0/1" % n])
    links.append(["SW%d:Gi0/1" % n, "%s:%s" % (name, lan_if)])

branch(4, "4.4.4.4", 80, ("10.1.24.2",), "10.1.24.0", 1, "10.1.40")
branch(5, "5.5.5.5", 760, ("10.2.35.2",), "10.2.35.0", 2, "10.2.50")
branch(6, "6.6.6.6", 330, ("10.3.26.2",), "10.3.26.0", 3, "10.3.60", serial=True)

dev("ISP", "2911", [650, 120], config=["hostname ISP", "no ip domain-lookup"]
    + ifc("GigabitEthernet0/0", "203.0.113.2", "255.255.255.252")
    + ifc("GigabitEthernet0/1", "198.51.100.1", "255.255.255.0"))
dev("INET-SRV", "Server-PT", [880, 120], ip="198.51.100.10/24", gateway="198.51.100.1", services={"http": True})

links += [["R1:Gi0/0", "R2:Gi0/0"], ["R2:Gi0/1", "R3:Gi0/0"], ["R1:Gi0/1", "R3:Gi0/1"],
          ["R2:Gi0/2", "R4:Gi0/0"], ["R3:Gi0/2", "R5:Gi0/0"],
          {"a": "R2:Se0/0/0", "b": "R6:Se0/0/0", "dce": "R2"},
          ["R1:Gi0/2", "ISP:Gi0/0"], ["ISP:Gi0/1", "INET-SRV:Fa0"]]

json.dump({"name": "wan-ospf-areas", "devices": devs, "links": links}, open(sys.argv[1], "w"), indent=1)
print("wrote", sys.argv[1], len(devs), "devices", len(links), "links")
