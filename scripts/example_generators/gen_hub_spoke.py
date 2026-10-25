import json, sys

N = 8
devs, links = [], []

def ifc(name, ip, mask, extra=()):
    return ["interface " + name, " ip address %s %s" % (ip, mask)] + [" " + e for e in extra] + [" no shutdown", " exit"]

def ospf(rid, nets, passive=()):
    c = ["router ospf 1", " router-id " + rid] + [" passive-interface " + p for p in passive]
    c += [" network %s %s area 0" % n for n in nets]
    return c + [" exit"]

devs.append({"name": "SW-CORE", "model": "2960-24TT"})
devs.append({"name": "R-HUB", "model": "2911", "config": ["hostname R-HUB", "no ip domain-lookup"]
             + ifc("GigabitEthernet0/0", "10.0.0.1", "255.255.255.0")
             + ifc("GigabitEthernet0/1", "10.100.0.1", "255.255.255.0")
             + ospf("1.1.1.1", [("10.0.0.0", "0.0.0.255"), ("10.100.0.0", "0.0.0.255")], passive=["GigabitEthernet0/1"])})
devs.append({"name": "SW-HUB", "model": "2960-24TT"})
devs.append({"name": "HQ-SRV", "model": "Server-PT", "ip": "10.100.0.10/24", "gateway": "10.100.0.1", "services": {"http": True}})
links += [["R-HUB:Gi0/0", "SW-CORE:Gi0/1"], ["R-HUB:Gi0/1", "SW-HUB:Gi0/1"], ["HQ-SRV:Fa0", "SW-HUB:Fa0/1"]]

for i in range(1, N + 1):
    r, s = "BR%d" % i, "SW%d" % i
    devs.append({"name": r, "model": "2911", "config": ["hostname " + r, "no ip domain-lookup"]
                 + ifc("GigabitEthernet0/0", "10.0.0.%d" % (i + 1), "255.255.255.0")
                 + ifc("GigabitEthernet0/1", "10.1.%d.1" % i, "255.255.255.0")
                 + ospf("%d.%d.%d.%d" % (i + 1, i + 1, i + 1, i + 1),
                        [("10.0.0.0", "0.0.0.255"), ("10.1.%d.0" % i, "0.0.0.255")], passive=["GigabitEthernet0/1"])})
    devs.append({"name": s, "model": "2960-24TT"})
    links.append(["%s:Gi0/0" % r, "SW-CORE:Fa0/%d" % i])
    links.append(["%s:Gi0/1" % r, "%s:Gi0/1" % s])
    for k in (1, 2, 3):
        pc = "PC%d-%d" % (i, k)
        devs.append({"name": pc, "model": "PC-PT", "ip": "10.1.%d.%d/24" % (i, 10 + k), "gateway": "10.1.%d.1" % i})
        links.append(["%s:Fa0" % pc, "%s:Fa0/%d" % (s, k)])

json.dump({"name": "hub-spoke-43", "devices": devs, "links": links}, open(sys.argv[1], "w"), indent=1)
print("wrote", sys.argv[1], len(devs), "devices", len(links), "links")
