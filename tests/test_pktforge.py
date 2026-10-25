import io
import json
import os
import contextlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

import pktforge
from pktforge import build, cli, lint, spec as specmod
from pktforge.issues import has_errors

import pkt_core

EXAMPLES = os.path.join(pktforge.DATA_DIR, "examples")


def sp(devices, links, **kw):
    d = {"name": "t", "devices": devices, "links": links}
    d.update(kw)
    return specmod.parse(d)


def codes(issues):
    return {i.code for i in issues}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class Examples(unittest.TestCase):
    def test_examples_lint_clean(self):
        for name in ("minimal", "bank-cs5", "campus-vlan", "ha-campus", "wifi-campus", "wan-ospf-areas",
                     "two-wan-modules", "model-mix", "hub-spoke-43"):
            s = specmod.load(os.path.join(EXAMPLES, name + ".json"))
            self.assertEqual([i for i in cli.check_spec(s)], [], name)

    def test_build_and_roundtrip(self):
        s = specmod.load(os.path.join(EXAMPLES, "bank-cs5.json"))
        with tempfile.TemporaryDirectory() as tmp:
            paths, _issues, manual, post = build.build_files(s, tmp)
            self.assertEqual(post, [])
            self.assertTrue(manual)
            raw = open(paths["pkt"], "rb").read()
            xml = pkt_core.decode_bytes(raw, "pkt").xml
            self.assertEqual(xml, open(paths["xml"], "rb").read())
            root = ET.fromstring(xml)
            self.assertEqual(len(root.findall("NETWORK/DEVICES/DEVICE")), 13)
            self.assertEqual(len(root.findall("NETWORK/LINKS/LINK")), 13)
            self.assertEqual(lint.check_net(lint.net_from_xml(root)), [])

    def test_build_is_deterministic(self):
        s = specmod.load(os.path.join(EXAMPLES, "minimal.json"))
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            pa = build.build_files(s, a)[0]["pkt"]
            pb = build.build_files(s, b)[0]["pkt"]
            self.assertEqual(open(pa, "rb").read(), open(pb, "rb").read())


class Sanitising(unittest.TestCase):
    """Each assertion is a lesson from docs/LESSONS.md."""

    @classmethod
    def setUpClass(cls):
        s = specmod.load(os.path.join(EXAMPLES, "bank-cs5.json"))
        lab, _i, _m = build.build_lab(s)
        build._cleanup_seed()
        cls.root = ET.fromstring(build.to_xml(lab))

    def dev(self, name):
        return next(d for d in self.root.findall("NETWORK/DEVICES/DEVICE") if d.findtext("ENGINE/NAME") == name)

    def test_l1_no_port_level_ip_on_ios_devices(self):
        for n in ("R1", "R2", "R3", "ISP", "SW-A"):
            for p in self.dev(n).iter("PORT"):
                self.assertFalse((p.findtext("IP") or "").strip(), n)

    def test_l2_ports_powered(self):
        for p in self.dev("R1").iter("PORT"):
            self.assertEqual(p.findtext("POWER"), "true")

    def test_l3_engine_gateway_matches_nic(self):
        d = self.dev("PC-CSD")
        self.assertEqual(d.findtext("ENGINE/GATEWAY"), "10.10.10.1")
        self.assertEqual(d.findtext(".//PORT/PORT_GATEWAY"), "10.10.10.1")

    def test_l4_server_has_no_foreign_dhcp_pool(self):
        d = self.dev("BANK-SRV")
        nets = [p.text for p in d.iter("NETWORK")]
        self.assertFalse([n for n in nets if n not in ("0.0.0.0", None)])

    def test_serial_clock_and_crossover(self):
        r1 = [l.text for l in self.dev("R1").findall("ENGINE/RUNNINGCONFIG/LINE")]
        self.assertIn(" clock rate 64000", r1)
        types = [l.findtext("CABLE/TYPE") for l in self.root.findall("NETWORK/LINKS/LINK")
                 if l.findtext("TYPE") == "eCopper"]
        self.assertEqual(types.count("eCrossOver"), 2)

    def test_startup_equals_running(self):
        for d in self.root.findall("NETWORK/DEVICES/DEVICE"):
            run_ = [l.text for l in d.findall("ENGINE/RUNNINGCONFIG/LINE")]
            st = [l.text for l in d.findall("ENGINE/STARTUPCONFIG/LINE")]
            if run_:
                self.assertEqual(run_, st, d.findtext("ENGINE/NAME"))


class Rules(unittest.TestCase):
    PC = {"name": "PC1", "model": "PC-PT", "ip": "10.0.0.5/24", "gateway": "10.0.0.1"}
    SW = {"name": "SW1", "model": "2960-24TT"}

    def router(self, cfg):
        return {"name": "R1", "model": "2911", "config": cfg}

    def test_overlapping_subnets_on_one_router(self):
        s = sp([self.router(["interface Gi0/0", " ip address 10.0.0.1 255.255.255.0",
                             "interface Gi0/1", " ip address 10.0.0.129 255.255.255.128"])], [])
        self.assertIn("E010", codes(cli.check_spec(s)))

    def test_lan_gateway_must_exist_on_lan(self):
        r = self.router(["interface GigabitEthernet0/0", " ip address 10.0.0.254 255.255.255.0"])
        s = sp([self.PC, self.SW, r], [["PC1:Fa0", "SW1:Fa0/1"], ["SW1:Gi0/1", "R1:Gi0/0"]])
        self.assertIn("E015", codes(cli.check_spec(s)))

    def test_different_subnets_on_one_link(self):
        r = self.router(["interface GigabitEthernet0/0", " ip address 10.9.9.1 255.255.255.0"])
        s = sp([self.PC, self.SW, r], [["PC1:Fa0", "SW1:Fa0/1"], ["SW1:Gi0/1", "R1:Gi0/0"]])
        self.assertIn("E014", codes(cli.check_spec(s)))

    def test_gateway_outside_subnet(self):
        pc = dict(self.PC, gateway="10.1.1.1")
        self.assertIn("E013", codes(cli.check_spec(sp([pc], []))))

    def test_duplicate_ip(self):
        a, b = dict(self.PC), dict(self.PC, name="PC2")
        self.assertIn("E011", codes(cli.check_spec(sp([a, b], []))))

    def test_bad_port_on_verified_model_is_error(self):
        s = sp([self.PC, self.SW], [["PC1:Fa0", "SW1:Fa0/99"]])
        iss = cli.check_spec(s)
        self.assertIn("E004", codes(iss))
        self.assertTrue(has_errors(iss))

    def test_port_reuse(self):
        pc2 = dict(self.PC, name="PC2", ip="10.0.0.6/24")
        s = sp([self.PC, pc2, self.SW], [["PC1:Fa0", "SW1:Fa0/1"], ["PC2:Fa0", "SW1:Fa0/1"]])
        self.assertIn("E005", codes(cli.check_spec(s)))

    def test_unreachable_static_route_next_hop(self):
        r = self.router(["interface GigabitEthernet0/0", " ip address 10.0.0.1 255.255.255.0",
                         "ip route 0.0.0.0 0.0.0.0 172.16.0.1"])
        self.assertIn("W030", codes(cli.check_spec(sp([r], []))))

    def test_wrong_ospf_wildcard(self):
        r = self.router(["interface GigabitEthernet0/0", " ip address 10.0.0.1 255.255.255.0",
                         "router ospf 1", " network 192.168.0.0 0.0.0.255 area 0"])
        self.assertIn("W031", codes(cli.check_spec(sp([r], []))))

    def test_serial_needs_serial_ports(self):
        a = {"name": "R1", "model": "2911", "modules": ["HWIC-2T"]}
        b = {"name": "R2", "model": "2911", "modules": ["HWIC-2T"]}
        s = sp([a, b], [{"a": "R1:Gi0/0", "b": "R2:Gi0/0", "type": "serial"}])
        self.assertIn("E008", codes(cli.check_spec(s)))

    def test_unknown_model_stops_build(self):
        s = sp([{"name": "X", "model": "NOPE-9000"}], [])
        with self.assertRaises(Exception) as cm:
            build.build_lab(s)
        self.assertIn("E001", [i.code for i in cm.exception.issues])

    def test_unknown_link_device(self):
        s = sp([self.PC], [["PC1:Fa0", "GHOST:Fa0/1"]])
        self.assertIn("E003", codes(cli.check_spec(s)))

    def test_prompt_only_lines_are_stripped(self):
        r = self.router(["enable", "configure terminal", "hostname R1", "end", "write memory"])
        s = sp([r], [])
        self.assertEqual(s.devices[0].config, ["hostname R1"])

    def test_cable_choice(self):
        from pktforge.ports import cable_type
        self.assertEqual(cable_type("pc", "PC-PT", "switch", "2960-24TT"), "eStraightThrough")
        self.assertEqual(cable_type("router", "2911", "switch", "2960-24TT"), "eStraightThrough")
        self.assertEqual(cable_type("router", "2911", "router", "2911"), "eCrossOver")
        self.assertEqual(cable_type("switch", "2960-24TT", "switch", "2960-24TT"), "eCrossOver")
        self.assertEqual(cable_type("router", "2911", "server", "Server-PT"), "eCrossOver")


class StressLessons(unittest.TestCase):
    """Each test is a defect the three stress-test networks exposed."""

    SW = {"name": "SW1", "model": "2960-24TT", "config": [
        "vlan 10", " name SALES", " exit", "vlan 20", " name ENG", " exit",
        "interface GigabitEthernet0/1", " switchport mode trunk", " exit",
        "interface FastEthernet0/1", " switchport mode access", " switchport access vlan 10", " exit",
        "interface FastEthernet0/2", " switchport mode access", " switchport access vlan 20", " exit"]}

    def router(self, extra=()):
        return {"name": "R1", "model": "2911", "config": [
            "interface GigabitEthernet0/0", " no ip address", " no shutdown", " exit",
            "interface GigabitEthernet0/0.10", " encapsulation dot1Q 10", " ip address 10.0.10.1 255.255.255.0", " exit",
            "interface GigabitEthernet0/0.20", " encapsulation dot1Q 20", " ip address 10.0.20.1 255.255.255.0", " exit"
        ] + list(extra)}

    def vlan_lab(self, gw2="10.0.20.1", a_vlan=None):
        sw = json.loads(json.dumps(self.SW))
        if a_vlan:
            sw["config"][sw["config"].index(" switchport access vlan 10")] = " switchport access vlan %d" % a_vlan
        return sp([self.router(), sw,
                   {"name": "PA", "model": "PC-PT", "ip": "10.0.10.11/24", "gateway": "10.0.10.1"},
                   {"name": "PB", "model": "PC-PT", "ip": "10.0.20.11/24", "gateway": gw2}],
                  [["PA:Fa0", "SW1:Fa0/1"], ["PB:Fa0", "SW1:Fa0/2"], ["SW1:Gi0/1", "R1:Gi0/0"]])

    def test_vlans_and_subinterfaces_are_not_false_positives(self):
        self.assertEqual(cli.check_spec(self.vlan_lab()), [])

    def test_gateway_in_the_wrong_vlan_is_caught(self):
        self.assertIn("E015", codes(cli.check_spec(self.vlan_lab(gw2="10.0.10.1"))))
        self.assertIn("E013", codes(cli.check_spec(self.vlan_lab(gw2="10.0.10.1"))))

    def test_host_in_the_wrong_access_vlan_is_caught(self):
        self.assertIn("E015", codes(cli.check_spec(self.vlan_lab(a_vlan=20))))

    def test_ip_before_encapsulation(self):
        r = {"name": "R1", "model": "2911", "config": [
            "interface GigabitEthernet0/0.10", " ip address 10.0.10.1 255.255.255.0", " encapsulation dot1Q 10"]}
        self.assertIn("E016", codes(cli.check_spec(sp([r], []))))

    def test_nat_pool_must_exist_first(self):
        r = {"name": "R1", "model": "2911", "config": [
            "access-list 1 permit any", "ip nat inside source list 1 pool P",
            "ip nat pool P 1.1.1.1 1.1.1.2 netmask 255.255.255.252"]}
        self.assertIn("E017", codes(cli.check_spec(sp([r], []))))

    def test_undefined_acl_and_dhcp_without_server(self):
        r = self.router()
        r["config"] += ["interface GigabitEthernet0/0.10", " ip access-group NOPE in", " exit"]
        s = sp([r, self.SW, {"name": "PA", "model": "PC-PT", "dhcp": True}],
               [["PA:Fa0", "SW1:Fa0/1"], ["SW1:Gi0/1", "R1:Gi0/0"]])
        found = codes(cli.check_spec(s))
        self.assertIn("W060", found)
        self.assertIn("W070", found)

    def test_dhcp_pool_satisfies_dhcp_client(self):
        r = self.router(["ip dhcp pool P", " network 10.0.10.0 255.255.255.0", " exit"])
        s = sp([r, self.SW, {"name": "PA", "model": "PC-PT", "dhcp": True}],
               [["PA:Fa0", "SW1:Fa0/1"], ["SW1:Gi0/1", "R1:Gi0/0"]])
        self.assertNotIn("W070", codes(cli.check_spec(s)))

    def test_vlan_database_is_synced(self):
        s = sp([self.SW], [])
        lab, _i, _m = build.build_lab(s)
        build._cleanup_seed()
        root = ET.fromstring(build.to_xml(lab))
        nums = {int(v.get("number")) for v in root.iter("VLAN")}
        self.assertTrue({10, 20} <= nums)
        names = {v.get("number"): v.get("name") for v in root.iter("VLAN")}
        self.assertEqual(names["10"], "SALES")
        self.assertEqual(lint.check_xml(root), [])

    def test_missing_vlan_in_xml_is_caught(self):
        s = sp([self.SW], [])
        lab, _i, _m = build.build_lab(s)
        build._cleanup_seed()
        root = ET.fromstring(build.to_xml(lab))
        for v in list(root.iter("VLAN")):
            if v.get("number") == "10":
                for parent in root.iter("VLANS"):
                    if v in list(parent):
                        parent.remove(v)
        self.assertIn("X009", codes(lint.check_xml(root)))

    def test_rejected_model_is_an_error(self):
        from unittest import mock
        from pktforge import ports
        s = sp([{"name": "AP", "model": "AccessPoint-PT"}], [])
        self.assertNotIn("E018", codes(cli.check_spec(s)))          # a fresh PT 9.0.1 template loads (LESSONS L11)
        with mock.patch.dict(ports.REJECTED, {"AccessPoint-PT": "test"}):
            self.assertIn("E018", codes(cli.check_spec(s)))

    def test_fibre_port_is_an_error(self):
        sw = {"name": "SW", "model": "Switch-PT"}
        pc = {"name": "PC", "model": "PC-PT"}
        s = sp([sw, pc], [["PC:Fa0", "SW:Fa4/1"]])
        self.assertIn("E009", codes(cli.check_spec(s)))

    def test_incompatible_module_warns(self):
        s = sp([{"name": "R", "model": "ISR4321", "modules": ["HWIC-2T"]}], [])
        self.assertIn("W002", codes(cli.check_spec(s)))

    def test_port_names_follow_packet_tracer(self):
        self.assertIn("GigabitEthernet0/0/1", build.port_catalog("ISR4321"))
        self.assertIn("GigabitEthernet1/0/24", build.port_catalog("3650-24PS"))
        self.assertIn("GigabitEthernet0/1", build.port_catalog("2950T-24"))       # PT renames the template's Gi1/1
        self.assertNotIn("GigabitEthernet1/1", build.port_catalog("2950T-24"))
        self.assertIn("Serial0/0/1", build.port_catalog("2911", ["HWIC-2T"]))

    def test_tree_layout_has_no_overlaps_and_hangs_lans_under_routers(self):
        s = specmod.load(os.path.join(EXAMPLES, "hub-spoke-43.json"))
        self.assertFalse(any(d.at for d in s.devices))
        pos = build._auto_positions(s)
        self.assertEqual(len(set(pos.values())), len(s.devices))
        pts = list(pos.values())
        for i in range(len(pts)):
            for j in range(i + 1, len(pts)):
                self.assertTrue(abs(pts[i][0] - pts[j][0]) >= 100 or abs(pts[i][1] - pts[j][1]) >= 100)
        self.assertLess(pos["R-HUB"][1], pos["BR1"][1])
        self.assertLess(pos["BR1"][1], pos["SW1"][1])
        self.assertLess(pos["SW1"][1], pos["PC1-1"][1])

    def test_printer_keeps_its_address_and_cable(self):
        s = sp([{"name": "PRN", "model": "Printer-PT", "ip": "192.168.1.20/24", "gateway": "192.168.1.1"},
                {"name": "SW", "model": "2960-24TT"},
                {"name": "R1", "model": "2911", "config": ["interface GigabitEthernet0/0",
                                                            " ip address 192.168.1.1 255.255.255.0", " no shutdown"]}],
               [["PRN:Fa0", "SW:Fa0/1"], ["SW:Gi0/1", "R1:Gi0/0"]])
        self.assertEqual(codes(cli.check_spec(s)), set())
        root, _ = built(s)
        prn =dev_of(root, "PRN")
        self.assertEqual(prn.find("ENGINE/TYPE").get("model"), "Printer-PT")
        self.assertEqual(prn.findtext(".//PORT/IP"), "192.168.1.20")
        self.assertEqual(len(root.findall("NETWORK/LINKS/LINK")), 2)

    def test_catalog(self):
        from pktforge import catalog
        es = {e["model"]: e for e in catalog.entries()}
        self.assertEqual(es["2911"]["status"], "traffic-verified")
        self.assertEqual(es["AccessPoint-PT"]["status"], "traffic-verified")
        self.assertEqual(es["Printer-PT"]["status"], "traffic-verified")
        self.assertEqual(es["Meraki-MX65W"]["status"], "ports-verified")
        self.assertEqual(es["LAP-PT"]["kind"], "access-point")
        md = catalog.markdown()
        self.assertIn("## Packet Tracer palette map", md)
        self.assertIn("`ISR4321`", md)
        self.assertEqual(catalog.compress(["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3", "GigabitEthernet0/1"]),
                         ["FastEthernet0/1-3", "GigabitEthernet0/1"])


class XmlAudit(unittest.TestCase):
    def test_stale_port_ip_is_caught(self):
        s = specmod.load(os.path.join(EXAMPLES, "minimal.json"))
        lab, _i, _m = build.build_lab(s)
        build._cleanup_seed()
        root = ET.fromstring(build.to_xml(lab))
        r1 = next(d for d in root.findall("NETWORK/DEVICES/DEVICE") if d.findtext("ENGINE/NAME") == "R1")
        port = next(r1.iter("PORT"))
        port.find("IP").text = "10.0.0.1"
        port.find("SUBNET").text = "255.0.0.0"
        self.assertIn("X005", codes(lint.check_xml(root)))


class Cli(unittest.TestCase):
    def test_exit_codes_and_json(self):
        ex = os.path.join(EXAMPLES, "minimal.json")
        rc, out, _ = run("check", ex, "--json")
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["ok"])
        bad = os.path.join(tempfile.mkdtemp(), "bad.json")
        json.dump({"devices": [{"name": "R1", "model": "2911"}], "links": [["R1:Gi0/0", "R9:Gi0/0"]]}, open(bad, "w"))
        rc, out, _ = run("check", bad, "--json")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["issues"][0]["code"], "E003")

    def test_build_refuses_on_errors_unless_forced(self):
        bad = os.path.join(tempfile.mkdtemp(), "bad.json")
        json.dump({"devices": [{"name": "PC1", "model": "PC-PT", "ip": "10.0.0.5/24", "gateway": "10.9.9.9"}]},
                  open(bad, "w"))
        out = tempfile.mkdtemp()
        rc, _o, _e = run("build", bad, "-o", out)
        self.assertEqual(rc, 1)
        self.assertEqual(os.listdir(out), [])

    def test_decode_encode(self):
        with tempfile.TemporaryDirectory() as tmp:
            run("build", os.path.join(EXAMPLES, "minimal.json"), "-o", tmp)
            pkt = os.path.join(tmp, "minimal.pkt")
            rc, _o, _e = run("decode", pkt, "-o", os.path.join(tmp, "x.xml"))
            self.assertEqual(rc, 0)
            rc, _o, _e = run("encode", os.path.join(tmp, "x.xml"), "-o", os.path.join(tmp, "y.pkt"))
            self.assertEqual(open(pkt, "rb").read(), open(os.path.join(tmp, "y.pkt"), "rb").read())

    def test_guide_doctor_schema(self):
        rc, out, _ = run("guide")
        self.assertEqual(rc, 0)
        self.assertIn("Machine contract", out)
        rc, out, _ = run("guide", "lessons")
        self.assertIn("L1.", out)
        rc, out, _ = run("doctor", "--json")
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["ok"])
        rc, out, _ = run("schema")
        self.assertIn("devices", json.loads(out)["properties"])

    def test_every_template_builds_clean(self):
        for t in ("minimal", "bank-cs5"):
            with tempfile.TemporaryDirectory() as tmp:
                rc, out, _ = run("build", os.path.join(EXAMPLES, t + ".json"), "-o", tmp, "--json")
                self.assertEqual(rc, 0, out)
                self.assertTrue(json.loads(out)["ok"])
                self.assertTrue(os.path.exists(os.path.join(tmp, t + ".pkt")))

    def test_init_and_models_and_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                self.assertEqual(run("init", "mylab")[0], 0)
                self.assertTrue(os.path.exists("mylab.json"))
                self.assertEqual(run("init", "mylab")[0], 2)      # refuses to overwrite
            finally:
                os.chdir(cwd)
        rc, out, _ = run("models", "--kind", "router", "--json")
        self.assertIn("2911", [m["model"] for m in json.loads(out)["models"]])
        rc, out, _ = run("ports", "2911", "--module", "HWIC-2T", "--json")
        ports_ = json.loads(out)["ports"]
        self.assertIn("Serial0/0/1", ports_)
        self.assertIn("GigabitEthernet0/2", ports_)
        self.assertNotIn("GigabitEthernet0/3", ports_)


def built(spec_obj):
    lab, issues, _m = build.build_lab(spec_obj)
    build._cleanup_seed()
    return ET.fromstring(build.to_xml(lab)), issues


def dev_of(root, name):
    return next(d for d in root.findall("NETWORK/DEVICES/DEVICE") if d.findtext("ENGINE/NAME") == name)


class ConfigParser(unittest.TestCase):
    def test_interface_range_expands(self):
        from pktforge import iosparse
        self.assertEqual(iosparse.expand_range("Fa0/1 - 3, Gi0/1"),
                         ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3", "GigabitEthernet0/1"])
        self.assertEqual(iosparse.expand_range("fa0/23 - fa0/24"), ["FastEthernet0/23", "FastEthernet0/24"])
        cfg = iosparse.parse(["interface range Fa0/1 - 2", " switchport mode access", " switchport access vlan 10"])
        self.assertEqual({n: i.access_vlan for n, i in cfg.ifaces.items()},
                         {"FastEthernet0/1": 10, "FastEthernet0/2": 10})

    def test_ha_and_channel_commands_parse(self):
        from pktforge import iosparse
        cfg = iosparse.parse(["interface Gi0/0.10", " encapsulation dot1Q 10", " ip address 10.0.10.2 255.255.255.0",
                              " standby 10 ip 10.0.10.1", " standby 10 priority 110", " standby 10 preempt",
                              "interface Fa0/23", " channel-group 1 mode active"])
        self.assertEqual(cfg.ifaces["GigabitEthernet0/0.10"].standby[10],
                         {"ip": "10.0.10.1", "priority": 110, "preempt": True})
        self.assertEqual((cfg.ifaces["FastEthernet0/23"].channel, cfg.ifaces["FastEthernet0/23"].channel_mode), (1, "active"))


class L2Features(unittest.TestCase):
    """EtherChannel, HSRP, port security and STP rules (LESSONS L17-L19). The ha-campus example is proven in Packet Tracer."""

    def sw(self, name, cfg):
        return {"name": name, "model": "2960-24TT", "config": cfg}

    def bundle(self, a_cfg, b_cfg):
        return sp([self.sw("A", a_cfg), self.sw("B", b_cfg)], [["A:Fa0/23", "B:Fa0/23"], ["A:Fa0/24", "B:Fa0/24"]])

    GOOD = ["interface Port-channel1", " switchport mode trunk", "interface range Fa0/23 - 24",
            " switchport mode trunk", " channel-group 1 mode active"]

    def test_good_bundle_is_clean(self):
        self.assertEqual(cli.check_spec(self.bundle(self.GOOD, self.GOOD)), [])

    def test_channel_group_before_port_channel_is_flagged(self):
        bad = ["interface range Fa0/23 - 24", " switchport mode trunk", " channel-group 1 mode active",
               "interface Port-channel1", " switchport mode trunk"]
        self.assertIn("E028", codes(cli.check_spec(self.bundle(bad, self.GOOD))))

    def test_mismatched_modes_never_bundle(self):
        passive = [l.replace("active", "on") for l in self.GOOD]
        self.assertIn("E021", codes(cli.check_spec(self.bundle(self.GOOD, passive))))

    def test_lacp_active_passive_is_fine(self):
        passive = [l.replace("active", "passive") for l in self.GOOD]
        self.assertNotIn("E021", codes(cli.check_spec(self.bundle(self.GOOD, passive))))

    def test_channel_group_needs_a_mode(self):
        s = sp([self.sw("A", ["interface Port-channel1", "interface Fa0/23", " channel-group 1"])], [])
        self.assertIn("E026", codes(cli.check_spec(s)))

    def test_port_security_needs_access_mode_first(self):
        s = sp([self.sw("A", ["interface Fa0/3", " switchport port-security", " switchport mode access"])], [])
        self.assertIn("E022", codes(cli.check_spec(s)))
        ok = sp([self.sw("A", ["interface Fa0/3", " switchport mode access", " switchport port-security"])], [])
        self.assertNotIn("E022", codes(cli.check_spec(ok)))

    def test_stp_priority_must_be_multiple_of_4096(self):
        s = sp([self.sw("A", ["spanning-tree vlan 1 priority 5000"])], [])
        self.assertIn("E023", codes(cli.check_spec(s)))

    def hsrp(self, vip2="10.0.0.1", vip_net="10.0.0.1"):
        r = lambda n, ip, vip: {"name": n, "model": "2911", "config": [
            "interface GigabitEthernet0/0", " ip address %s 255.255.255.0" % ip, " standby 1 ip %s" % vip, " no shutdown"]}
        pc = {"name": "PC", "model": "PC-PT", "ip": "10.0.0.50/24", "gateway": "10.0.0.1"}
        sw = {"name": "SW", "model": "2960-24TT"}
        return sp([r("R1", "10.0.0.2", vip_net), r("R2", "10.0.0.3", vip2), pc, sw],
                  [["R1:Gi0/0", "SW:Fa0/1"], ["R2:Gi0/0", "SW:Fa0/2"], ["PC:Fa0", "SW:Fa0/3"]])

    def test_hsrp_virtual_ip_is_a_valid_gateway(self):
        found = codes(cli.check_spec(self.hsrp()))
        self.assertNotIn("E015", found)            # the gateway is the virtual IP, which no interface owns
        self.assertNotIn("E011", found)            # and the shared virtual IP is not a duplicate address

    def test_hsrp_group_with_two_virtual_ips(self):
        self.assertIn("E025", codes(cli.check_spec(self.hsrp(vip2="10.0.0.9"))))

    def test_hsrp_virtual_ip_outside_subnet(self):
        self.assertIn("E024", codes(cli.check_spec(self.hsrp(vip2="10.0.0.1", vip_net="10.9.9.1"))))


class ServerDhcp(unittest.TestCase):
    SRV = {"name": "S", "model": "Server-PT", "ip": "10.0.20.10/24", "gateway": "10.0.20.1",
           "dhcp_pools": [{"network": "10.0.10.0/24", "gateway": "10.0.10.1", "dns": "10.0.20.10",
                           "start": "10.0.10.100", "max_users": 50}]}

    def test_pool_is_written_and_enabled(self):
        root, _ = built(sp([self.SRV], []))
        srv = dev_of(root, "S")
        pools = srv.findall("ENGINE/DHCP_SERVERS/ASSOCIATED_PORTS/ASSOCIATED_PORT/DHCP_SERVER[ENABLED='1']/POOLS/POOL")
        self.assertEqual(len(pools), 1)
        p = pools[0]
        self.assertEqual((p.findtext("NETWORK"), p.findtext("MASK"), p.findtext("DEFAULT_ROUTER"), p.findtext("DNS_SERVER"),
                          p.findtext("START_IP"), p.findtext("MAX_USERS")),
                         ("10.0.10.0", "255.255.255.0", "10.0.10.1", "10.0.20.10", "10.0.10.100", "50"))

    def test_gateway_outside_pool(self):
        bad = dict(self.SRV, dhcp_pools=[{"network": "10.0.10.0/24", "gateway": "10.7.7.1"}])
        self.assertIn("E027", codes(cli.check_spec(sp([bad], []))))

    def test_bad_pool_is_a_spec_error(self):
        with self.assertRaises(Exception):
            sp([dict(self.SRV, dhcp_pools=[{"gateway": "1.1.1.1"}])], [])

    def test_helper_without_matching_pool_warns_and_pool_satisfies_w070(self):
        r = {"name": "R", "model": "2911", "config": [
            "interface GigabitEthernet0/0", " ip address 10.0.10.1 255.255.255.0", " ip helper-address 10.0.20.10",
            "interface GigabitEthernet0/1", " ip address 10.0.20.1 255.255.255.0"]}
        sw = {"name": "SW", "model": "2960-24TT"}
        pc = {"name": "PC", "model": "PC-PT", "dhcp": True}
        links = [["PC:Fa0", "SW:Fa0/1"], ["SW:Fa0/2", "R:Gi0/0"], ["S:Fa0", "R:Gi0/1"]]
        other = dict(self.SRV, dhcp_pools=[{"network": "10.0.99.0/24"}])
        self.assertIn("W071", codes(cli.check_spec(sp([r, sw, pc, other], links))))
        self.assertNotIn("W071", codes(cli.check_spec(sp([r, sw, pc, self.SRV], links))))


class Cables(unittest.TestCase):
    """Console and fibre cables are written exactly as Packet Tracer 9.0.1 saves them (LESSONS L16)."""

    DEVS = [{"name": "SWA", "model": "Switch-PT"}, {"name": "SWB", "model": "Switch-PT"},
            {"name": "PC", "model": "PC-PT"}, {"name": "R", "model": "2911"}]

    def test_fibre_and_console_xml(self):
        root, _ = built(sp(self.DEVS, [["SWA:Fa5/1", "SWB:Fa5/1"], {"a": "PC:RS232", "b": "R:Console", "type": "console"}]))
        fib, con = root.findall("NETWORK/LINKS/LINK")
        self.assertEqual((fib.findtext("TYPE"), fib.findtext("CABLE/TYPE"), fib.findtext("CABLE/OVERWITE_MISMATCH_FIBER")),
                         ("eFiber", "eMultiMode", "false"))
        self.assertEqual((con.findtext("TYPE"), con.findtext("CABLE/TYPE")), ("eCopper", "eRollOver"))
        self.assertEqual([p.text for p in con.findall("CABLE/PORT")], ["RS 232", "Console"])

    def test_console_cable_is_not_a_data_link(self):
        pc = {"name": "PC", "model": "PC-PT", "ip": "10.0.0.5/24", "gateway": "10.0.0.1"}
        s = sp([pc, {"name": "R", "model": "2911"}], [["PC:RS232", "R:Console"]])
        self.assertEqual(cli.check_spec(s), [])

    def test_copper_on_fibre_port_and_fibre_on_copper_port(self):
        self.assertIn("E009", codes(cli.check_spec(sp(self.DEVS, [["PC:Fa0", "SWA:Fa4/1"]]))))
        self.assertIn("E029", codes(cli.check_spec(sp(self.DEVS, [{"a": "SWA:Fa0/1", "b": "SWB:Fa0/1", "type": "fiber"}]))))

    def test_xml_audit_reads_fibre_and_console(self):
        root, _ = built(sp(self.DEVS, [["SWA:Fa5/1", "SWB:Fa5/1"], ["PC:RS232", "R:Console"]]))
        self.assertEqual([i for i in lint.check_net(lint.net_from_xml(root)) if i.severity == "error"], [])


class SecondWanModule(unittest.TestCase):
    def test_serial_links_on_the_second_module(self):
        s = specmod.load(os.path.join(EXAMPLES, "two-wan-modules.json"))
        root, _ = built(s)
        r1 = dev_of(root, "R1")
        bays = [sl for sl in r1.iter("SLOT") if sl.findtext("TYPE") == "eInterfaceCard"]
        clocked = [[p.findtext("CLOCKRATEFLAG") for p in bay.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"]
                   for bay in bays[:2]]
        self.assertEqual(clocked, [["true", "false"], ["true", "true"]])     # Serial0/0/0; Serial0/1/0 and 0/1/1
        self.assertEqual(build.model_ports("2911", ["HWIC-2T", "HWIC-2T"])[-4:],
                         ["Serial0/0/0", "Serial0/0/1", "Serial0/1/0", "Serial0/1/1"])


class WirelessAndPortNames(unittest.TestCase):
    def test_ssid_reaches_ap_and_clients_and_nic_is_fitted(self):
        root, issues = built(specmod.load(os.path.join(EXAMPLES, "wifi-campus.json")))
        self.assertEqual(dev_of(root, "AP1").findtext("ENGINE/WIRELESS_SERVER/WIRELESS_COMMON/SSID"), "CAMPUS")
        lap = dev_of(root, "LAP1")
        self.assertEqual(lap.findtext("ENGINE/WIRELESS_CLIENT/WIRELESS_COMMON/SSID"), "CAMPUS")
        self.assertEqual(lap.findtext("ENGINE/WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE/SSID"), "CAMPUS")
        self.assertEqual(lap.findtext(".//PORT/TYPE"), "eHostWirelessG")
        self.assertIn("S061", codes(issues))
        static = dev_of(root, "LAP2")
        self.assertEqual(static.findtext(".//PORT/IP"), "10.9.1.50")
        self.assertEqual(static.findtext("ENGINE/WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE/IP_ADDRESS"), "10.9.1.50")

    def test_clients_are_placed_inside_ap_coverage(self):
        root, issues = built(specmod.load(os.path.join(EXAMPLES, "wifi-campus.json")))
        xy = lambda n: tuple(int(dev_of(root, n).findtext("WORKSPACE/LOGICAL/" + a)) for a in "XY")
        ap = xy("AP1")
        for n in ("LAP1", "LAP2"):
            self.assertLess(((xy(n)[0] - ap[0]) ** 2 + (xy(n)[1] - ap[1]) ** 2) ** 0.5, 140)
        self.assertNotIn("W092", codes(issues))

    def test_wireless_lint(self):
        lap = {"name": "L", "model": "Laptop-PT", "wireless": "GUEST"}
        ap = {"name": "AP", "model": "AccessPoint-PT", "wireless": {"ssid": "OTHER"}}
        self.assertIn("W090", codes(cli.check_spec(sp([lap, ap], []))))
        self.assertIn("E032", codes(cli.check_spec(sp([{"name": "S", "model": "2960-24TT", "wireless": "X"}], []))))
        far = dict(lap, wireless="OTHER", at=[900, 900])
        _, issues = built(sp([far, dict(ap, at=[100, 100])], []))
        self.assertIn("W092", codes(issues))

    def test_port_names_with_spaces_are_normalised(self):
        s = sp([{"name": "MX", "model": "Meraki-MX65W"}, {"name": "SW", "model": "2960-24TT"}],
               [["MX:Gi3", "SW:Gi0/1"], ["MX:Ethernet 12", "SW:Fa0/24"]])
        self.assertEqual(cli.check_spec(s), [])
        root, _ = built(s)
        self.assertEqual([p.text for p in root.findall("NETWORK/LINKS/LINK")[0].findall("CABLE/PORT")],
                         ["GigabitEthernet 3", "GigabitEthernet0/1"])


if __name__ == "__main__":
    unittest.main()
