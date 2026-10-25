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
        for name in ("minimal", "bank-cs5"):
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


if __name__ == "__main__":
    unittest.main()
