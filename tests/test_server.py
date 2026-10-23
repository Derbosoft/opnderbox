"""Tests du serveur OPNderbox (bibliothèque standard seulement) : python3 -m unittest discover -s tests"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="opnderbox-test-"))
os.environ["OPNDERBOX_STATE"] = str(TMP / "etat")
os.environ["OPNDERBOX_CONFIG"] = str(TMP / "config.json")
sys.path.insert(0, str(ROOT / "opnderbox"))
import server  # noqa: E402


class Outils(unittest.TestCase):
    def test_cle_api(self):
        self.assertEqual(server.parse_api_key("key=AAA\nsecret=BBB\n"), ("AAA", "BBB"))
        self.assertEqual(server.parse_api_key(" key = A1 \r\n secret=B2"), ("A1", "B2"))
        self.assertEqual(server.parse_api_key("rien"), (None, None))
        self.assertIsNone(server.basic_auth("A", None))

    def test_adresse_opnsense(self):
        self.assertEqual(server.clean_url("192.168.1.1"), "https://192.168.1.1")
        self.assertEqual(server.clean_url("https://pare-feu.lan:8443/"), "https://pare-feu.lan:8443")
        for bad in ("http://192.168.1.1", "https://a/ui", "https://user@a", ""):
            with self.assertRaises(server.ApiError):
                server.clean_url(bad)

    def test_mot_de_passe(self):
        h = server.hash_password("un mot de passe solide")
        self.assertTrue(server.check_password("un mot de passe solide", h))
        self.assertFalse(server.check_password("autre", h))
        self.assertFalse(server.check_password("x", "pas un hachage"))

    def test_configure(self):
        self.assertFalse(server.configured({}))
        base = {"opnsense": "https://a", "opnsense_fingerprint": "f" * 64, "_auth": "Basic x"}
        self.assertFalse(server.configured(base))
        self.assertTrue(server.configured(base | {"password_hash": "scrypt$a$b"}))

    def test_identifiants_provisoires(self):
        idmap = {"new-1": "uuid-1", "newiface-x": "opt6"}
        op = {"op": "set", "rule": {"interface": "opt2,newiface-x", "destination_net": "newiface-xip", "description": "new-1"}}
        out = server.remap(op, idmap)
        self.assertEqual(out["rule"]["interface"], "opt2,opt6")
        self.assertEqual(out["rule"]["destination_net"], "opt6ip")
        self.assertEqual(out["rule"]["description"], "uuid-1")

    def test_resume(self):
        ops = [{"op": "add"}, {"op": "set"}, {"op": "alias_add"}, {"op": "vlan_add"}, {"op": "range_add"}, {"op": "sched_set"}]
        n = server.summarize(ops)
        self.assertEqual((n["add"], n["set"], n["objets"], n["reseau"], n["dhcp"]), (1, 1, 2, 1, 1))


class Plannings(unittest.TestCase):
    def test_validation(self):
        doc = {"objects": [{"name": "T_NUIT", "days": [7, 1, 1], "start": "22:00", "end": "06:00"}], "rules": [["0a0b0c0d-0000-4000-8000-000000000001", "T_NUIT"]]}
        out = server.check_sched(doc)
        self.assertEqual(out["objects"][0]["days"], [1, 7])
        for bad in ({"objects": [{"name": "1X", "days": [1], "start": "08:00", "end": "09:00"}], "rules": []},
                    {"objects": [{"name": "T", "days": [8], "start": "08:00", "end": "09:00"}], "rules": []},
                    {"objects": [{"name": "T", "days": [1], "start": "25:00", "end": "09:00"}], "rules": []},
                    {"objects": [], "rules": [["pas-un-uuid", "T"]]}):
            with self.assertRaises(server.ApiError):
                server.check_sched(bad)

    def test_plages(self):
        lundi_23h = time.mktime((2026, 10, 19, 23, 0, 0, 0, 0, -1))      # 19/10/2026 : un lundi
        mardi_5h = lundi_23h + 6 * 3600
        mardi_7h = lundi_23h + 8 * 3600
        nuit = {"days": [1], "start": "22:00", "end": "06:00"}
        self.assertTrue(server.in_window(nuit, lundi_23h))
        self.assertTrue(server.in_window(nuit, mardi_5h))          # la plage déborde sur le lendemain
        self.assertFalse(server.in_window(nuit, mardi_7h))
        self.assertTrue(server.in_window({"days": [2], "start": "00:00", "end": "00:00"}, mardi_7h))
        self.assertFalse(server.in_window({"days": [1], "start": "08:00", "end": "18:00"}, mardi_7h))


class Separateurs(unittest.TestCase):
    def test_enregistrement(self):
        ok = server.save_separators([{"id": "s1", "before": "0a0b0c0d-0000-4000-8000-000000000001", "title": "  Titre  ", "color": "blue"}])
        self.assertEqual(ok[0]["title"], "Titre")
        self.assertEqual(server.load_separators(), ok)
        with self.assertRaises(server.ApiError):
            server.save_separators([{"id": "s1", "before": "x", "title": "t", "color": "blue"}])
        with self.assertRaises(server.ApiError):
            server.save_colors({"wan; rm": "blue"})


class Droits(unittest.TestCase):
    """contrôle des droits du compte API, avec un OPNsense simulé au niveau des appels bruts."""
    def setUp(self):
        self.orig = server.api_request

    def tearDown(self):
        server.api_request = self.orig

    def test_etats(self):
        def fake(base, fp, auth, method, path, body=None):
            if path.startswith("crowdsec"):
                return 404, b"{}"
            if path.startswith("core/firmware"):
                return 403, b"{}"
            if path.startswith("ids"):
                raise RuntimeError("panne inattendue")
            return 200, b"{}"
        server.api_request = fake
        res = {r["priv"]: r["state"] for r in server.check_rights("https://a", "0" * 64, "Basic x")}
        self.assertEqual(len(res), len(server.RIGHTS))
        self.assertEqual(res["page-user-crowdsec"], "absent")
        self.assertEqual(res["page-system-firmware-manualupdate"], "refuse")
        self.assertEqual(res["page-services-ids"], "erreur")
        self.assertEqual(res["page-filter-api"], "ok")

    def test_assistant(self):
        """jeton, contrôle, enregistrement de la configuration (fichiers 0600) puis refus d'une seconde configuration."""
        server.api_request = lambda *a, **k: (200, json.dumps({"name": "fw", "versions": ["OPNsense 26.7"]}).encode())
        server.CONFIG_PATH.unlink(missing_ok=True)
        server.CFG = server.load_config()
        self.assertFalse(server.configured())
        tok = server.setup_token()
        self.assertEqual(server.setup_token(), tok)
        body = {"url": "192.0.2.1", "fingerprint": "AB:" * 31 + "AB", "key": "A" * 40, "secret": "B" * 40, "password": "motdepasse-solide"}
        with self.assertRaises(server.ApiError):
            server.setup_save(body | {"password": "court"}, "127.0.0.1")
        server.setup_save(body, "127.0.0.1")
        self.assertTrue(server.configured())
        self.assertEqual(server.CFG["opnsense"], "https://192.0.2.1")
        self.assertEqual(oct(server.CONFIG_PATH.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(Path(server.CFG["key_file"]).stat().st_mode & 0o777), "0o600")
        self.assertNotIn("_auth", json.loads(server.CONFIG_PATH.read_text()))
        self.assertFalse((server.STATE_DIR / "setup-token").exists())


class Demonstration(unittest.TestCase):
    """lance demo/demo.py et interroge son API comme le ferait le navigateur."""
    @classmethod
    def setUpClass(cls):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.proc = subprocess.Popen([sys.executable, str(ROOT / "demo" / "demo.py"), "--port", str(cls.port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/api/session", timeout=1)
                break
            except OSError:
                time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(5)

    def get(self, path):
        return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=20).read())

    def post(self, path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-OPNderbox": "1"})
        return json.loads(urllib.request.urlopen(req, timeout=20).read())

    def test_etat(self):
        st = self.get("/api/state")
        self.assertTrue(st["demo"])
        self.assertGreater(len(st["rules"]), 15)
        self.assertTrue(st["interfaces"]["wan"].get("wan"))
        self.assertFalse(st["interfaces"]["opt1"].get("wan"))
        self.assertEqual(st["ids"]["mode"], "netmap")
        self.assertIn("<title>OPNderbox</title>", urllib.request.urlopen(f"http://127.0.0.1:{self.port}/").read().decode())

    def test_modules(self):
        self.assertGreater(len(self.get("/api/implicit")["rules"]), 5)
        self.assertEqual(len(self.get("/api/rights")["rights"]), len(server.RIGHTS))
        self.assertIn("rows", self.get("/api/log?limit=50"))
        self.assertIn("devices", self.get("/api/dashboard")["disk"])

    def test_application_et_retour_arriere(self):
        """une modification appliquée puis annulée laisse les règles comme avant."""
        self.post("/api/write", {"on": True})
        avant = {r["@uuid"]: r["description"] for r in self.get("/api/state")["rules"]}
        u = next(iter(avant))
        rule = next(r for r in self.get("/api/state")["rules"] if r["@uuid"] == u)
        rule = {k: rule.get(k, "") for k in server.RULE_FIELDS} | {"description": "modifiée par le test"}
        res = self.post("/api/apply", {"ops": [{"op": "set", "uuid": u, "rule": rule}]})
        self.assertEqual(res["status"], "pending")
        self.assertEqual({r["@uuid"]: r["description"] for r in self.get("/api/state")["rules"]}[u], "modifiée par le test")
        self.post("/api/rollback", {})
        self.assertEqual({r["@uuid"]: r["description"] for r in self.get("/api/state")["rules"]}, avant)


if __name__ == "__main__":
    unittest.main()
