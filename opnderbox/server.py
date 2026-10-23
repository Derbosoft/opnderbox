#!/usr/bin/env python3
"""OPNderbox - console d'administration facon Stormshield SNS pour OPNsense.

Serveur HTTPS minimal (bibliotheque standard de Python uniquement) qui :
  - sert l'interface web (static/index.html) ;
  - relaie vers l'API OPNsense avec un compte aux droits limites ;
  - applique les modifications avec retour arriere automatique si elles ne sont pas confirmees.

Configuration : /etc/opnderbox/config.json (voir config.example.json). Sans configuration, le service
demarre en mode « premiere configuration » : un assistant web relie OPNderbox a OPNsense.

Commandes : server.py            lance le service
            server.py password   change le mot de passe de l'interface
            server.py setup      affiche l'adresse de l'assistant de premiere configuration
"""
import base64
import csv
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APP_NAME = "OPNderbox"
APP_VERSION = "1.0.0"
CONFIG_PATH = Path(os.environ.get("OPNDERBOX_CONFIG", "/etc/opnderbox/config.json"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATE_DIR = Path(os.environ.get("OPNDERBOX_STATE", "/var/lib/opnderbox"))
DEFAULT_PORT = int(os.environ.get("OPNDERBOX_PORT", "443"))

SESSION_IDLE = 30 * 60          # deconnexion apres 30 min d'inactivite
SESSION_MAX = 8 * 3600          # et au plus tard apres 8 h
LOGIN_MAX_FAILS = 5             # echecs avant blocage temporaire
LOGIN_LOCK = 5 * 60

# champs d'une regle que l'interface peut ecrire
RULE_FIELDS = (
    "enabled", "sequence", "action", "quick", "interface", "direction", "ipprotocol", "protocol",
    "icmptype", "source_net", "source_not", "source_port", "destination_net", "destination_not",
    "destination_port", "log", "categories", "description",
)


def parse_api_key(text):
    """contenu du fichier apikey.txt telecharge depuis OPNsense : lignes « key=... » et « secret=... »."""
    key = secret = None
    for line in str(text or "").splitlines():
        name, _, value = line.partition("=")
        if name.strip() == "key":
            key = value.strip()
        elif name.strip() == "secret":
            secret = value.strip()
    return key, secret


def basic_auth(key, secret):
    return "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode() if key and secret else None


def load_config():
    """configuration du service. Absente ou incomplete : mode premiere configuration (assistant web)."""
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        cfg = {}
    cfg.setdefault("key_file", str(CONFIG_PATH.parent / "apikey.txt"))
    cfg.setdefault("tls_cert", str(CONFIG_PATH.parent / "tls.crt"))
    cfg.setdefault("tls_key", str(CONFIG_PATH.parent / "tls.key"))
    keyfile = Path(cfg["key_file"])
    cfg["_auth"] = basic_auth(*parse_api_key(keyfile.read_text() if keyfile.is_file() else ""))
    return cfg


def configured(cfg=None):
    cfg = CFG if cfg is None else cfg
    return bool(cfg.get("opnsense") and cfg.get("opnsense_fingerprint") and cfg.get("_auth")
                and (cfg.get("password_hash") or cfg.get("auth_disabled")))


CFG = {}   # charge dans main() : la commande « password » doit marcher sans configuration


# ---------------------------------------------------------------- mot de passe de l'interface
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def check_password(password, stored):
    try:
        _, salt, digest = stored.split("$")
        expected = hash_password(password, base64.b64decode(salt)).split("$")[2]
        return hmac.compare_digest(expected, digest)
    except (ValueError, KeyError):
        return False


# ---------------------------------------------------------------- client API OPNsense
class ApiError(Exception):
    def __init__(self, message, detail=None):
        super().__init__(message)
        self.detail = detail


def tls_connect(base_url, timeout=60):
    """connexion TLS sans verification par autorite : l'identite d'OPNsense est verifiee par epinglage (empreinte)."""
    url = urlparse(base_url)
    if url.scheme != "https" or not url.hostname:
        raise ApiError("adresse d'OPNsense invalide : https://adresse attendu")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # verification remplacee par l'epinglage
    conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=timeout)
    try:
        conn.connect()
    except (OSError, ssl.SSLError) as e:
        conn.close()
        reason = str(e) or ("delai depasse : un pare-feu filtre-t-il l'acces a son interface ?" if isinstance(e, TimeoutError) else type(e).__name__)
        raise ApiError(f"OPNsense injoignable ({url.hostname}:{url.port or 443}) : {reason}")
    return conn


def fingerprint_of(conn):
    return hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()


def api_request(base_url, fingerprint, auth, method, path, body=None):
    """un appel a l'API OPNsense : (code HTTP, contenu brut)."""
    conn = tls_connect(base_url)
    try:
        if not hmac.compare_digest(fingerprint_of(conn), str(fingerprint or "").replace(":", "").lower()):
            raise ApiError("empreinte du certificat OPNsense inattendue : connexion refusee")
        headers = {"Authorization": auth, "Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, "/api/" + path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (OSError, http.client.HTTPException) as e:
        raise ApiError(f"echange avec OPNsense interrompu : {e}")
    finally:
        conn.close()


def opn(method, path, body=None, raw=False):
    """Appel a l'API OPNsense avec la configuration du service, certificat epingle par empreinte SHA-256."""
    if not CFG.get("_auth"):
        raise ApiError(f"cle API OPNsense absente : relancer l'assistant de configuration ou deposer apikey.txt dans {CFG.get('key_file')}")
    status, data = api_request(CFG["opnsense"], CFG.get("opnsense_fingerprint"), CFG["_auth"], method, path, body)

    if status == 401 or status == 403:
        raise ApiError(f"OPNsense refuse l'acces a {path} ({status}) : verifier les droits du compte API")
    if status >= 400:
        raise ApiError(f"OPNsense a repondu {status} sur {path}", data[:300].decode(errors="replace"))
    if raw:
        return data.decode()
    try:
        return json.loads(data or b"{}")
    except json.JSONDecodeError:
        raise ApiError(f"reponse illisible sur {path}", data[:300].decode(errors="replace"))


def parse_csv(text):
    if not text.strip():
        return []
    sep = ";" if text.find(";") != -1 and (text.find(",") == -1 or text.find(";") < text.find(",")) else ","
    return list(csv.DictReader(io.StringIO(text), delimiter=sep, escapechar="\\"))


def download_rules():
    return opn("GET", "firewall/filter/download_rules", raw=True)


def download_nat():
    return opn("GET", "firewall/d_nat/download_rules", raw=True)


def search_hosts():
    return opn("GET", "dnsmasq/settings/search_host?rowCount=-1").get("rows", [])


def categories_map():
    """nom -> uuid des categories."""
    data = opn("GET", "firewall/category/search_item?rowCount=-1")
    return {row["name"]: row["uuid"] for row in data.get("rows", [])}


def features():
    """fonctions presentes sur ce pare-feu (plugins) : le menu masque ce qui n'existe pas. None : inconnu (droit manquant)."""
    res = safe("GET", "core/service/search")
    if "_error" in res:
        return None
    names = {r.get("name") for r in res.get("rows", [])}
    return {"crowdsec": "crowdsec" in names, "ids": "suricata" in names, "dnsmasq": "dnsmasq" in names}


def ids_settings():
    """Suricata : actif, mode (pcap = detection seule, netmap / divert = prevention) et interfaces inspectees."""
    res = safe("GET", "ids/settings/get")
    if "_error" in res:
        return None
    g = res.get("ids", {}).get("general", {})
    sel = lambda v: [k for k, x in v.items() if isinstance(x, dict) and str(x.get("selected")) == "1"] if isinstance(v, dict) else []  # noqa: E731
    return {"enabled": g.get("enabled") == "1", "mode": (sel(g.get("mode")) or ["pcap"])[0], "interfaces": sel(g.get("interfaces"))}


def implicit_rules():
    """regles generees par OPNsense et ses plugins (DHCP, anti-blocage, bogons, CrowdSec...), regroupees par nom.
    Lecture seule, comme le module « Regles implicites » de Stormshield : elles se reglent dans OPNsense."""
    rows = opn("GET", "firewall/filter/search_rule?show_all=1&rowCount=-1").get("rows", [])
    groups = {}
    for r in rows:
        if not r.get("legacy"):
            continue
        key = (r.get("description") or "", r.get("action") or "pass", r.get("direction") or "in")
        g = groups.setdefault(key, {"description": key[0], "action": key[1], "direction": key[2], "interfaces": set(), "all": False,
                                    "pf_rules": 0, "packets": 0, "evaluations": 0, "enabled": True, "order": r.get("sort_order", ""),
                                    "labels": []})
        if r.get("interface"):
            g["interfaces"].add(r["interface"])
        else:
            g["all"] = True
        g["pf_rules"] += int(r.get("pf_rules") or 0)
        g["packets"] += int(r.get("packets") or 0)
        g["evaluations"] += int(r.get("evaluations") or 0)
        g["enabled"] = g["enabled"] and str(r.get("enabled", "1")) == "1" and r.get("disabled") is not True
        g["labels"].append(r.get("uuid", ""))
    out = sorted(groups.values(), key=lambda g: g["order"])
    for g in out:
        g["interfaces"] = sorted(g["interfaces"])
    return {"rules": out, "at": time.time()}


# ---------------------------------------------------------------- etat complet pour l'interface
def gather_state():
    rules = parse_csv(download_rules())
    aliases_raw = opn("GET", "firewall/alias/export")
    aliases = []
    for uuid, a in (aliases_raw.get("aliases", {}).get("alias", {}) or {}).items():
        content = a.get("content", "")
        if isinstance(content, dict):
            content = ",".join(k for k, v in content.items() if not isinstance(v, dict) or v.get("selected"))
        aliases.append({
            "uuid": uuid, "name": a.get("name", ""), "type": a.get("type", ""), "enabled": a.get("enabled", "1"),
            "content": [c for c in str(content).replace(",", "\n").split("\n") if c.strip()],
            "description": a.get("description", ""),
        })
    interfaces = {}
    for section in opn("GET", "firewall/filter/get_interface_list").values():
        for item in section.get("items", []):
            if item.get("type") in ("interface", "group") and item["value"] not in CFG.get("hide_interfaces", []):
                interfaces[item["value"]] = {"descr": item["label"], "type": item["type"]}
    for name, sub in CFG.get("subnets", {}).items():
        interfaces.setdefault(name, {"descr": name.upper(), "type": "interface"})["subnet"] = sub
    stats = opn("GET", "firewall/filter_util/rule_stats").get("stats", {})
    try:
        nat = parse_csv(download_nat())
    except ApiError:
        nat = []
    try:
        hosts = search_hosts()
    except ApiError:
        hosts = None
    net = {}
    for kind in ("vlan", "iface", "range", "option"):
        try:
            net[kind] = GRIDS[kind].search()
        except ApiError as e:
            net[kind] = {"_error": str(e)}
    try:
        net["dhcp"] = dhcp_settings()
    except ApiError as e:
        net["dhcp"] = {"_error": str(e)}
    try:
        devs = opn("GET", "interfaces/assignment/get_item").get("interface", {}).get("if", {})
        net["devices"] = {k: v.get("value", k) for k, v in devs.items() if k}
    except ApiError as e:
        net["devices"] = {"_error": str(e)}
    try:
        net["protected"] = protected_iface(net["iface"]) if isinstance(net["iface"], list) else {}
    except OSError:
        net["protected"] = {}
    # sous-reseau de chaque interface statique
    for r in net["iface"] if isinstance(net["iface"], list) else []:
        if r.get("type4") == "staticv4" and "/" in str(r.get("ipaddr", "")) and r["uuid"] in interfaces:
            try:
                interfaces[r["uuid"]].setdefault("subnet", str(ipaddress.ip_interface(r["ipaddr"]).network))
            except ValueError:
                pass
    # interfaces tournees vers l'exterieur : WAN, interface avec passerelle ou adresse obtenue du fournisseur
    for r in net["iface"] if isinstance(net["iface"], list) else []:
        if r["uuid"] in interfaces and (r.get("gateway") or r.get("type4") in ("dhcp", "pppoe", "pptp", "l2tp")):
            interfaces[r["uuid"]]["wan"] = True
    for k in ["wan", *CFG.get("wan_interfaces", [])]:
        if k in interfaces:
            interfaces[k]["wan"] = True
    global TOP_IFS
    TOP_IFS = [k for k, v in interfaces.items() if v["type"] == "interface"]
    try:
        tables = opn("GET", "firewall/alias/get_table_size")
    except ApiError:
        tables = {}
    sysinfo = safe("GET", "diagnostics/system/system_information")
    return {
        "rules": rules, "aliases": aliases, "interfaces": interfaces,
        "categories": sorted(categories_map()), "stats": stats, "nat": nat, "tables": tables, "hosts": hosts, "net": net,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "pending": TXN.status(),
        "host": CFG.get("display_name") or sysinfo.get("name") or urlparse(CFG["opnsense"]).hostname, "opnsense": CFG["opnsense"],
        "devices": safe("GET", "diagnostics/interface/get_interface_names"),
        "sysinfo": sysinfo, "features": features(), "ids": ids_settings(), "app": {"name": APP_NAME, "version": APP_VERSION},
        "rule_prefix": CFG.get("rule_prefix", ""),
        "separators": load_separators(), "colors": load_colors(),
        "usage": rule_usage(), "sched": load_sched(), "now": time.time(),
        "rollback_seconds": int(CFG.get("rollback_seconds", 60)),
        "auth_disabled": bool(CFG.get("auth_disabled")) and not CFG.get("demo"), "demo": bool(CFG.get("demo")),
    }


# ---------------------------------------------------------------- transaction avec retour arriere
ALIAS_FIELDS = ("enabled", "name", "type", "content", "description")
ALIAS_EDITABLE_TYPES = ("host", "network", "port")
NAT_FIELDS = ("sequence", "disabled", "nordr", "interface", "ipprotocol", "protocol", "source.network", "source.port",
              "source.not", "destination.network", "destination.port", "destination.not", "target", "local-port", "log",
              "descr", "natreflection", "pass")
HOST_FIELDS = ("host", "domain", "local", "ip", "cnames", "client_id", "hwaddr", "lease_time", "ignore", "descr",
               "comments", "aliases")
VLAN_FIELDS = ("if", "tag", "pcp", "proto", "descr", "vlanif")
IFACE_FIELDS = ("descr", "if", "enable", "lock", "blockpriv", "blockbogons", "mtu", "type4", "ipaddr", "gateway")
RANGE_FIELDS = ("interface", "start_addr", "end_addr", "subnet_mask", "lease_time", "domain_type", "domain", "description")
OPTION_FIELDS = ("type", "option", "option6", "interface", "tag", "set_tag", "value", "force", "description")
DHCP_FIELDS = ("regdhcp", "regdhcpstatic", "dhcp.domain", "dhcp.authoritative", "dhcp.lease_max", "dhcp.default_fw_rules", "dhcp.fqdn")
# ordre d'execution : VLAN puis interfaces (une interface peut utiliser un VLAN cree dans le meme lot),
# objets crees/modifies avant les regles qui les utilisent, objets et VLAN supprimes apres, DHCP a la fin
OP_ORDER = {"vlan_add": -3, "vlan_set": -3, "iface_add": -2, "iface_set": -2,
            "alias_add": 0, "alias_set": 1, "add": 2, "set": 2, "del": 2, "nat_add": 2, "nat_set": 2, "nat_del": 2,
            "alias_del": 3, "vlan_del": 3.5, "host_add": 4, "host_set": 4, "host_del": 4, "range_add": 4, "range_set": 4,
            "range_del": 4, "option_add": 4, "option_set": 4, "option_del": 4, "dhcp_set": 4, "sched_set": 5}
DNSMASQ_KINDS = {"host", "range", "option", "dhcp"}


class Grid:
    """tableau d'un modele OPNsense (VLAN, interfaces, plages DHCP...) : lecture, ecriture, restauration."""
    def __init__(self, name, base, wrap, fields, label, search="search_item", add="add_item", set_="set_item",
                 delete="del_item", reconf=None):
        self.name, self.base, self.wrap, self.fields, self.label = name, base, wrap, fields, label
        self.paths = {"search": search, "add": add, "set": set_, "del": delete}
        self.reconf = reconf

    def search(self):
        rows = opn("GET", f"{self.base}/{self.paths['search']}?rowCount=-1").get("rows", [])
        for r in rows:
            if self.name == "vlan":          # « vlan0.1 [INFRA] » -> « vlan0.1 »
                r["vlanif"] = str(r.get("vlanif", "")).split(" ")[0]
        return rows

    def clean(self, item):
        return {k: str(v) for k, v in item.items() if k in self.fields}

    def add(self, item):
        res = opn("POST", f"{self.base}/{self.paths['add']}", {self.wrap: self.clean(item)})
        Transaction._check(res, "saved", self.label)
        return res

    def set(self, key, item):
        Transaction._check(opn("POST", f"{self.base}/{self.paths['set']}/{key}", {self.wrap: self.clean(item)}), "saved", self.label)

    def delete(self, key):
        Transaction._check(opn("POST", f"{self.base}/{self.paths['del']}/{key}", {}), "deleted", "suppression : " + self.label)

    def restore(self, rows):
        """remet chaque entree de l'instantane (modifiee ou supprimee) et retire les ajouts."""
        current = {r["uuid"]: r for r in self.search()}
        for r in rows:
            fields = {k: str(r.get(k, "")) for k in self.fields}
            if r["uuid"] in current:
                if any(str(current[r["uuid"]].get(k, "")) != v for k, v in fields.items()):
                    self.set(r["uuid"], fields)
            elif self.name != "iface":       # une interface supprimee ne se recree pas a l'identique (jamais propose)
                self.add(fields)
        keep = {r["uuid"] for r in rows}
        for key, r in current.items():
            if key not in keep:
                if self.name == "iface" and r.get("lock") == "1":
                    self.set(key, {"lock": "0"})
                self.delete(key)


GRIDS = {
    "vlan": Grid("vlan", "interfaces/vlan_settings", "vlan", VLAN_FIELDS, "VLAN", reconf="interfaces/vlan_settings/reconfigure"),
    "iface": Grid("iface", "interfaces/assignment", "interface", IFACE_FIELDS, "interface", reconf="interfaces/assignment/reconfigure"),
    "host": Grid("host", "dnsmasq/settings", "host", HOST_FIELDS, "reservation", "search_host", "add_host", "set_host", "del_host"),
    "range": Grid("range", "dnsmasq/settings", "range", RANGE_FIELDS, "plage DHCP", "search_range", "add_range", "set_range", "del_range"),
    "option": Grid("option", "dnsmasq/settings", "option", OPTION_FIELDS, "option DHCP", "search_option", "add_option", "set_option", "del_option"),
}


def dhcp_settings():
    """reglages generaux du DHCP (dnsmasq), a plat : « dhcp.domain », « regdhcp »..."""
    d = opn("GET", "dnsmasq/settings/get").get("dnsmasq", {})
    out = {}
    for k in DHCP_FIELDS:
        head, _, tail = k.partition(".")
        v = d.get(head, "") if not tail else (d.get(head) or {}).get(tail, "")
        out[k] = v if isinstance(v, str) else ""
    return out


def protected_iface(rows=None):
    """interfaces sur le chemin OPNderbox -> OPNsense : celle par ou entrent les paquets d'OPNderbox et celle qui porte
    l'adresse visee. Les casser rendrait le retour arriere impossible."""
    host = urlparse(CFG["opnsense"]).hostname
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:     # aucune emission : sert a connaitre notre adresse
        s.connect((host, 443))
        local = s.getsockname()[0]
    out = {"ifaces": [], "devices": [], "local": local}
    for r in rows if rows is not None else GRIDS["iface"].search():
        addr = str(r.get("ipaddr", ""))
        try:
            hit = addr.split("/")[0] == host or ("/" in addr and ipaddress.ip_address(local) in ipaddress.ip_interface(addr).network)
        except ValueError:
            hit = False
        if hit:
            out["ifaces"].append(r["uuid"]); out["devices"].append(r.get("if", ""))
    return out


def nest(flat):
    """« source.network » -> {"source": {"network": ...}} : format attendu par OPNsense en ecriture."""
    out = {}
    for k, v in flat.items():
        head, _, tail = k.partition(".")
        if tail:
            out.setdefault(head, {})[tail] = str(v)
        else:
            out[k] = str(v)
    return out


def user_aliases():
    """alias de l'utilisateur (hors tables internes/externes, sauf la quarantaine), format brut de l'export OPNsense."""
    raw = opn("GET", "firewall/alias/export").get("aliases", {}).get("alias", {}) or {}
    return {u: a for u, a in raw.items() if a.get("type") not in ("internal", "external") or a.get("name") == QUAR_ALIAS}


class Transaction:
    def __init__(self):
        self.lock = threading.Lock()
        self.pending = None      # {"id", "deadline", "snap", "summary"}
        self.timer = None

    def status(self):
        p = self.pending
        if not p:
            return None
        return {"id": p["id"], "remaining": max(0, round(p["deadline"] - time.time())), "summary": p["summary"]}

    def _snapshot(self, tid, kinds):
        rules = download_rules()
        snap = {"rules": rules, "rule_uuids": {r["@uuid"] for r in parse_csv(rules) if r.get("@uuid")},
                "aliases": None, "nat": None, "grids": {}, "dhcp": None}
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / f"avant-{tid}.csv").write_text(rules)
        if "alias" in kinds:
            snap["aliases"] = user_aliases()
            (STATE_DIR / f"avant-{tid}-objets.json").write_text(json.dumps(snap["aliases"], ensure_ascii=False, indent=1))
        if "nat" in kinds:
            snap["nat"] = download_nat()
            snap["nat_uuids"] = {r["@uuid"] for r in parse_csv(snap["nat"]) if r.get("@uuid")}
            (STATE_DIR / f"avant-{tid}-nat.csv").write_text(snap["nat"])
        for kind in GRIDS:
            if kind in kinds or (kind == "iface" and "vlan" in kinds):
                snap["grids"][kind] = GRIDS[kind].search()
        if "dhcp" in kinds:
            snap["dhcp"] = dhcp_settings()
        if snap["grids"] or snap["dhcp"]:
            (STATE_DIR / f"avant-{tid}-reseau.json").write_text(json.dumps({"grids": snap["grids"], "dhcp": snap["dhcp"]}, ensure_ascii=False, indent=1))
        if "sched" in kinds:
            snap["sched"] = load_sched()
        return snap

    def apply(self, ops, client_ip):
        with self.lock:
            if self.pending:
                raise ApiError("des modifications attendent deja une confirmation")
            tid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
            kinds = {op_kind(op) for op in ops}
            if kinds & {"iface", "vlan"} and opn("GET", "interfaces/assignment/pending").get("status") != "ok":
                raise ApiError("des changements d'interface non appliques existent deja dans OPNsense : appliquez-les ou annulez-les d'abord")
            snap = self._snapshot(tid, kinds)
            self.cur_snap = snap
            self.protect = protected_iface() if kinds & {"iface", "vlan"} else {}
            cats = categories_map()
            errors, done = [], 0
            idmap = {}                          # identifiants provisoires du navigateur -> vrais (ex. opt6)
            vlans_up = False
            for op in sorted(ops, key=lambda o: OP_ORDER.get(o.get("op"), 9)):
                try:
                    # OPNsense n'accepte une interface que sur un peripherique existant : on cree les VLAN avant
                    if "vlan" in kinds and not vlans_up and op_kind(op) != "vlan":
                        opn("POST", "interfaces/vlan_settings/reconfigure", {})
                        vlans_up = True
                    op = remap(op, idmap)
                    res = self._run(op, cats)
                    if op.get("tmp") and isinstance(res, dict) and res.get("uuid"):
                        idmap[op["tmp"]] = res["uuid"]
                    done += 1
                except ApiError as e:
                    label = op_label(op)
                    errors.append({"op": op.get("op"), "uuid": op.get("uuid"), "description": label,
                                   "message": str(e), "detail": e.detail})
                    break                       # on s'arrete a la premiere erreur
            if errors:
                if done:                        # rien a defaire si aucune operation n'a abouti
                    try:
                        self._restore(snap)
                    except ApiError as e:
                        journal({"evt": "ECHEC-restauration", "id": tid, "erreur": str(e)})
                        errors.append({"op": "restauration", "description": "retour a l'etat precedent",
                                       "message": f"ECHEC : {e} - instantanes dans {STATE_DIR}/avant-{tid}*", "detail": e.detail})
                journal({"evt": "refuse", "ip": client_ip, "ops": len(ops), "errors": errors})
                return {"status": "refused", "errors": errors}
            if "vlan" in kinds:
                opn("POST", "interfaces/vlan_settings/reconfigure", {})
            if kinds & {"vlan", "iface"}:
                opn("POST", "interfaces/assignment/reconfigure", {})
            if "alias" in kinds:
                opn("POST", "firewall/alias/reconfigure", {})
            if kinds & {"alias", "rule", "nat", "iface"}:
                opn("POST", "firewall/filter/apply", {})
            if kinds & DNSMASQ_KINDS:
                opn("POST", "dnsmasq/service/reconfigure", {})
            delay = int(CFG.get("rollback_seconds", 60))
            self.pending = {"id": tid, "deadline": time.time() + delay, "snap": snap, "summary": summarize(ops)}
            self.timer = threading.Timer(delay, self._expire, args=(tid,))
            self.timer.daemon = True
            self.timer.start()
            journal({"evt": "applique", "id": tid, "ip": client_ip, "ops": ops})
            return {"status": "pending", "pending": self.status()}

    @staticmethod
    def _check(res, expected, what):
        if res.get("result") != expected:
            msgs = res.get("validations") or res.get("errorMessage") or res
            raise ApiError(f"{what} refuse par OPNsense : " + (msgs if isinstance(msgs, str) else json.dumps(msgs, ensure_ascii=False)))

    def _run(self, op, cats):
        kind = op.get("op")
        if kind in ("add", "set"):
            rule = {k: str(v) for k, v in op["rule"].items() if k in RULE_FIELDS}
            if "categories" in rule:
                rule["categories"] = ",".join(cats[c] for c in rule["categories"].split(",") if c in cats)
            path = "firewall/filter/add_rule" if kind == "add" else f"firewall/filter/set_rule/{op['uuid']}"
            res = opn("POST", path, {"rule": rule})
            self._check(res, "saved", "regle")
            return res
        elif kind == "del":
            self._check(opn("POST", f"firewall/filter/del_rule/{op['uuid']}", {}), "deleted", "suppression de regle")
        elif kind in ("alias_add", "alias_set"):
            alias = {k: v for k, v in op["alias"].items() if k in ALIAS_FIELDS}
            if alias.get("type") not in ALIAS_EDITABLE_TYPES and not (alias.get("type") == "external" and alias.get("name") == QUAR_ALIAS):
                raise ApiError(f"type d'objet non modifiable ici : {alias.get('type')}")
            if isinstance(alias.get("content"), list):
                alias["content"] = "\n".join(alias["content"])
            path = "firewall/alias/add_item" if kind == "alias_add" else f"firewall/alias/set_item/{op['uuid']}"
            self._check(opn("POST", path, {"alias": {k: str(v) for k, v in alias.items()}}), "saved", "objet")
        elif kind == "alias_del":
            self._check(opn("POST", f"firewall/alias/del_item/{op['uuid']}", {}), "deleted", "suppression d'objet")
        elif kind in ("nat_add", "nat_set"):
            rule = nest({k: v for k, v in op["nat"].items() if k in NAT_FIELDS})
            path = "firewall/d_nat/add_rule" if kind == "nat_add" else f"firewall/d_nat/set_rule/{op['uuid']}"
            self._check(opn("POST", path, {"rule": rule}), "saved", "redirection")
        elif kind == "nat_del":
            self._check(opn("POST", f"firewall/d_nat/del_rule/{op['uuid']}", {}), "deleted", "suppression de redirection")
        elif kind == "dhcp_set":
            fields = {k: v for k, v in op["dhcp"].items() if k in DHCP_FIELDS}
            self._check(opn("POST", "dnsmasq/settings/set", {"dnsmasq": nest(fields)}), "saved", "reglages DHCP")
        elif kind == "sched_set":
            save_sched(check_sched(op.get("sched")))
        elif op_kind(op) in GRIDS and kind.split("_", 1)[1] in ("add", "set", "del"):
            g, action = GRIDS[op_kind(op)], kind.split("_", 1)[1]
            self._guard(g.name, action, op)
            if action == "add":
                return g.add({**op[g.name], "lock": "0"} if g.name == "iface" else op[g.name])
            elif action == "set":
                g.set(op["uuid"], op[g.name])
            elif g.name == "iface":
                raise ApiError("la suppression d'une interface n'est pas proposee (OPNsense effacerait aussi ses regles)")
            else:
                g.delete(op["uuid"])
        else:
            raise ApiError(f"operation inconnue : {kind}")

    def _guard(self, kind, action, op):
        """refuse ce qui couperait le lien entre OPNderbox et OPNsense (le retour arriere deviendrait impossible)."""
        prot = getattr(self, "protect", {}) or {}
        if kind == "iface" and action == "set" and op["uuid"] in prot.get("ifaces", []):
            cur = next((r for r in self.snap_rows("iface") if r["uuid"] == op["uuid"]), {})
            if any(str(cur.get(k, "")) != str(v) for k, v in op["iface"].items() if k in IFACE_FIELDS and k != "descr"):
                raise ApiError(f"interface utilisee par {APP_NAME} pour joindre le pare-feu : seule sa description peut changer ici")
        if kind == "vlan" and action in ("set", "del") and prot.get("devices"):
            cur = next((r for r in self.snap_rows("vlan") if r["uuid"] == op["uuid"]), {})
            if cur.get("vlanif") in prot["devices"] and (action == "del" or any(
                    str(cur.get(k, "")) != str(v) for k, v in op["vlan"].items() if k in VLAN_FIELDS and k != "descr")):
                raise ApiError(f"VLAN utilise par {APP_NAME} pour joindre le pare-feu : seule sa description peut changer ici")

    def snap_rows(self, kind):
        return (getattr(self, "cur_snap", None) or {}).get("grids", {}).get(kind, [])

    def _restore(self, snap):
        """Remet objets et regles dans l'etat de l'instantane. Ordre : objets d'origine (les regles
        restaurees peuvent y faire reference), regles, puis suppression de ce qui a ete ajoute."""
        grids = snap.get("grids", {})
        if "iface" in grids:                 # interfaces appliquees avant les VLAN : un VLAN affecte ne se supprime pas
            GRIDS["iface"].restore(grids["iface"])
            opn("POST", "interfaces/assignment/reconfigure", {})
        if "vlan" in grids:
            GRIDS["vlan"].restore(grids["vlan"])
            opn("POST", "interfaces/vlan_settings/reconfigure", {})
        if snap["aliases"] is not None:
            res = opn("POST", "firewall/alias/import", {"data": {"aliases": {"alias": snap["aliases"]}}})
            if res.get("status") != "ok":
                journal({"evt": "restauration-objets-incomplete", "detail": res})
        opn("POST", "firewall/filter/upload_rules", {"payload": snap["rules"]})
        for r in parse_csv(download_rules()):
            if r.get("@uuid") and r["@uuid"] not in snap["rule_uuids"]:
                opn("POST", f"firewall/filter/del_rule/{r['@uuid']}", {})
        if snap["nat"] is not None:
            opn("POST", "firewall/d_nat/upload_rules", {"payload": snap["nat"]})
            for r in parse_csv(download_nat()):
                if r.get("@uuid") and r["@uuid"] not in snap["nat_uuids"]:
                    opn("POST", f"firewall/d_nat/del_rule/{r['@uuid']}", {})
        if snap["aliases"] is not None:
            names = {a.get("name") for a in snap["aliases"].values()}
            for uuid, a in user_aliases().items():
                if a.get("name") not in names:
                    opn("POST", f"firewall/alias/del_item/{uuid}", {})
            opn("POST", "firewall/alias/reconfigure", {})
        opn("POST", "firewall/filter/apply", {})
        dns = False
        for kind in ("host", "range", "option"):
            if kind in grids:
                GRIDS[kind].restore(grids[kind]); dns = True
        if snap.get("dhcp") is not None:
            opn("POST", "dnsmasq/settings/set", {"dnsmasq": nest(snap["dhcp"])}); dns = True
        if dns:
            opn("POST", "dnsmasq/service/reconfigure", {})
        if snap.get("sched") is not None:
            save_sched(snap["sched"])

    def _expire(self, tid):
        with self.lock:
            if self.pending and self.pending["id"] == tid:
                try:
                    self._restore(self.pending["snap"])
                    journal({"evt": "retour-arriere-automatique", "id": tid})
                except Exception as e:  # noqa: BLE001 - on journalise toute erreur de restauration
                    journal({"evt": "ECHEC-retour-arriere", "id": tid, "erreur": str(e)})
                self.pending = None

    def confirm(self, client_ip):
        with self.lock:
            if not self.pending:
                raise ApiError("aucune modification en attente")
            if self.timer:
                self.timer.cancel()
            journal({"evt": "confirme", "id": self.pending["id"], "ip": client_ip})
            self.pending = None

    def rollback(self, client_ip):
        with self.lock:
            if not self.pending:
                raise ApiError("aucune modification en attente")
            if self.timer:
                self.timer.cancel()
            self._restore(self.pending["snap"])
            journal({"evt": "annule", "id": self.pending["id"], "ip": client_ip})
            self.pending = None


def remap(obj, idmap):
    """remplace les identifiants provisoires (interface creee dans le meme lot) par les vrais."""
    if not idmap:
        return obj
    if isinstance(obj, dict):
        return {k: remap(v, idmap) for k, v in obj.items()}
    if isinstance(obj, list):
        return [remap(v, idmap) for v in obj]
    if isinstance(obj, str) and obj:
        return ",".join(idmap.get(p) or (idmap[p[:-2]] + "ip" if p.endswith("ip") and p[:-2] in idmap else p) for p in obj.split(","))
    return obj


def op_kind(op):
    """famille d'une operation : rule, alias, nat, host, vlan, iface, range, option ou dhcp."""
    name = op.get("op", "")
    return name.split("_")[0] if "_" in name else "rule"


def op_label(op):
    vlan = op.get("vlan", {})
    return (op.get("rule", {}).get("description") or op.get("alias", {}).get("name") or op.get("nat", {}).get("descr")
            or op.get("host", {}).get("host") or (f"VLAN {vlan.get('tag')} {vlan.get('descr', '')}".strip() if vlan else "")
            or op.get("iface", {}).get("descr") or op.get("range", {}).get("description")
            or op.get("option", {}).get("description") or ("reglages DHCP" if op.get("dhcp") else "")
            or ("objets temps (plannings)" if op.get("sched") else "") or op.get("name", ""))


def summarize(ops):
    n = {"add": 0, "set": 0, "del": 0, "objets": 0, "nat": 0, "dhcp": 0, "reseau": 0}
    for op in ops:
        k = {"alias": "objets", "nat": "nat", "host": "dhcp", "range": "dhcp", "option": "dhcp", "dhcp": "dhcp",
             "vlan": "reseau", "iface": "reseau", "sched": "objets"}.get(op_kind(op), op.get("op"))
        n[k] = n.get(k, 0) + 1
    return n


def journal(entry):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entry["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(STATE_DIR / "journal.log", "a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


TXN = Transaction()


# ---------------------------------------------------------------- supervision (lecture seule)
LOG_FIELDS = ("__timestamp__", "__digest__", "action", "interface", "dir", "src", "dst", "srcport", "dstport",
              "protoname", "rid", "label", "tcpflags", "length", "ipversion", "ttl")
IDS_FIELDS = ("timestamp", "alert", "alert_sid", "alert_action", "src_ip", "src_port", "dest_ip", "dest_port",
              "proto", "in_iface", "direction")


def safe(method, path, body=None):
    """appel tolerant : un droit manquant vide un panneau, pas toute la page."""
    try:
        return opn(method, path, body)
    except ApiError as e:
        return {"_error": str(e)}


def parallel(calls):
    with ThreadPoolExecutor(len(calls)) as pool:
        futures = {k: pool.submit(safe, *v) for k, v in calls.items()}
    return {k: f.result() for k, f in futures.items()}


def trim_log(rows):
    return [{k: r.get(k, "") for k in LOG_FIELDS} for r in rows] if isinstance(rows, list) else rows


def ids_alerts(limit, query=""):
    res = safe("POST", "ids/service/query_alerts", {"rowCount": limit, "current": 1, "searchPhrase": query})
    if "_error" in res:
        return res
    return {"total": res.get("total", 0), "rows": [{k: r.get(k, "") for k in IDS_FIELDS} for r in res.get("rows", [])]}


def ids_family(signature):
    """« ET DROP Spamhaus DROP Listed ... » -> « DROP Spamhaus » : regroupe les signatures par source."""
    words = str(signature).split()
    return " ".join(words[1:3]) if len(words) > 2 else str(signature)


def log_summary(rows):
    """blocages des dernieres lignes du journal : qui, vers quoi, par quelle regle."""
    if not isinstance(rows, list):
        return rows
    blocked = [r for r in rows if r.get("action") == "block"]
    inbound = [r for r in rows if r.get("dir") != "out"]
    return {
        "lines": len(rows), "blocked": len(blocked),
        "in": len(inbound), "in_blocked": sum(1 for r in inbound if r.get("action") == "block"),
        "since": rows[-1].get("__timestamp__", "") if rows else "",
        "sources": Counter(r.get("src", "") for r in blocked).most_common(6),
        "ports": Counter(f"{r.get('protoname', '')}/{r.get('dstport', '')}" for r in blocked if r.get("dstport")).most_common(6),
        "interfaces": Counter(r.get("interface", "") for r in blocked).most_common(),
        "rules": Counter((r.get("rid", ""), r.get("label", "")) for r in blocked).most_common(6),
    }


def dashboard(part):
    if part == "fast":
        out = parallel({
            "time": ("GET", "diagnostics/system/system_time"),
            "resources": ("GET", "diagnostics/system/system_resources"),
            "states": ("GET", "diagnostics/firewall/pf_states"),
            "traffic": ("GET", "diagnostics/traffic/interface"),
            "gateways": ("GET", "routes/gateway/status"),
        })
    else:
        out = parallel({
            "info": ("GET", "diagnostics/system/system_information"),
            "temperature": ("GET", "diagnostics/system/system_temperature"),
            "tables": ("GET", "firewall/alias/get_table_size"),
            "log": ("GET", "diagnostics/firewall/log?limit=1000"),
            "disk": ("GET", "diagnostics/system/system_disk"),
        })
        out["log"] = log_summary(out["log"])
        ids = ids_alerts(500)
        if "_error" not in ids:
            ids = {"total": ids["total"], "rows": ids["rows"][:60],
                   "families": Counter(ids_family(a["alert"]) for a in ids["rows"]).most_common()}
        out["ids"] = ids
        out["history"] = history(1)
        out["firmware"] = firmware()["status"]
    out["at"] = time.time()
    return out


def history(limit=300):
    """journal des actions de l'interface, le plus recent en premier, operations resumees."""
    path = STATE_DIR / "journal.log"
    if not path.is_file():
        return []
    out = []
    for line in reversed(path.read_text().splitlines()[-limit:]):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e.get("ops"), list):
            e["ops"] = [{"op": o.get("op"), "label": op_label(o)} for o in e["ops"]]
        out.append(e)
    return out


def network():
    return parallel({
        "ifaces": ("GET", "interfaces/overview/interfaces_info"),
        "services": ("GET", "core/service/search"),
        "traffic": ("GET", "diagnostics/traffic/interface"),
    }) | {"at": time.time()}


def dhcp():
    return parallel({
        "ranges": ("GET", "dnsmasq/settings/search_range?rowCount=-1"),
        "leases": ("GET", "dnsmasq/leases/search?rowCount=-1"),
    }) | {"at": time.time()}


def crowdsec():
    return parallel({
        "decisions": ("GET", "crowdsec/decisions/search?rowCount=-1"),
        "alerts": ("GET", "crowdsec/alerts/search?rowCount=-1"),
        "tables": ("GET", "firewall/alias/get_table_size"),
    })


# services qu'on ne laisse jamais arreter depuis l'interface (on perdrait le pare-feu ou l'acces)
NEVER_STOP = {"pf", "configd", "webgui", "routing", "login", "sysctl"}


def service_action(name, action, client_ip):
    if action not in ("start", "stop", "restart") or not re.fullmatch(r"[a-z0-9_.-]{1,64}", name or ""):
        raise ApiError("action de service invalide")
    known = {r["name"]: r for r in opn("GET", "core/service/search").get("rows", [])}
    if name not in known:
        raise ApiError(f"service inconnu : {name}")
    if action == "stop" and (name in NEVER_STOP or known[name].get("locked")):
        raise ApiError(f"le service {name} est indispensable : arret refuse")
    res = opn("POST", f"core/service/{action}/{name}", {})
    journal({"evt": "service", "ip": client_ip, "service": name, "action": action, "result": res.get("result", "")})
    return res


def unban(decision_id, client_ip):
    if not isinstance(decision_id, int) or decision_id <= 0:
        raise ApiError("identifiant de bannissement invalide")
    res = opn("POST", f"crowdsec/decisions/del/{decision_id}", {})
    if res.get("result") != "deleted":
        raise ApiError(f"debannissement refuse : {res.get('result', res)}")
    journal({"evt": "debannissement", "ip": client_ip, "decision": decision_id})
    return res


# ---------------------------------------------------------------- etape 3 : machines, connexions, routage, systeme
TOP_TTL = 30                    # la mesure « top » d'OPNsense dure ~10 s : on la garde 30 s


class TopCache:
    """machines les plus actives, mesurees en arriere-plan pour ne jamais bloquer la page."""
    def __init__(self):
        self.lock = threading.Lock()
        self.data, self.at, self.busy = None, 0, False

    def _fetch(self, ifs):
        try:
            data = safe("GET", "diagnostics/traffic/top/" + ifs)
        finally:
            with self.lock:
                self.busy = False
        with self.lock:
            self.data, self.at = data, time.time()

    def get(self):
        ifs = ",".join(TOP_IFS or ["wan"])
        with self.lock:
            if time.time() - self.at > TOP_TTL and not self.busy:
                self.busy = True
                threading.Thread(target=self._fetch, args=(ifs,), daemon=True).start()
            return {"top": self.data, "at": self.at, "busy": self.busy}


TOP = TopCache()
TOP_IFS = []                    # interfaces mesurees, connues au premier chargement de l'etat


def machines():
    return parallel({"arp": ("GET", "diagnostics/interface/get_arp"),
                     "leases": ("GET", "dnsmasq/leases/search?rowCount=-1")}) | TOP.get()


STATE_FIELDS = ("descr", "label", "proto", "ipproto", "direction", "src_addr", "src_port", "dst_addr", "dst_port",
                "nat_addr", "nat_port", "state", "age", "expires", "pkts", "bytes", "id")


def states(limit, query):
    res = safe("POST", "diagnostics/firewall/query_states", {"rowCount": limit, "current": 1, "searchPhrase": query})
    if "_error" in res:
        return res
    return {"total": res.get("total", 0), "rows": [{k: r.get(k) for k in STATE_FIELDS} for r in res.get("rows", [])]}


def kill_state(state_id, client_ip):
    m = re.fullmatch(r"([0-9a-f]{1,16})/([0-9a-f]{1,8})", str(state_id))
    if not m:
        raise ApiError("identifiant de connexion invalide")
    res = opn("POST", f"diagnostics/firewall/del_state/{m.group(1)}/{m.group(2)}", {})
    journal({"evt": "connexion-coupee", "ip": client_ip, "etat": state_id})
    return res


def routing():
    return parallel({"routes": ("GET", "diagnostics/interface/get_routes"),
                     "gateways": ("GET", "routes/gateway/status")})


def routes_config():
    """configuration du routage : passerelles (dont celle par defaut) et routes statiques."""
    return parallel({"gateways": ("GET", "routing/settings/search_gateway?rowCount=-1"),
                     "routes": ("GET", "routes/routes/searchroute?rowCount=-1")})


def sysinfo():
    """supervision du systeme : les memes appels que les widgets du tableau de bord d'OPNsense."""
    return parallel({k: ("GET", "diagnostics/system/system_" + k) for k in ("information", "resources", "disk", "temperature", "swap", "mbuf", "time")})


# journaux d'OPNsense lisibles : source -> portee de diagnostics/log/core/<portee>
SYSLOG_SCOPES = {"system": "system", "routage": "gateways"}
SYSLOG_FIELDS = ("timestamp", "severity", "process_name", "pid", "line", "rnum")


def syslog(source, limit, query=""):
    if source not in SYSLOG_SCOPES:
        raise ApiError("journal inconnu")
    res = safe("POST", f"diagnostics/log/core/{SYSLOG_SCOPES[source]}", {"current": 1, "rowCount": limit, "searchPhrase": query})
    if "_error" in res:
        return res
    return {"total": res.get("total", 0), "rows": [{k: r.get(k, "") for k in SYSLOG_FIELDS} for r in res.get("rows", [])]}


# lignes de configuration a ne jamais montrer, meme hachees (mots de passe, cles)
SECRET_RX = re.compile(r"(&lt;(apikeys|password|bcrypt-hash|authorizedkeys|prv|secret|psk|privkey|key|otp_seed)&gt;)(.*?)(&lt;/\2&gt;|$)", re.I)
BACKUP_RX = re.compile(r"config-[0-9.]+\.xml")


def backups():
    return safe("GET", "core/backup/backups/this")


def backup_diff(b1, b2):
    if not (BACKUP_RX.fullmatch(b1) and BACKUP_RX.fullmatch(b2)):
        raise ApiError("version invalide")
    res = opn("GET", f"core/backup/diff/this/{b1}/{b2}")
    return {"lines": [SECRET_RX.sub(lambda m: m.group(1) + "••••" + m.group(4), line) for line in res.get("items", [])][:4000]}


def backup_download(name, client_ip):
    if not BACKUP_RX.fullmatch(name):
        raise ApiError("version invalide")
    data = opn("GET", f"core/backup/download/this/{name}", raw=True)
    journal({"evt": "sauvegarde-telechargee", "ip": client_ip, "version": name})
    return data


FW_FIELDS = ("product_version", "os_version", "last_check", "status", "status_msg", "needs_reboot", "upgrade_needs_reboot",
             "download_size", "upgrade_packages", "new_packages", "remove_packages", "upgrade_major_version", "upgrade_major_message")


def firmware():
    out = parallel({"status": ("GET", "core/firmware/status"), "running": ("GET", "core/firmware/running")})
    if "_error" not in out["status"]:
        out["status"] = {k: out["status"].get(k) for k in FW_FIELDS}
    return out


def firmware_action(action, client_ip):
    if action not in ("check", "update"):
        raise ApiError("action invalide")
    if action == "update" and opn("GET", "core/firmware/running").get("status") != "ready":
        raise ApiError("une operation de mise a jour est deja en cours")
    res = opn("POST", f"core/firmware/{action}", {})
    journal({"evt": "mise-a-jour" if action == "update" else "recherche-mises-a-jour", "ip": client_ip})
    return res


# politiques enregistrees (10 emplacements, comme Stormshield) : copies des regles, chargees dans la
# copie de travail puis appliquees avec le retour arriere habituel
POL_DIR = "politiques"
POL_MAX = 10


def policies(pid=None):
    d = STATE_DIR / POL_DIR
    if pid is not None:
        if not re.fullmatch(r"[0-9]{1,2}", str(pid)):
            raise ApiError("politique invalide")
        try:
            return json.loads((d / f"{pid}.json").read_text())
        except OSError:
            raise ApiError("politique introuvable")
    out = []
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            p = json.loads(f.read_text())
            out.append({k: p.get(k) for k in ("id", "name", "date", "ip")} | {"count": len(p.get("rules", []))})
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(out, key=lambda p: int(p["id"]))


def policy_action(body, client_ip):
    action, pid = body.get("action"), str(body.get("id", ""))
    if not re.fullmatch(r"[0-9]{1,2}", pid) or not 1 <= int(pid) <= POL_MAX:
        raise ApiError("emplacement invalide (1 a 10)")
    path = STATE_DIR / POL_DIR / f"{pid}.json"
    if action == "delete":
        path.unlink(missing_ok=True)
    elif action in ("save", "rename"):
        name = str(body.get("name", "")).strip()[:60] or f"Politique {pid}"
        if action == "rename":
            p = policies(pid)
            p["name"] = name
        else:
            rules = body.get("rules")
            if not isinstance(rules, list) or len(rules) > 500:
                raise ApiError("regles invalides")
            clean_rules = []
            for r in rules:
                uuid = r.get("uuid") if isinstance(r, dict) else None
                if uuid is not None and not re.fullmatch(r"[0-9a-f-]{32,36}", str(uuid)):
                    raise ApiError("regle invalide")
                clean_rules.append({"uuid": uuid, "f": {k: str(v) for k, v in (r.get("f") or {}).items() if k in RULE_FIELDS}})
            p = {"id": pid, "name": name, "date": time.strftime("%Y-%m-%d %H:%M"), "ip": client_ip, "rules": clean_rules}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(p, ensure_ascii=False, indent=1))
        tmp.replace(path)
    else:
        raise ApiError("action invalide")
    journal({"evt": "politique", "ip": client_ip, "action": action, "id": pid})
    return {"policies": policies()}


def qint(qs, name, default, lo, hi):
    try:
        return max(lo, min(hi, int(qs.get(name, [default])[0])))
    except ValueError:
        return default


# ---------------------------------------------------------------- droit de modification
# Comme sur Stormshield : on consulte librement, mais un seul poste a la fois peut modifier.
WRITE_IDLE = 15 * 60            # le droit se perd apres 15 min sans activite


class WriteLock:
    def __init__(self):
        self.lock = threading.Lock()
        self.holder = None      # {"key", "ip", "since", "seen"}

    def _alive(self, now):
        return self.holder is not None and now - self.holder["seen"] < WRITE_IDLE

    def status(self, key):
        with self.lock:
            if not self._alive(time.time()):
                self.holder = None
            h = self.holder
            return {"mine": bool(h and h["key"] == key), "held": bool(h), "ip": h["ip"] if h else None,
                    "since": h["since"] if h else None}

    def take(self, key, ip):
        now = time.time()
        with self.lock:
            if self._alive(now) and self.holder["key"] != key:
                raise ApiError(f"droit de modification deja pris par {self.holder['ip']} "
                               f"(depuis {time.strftime('%H:%M', time.localtime(self.holder['since']))})")
            if not (self.holder and self.holder["key"] == key):
                self.holder = {"key": key, "ip": ip, "since": now, "seen": now}
                journal({"evt": "droit-modification", "ip": ip})
            self.holder["seen"] = now

    def release(self, key, ip):
        with self.lock:
            if self.holder and self.holder["key"] == key:
                self.holder = None
                journal({"evt": "fin-modification", "ip": ip})

    def require(self, key):
        now = time.time()
        with self.lock:
            if not (self._alive(now) and self.holder["key"] == key):
                raise ApiError("mode lecture seule : obtenez d'abord le droit de modification")
            self.holder["seen"] = now


WLOCK = WriteLock()


# ---------------------------------------------------------------- separateurs de la grille de filtrage
# OPNsense ne connait pas les separateurs : OPNderbox les garde de son cote, accroches a une regle (uuid).
SEP_COLORS = ("blue", "orange", "teal", "yellow", "pink", "violet", "red", "gray")
SEP_FILE = "separateurs.json"


def load_separators():
    try:
        return json.loads((STATE_DIR / SEP_FILE).read_text())
    except (OSError, json.JSONDecodeError):
        return []


def save_separators(items):
    if not isinstance(items, list) or len(items) > 200:
        raise ApiError("separateurs invalides")
    out = []
    for it in items:
        if not isinstance(it, dict):
            raise ApiError("separateur invalide")
        sid, before, title, color = (str(it.get(k, "")) for k in ("id", "before", "title", "color"))
        if not re.fullmatch(r"[a-z0-9-]{1,40}", sid) or not re.fullmatch(r"[0-9a-f-]{32,36}", before) or color not in SEP_COLORS:
            raise ApiError("separateur invalide")
        out.append({"id": sid, "before": before, "title": title.strip()[:80], "color": color})
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_DIR / (SEP_FILE + ".tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, indent=1))
    tmp.replace(STATE_DIR / SEP_FILE)
    return out


# couleur de chaque interface (pastilles, groupes de regles) : reglage d'affichage propre a OPNderbox
IF_COLORS = ("blue", "green", "ochre", "red", "violet", "teal", "pink", "orange", "gray", "navy", "olive", "brown")
COLOR_FILE = "couleurs.json"


def load_colors():
    return load_json(COLOR_FILE, {})


def save_colors(colors):
    if not isinstance(colors, dict) or len(colors) > 100 or any(
            not re.fullmatch(r"(wan|lan|opt\d{1,3})", str(k)) or v not in IF_COLORS for k, v in colors.items()):
        raise ApiError("couleurs invalides")
    save_json(COLOR_FILE, colors)
    return colors


def load_json(name, default):
    try:
        return json.loads((STATE_DIR / name).read_text())
    except (OSError, json.JSONDecodeError):
        return default


def save_json(name, data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_DIR / (name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    tmp.replace(STATE_DIR / name)


# ---------------------------------------------------------------- etape 5 : historiques (graphiques RRD d'OPNsense)
RRD_RX = re.compile(r"[a-z0-9]{1,20}-(system|traffic|packets)")
# periode -> (jeu de donnees OPNsense, duree) ; jeux : 0 = 1 min sur 20 h, 1 = 5 min sur 60 h, 2 = 1 h sur 77 j, 3 = 1 j
RRD_RANGES = {"hour": (0, 3600), "day": (1, 86400), "week": (2, 7 * 86400), "month": (2, 31 * 86400), "year": (3, 366 * 86400)}
RRD_POINTS = 360


def rrd_series(name, rng):
    if not RRD_RX.fullmatch(name):
        return {"_error": "serie invalide"}
    detail, span = RRD_RANGES[rng]
    res = safe("GET", f"diagnostics/systemhealth/get_system_health/{name}/{detail}")
    if "_error" in res:
        return res
    data = (res.get("set") or {}).get("data") if isinstance(res.get("set"), dict) else None
    if not data:
        return {"_error": "aucune donnee pour " + name}
    end = max((t for ds in data for t, v in ds.get("values", []) if isinstance(v, (int, float))), default=0) // 1000
    series = {}
    for ds in data:
        pts = [(t // 1000, v) for t, v in ds.get("values", []) if isinstance(v, (int, float)) and v == v and t // 1000 > end - span]
        size = max(1, -(-len(pts) // RRD_POINTS))          # moyenne par paquets : 360 points au plus
        series[ds["key"]] = [[pts[min(i + size, len(pts)) - 1][0], round(sum(v for _, v in pts[i:i + size]) / len(pts[i:i + size]), 3)]
                             for i in range(0, len(pts), size)]
    return {"step": int((res.get("set") or {}).get("step_size") or 60), "series": series}


def rrd(names, rng):
    if rng not in RRD_RANGES:
        raise ApiError("periode invalide")
    names = [n for n in names if n][:12]
    with ThreadPoolExecutor(max(1, len(names))) as pool:
        futures = {n: pool.submit(rrd_series, n, rng) for n in names}
    return {n: f.result() for n, f in futures.items()} | {"at": time.time()}


# ---------------------------------------------------------------- etape 5 : quarantaine
# Table du pare-feu (alias « external », contenu hors configuration) bloquee par deux regles en tete de politique.
# OPNderbox ajoute et retire les adresses (effet immediat), gere les durees et remet la table apres un redemarrage.
QUAR_ALIAS = "QUARANTAINE"
QUAR_FILE = "quarantaine.json"
QUAR_LOCK = threading.Lock()


def quar_table():
    res = opn("GET", f"firewall/alias_util/list/{QUAR_ALIAS}")
    return {r.get("ip", "").split("/")[0] for r in res.get("rows", [])}


def quar_installed():
    aliases = opn("GET", "firewall/alias/export").get("aliases", {}).get("alias", {}) or {}
    alias = any(a.get("name") == QUAR_ALIAS and a.get("type") == "external" for a in aliases.values())
    rules = [r for r in parse_csv(download_rules()) if QUAR_ALIAS in (r.get("source_net"), r.get("destination_net")) and r.get("enabled") == "1"]
    return {"alias": alias, "rules": len(rules), "ok": alias and len(rules) >= 2}


def quar_protected(client_ip=None):
    """adresses qu'on ne met jamais en quarantaine : le poste d'administration, OPNderbox, le pare-feu, les passerelles."""
    prot = {urlparse(CFG["opnsense"]).hostname: "pare-feu"}
    try:
        info = protected_iface()
        prot[info["local"]] = APP_NAME
        for r in GRIDS["iface"].search():
            if "/" in str(r.get("ipaddr", "")):
                prot[r["ipaddr"].split("/")[0]] = "pare-feu (" + (r.get("descr") or r["uuid"]) + ")"
    except (ApiError, OSError):
        pass
    for g in (safe("GET", "routes/gateway/status").get("items") or []):
        if g.get("address"):
            prot[g["address"]] = "passerelle " + g.get("name", "")
    if client_ip:
        prot[client_ip] = "votre poste"
    return prot


def quarantine():
    st = quar_installed()
    try:
        table = quar_table() if st["alias"] else set()
    except ApiError:
        table = set()
    now = time.time()
    with QUAR_LOCK:
        d = load_json(QUAR_FILE, {})
    return {"installed": st, "now": now, "entries": [{"ip": ip, **e, "active": ip in table} for ip, e in sorted(d.items(), key=lambda x: -x[1]["since"])],
            "others": sorted(table - set(d))}


def quarantine_action(body, client_ip):
    action = body.get("action")
    try:
        ip = str(ipaddress.ip_address(str(body.get("ip", "")).strip()))
    except ValueError:
        raise ApiError("adresse IP invalide")
    with QUAR_LOCK:
        d = load_json(QUAR_FILE, {})
        if action == "add":
            prot = quar_protected(client_ip)
            if ip in prot:
                raise ApiError(f"{ip} ne peut pas etre mise en quarantaine : {prot[ip]}")
            if not quar_installed()["alias"]:
                raise ApiError("la quarantaine n'est pas installee (objet QUARANTAINE et ses deux regles)")
            minutes = int(body.get("minutes") or 0)
            if not 0 <= minutes <= 525600:
                raise ApiError("duree invalide")
            res = opn("POST", f"firewall/alias_util/add/{QUAR_ALIAS}", {"address": ip})
            if res.get("status") != "done":
                raise ApiError(f"ajout refuse par OPNsense : {res}")
            killed = safe("POST", "diagnostics/firewall/kill_states", {"filter": ip}).get("dropped_states", 0)
            now = time.time()
            d[ip] = {"since": now, "until": now + minutes * 60 if minutes else 0, "by": client_ip, "reason": str(body.get("reason", ""))[:120]}
            save_json(QUAR_FILE, d)
            journal({"evt": "quarantaine", "ip": client_ip, "cible": ip, "minutes": minutes, "connexions": killed})
            return {"ok": True, "killed": killed}
        if action == "del":
            opn("POST", f"firewall/alias_util/delete/{QUAR_ALIAS}", {"address": ip})
            d.pop(ip, None)
            save_json(QUAR_FILE, d)
            journal({"evt": "quarantaine-fin", "ip": client_ip, "cible": ip})
            return {"ok": True}
    raise ApiError("action invalide")


def quarantine_tick():
    """expirations, et remise des adresses perdues (table videe par un redemarrage du pare-feu)."""
    with QUAR_LOCK:
        d = load_json(QUAR_FILE, {})
        if not d:
            return
        now, table, changed = time.time(), quar_table(), False
        for ip, e in list(d.items()):
            if e.get("until") and e["until"] <= now:
                if ip in table:
                    opn("POST", f"firewall/alias_util/delete/{QUAR_ALIAS}", {"address": ip})
                d.pop(ip); changed = True
                journal({"evt": "quarantaine-expiree", "cible": ip})
            elif ip not in table:
                opn("POST", f"firewall/alias_util/add/{QUAR_ALIAS}", {"address": ip})
        if changed:
            save_json(QUAR_FILE, d)


# ---------------------------------------------------------------- etape 5 : utilisation des regles
# Les compteurs d'OPNsense repartent de zero a chaque rechargement du filtre : OPNderbox note la derniere hausse.
USAGE_FILE = "regles-usage.json"


def usage_tick():
    stats = opn("GET", "firewall/filter_util/rule_stats").get("stats", {})
    now = time.time()
    d = load_json(USAGE_FILE, {"since": now, "rules": {}})
    for uuid, s in stats.items():
        n, r = int(s.get("packets") or 0), d["rules"].get(uuid)
        if r is None:
            d["rules"][uuid] = {"n": n, "last": now if n else None, "approx": bool(n)}
        else:
            if n > r["n"] or 0 < n < r["n"]:
                r["last"], r["approx"] = now, False
            r["n"] = n
    save_json(USAGE_FILE, d)


def rule_usage():
    d = load_json(USAGE_FILE, {"since": None, "rules": {}})
    return {"since": d["since"], "rules": {u: {"last": r["last"], "approx": r.get("approx", False)} for u, r in d["rules"].items()}}


# ---------------------------------------------------------------- etape 5 : objets temps (plannings)
# OPNsense n'expose pas ses plannings par l'API : OPNderbox garde les plannings et active / desactive les regles concernees.
SCHED_FILE = "plannings.json"
HM_RX = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


def load_sched():
    return load_json(SCHED_FILE, {"objects": [], "rules": []})


def save_sched(doc):
    save_json(SCHED_FILE, doc)


def check_sched(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("objects"), list) or not isinstance(doc.get("rules"), list) \
            or len(doc["objects"]) > 50 or len(doc["rules"]) > 500:
        raise ApiError("plannings invalides")
    objs, names = [], set()
    for o in doc["objects"]:
        name, days = str(o.get("name", "")), o.get("days")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", name) or name in names or not isinstance(days, list) \
                or not days or any(d not in range(1, 8) for d in days) \
                or not HM_RX.fullmatch(str(o.get("start", ""))) or not HM_RX.fullmatch(str(o.get("end", ""))):
            raise ApiError(f"planning invalide : {name}")
        names.add(name)
        objs.append({"name": name, "days": sorted(set(days)), "start": o["start"], "end": o["end"], "description": str(o.get("description", ""))[:120]})
    rules = []
    for pair in doc["rules"]:
        if not (isinstance(pair, list) and len(pair) == 2 and re.fullmatch(r"[0-9a-f-]{32,36}", str(pair[0])) and pair[1] in names):
            raise ApiError("association regle / planning invalide")
        rules.append([pair[0], pair[1]])
    return {"objects": objs, "rules": rules}


def hm(s):
    return int(s[:2]) * 60 + int(s[3:])


def in_window(o, now=None):
    """planning actif ? Une plage qui passe minuit (22:00 -> 06:00) commence le jour coche ; debut = fin : toute la journee."""
    t = time.localtime(now)
    mins, day = t.tm_hour * 60 + t.tm_min, t.tm_wday + 1
    s, e, days = hm(o["start"]), hm(o["end"]), set(o["days"])
    if s < e:
        return day in days and s <= mins < e
    if s == e:
        return day in days
    return (day in days and mins >= s) or ((7 if day == 1 else day - 1) in days and mins < e)


def sched_tick():
    doc = load_sched()
    if not doc["rules"] or not TXN.lock.acquire(blocking=False):
        return
    try:
        if TXN.pending:                 # jamais pendant une confirmation : le retour arriere doit retrouver son etat
            return
        objs = {o["name"]: o for o in doc["objects"]}
        rules = {r["@uuid"]: r for r in parse_csv(download_rules()) if r.get("@uuid")}
        changed = []
        for uuid, name in doc["rules"]:
            if uuid not in rules or name not in objs:
                continue
            want = "1" if in_window(objs[name]) else "0"
            if rules[uuid].get("enabled") != want:
                opn("POST", f"firewall/filter/toggle_rule/{uuid}/{want}", {})
                changed.append({"regle": rules[uuid].get("description", ""), "planning": name, "active": want == "1"})
        if changed:
            opn("POST", "firewall/filter/apply", {})
            journal({"evt": "planning", "regles": changed})
    finally:
        TXN.lock.release()


def background():
    """taches de fond : quarantaine et plannings toutes les 30 s, utilisation des regles toutes les minutes."""
    n = 0
    while True:
        if not configured():            # assistant de premiere configuration pas encore termine
            time.sleep(15)
            continue
        for fn, every in ((quarantine_tick, 2), (sched_tick, 2), (usage_tick, 4)):
            if n % every == 0:
                try:
                    fn()
                except Exception as e:  # noqa: BLE001 - une tache en echec ne doit pas arreter les autres
                    sys.stderr.write(f"tache {fn.__name__} : {e}\n")
        n += 1
        time.sleep(15)


def start_background():
    threading.Thread(target=background, daemon=True).start()


# ---------------------------------------------------------------- premiere configuration et droits du compte API
# droits OPNsense utilises : (privilege, nom affiche dans OPNsense, fonction d'OPNderbox, indispensable, appel de test sans effet)
NIL_UUID = "00000000-0000-4000-8000-000000000000"
RIGHTS = (
    ("page-filter-api", "Firewall: Rules [new]", "règles de filtrage", True, ("GET", "firewall/filter/get_interface_list", None)),
    ("page-firewall-rules", "Firewall: Rules", "compteurs des règles", True, ("GET", "firewall/filter_util/rule_stats", None)),
    ("page-firewall-aliases", "Firewall: Aliases", "objets (lecture)", True, ("GET", "firewall/alias/export", None)),
    ("page-firewall-alias-edit", "Firewall: Alias: Edit", "objets (modification)", True, ("POST", f"firewall/alias/del_item/{NIL_UUID}", {})),
    ("page-system-login-logout", "Lobby: Dashboard", "tableau de bord", True, ("GET", "diagnostics/system/system_resources", None)),
    ("page-diagnostics-logs-firewall-dynamic", "Diagnostics: Logs: Firewall: Live View", "journal de filtrage", True, ("GET", "diagnostics/firewall/log?limit=1", None)),
    ("page-firewall-nat-portforward-edit", "Firewall: NAT: Destination NAT", "redirections de ports", False, ("GET", "firewall/d_nat/download_rules", None)),
    ("page-status-trafficgraph", "Reporting: Traffic", "débits des interfaces", False, ("GET", "diagnostics/traffic/interface", None)),
    ("page-diagnostics-health", "Diagnostics: System Health", "historiques", False, ("GET", "diagnostics/systemhealth/get_interfaces", None)),
    ("page-diagnostics-tables", "Diagnostics: PF Table IP addresses", "quarantaine", False, ("GET", "firewall/alias_util/aliases", None)),
    ("page-diagnostics-showstates", "Diagnostics: Show States", "connexions", False, ("POST", "diagnostics/firewall/query_states", {"rowCount": 1, "current": 1})),
    ("page-diagnostics-arptable", "Diagnostics: ARP Table", "machines", False, ("GET", "diagnostics/interface/get_arp", None)),
    ("page-diagnostics-routingtables", "Diagnostics: Routing tables", "routage", False, ("GET", "diagnostics/interface/get_routes", None)),
    ("page-system-gateways", "System: Gateways", "passerelles", False, ("GET", "routes/gateway/status", None)),
    ("page-system-staticroutes", "System: Static Routes", "routes statiques", False, ("GET", "routes/routes/searchroute?rowCount=1", None)),
    ("page-diagnostics-logs-system", "Diagnostics: Logs: System", "évènements système", False, ("POST", "diagnostics/log/core/system", {"rowCount": 1, "current": 1})),
    ("page-diagnostics-logs-gateways", "Diagnostics: Logs: Gateways", "journal de routage", False, ("POST", "diagnostics/log/core/gateways", {"rowCount": 1, "current": 1})),
    ("page-status-interfaces", "Status: Interfaces", "état des interfaces", False, ("GET", "interfaces/overview/interfaces_info", None)),
    ("page-status-services", "Status: Services", "services", False, ("GET", "core/service/search", None)),
    ("page-interfaces-vlan-edit", "Interfaces: VLAN", "VLAN", False, ("GET", "interfaces/vlan_settings/search_item", None)),
    ("page-interfaces-assignnetworkports", "Interfaces: Assign network ports", "interfaces", False, ("GET", "interfaces/assignment/search_item", None)),
    ("page-services-dnsforwarder", "Services: Dnsmasq DNS/DHCP: Settings", "DHCP et DNS (dnsmasq)", False, ("GET", "dnsmasq/settings/get", None)),
    ("page-diagnostics-configurationhistory", "Diagnostics: Configuration History", "sauvegardes", False, ("GET", "core/backup/backups/this", None)),
    ("page-system-firmware-manualupdate", "System: Firmware", "mises à jour", False, ("GET", "core/firmware/running", None)),
    ("page-services-ids", "Services: Intrusion Detection", "alertes IDS (Suricata)", False, ("GET", "ids/service/status", None)),
    ("page-user-crowdsec", "CrowdSec", "menaces (plugin CrowdSec)", False, ("GET", "crowdsec/decisions/search?rowCount=1", None)),
)


def check_rights(base_url, fingerprint, auth):
    """teste chaque droit par un appel sans effet. 403 : droit absent ; 404 : fonction absente d'OPNsense (plugin)."""
    def one(item):
        priv, name, feature, required, (method, path, body) = item
        out = {"priv": priv, "name": name, "feature": feature, "required": required}
        try:
            status, _ = api_request(base_url, fingerprint, auth, method, path, body)
        except Exception as e:  # noqa: BLE001 - un appel en echec ne doit pas empecher de tester les autres droits
            return out | {"state": "erreur", "detail": str(e)}
        return out | {"state": "ok" if status < 400 else "refuse" if status in (401, 403) else "absent" if status == 404 else "erreur",
                      "code": status}
    with ThreadPoolExecutor(8) as pool:
        return list(pool.map(one, RIGHTS))


def rights_status():
    """droits du compte API en service (vue Système > Connexion à OPNsense)."""
    rights = check_rights(CFG["opnsense"], CFG.get("opnsense_fingerprint"), CFG.get("_auth"))
    return {"opnsense": CFG["opnsense"], "fingerprint": CFG.get("opnsense_fingerprint"), "rights": rights}


SCRIPT_NAME = "opnderbox-compte-api.php"


def account_script():
    """script a lancer sur OPNsense pour creer le compte API (livre avec OPNderbox, servi par l'assistant)."""
    for d in (STATIC_DIR.parent / "opnsense", STATIC_DIR.parent.parent / "opnsense"):
        if (d / SCRIPT_NAME).is_file():
            return (d / SCRIPT_NAME).read_bytes()
    return None


def setup_token():
    """jeton de l'assistant : seul qui lit les journaux du service (ou ce fichier) peut relier OPNderbox a un pare-feu."""
    path = STATE_DIR / "setup-token"
    try:
        token = path.read_text().strip()
    except OSError:
        token = ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", token):
        token = secrets.token_urlsafe(18)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        write_private(path, token + "\n")
    return token


def write_private(path, text):
    """ecriture atomique d'un fichier lisible par le seul compte du service (configuration, cle API)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    tmp.replace(path)


def clean_url(value):
    url = str(value or "").strip().rstrip("/")
    if not re.match(r"^[a-z]+://", url):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname or p.path not in ("", "/") or p.query or p.username:
        raise ApiError("adresse attendue sous la forme https://adresse-du-pare-feu (port facultatif)")
    return f"https://{p.netloc}"


def cert_info(der):
    """sujet, emetteur et fin de validite du certificat d'OPNsense, pour que l'administrateur le reconnaisse."""
    import tempfile
    name = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
            name = fh.name
        d = ssl._ssl._test_decode_cert(name)        # decodeur interne de CPython : evite une dependance
    except Exception:  # noqa: BLE001 - informatif seulement
        return {}
    finally:
        if name:
            os.unlink(name)
    flat = lambda seq: ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)  # noqa: E731
    return {"subject": flat(d.get("subject", ())), "issuer": flat(d.get("issuer", ())), "not_after": d.get("notAfter", "")}


def setup_cert(body):
    url = clean_url(body.get("url"))
    conn = tls_connect(url, timeout=10)
    try:
        der = conn.sock.getpeercert(binary_form=True)
    finally:
        conn.close()
    return {"url": url, "fingerprint": hashlib.sha256(der).hexdigest()} | cert_info(der)


def setup_check(body):
    url, fp = clean_url(body.get("url")), str(body.get("fingerprint", "")).replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fp):
        raise ApiError("empreinte du certificat manquante : recommencez a l'etape precedente")
    key, secret = str(body.get("key", "")).strip(), str(body.get("secret", "")).strip()
    auth = basic_auth(key, secret)
    if not auth or not re.fullmatch(r"[A-Za-z0-9+/=]{20,200}", key) or not re.fullmatch(r"[A-Za-z0-9+/=]{20,200}", secret):
        raise ApiError("cle et secret attendus (contenu du fichier apikey.txt telecharge depuis OPNsense)")
    status, data = api_request(url, fp, auth, "GET", "diagnostics/system/system_information")
    if status == 401:
        raise ApiError("OPNsense refuse cette cle : verifiez la cle et le secret")
    try:
        info = json.loads(data) if status == 200 else {}
    except json.JSONDecodeError:
        info = {}
    rights = check_rights(url, fp, auth)
    return {"url": url, "fingerprint": fp, "key": key, "secret": secret, "rights": rights,
            "system": {"name": info.get("name", ""), "versions": info.get("versions", [])},
            "ok": all(r["state"] == "ok" for r in rights if r["required"])}


def setup_save(body, client_ip):
    global CFG
    res = setup_check(body)
    if not res["ok"]:
        raise ApiError("droits indispensables manquants : " + ", ".join(r["name"] for r in res["rights"] if r["required"] and r["state"] != "ok"))
    password = str(body.get("password", ""))
    if len(password) < 10:
        raise ApiError("mot de passe de l'interface : 10 caracteres au moins")
    cfg = {k: v for k, v in CFG.items() if not k.startswith("_") and k != "auth_disabled"}
    cfg.update({"opnsense": res["url"], "opnsense_fingerprint": res["fingerprint"], "password_hash": hash_password(password)})
    write_private(Path(cfg["key_file"]), f"key={res['key']}\nsecret={res['secret']}\n")
    write_private(CONFIG_PATH, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    CFG = load_config()
    (STATE_DIR / "setup-token").unlink(missing_ok=True)
    journal({"evt": "configuration-initiale", "ip": client_ip, "opnsense": res["url"]})
    return {"ok": True}


def ensure_tls(cfg):
    """certificat de l'interface : genere (auto-signe, 10 ans) au premier demarrage s'il n'existe pas."""
    cert, key = Path(cfg["tls_cert"]), Path(cfg["tls_key"])
    if cert.is_file() and key.is_file():
        return
    import subprocess
    host = socket.gethostname()
    san = f"DNS:{host},DNS:localhost,IP:127.0.0.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:     # aucune emission : sert a connaitre notre adresse
            s.connect(("192.0.2.1", 9))
            san += ",IP:" + s.getsockname()[0]
    except OSError:
        pass
    cert.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3650",
                        "-subj", f"/CN={host}/O={APP_NAME}", "-addext", f"subjectAltName={san}", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True, timeout=60)
        os.chmod(key, 0o600)
    except (OSError, subprocess.SubprocessError) as e:
        sys.exit(f"certificat introuvable ({cert}) et generation impossible : {e}. Installez openssl ou fournissez tls_cert / tls_key.")


# ---------------------------------------------------------------- sessions
SESSIONS = {}
FAILS = {}
SLOCK = threading.Lock()


def new_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with SLOCK:
        SESSIONS[token] = {"created": now, "seen": now}
    return token


def valid_session(token):
    if CFG.get("auth_disabled"):           # mode developpement : pas de mot de passe (acces limite aux ADMINS par le pare-feu)
        return True
    now = time.time()
    with SLOCK:
        s = SESSIONS.get(token or "")
        if not s or now - s["seen"] > SESSION_IDLE or now - s["created"] > SESSION_MAX:
            SESSIONS.pop(token or "", None)
            return False
        s["seen"] = now
        return True


# ---------------------------------------------------------------- serveur HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = APP_NAME
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/json")) else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "opnderbox_session":
                return value
        return None

    def _who(self):
        """identite du poste pour le droit de modification : la session, ou l'adresse sans mot de passe."""
        return self._token() or "ip:" + self.client_address[0]

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2_000_000:
            raise ApiError("requete trop volumineuse")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        url = urlparse(self.path)
        path, qs = url.path, parse_qs(url.query)
        if path in ("/", "/index.html"):
            return self._send(200, (STATIC_DIR / "index.html").read_bytes(), "text/html")
        if re.fullmatch(r"/fonts/[a-z0-9-]{1,60}\.woff2", path) and (STATIC_DIR / path[1:]).is_file():
            return self._send(200, (STATIC_DIR / path[1:]).read_bytes(), "font/woff2")
        if path == "/setup/" + SCRIPT_NAME and account_script():
            return self._send(200, account_script(), "text/plain")
        if path == "/api/session":
            if not configured():
                script = account_script()
                return self._send(200, {"authenticated": False, "setup": True, "app": APP_NAME, "version": APP_VERSION,
                                        "script": {"name": SCRIPT_NAME, "sha256": hashlib.sha256(script).hexdigest()} if script else None})
            return self._send(200, {"authenticated": valid_session(self._token()), "app": APP_NAME, "version": APP_VERSION})
        if not configured():
            return self._send(503, {"error": "configuration initiale requise", "setup": True})
        if not valid_session(self._token()):
            return self._send(401, {"error": "session expiree"})
        try:
            if path == "/api/state":
                return self._send(200, gather_state() | {"write": WLOCK.status(self._who())})
            if path == "/api/status":
                return self._send(200, {"pending": TXN.status(), "write": WLOCK.status(self._who())})
            if path == "/api/dashboard":
                return self._send(200, dashboard("fast" if qs.get("part") == ["fast"] else "slow"))
            if path == "/api/log":
                digest = qs.get("digest", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{0,32}", digest):
                    return self._send(400, {"error": "requete invalide"})
                limit = qint(qs, "limit", 500, 1, 5000)
                res = {"rows": trim_log(safe("GET", f"diagnostics/firewall/log?limit={limit}&digest={digest}"))}
                if qs.get("names") == ["1"]:
                    res["names"] = safe("GET", "diagnostics/interface/get_interface_names")
                return self._send(200, res)
            if path == "/api/ids":
                return self._send(200, ids_alerts(qint(qs, "limit", 300, 1, 2000), qs.get("q", [""])[0][:100]))
            if path == "/api/history":
                return self._send(200, {"rows": history()})
            if path == "/api/network":
                return self._send(200, network())
            if path == "/api/dhcp":
                return self._send(200, dhcp())
            if path == "/api/crowdsec":
                return self._send(200, crowdsec())
            if path == "/api/machines":
                return self._send(200, machines())
            if path == "/api/states":
                return self._send(200, states(qint(qs, "limit", 500, 1, 5000), qs.get("q", [""])[0][:100]))
            if path == "/api/routing":
                return self._send(200, routing())
            if path == "/api/routes":
                return self._send(200, routes_config())
            if path == "/api/sysinfo":
                return self._send(200, sysinfo())
            if path == "/api/syslog":
                return self._send(200, syslog(qs.get("src", [""])[0], qint(qs, "limit", 500, 1, 5000), qs.get("q", [""])[0][:100]))
            if path == "/api/backups":
                return self._send(200, backups())
            if path == "/api/backup/diff":
                return self._send(200, backup_diff(qs.get("a", [""])[0], qs.get("b", [""])[0]))
            if path == "/api/backup/download":
                WLOCK.require(self._who())      # config.xml contient des secrets : reserve au poste en modification
                name = qs.get("id", [""])[0]
                return self._send(200, backup_download(name, self.client_address[0]).encode(), "application/xml",
                                  extra={"Content-Disposition": f'attachment; filename="opnsense-{name}"'})
            if path == "/api/firmware":
                return self._send(200, firmware())
            if path == "/api/firmware/log":
                return self._send(200, safe("GET", "core/firmware/upgradestatus"))
            if path == "/api/policies":
                return self._send(200, policies(qs["id"][0]) if "id" in qs else {"policies": policies()})
            if path == "/api/rrd":
                return self._send(200, rrd(qs.get("names", [""])[0].split(","), qs.get("range", ["day"])[0]))
            if path == "/api/quarantine":
                return self._send(200, quarantine())
            if path == "/api/implicit":
                return self._send(200, implicit_rules())
            if path == "/api/rights":
                return self._send(200, rights_status())
        except ApiError as e:
            return self._send(502, {"error": str(e), "detail": e.detail})
        return self._send(404, {"error": "inconnu"})

    def _setup(self, path, ip):
        """assistant de premiere configuration : seulement tant qu'OPNderbox n'est relie a aucun pare-feu, et avec le jeton."""
        if configured():
            return self._send(409, {"error": f"{APP_NAME} est deja relie a un pare-feu"})
        now = time.time()
        f = FAILS.get(ip, {"n": 0, "until": 0})
        if f["until"] > now:
            return self._send(429, {"error": f"trop d'essais, reessayez dans {int(f['until'] - now)} s"})
        body = self._body()
        if not hmac.compare_digest(str(body.get("token", "")).encode(), setup_token().encode()):
            f["n"] += 1
            if f["n"] >= LOGIN_MAX_FAILS:
                f = {"n": 0, "until": now + LOGIN_LOCK}
            FAILS[ip] = f
            time.sleep(1)
            return self._send(403, {"error": "jeton de configuration incorrect"})
        FAILS.pop(ip, None)
        if path == "/api/setup/token":
            return self._send(200, {"ok": True})
        if path == "/api/setup/cert":
            return self._send(200, setup_cert(body))
        if path == "/api/setup/check":
            res = setup_check(body)
            return self._send(200, {k: v for k, v in res.items() if k not in ("key", "secret")})
        if path == "/api/setup/save":
            return self._send(200, setup_save(body, ip))
        return self._send(404, {"error": "inconnu"})

    def do_POST(self):
        path = urlparse(self.path).path
        ip = self.client_address[0]
        if self.headers.get("X-OPNderbox") != "1":        # protection CSRF (en plus de SameSite=Strict)
            return self._send(403, {"error": "en-tete manquant"})
        try:
            if path.startswith("/api/setup/"):
                return self._setup(path, ip)
            if not configured():
                return self._send(503, {"error": "configuration initiale requise", "setup": True})
            if path == "/api/login":
                now = time.time()
                f = FAILS.get(ip, {"n": 0, "until": 0})
                if f["until"] > now:
                    return self._send(429, {"error": f"trop d'essais, reessayez dans {int(f['until'] - now)} s"})
                if check_password(str(self._body().get("password", "")), CFG["password_hash"]):
                    FAILS.pop(ip, None)
                    token = new_session()
                    journal({"evt": "connexion", "ip": ip})
                    return self._send(200, {"ok": True}, extra={
                        "Set-Cookie": f"opnderbox_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/"})
                f["n"] += 1
                if f["n"] >= LOGIN_MAX_FAILS:
                    f = {"n": 0, "until": now + LOGIN_LOCK}
                FAILS[ip] = f
                journal({"evt": "echec-connexion", "ip": ip})
                time.sleep(1)
                return self._send(401, {"error": "mot de passe incorrect"})
            if path == "/api/logout":
                with SLOCK:
                    SESSIONS.pop(self._token() or "", None)
                return self._send(200, {"ok": True}, extra={
                    "Set-Cookie": "opnderbox_session=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/"})
            if not valid_session(self._token()):
                return self._send(401, {"error": "session expiree"})
            if path == "/api/write":
                if self._body().get("on"):
                    WLOCK.take(self._who(), ip)
                else:
                    WLOCK.release(self._who(), ip)
                return self._send(200, WLOCK.status(self._who()))
            if path in ("/api/apply", "/api/service", "/api/unban", "/api/separators", "/api/kill", "/api/firmware", "/api/policies",
                        "/api/quarantine", "/api/colors"):
                WLOCK.require(self._who())
            if path == "/api/quarantine":
                return self._send(200, quarantine_action(self._body(), ip))
            if path == "/api/colors":
                return self._send(200, {"colors": save_colors(self._body().get("colors"))})
            if path == "/api/separators":
                return self._send(200, {"separators": save_separators(self._body().get("separators"))})
            if path == "/api/kill":
                return self._send(200, kill_state(self._body().get("id"), ip))
            if path == "/api/firmware":
                return self._send(200, firmware_action(self._body().get("action"), ip))
            if path == "/api/policies":
                return self._send(200, policy_action(self._body(), ip))
            if path == "/api/apply":
                ops = self._body().get("ops", [])
                if not isinstance(ops, list) or not ops:
                    return self._send(400, {"error": "aucune modification"})
                return self._send(200, TXN.apply(ops, ip))
            if path == "/api/confirm":
                TXN.confirm(ip)
                return self._send(200, {"ok": True})
            if path == "/api/rollback":
                TXN.rollback(ip)
                return self._send(200, {"ok": True})
            if path == "/api/service":
                body = self._body()
                return self._send(200, service_action(str(body.get("name", "")), str(body.get("action", "")), ip))
            if path == "/api/unban":
                return self._send(200, unban(self._body().get("id"), ip))
        except ApiError as e:
            return self._send(409, {"error": str(e), "detail": e.detail})
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "requete invalide"})
        return self._send(404, {"error": "inconnu"})


def local_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:     # aucune emission : sert a connaitre notre adresse
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "adresse-du-serveur"


def setup_url(port):
    # dans un conteneur, l'adresse locale est celle du reseau Docker, pas celle que joint le navigateur
    host = "adresse-de-la-machine-docker" if Path("/.dockerenv").exists() else local_address()
    return f"https://{host}{'' if port == 443 else ':' + str(port)}/#setup={setup_token()}"


def main():
    global CFG
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd in ("password", "hash"):
        import getpass
        pw = getpass.getpass("Nouveau mot de passe de l'interface : ")
        if pw != getpass.getpass("Confirmation : ") or len(pw) < 10:
            sys.exit("mots de passe differents ou trop court (10 caracteres minimum)")
        if cmd == "hash":
            print(hash_password(pw))
            return
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
        except FileNotFoundError:
            sys.exit(f"{CONFIG_PATH} absent : terminez d'abord l'assistant de premiere configuration")
        cfg["password_hash"] = hash_password(pw)
        cfg.pop("auth_disabled", None)
        write_private(CONFIG_PATH, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
        print("Mot de passe change. Redemarrez le service pour fermer les sessions ouvertes.")
        return
    CFG = load_config()
    port = int(CFG.get("port", DEFAULT_PORT))
    if cmd == "setup":
        print(f"{APP_NAME} est deja relie a {CFG['opnsense']}." if configured() else f"Assistant de premiere configuration : {setup_url(port)}")
        return
    if cmd:
        sys.exit(__doc__)
    ensure_tls(CFG)
    httpd = ThreadingHTTPServer((CFG.get("listen", "0.0.0.0"), port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CFG["tls_cert"], CFG["tls_key"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    start_background()
    print(f"{APP_NAME} {APP_VERSION} a l'ecoute sur {CFG.get('listen', '0.0.0.0')}:{port}", flush=True)
    if not configured():
        print(f"Premiere configuration : ouvrez {setup_url(port)}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
