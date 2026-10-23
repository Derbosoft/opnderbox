#!/usr/bin/env python3
"""OPNderbox en démonstration : un OPNsense simulé (PME fictive), sans pare-feu ni configuration.

    python3 demo/demo.py            puis ouvrir http://127.0.0.1:8080
    python3 demo/demo.py --port 9000 --ecoute 0.0.0.0

Les modifications restent dans ce processus : rien ne quitte le poste. Toutes les adresses publiques
sont des adresses de documentation (RFC 5737), les noms et les machines sont inventés.
"""
import argparse
import csv
import hashlib
import io
import json
import math
import random
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "opnderbox"))
import os  # noqa: E402

STATE = Path(tempfile.mkdtemp(prefix="opnderbox-demo-"))
os.environ["OPNDERBOX_STATE"] = str(STATE)
os.environ["OPNDERBOX_CONFIG"] = str(STATE / "config.json")
import server  # noqa: E402

R = random.Random(42)
NOW = time.time()
uid = lambda name: str(uuid.uuid5(uuid.NAMESPACE_URL, "opnderbox-demo/" + name))  # noqa: E731

# ---------------------------------------------------------------- réseau de la PME fictive
IFACES = {  # clé OPNsense : (nom, périphérique, adresse, VLAN)
    "wan": ("WAN", "igc0", "dhcp", None),
    "opt1": ("LAN", "vlan0.10", "192.168.10.1/24", 10),
    "opt2": ("SERVEURS", "vlan0.20", "192.168.20.1/24", 20),
    "opt3": ("INVITES", "vlan0.30", "192.168.30.1/24", 30),
    "opt4": ("IOT", "vlan0.40", "192.168.40.1/24", 40),
    "opt5": ("DMZ", "vlan0.50", "192.168.50.1/24", 50),
}
INTERNAL = ["opt1", "opt2", "opt3", "opt4", "opt5"]
WAN_IP, WAN_GW = "203.0.113.42", "203.0.113.1"

ALIASES = {}


def alias(name, typ, content, descr):
    ALIASES[uid("alias/" + name)] = {"enabled": "1", "name": name, "type": typ, "content": "\n".join(content), "description": descr}


alias("ADMINS", "host", ["192.168.10.20", "192.168.10.21"], "Postes d'administration")
alias("H_NAS", "host", ["192.168.20.10"], "Serveur de fichiers")
alias("H_GESTION", "host", ["192.168.20.20"], "Logiciel de gestion")
alias("H_MESSAGERIE", "host", ["192.168.20.30"], "Serveur de messagerie")
alias("H_IMPRIMANTE", "host", ["192.168.10.50"], "Imprimante du bureau")
alias("H_SITE_WEB", "host", ["192.168.50.10"], "Site web public")
alias("G_SERVEURS", "host", ["H_NAS", "H_GESTION", "H_MESSAGERIE"], "Serveurs internes")
alias("NET_PRIVES", "network", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "Réseaux privés (RFC 1918)")
alias("D_MISES_A_JOUR", "host", ["deb.debian.org", "security.debian.org", "download.windowsupdate.com"], "Dépôts de mises à jour")
alias("P_WEB", "port", ["80", "443"], "Web")
alias("P_SMB", "port", ["445"], "Partages Windows")
alias("P_DNS", "port", ["53"], "DNS")
alias("P_NTP", "port", ["123"], "Heure")
alias("P_IMPRESSION", "port", ["631", "9100"], "Impression")
alias("P_MESSAGERIE", "port", ["25", "587", "993"], "Courriel")
alias("P_INUTILISE", "port", ["8080"], "Ancien proxy (plus utilisé)")
for name, typ in (("bogons", "internal"), ("bogonsv6", "internal"), ("virusprot", "internal"), ("sshlockout", "internal"), ("crowdsec_blocklists", "external")):
    ALIASES[uid("alias/" + name)] = {"enabled": "1", "name": name, "type": typ, "content": "", "description": ""}

F = list(server.RULE_FIELDS)
RULES, COUNTS = {}, {}


def rule(key, iface, action, src="any", dst="any", port="", proto="any", descr="", log="0", seq=0, icmp="", enabled="1", hits=0):
    u = uid("rule/" + key)
    RULES[u] = {"enabled": enabled, "sequence": str(seq), "action": action, "quick": "1", "interface": iface, "direction": "in",
                "ipprotocol": "inet", "protocol": proto, "icmptype": icmp, "source_net": src, "source_not": "0", "source_port": "",
                "destination_net": dst, "destination_not": "0", "destination_port": port, "log": log, "categories": "", "description": descr}
    COUNTS[u] = hits
    return u


ALL = ",".join(INTERNAL)
rule("ping", ALL, "pass", proto="ICMP", icmp="echoreq", descr="Ping (diagnostic)", seq=100, hits=48210)
rule("dns", ALL, "pass", dst="(self)", port="P_DNS", proto="TCP/UDP", descr="DNS du pare-feu", seq=110, hits=1830442)
rule("ntp", ALL, "pass", dst="(self)", port="P_NTP", proto="UDP", descr="Heure (NTP) du pare-feu", seq=120, hits=20915)
rule("lan-admin", "opt1", "pass", src="ADMINS", dst="(self)", port="P_WEB", proto="TCP", descr="Administration du pare-feu", log="1", seq=1000, hits=9020)
U_NAS = rule("lan-nas", "opt1", "pass", dst="H_NAS", port="P_SMB", proto="TCP", descr="Partages de fichiers", seq=1010, hits=650221)
rule("lan-gestion", "opt1", "pass", dst="H_GESTION", port="P_WEB", proto="TCP", descr="Logiciel de gestion", seq=1020, hits=210440)
rule("lan-mail", "opt1", "pass", dst="H_MESSAGERIE", port="P_MESSAGERIE", proto="TCP", descr="Messagerie", seq=1030, hits=88112)
rule("lan-print", "opt1", "pass", dst="H_IMPRIMANTE", port="P_IMPRESSION", proto="TCP", descr="Impression", seq=1040, hits=0)
U_LAN_FW = rule("lan-fw", "opt1", "block", dst="(self)", descr="Bloquer l'accès au pare-feu", log="1", seq=1050, hits=412)
rule("lan-iso", "opt1", "block", dst="NET_PRIVES", descr="Cloisonnement des réseaux", log="1", seq=1060, hits=3302)
rule("lan-inet", "opt1", "pass", src="opt1", descr="Internet", seq=1070, hits=9502113)
rule("srv-maj", "opt2", "pass", dst="D_MISES_A_JOUR", port="P_WEB", proto="TCP", descr="Mises à jour des serveurs", seq=2000, hits=50110)
rule("srv-mail", "opt2", "pass", src="H_MESSAGERIE", port="P_MESSAGERIE", proto="TCP", descr="Envoi des courriels", seq=2010, hits=4410)
rule("srv-iso", "opt2", "block", dst="NET_PRIVES", descr="Cloisonnement des réseaux", log="1", seq=2020, hits=120)
rule("srv-rien", "opt2", "block", descr="Pas d'autre accès à Internet pour les serveurs", log="1", seq=2030, hits=2210)
rule("inv-iso", "opt3", "block", dst="NET_PRIVES", descr="Isoler le Wi-Fi des invités", log="1", seq=3000, hits=8021)
rule("inv-web", "opt3", "pass", port="P_WEB", proto="TCP", descr="Navigation web", seq=3010, hits=1204511)
rule("inv-rien", "opt3", "block", descr="Tout le reste", log="1", seq=3020, hits=30418)
rule("iot-iso", "opt4", "block", dst="NET_PRIVES", descr="Cloisonnement des objets connectés", log="1", seq=4000, hits=1530)
U_IOT = rule("iot-inet", "opt4", "pass", src="opt4", descr="Internet (heures ouvrées)", seq=4010, hits=40120)
rule("dmz-maj", "opt5", "pass", src="H_SITE_WEB", dst="D_MISES_A_JOUR", port="P_WEB", proto="TCP", descr="Mises à jour du site", seq=5000, hits=310)
rule("dmz-iso", "opt5", "block", dst="NET_PRIVES", descr="La DMZ ne joint pas le réseau interne", log="1", seq=5010, hits=12)
rule("dmz-rien", "opt5", "block", descr="Rien d'autre", log="1", seq=5020, hits=0)
DENY = "02f4bab031b57d1e30553ce08e0ec131"
COUNTS[DENY] = 214503

NAT = {uid("nat/web"): {"sequence": "100", "disabled": "0", "nordr": "0", "interface": "wan", "ipprotocol": "inet", "protocol": "tcp", "source.network": "", "source.port": "", "source.not": "0",
                        "destination.network": "wanip", "destination.port": "443", "destination.not": "0", "target": "H_SITE_WEB", "local-port": "443", "log": "0", "descr": "Site web public", "natreflection": "", "pass": "pass"}}

VLANS = {uid("vlan/%d" % t): {"if": "igc1", "tag": str(t), "pcp": "0", "proto": "", "descr": IFACES[k][0], "vlanif": IFACES[k][1]} for k, (_, _, _, t) in IFACES.items() if t}
ASSIGN = {k: {"descr": d, "if": dev, "enable": "1", "lock": "0", "blockpriv": "1" if k == "wan" else "0", "blockbogons": "1" if k == "wan" else "0", "mtu": "",
              "type4": "dhcp" if ip == "dhcp" else "staticv4", "ipaddr": "" if ip == "dhcp" else ip, "gateway": ""} for k, (d, dev, ip, _) in IFACES.items()}
DEVICES = {"igc0": "igc0 (00:0d:b9:00:00:01)", "igc1": "igc1 (00:0d:b9:00:00:02)", "igc2": "igc2 (00:0d:b9:00:00:03)"} | {v["vlanif"]: f"{v['vlanif']} {v['descr']} (Parent: igc1, Tag: {v['tag']})" for v in VLANS.values()}

VENDORS = ["Dell Inc.", "HP Inc.", "Apple, Inc.", "Samsung Electronics", "Raspberry Pi Trading", "Espressif Inc.", "Lenovo", "Brother Industries", "Synology Incorporated", "Sonos, Inc."]
MACHINES = []   # (nom, ip, mac, fabricant, interface, réservée)
for i, (name, ip, vend, k, res) in enumerate([
        ("poste-compta", "192.168.10.101", 0, "opt1", False), ("poste-direction", "192.168.10.102", 6, "opt1", False), ("portable-commercial", "192.168.10.103", 2, "opt1", False),
        ("poste-accueil", "192.168.10.104", 1, "opt1", False), ("admin-1", "192.168.10.20", 6, "opt1", True), ("admin-2", "192.168.10.21", 0, "opt1", True),
        ("imprimante", "192.168.10.50", 7, "opt1", True), ("nas", "192.168.20.10", 8, "opt2", True), ("gestion", "192.168.20.20", 0, "opt2", True),
        ("messagerie", "192.168.20.30", 1, "opt2", True), ("telephone-invite", "192.168.30.110", 3, "opt3", False), ("tablette-invite", "192.168.30.111", 2, "opt3", False),
        ("enceinte-salle", "192.168.40.120", 9, "opt4", False), ("capteur-clim", "192.168.40.121", 5, "opt4", False), ("camera-entree", "192.168.40.122", 5, "opt4", False),
        ("site-web", "192.168.50.10", 4, "opt5", True)]):
    MACHINES.append((name, ip, "02:00:5e:%02x:%02x:%02x" % (i, i * 7 % 256, i * 13 % 256), VENDORS[vend], k, res))
HOSTS = {uid("host/" + m[0]): {"host": m[0], "domain": "", "local": "0", "ip": m[1], "cnames": "", "client_id": "", "hwaddr": m[2].upper(), "lease_time": "", "ignore": "0",
                               "descr": m[3], "comments": "", "aliases": ""} for m in MACHINES if m[5]}
RANGES = {uid("range/" + k): {"interface": k, "start_addr": IFACES[k][2].split(".1/")[0] + ".100", "end_addr": IFACES[k][2].split(".1/")[0] + ".199", "subnet_mask": "",
                              "lease_time": "", "domain_type": "range", "domain": "", "description": "DHCP " + IFACES[k][0]} for k in ("opt1", "opt3", "opt4")}
OPTIONS = {uid("opt/" + k): {"type": "set", "option": "6", "option6": "", "interface": k, "tag": "", "set_tag": "", "value": IFACES[k][2].split("/")[0], "force": "0",
                             "description": "DNS : le pare-feu"} for k in ("opt1", "opt3", "opt4")}
DNSMASQ = {"regdhcp": "1", "regdhcpstatic": "1", "dhcp": {"domain": "exemple.lan", "authoritative": "1", "lease_max": "", "default_fw_rules": "1", "fqdn": "1"}}
SERVICES = [("configd", "Configd", 1), ("cron", "Cron", 0), ("crowdsec", "CrowdSec", 0), ("dnsmasq", "Dnsmasq DNS/DHCP", 0), ("ntpd", "Network Time Daemon", 0),
            ("openssh", "Secure Shell Daemon", 0), ("pf", "Packet Filter", 1), ("routing", "System routing", 1), ("suricata", "Intrusion Detection", 0),
            ("syslog-ng", "Syslog-ng Daemon", 0), ("webgui", "Web GUI", 1), ("login", "Users and Groups", 1), ("sysctl", "System tunables", 1)]
DECISIONS = [{"id": 70000 + i, "source": "crowdsec", "scope_value": f"Ip:{ip}", "reason": r, "action": "ban", "country": c, "as": "AS-EXEMPLE-" + c, "events_count": 5 + 3 * i,
              "expiration": f"{3 - i % 3}h{12 + i}m4s", "alert_id": 10 + i}
             for i, (ip, r, c) in enumerate([("198.51.100.23", "crowdsecurity/ssh-bf", "NL"), ("198.51.100.77", "firewallservices/pf-scan-multi_ports", "US"),
                                             ("203.0.113.200", "crowdsecurity/http-probing", "DE"), ("192.0.2.150", "firewallservices/pf-scan-multi_ports", "CN"),
                                             ("192.0.2.33", "crowdsecurity/ssh-slow-bf", "RU"), ("198.51.100.140", "crowdsecurity/http-crawl-non_statics", "BR")])]
TABLES = {"QUARANTAINE": set()}
TRAFFIC = {k: {"rx": R.randint(10 ** 9, 10 ** 11), "tx": R.randint(10 ** 8, 10 ** 10)} for k in IFACES}

# ---------------------------------------------------------------- journal de filtrage et alertes simulés
LOG = []


def log_row(ts):
    kind = R.random()
    if kind < .45:     # balayages venant d'Internet, bloqués par la politique par défaut
        src, dst, dev, rid, act, port = "%s.%d" % (R.choice(["198.51.100", "203.0.113", "192.0.2"]), R.randint(2, 250)), WAN_IP, "igc0", DENY, "block", R.choice([22, 23, 445, 3389, 1433, 5900, 8080, 6379])
    elif kind < .8:    # postes vers Internet
        m = R.choice([m for m in MACHINES if m[4] in ("opt1", "opt3")])
        src, dst, dev, act, port = m[1], "%s.%d" % (R.choice(["198.51.100", "203.0.113"]), R.randint(2, 250)), IFACES[m[4]][1], "pass", R.choice([443, 443, 443, 80, 53])
        rid = uid("rule/lan-inet") if m[4] == "opt1" else uid("rule/inv-web")
    else:              # cloisonnement entre réseaux
        m = R.choice([m for m in MACHINES if m[4] in ("opt3", "opt4")])
        src, dst, dev, act, port = m[1], R.choice(["192.168.20.10", "192.168.10.50", "192.168.10.1"]), IFACES[m[4]][1], "block", R.choice([445, 80, 9100, 22])
        rid = uid("rule/inv-iso") if m[4] == "opt3" else uid("rule/iot-iso")
    return {"__timestamp__": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)), "__digest__": hashlib.md5(f"{ts}{R.random()}".encode()).hexdigest(),
            "action": act, "interface": dev, "dir": "in", "src": src, "dst": dst, "srcport": str(R.randint(1024, 65000)), "dstport": str(port),
            "protoname": "tcp", "rid": rid, "label": "Default deny / state violation rule" if rid == DENY else "", "tcpflags": "S", "length": "60", "ipversion": "4", "ttl": str(R.randint(40, 64))}


for i in range(900):
    LOG.append(log_row(NOW - i * 4.1))
SIGS = ["ET SCAN Suspicious inbound to MSSQL port 1433", "ET DROP Spamhaus DROP Listed Traffic Inbound group 7", "ET CINS Active Threat Intelligence Poor Reputation IP group 41",
        "ET SCAN Potential SSH Scan", "ET DROP Dshield Block Listed Source group 1", "ET SCAN Sipvicious User-Agent Detected (friendly-scanner)"]
IDS = [{"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0200", time.localtime(NOW - i * 97)), "alert": R.choice(SIGS[:3] * 4 + SIGS[3:]), "alert_sid": 2400000 + i % 50,
        "alert_action": "blocked", "src_ip": "%s.%d" % (R.choice(["198.51.100", "203.0.113", "192.0.2"]), R.randint(2, 250)), "src_port": R.randint(1024, 65000),
        "dest_ip": WAN_IP, "dest_port": R.choice([22, 1433, 445, 5060]), "proto": "TCP", "in_iface": "igc0", "direction": "to_server"} for i in range(180)]


# ---------------------------------------------------------------- l'API simulée
def syslog_rows():
    ts = lambda m: time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(NOW - m * 60)) + "+02:00"  # noqa: E731
    sysl = [(3, "Notice", "configd.py", "[a1b2] Reloading filter"), (4, "Notice", "opnsense", "/api/firewall/filter/apply: OPNsense\\Firewall\\Filter: apply"),
            (9, "Informational", "dhclient", "DHCPACK from 203.0.113.1"), (9, "Informational", "dhclient", "bound to 203.0.113.42 -- renewal in 43200 seconds."),
            (21, "Warning", "kernel", "igc1: link state changed to DOWN"), (21, "Notice", "kernel", "igc1: link state changed to UP"),
            (35, "Error", "sshd", "error: maximum authentication attempts exceeded for root from 198.51.100.77 port 52211 ssh2"),
            (48, "Notice", "audit", "user admin authenticated successfully for WebGui [using OPNsense\\Auth\\Services\\WebGui + OPNsense\\Auth\\Local]"),
            (60, "Notice", "pkg-static", "opnsense-update: checking for updates")]
    gw = [(5, "Notice", "dpinger", "WAN_DHCP 203.0.113.1: sendto error: 65"), (5, "Warning", "dpinger", "ALERT: WAN_DHCP (Addr: 203.0.113.1 Alarm: down -> loss RTT: 0.0 ms RTTd: 0.0 ms Loss: 100.0 %)"),
          (4, "Notice", "dpinger", "ALERT: WAN_DHCP (Addr: 203.0.113.1 Alarm: loss -> none RTT: 4.1 ms RTTd: 0.3 ms Loss: 0.0 %)"),
          (4, "Notice", "rc.routing_configure", "ROUTING: entering configure using wan"), (4, "Notice", "rc.routing_configure", "ROUTING: setting IPv4 default route to 203.0.113.1")]
    mk = lambda lst: [{"timestamp": ts(m), "severity": sv, "process_name": p, "pid": str(1000 + i * 37), "line": l, "rnum": i} for i, (m, sv, p, l) in enumerate(sorted(lst, key=lambda x: x[0]))]  # noqa: E731
    return {"system": mk(sysl), "gateways": mk(gw)}


SYSLOG = syslog_rows()


def rules_csv(rows, cols):
    out = io.StringIO()
    w = csv.writer(out, delimiter=";", escapechar="\\", lineterminator="\n")
    w.writerow(["@uuid"] + cols)
    for u, r in rows.items():
        w.writerow([u] + [r.get(k, "") for k in cols])
    return out.getvalue()


def flat(d, pre=""):
    o = {}
    for k, v in d.items():
        o.update(flat(v, k + ".") if isinstance(v, dict) else {pre + k: v})
    return o


def grid(store, wrap, path, body):
    act = path.rsplit("/", 1)[-1] if path.count("/") == 2 else path.split("/")[2]
    if act.startswith("search"):
        return {"rows": [{"uuid": k, **v} for k, v in store.items()], "total": len(store)}
    if act.startswith("add"):
        k = str(uuid.uuid4()) if wrap != "interface" else "opt%d" % (max(int(x[3:]) for x in store if x.startswith("opt")) + 1)
        store[k] = dict(body[wrap])
        return {"result": "saved", "uuid": k}
    key = path.rsplit("/", 1)[1]
    if act.startswith("set"):
        store[key] = {**store.get(key, {}), **body[wrap]}
        return {"result": "saved"}
    if act.startswith("del"):
        return {"result": "deleted" if store.pop(key, None) is not None else "not found"}
    return None


def health(name, detail):
    keys = {"processor": ["user", "nice", "system", "interrupt"], "memory": ["active", "inactive", "free", "wire"], "states": ["pfstates"], "cputemp": ["cpu0temp"]}
    traf = ["inpass", "outpass", "inblock", "outblock", "inpass6", "outpass6", "inblock6", "outblock6"]
    ks = traf if name.endswith(("-traffic", "-packets")) else keys.get(name.split("-")[0], [])
    step, n = {0: (60, 1200), 1: (300, 720), 2: (3600, 1860), 3: (86400, 247)}[detail]
    end = int(time.time()) // step * step

    def val(k, t):
        w = 1 + .6 * math.sin((t % 86400) / 86400 * 2 * math.pi - 1.2)
        z = (hash((name, k, t // 60)) % 1000) / 1000
        if k in traf:
            s = {"inpass": 3e6, "outpass": 6e5, "inblock": 3e3, "outblock": 40}.get(k, 0) * (3 if name.startswith("wan") else 1) * (1e-3 if name.endswith("-packets") else 1)
            return s * w * (.6 + .8 * z)
        return {"user": 4 * w + 2 * z, "system": 1 + z, "interrupt": .3 * z, "nice": 0, "active": 3 + z, "wire": 12, "inactive": 15, "free": 70,
                "pfstates": 700 * w + 150 * z, "cpu0temp": 38 + 5 * w + z}.get(k, 0)
    return {"set": {"step_size": step, "data": [{"key": k, "values": [[(end - (n - 1 - i) * step) * 1000, val(k, end - (n - 1 - i) * step)] for i in range(n)]} for k in ks]}}


def iface_info():
    rows = []
    for dev, up in (("igc0", True), ("igc1", True), ("igc2", False)):
        k = next((k for k, v in ASSIGN.items() if v["if"] == dev), None)
        rows.append({"device": dev, "is_physical": True, "status": "up" if up else "no carrier", "identifier": k or "", "description": ASSIGN[k]["descr"] if k else "",
                     "media": "1000baseT <full-duplex>" if up else "", "macaddr": DEVICES[dev].split("(")[1][:-1], "config": {"enable": "1"} if k else {},
                     "addr4": WAN_IP + "/24" if k == "wan" else "", "gateways": [WAN_GW] if k == "wan" else [], "link_type": "dhcp" if k == "wan" else "static"})
    for v in VLANS.values():
        k = next((k for k, a in ASSIGN.items() if a["if"] == v["vlanif"]), "")
        rows.append({"device": v["vlanif"], "is_physical": False, "status": "up", "identifier": k, "description": v["descr"], "vlan": {"parent": "igc1", "tag": v["tag"]},
                     "vlan_tag": v["tag"], "addr4": ASSIGN[k]["ipaddr"] if k else "", "media": "", "gateways": []})
    return {"rows": rows, "total": len(rows)}


def api(method, path, body=None, raw=False):
    body = body or {}
    base = path.split("?")[0]
    if base == "firewall/filter/download_rules":
        return rules_csv(RULES, F)
    if base == "firewall/d_nat/download_rules":
        return rules_csv(NAT, list(server.NAT_FIELDS))
    if base == "firewall/alias/export":
        return {"aliases": {"alias": {u: dict(a) for u, a in ALIASES.items()}}}
    if base == "firewall/filter/get_interface_list":
        return {"interfaces": {"items": [{"value": k, "label": v["descr"], "type": "interface"} for k, v in ASSIGN.items()]}}
    if base == "firewall/filter_util/rule_stats":
        return {"stats": {u: {"packets": n} for u, n in COUNTS.items()}}
    if base == "firewall/alias/get_table_size":
        return {"crowdsec_blocklists": 18342, "bogons": 1250, "QUARANTAINE": len(TABLES["QUARANTAINE"])}
    if base == "firewall/category/search_item":
        return {"rows": [{"uuid": uid("cat/" + n), "name": n} for n in ("Bureautique", "Serveurs", "Invités")]}
    if base in ("firewall/filter/apply", "firewall/alias/reconfigure", "dnsmasq/service/reconfigure", "interfaces/vlan_settings/reconfigure", "interfaces/assignment/reconfigure"):
        return {"status": "ok"}
    if base == "firewall/filter/add_rule":
        u = str(uuid.uuid4())
        RULES[u] = {**{k: "" for k in F}, **body["rule"]}
        COUNTS[u] = 0
        return {"result": "saved", "uuid": u}
    if base.startswith("firewall/filter/set_rule/"):
        RULES[base.rsplit("/", 1)[1]].update(body["rule"])
        return {"result": "saved"}
    if base.startswith("firewall/filter/del_rule/"):
        RULES.pop(base.rsplit("/", 1)[1], None)
        return {"result": "deleted"}
    if base.startswith("firewall/filter/toggle_rule/"):
        u, v = base.split("/")[-2:]
        RULES[u]["enabled"] = v
        return {"result": "ok", "changed": True}
    if base == "firewall/filter/upload_rules":
        for row in server.parse_csv(body["payload"]):
            u = row.pop("@uuid")
            RULES[u] = {**RULES.get(u, {}), **row}
        return {"status": "ok"}
    if base == "firewall/alias/add_item":
        if any(a["name"] == body["alias"]["name"] for a in ALIASES.values()):
            return {"result": "failed", "validations": {"alias.name": "un objet porte déjà ce nom"}}
        u = str(uuid.uuid4())
        ALIASES[u] = dict(body["alias"])
        return {"result": "saved", "uuid": u}
    if base.startswith("firewall/alias/set_item/"):
        ALIASES[base.rsplit("/", 1)[1]].update(body["alias"])
        return {"result": "saved"}
    if base.startswith("firewall/alias/del_item/"):
        return {"result": "deleted" if ALIASES.pop(base.rsplit("/", 1)[1], None) else "not found"}
    if base == "firewall/alias/import":
        for a in body["data"]["aliases"]["alias"].values():
            k = next((u for u, x in ALIASES.items() if x["name"] == a["name"]), str(uuid.uuid4()))
            ALIASES[k] = {**ALIASES.get(k, {}), **a}
        return {"status": "ok"}
    if base.startswith("firewall/d_nat/"):
        act = base.split("/")[2]
        if act == "add_rule":
            u = str(uuid.uuid4())
            NAT[u] = flat(body["rule"])
            return {"result": "saved", "uuid": u}
        if act == "set_rule":
            NAT[base.rsplit("/", 1)[1]].update(flat(body["rule"]))
            return {"result": "saved"}
        if act == "del_rule":
            NAT.pop(base.rsplit("/", 1)[1], None)
            return {"result": "deleted"}
        if act == "upload_rules":
            for row in server.parse_csv(body["payload"]):
                NAT[row.pop("@uuid")] = row
            return {"status": "ok"}
    if base.startswith("firewall/alias_util/"):
        act, name = base.split("/")[2], base.split("/")[-1]
        if act == "aliases":
            return sorted(a["name"] for a in ALIASES.values())
        if act == "list":
            return {"rows": [{"ip": ip} for ip in sorted(TABLES.get(name, set()))]}
        if name not in {a["name"] for a in ALIASES.values()}:
            return {"status": "failed"}
        (TABLES.setdefault(name, set()).add if act == "add" else TABLES.setdefault(name, set()).discard)(body["address"])
        return {"status": "done"}
    if base == "firewall/filter/search_rule":
        impl = [("Default deny / state violation rule", "block", None, COUNTS[DENY]), ("IPv6 RFC4890 requirements (ICMP)", "pass", None, 310),
                ("block all targeting port 0", "block", None, 3), ("sshlockout", "block", None, 0), ("allow DHCP client on WAN", "pass", "WAN", 22),
                ("CrowdSec (IPv4) in", "block", None, 5021), ("CrowdSec (IPv4) out", "block", None, 0)] + \
               [("allow access to DHCP server", "pass", IFACES[k][0], 300 + i * 41) for i, k in enumerate(("opt1", "opt3", "opt4"))] + \
               [("Block bogon IPv4 networks from WAN", "block", "WAN", 108), ("Block private networks from WAN", "block", "WAN", 51),
                ("let out anything from firewall host itself", "pass", None, 1204331), ("anti-lockout rule", "pass", "LAN", 0)]
        return {"rows": [{"uuid": hashlib.md5(d.encode() + str(i).encode()).hexdigest(), "sort_order": "%06d" % i, "legacy": True, "description": d, "action": a,
                          "interface": f, "direction": "in", "enabled": "1", "pf_rules": 1, "evaluations": n * 7 + 100, "packets": n} for i, (d, a, f, n) in enumerate(impl)]}
    # réseau
    if base.startswith("interfaces/vlan_settings/"):
        r = grid(VLANS, "vlan", base, body)
        if r and "rows" in r:
            for x in r["rows"]:
                x["%if"] = DEVICES.get(x["if"], x["if"])
        return r
    if base == "interfaces/assignment/pending":
        return {"status": "ok"}
    if base == "interfaces/assignment/get_item":
        return {"interface": {"if": {k: {"value": v, "selected": 0} for k, v in DEVICES.items()}}}
    if base.startswith("interfaces/assignment/"):
        r = grid(ASSIGN, "interface", base, body)
        if r and "rows" in r:
            for x in r["rows"]:
                x["identifier"] = x["uuid"]
                x["%if"] = DEVICES.get(x["if"], x["if"])
        return r
    if base.startswith("dnsmasq/settings/"):
        act = base.split("/")[2]
        for kw, store, wrap in (("host", HOSTS, "host"), ("range", RANGES, "range"), ("option", OPTIONS, "option")):
            if act.endswith("_" + kw):
                return grid(store, wrap, base.replace("_" + kw, ""), body)
        if act == "get":
            return {"dnsmasq": json.loads(json.dumps(DNSMASQ))}
        if act == "set":
            for k, v in body.get("dnsmasq", {}).items():
                (DNSMASQ.setdefault(k, {}).update(v) if isinstance(v, dict) else DNSMASQ.__setitem__(k, v))
            return {"result": "saved"}
    if base == "dnsmasq/leases/search":
        return {"rows": [{"address": m[1], "hwaddr": m[2], "hostname": m[0], "mac_info": m[3], "if_name": m[4], "if_descr": IFACES[m[4]][0], "lease_type": "static" if m[5] else "dynamic",
                          "expire": int(NOW + 3600)} for m in MACHINES]}
    # supervision
    if base == "diagnostics/system/system_information":
        return {"name": "pare-feu.exemple.lan", "versions": ["OPNsense 26.7.7-amd64", "FreeBSD 14.3-RELEASE-p4", "OpenSSL 3.0.17"]}
    if base == "diagnostics/system/system_time":
        return {"uptime": "12 days 04:10:33", "boottime": "Sat Oct 11 08:12:40 CEST 2026", "config": "Thu Oct 23 09:41:02 CEST 2026", "loadavg": "0.18, 0.22, 0.20"}
    if base == "diagnostics/system/system_resources":
        return {"memory": {"total": "8473067520", "used": str(2100000000 + R.randint(0, 10 ** 8))}}
    if base == "diagnostics/system/system_temperature":
        return [{"device": f"dev.cpu.{i}.temperature", "temperature": "%.1f" % (41 + i), "type_translated": "Processeur", "type": "cpu"} for i in range(4)]
    if base == "diagnostics/system/system_disk":
        return {"devices": [{"device": "/dev/gpt/rootfs", "type": "ufs", "total": "113G", "used": "15G", "available": "89G", "used_pct": 14, "mountpoint": "/"}]}
    if base == "diagnostics/system/system_swap":
        return {"swap": [{"device": "/dev/gpt/swapfs", "total": "8388608", "used": "0"}]}
    if base == "diagnostics/system/system_mbuf":
        return {"mbuf-statistics": {"mbuf-current": 5120, "mbuf-cache": 4986, "mbuf-total": 10106, "cluster-current": 4092, "cluster-max": 1012384}}
    if base in ("diagnostics/log/core/system", "diagnostics/log/core/gateways"):
        rows = SYSLOG[base.rsplit("/", 1)[1]]
        q = str(body.get("searchPhrase", "")).lower()
        rows = [r for r in rows if not q or q in (r["process_name"] + " " + r["line"]).lower()]
        return {"total": len(rows), "rows": rows[:int(body.get("rowCount", 500))]}
    if base == "diagnostics/firewall/pf_states":
        return {"current": str(800 + R.randint(0, 200)), "limit": "800000"}
    if base == "diagnostics/firewall/log":
        for _ in range(R.randint(0, 3)):
            LOG.insert(0, log_row(time.time()))
        from urllib.parse import parse_qs
        q = parse_qs(path.split("?", 1)[1] if "?" in path else "")
        lim, dg, out = int(q.get("limit", ["500"])[0]), q.get("digest", [""])[0], []
        for r in LOG:
            if dg and r["__digest__"] == dg or len(out) >= lim:
                break
            out.append(r)
        return out
    if base == "diagnostics/interface/get_interface_names":
        return {v[1]: v[0] for v in IFACES.values()}
    if base == "diagnostics/traffic/interface":
        for t in TRAFFIC.values():
            t["rx"] += R.randint(10 ** 5, 4 * 10 ** 7)
            t["tx"] += R.randint(10 ** 5, 10 ** 7)
        return {"interfaces": {k: {"device": IFACES[k][1], "name": IFACES[k][0], "link state": "2", "bytes received": str(t["rx"]), "bytes transmitted": str(t["tx"]),
                                   "input errors": "0", "output errors": "0"} for k, t in TRAFFIC.items()}}
    if base.startswith("diagnostics/traffic/top/"):
        return {k: {"records": [{"address": m[1], "rate_bits_in": R.randint(10 ** 4, 4 * 10 ** 6), "rate_bits_out": R.randint(10 ** 3, 5 * 10 ** 5), "cumulative_bytes": R.randint(10 ** 6, 10 ** 9)}
                                for m in MACHINES if m[4] == k][:4]} for k in INTERNAL} | {"wan": {"records": []}}
    if base == "diagnostics/interface/get_arp":
        return [{"mac": m[2], "ip": m[1], "intf": IFACES[m[4]][1], "expired": False, "permanent": False, "manufacturer": m[3], "hostname": m[0]} for m in MACHINES]
    if base == "diagnostics/interface/get_routes":
        return [{"proto": "ipv4", "destination": "default", "gateway": WAN_GW, "flags": "UGS", "netif": "igc0", "mtu": "1500", "intf_description": "WAN"}] + \
               [{"proto": "ipv4", "destination": IFACES[k][2].replace(".1/", ".0/"), "gateway": "link#%d" % i, "flags": "U", "netif": IFACES[k][1], "mtu": "1500",
                 "intf_description": IFACES[k][0]} for i, k in enumerate(INTERNAL)]
    if base == "routing/settings/search_gateway":
        return {"rows": [{"uuid": uid("gw/wan"), "name": "WAN_DHCP", "interface": "wan", "interface_descr": "WAN", "ipprotocol": "inet", "gateway": WAN_GW, "defaultgw": "1",
                          "monitor": WAN_GW, "disabled": "0", "priority": "254", "descr": "Passerelle du fournisseur d'accès", "dynamic": True},
                         {"uuid": uid("gw/vpn"), "name": "SITE_B", "interface": "opt2", "interface_descr": "SERVEURS", "ipprotocol": "inet", "gateway": "192.168.20.2",
                          "defaultgw": "0", "monitor": "", "disabled": "0", "priority": "255", "descr": "Routeur VPN vers l'agence"}], "total": 2}
    if base == "routes/routes/searchroute":
        return {"rows": [{"uuid": uid("route/agence"), "network": "10.20.0.0/16", "gateway": "SITE_B - 192.168.20.2", "descr": "Réseau de l'agence (VPN)", "disabled": "0"}], "total": 1}
    if base == "routes/gateway/status":
        return {"items": [{"name": "WAN_DHCP", "address": WAN_GW, "status": "none", "loss": "0.0 %", "delay": "4.1 ms", "stddev": "0.3 ms", "monitor": WAN_GW, "status_translated": "Online"}]}
    if base == "diagnostics/firewall/query_states":
        rows = [{"label": uid("rule/lan-inet"), "descr": "Internet", "proto": "tcp", "ipproto": "ipv4", "direction": "in", "src_addr": m[1], "src_port": str(40000 + i),
                 "dst_addr": "198.51.100.%d" % (10 + i), "dst_port": "443", "state": "ESTABLISHED:ESTABLISHED", "age": "00:0%d:12" % (i % 10), "pkts": [120 * i, 90 * i],
                 "bytes": [80000 * i, 12000 * i], "id": "%016x/%08x" % (i + 1, 1)} for i, m in enumerate(MACHINES[:12])]
        return {"rows": rows[:int(body.get("rowCount", 100))], "total": 812}
    if base in ("diagnostics/firewall/kill_states",):
        return {"result": "ok", "dropped_states": 2}
    if base.startswith("diagnostics/firewall/del_state/"):
        return {"result": "killed 1"}
    if base == "interfaces/overview/interfaces_info":
        return iface_info()
    if base == "core/service/search":
        return {"rows": [{"id": n, "name": n, "description": d, "locked": lk, "running": 1} for n, d, lk in SERVICES], "total": len(SERVICES)}
    if base.startswith("core/service/"):
        return {"result": "ok"}
    if base == "core/backup/backups/this":
        return {"items": [{"time": str(NOW - i * 86400 * 2.5), "time_iso": time.strftime("%Y-%m-%dT%H:%M:%S+02:00", time.localtime(NOW - i * 86400 * 2.5)),
                           "description": "/api/firewall/filter/apply made changes", "username": "opnderbox@192.168.10.20", "filesize": 98000 + i * 300,
                           "id": "config-%d.%04d.xml" % (NOW - i * 86400 * 2.5, i)} for i in range(6)]}
    if base.startswith("core/backup/diff/"):
        return {"items": ["@@ -120,7 +120,7 @@", "-      &lt;descr&gt;Navigation&lt;/descr&gt;", "+      &lt;descr&gt;Navigation web&lt;/descr&gt;"]}
    if base.startswith("core/backup/download/"):
        return '<?xml version="1.0"?>\n<opnsense><!-- configuration simulée --></opnsense>\n'
    if base == "core/firmware/status":
        return {"product_version": "26.7.7", "os_version": "FreeBSD 14.3-RELEASE-p4", "last_check": "Thu Oct 23 06:00:12 CEST 2026", "status": "none",
                "status_msg": "There are no updates available on the selected mirror.", "upgrade_packages": [], "new_packages": [], "remove_packages": []}
    if base == "core/firmware/running":
        return {"status": "ready"}
    if base in ("core/firmware/check", "core/firmware/update"):
        return {"status": "ok"}
    if base == "core/firmware/upgradestatus":
        return {"status": "done", "log": "Simulation : rien à installer.\n"}
    if base == "ids/service/query_alerts":
        ph = body.get("searchPhrase", "")
        rows = [a for a in IDS if not ph or ph in json.dumps(a)]
        return {"rows": rows[:int(body.get("rowCount", 50))], "total": len(rows)}
    if base == "ids/service/status":
        return {"status": "running"}
    if base == "ids/settings/get":
        return {"ids": {"general": {"enabled": "1", "mode": {"netmap": {"selected": 1}, "pcap": {"selected": 0}},
                                    "interfaces": {"wan": {"selected": 1}, "opt1": {"selected": 1}, "opt5": {"selected": 1}}}}}
    if base == "crowdsec/decisions/search":
        return {"rows": DECISIONS, "total": len(DECISIONS)}
    if base == "crowdsec/alerts/search":
        return {"rows": [{"id": d["alert_id"]} for d in DECISIONS], "total": len(DECISIONS)}
    if base.startswith("crowdsec/decisions/del/"):
        n = len(DECISIONS)
        DECISIONS[:] = [d for d in DECISIONS if d["id"] != int(base.rsplit("/", 1)[1])]
        return {"result": "deleted" if len(DECISIONS) < n else "not found"}
    if base.startswith("diagnostics/systemhealth/get_system_health/"):
        name, detail = base.split("/")[-2], int(base.split("/")[-1])
        return health(name, detail)
    if base == "diagnostics/systemhealth/get_interfaces":
        return {k: {"descr": v[0]} for k, v in IFACES.items()}
    raise server.ApiError(f"simulation : {path} n'existe pas dans la démonstration")


def raw_request(base_url, fingerprint, auth, method, path, body=None):
    try:
        res = api(method, path, body)
    except server.ApiError:
        return 404, b"{}"
    return 200, (res if isinstance(res, str) else json.dumps(res)).encode()


def seed_state():
    """séparateurs, objet temps et suivi d'utilisation pour que la démonstration ressemble à un pare-feu en service."""
    server.save_separators([{"id": "s-acces", "before": U_NAS, "title": "Accès aux serveurs", "color": "blue"},
                            {"id": "s-fin", "before": U_LAN_FW, "title": "Protection et Internet", "color": "orange"}])
    server.save_sched({"objects": [{"name": "T_HEURES_OUVREES", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "19:00", "description": "Du lundi au vendredi"}],
                       "rules": [[U_IOT, "T_HEURES_OUVREES"]]})
    since = NOW - 9 * 86400
    server.save_json(server.USAGE_FILE, {"since": since, "rules": {u: {"n": n, "last": (NOW - R.randint(60, 7200)) if n else None, "approx": False} for u, n in COUNTS.items()}})


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ecoute", default="127.0.0.1", help="adresse d'écoute (127.0.0.1 par défaut)")
    a = ap.parse_args()
    server.opn = api
    server.api_request = raw_request
    server.CFG = {"opnsense": "https://192.0.2.254", "opnsense_fingerprint": "0" * 64, "_auth": "simulation", "password_hash": "", "auth_disabled": True,
                  "rollback_seconds": 60, "demo": True, "key_file": str(STATE / "apikey.txt")}
    server.valid_session = lambda token: True
    seed_state()
    server.start_background()
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer((a.ecoute, a.port), server.Handler)
    print(f"Démonstration d'OPNderbox : http://{'127.0.0.1' if a.ecoute == '0.0.0.0' else a.ecoute}:{a.port}  (Ctrl+C pour arrêter)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
