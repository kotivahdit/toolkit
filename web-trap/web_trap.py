#!/usr/bin/env python3
"""Web-ansa. Portit 80 ja 443 (itse allekirjoitettu varmenne).
Bottiverkot levittäytyvät murtamalla reitittimien/kameroiden web-hallintoja (GPON, Hikvision, HNAP, Boa, ThinkPHP,
Log4j …). Ansa näyttää yleiseltä reitittimen kirjautumissivulta, EI aja mitään, ja kirjaa jokaisen pyynnön:
aika, IP, portti, metodi, polku, Host, User-Agent, rungon alku (≤ 4 kt), murtoyrityksen tunnisteet ja upotetut
haittaohjelma-URL:t (wget/curl http://…). Loki /var/lib/verkkokuoppa/verkkokuoppa.jsonl ⇒ raportoija (AbuseIPDB 21),
abusech.py (URLhaus/MalwareBazaar), tilastot (kojelauta).
Turvallisuus: ajetaan DynamicUser-käyttäjänä (ei root), vain CAP_NET_BIND_SERVICE, ProtectSystem=strict, säiekatto."""
import json, re, socket, ssl, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HAK = "/var/lib/verkkokuoppa"
LOKI = f"{HAK}/verkkokuoppa.jsonl"
MAX = 150
auki = threading.BoundedSemaphore(MAX)
lukko = threading.Lock()
# 20.11.: murtoyritykseen (tunniste osui) vastataan tervakuoppana: otsakerivi 10 s välein
# enintään 15 min ⇒ skannerin säie/yhteys jumissa. Katto 100 yhtäaikaista, 3 / IP; loppu 50 paikkaa tavallisille pyynnöille.
KUOPPA_MAX, KUOPPA_IP, KUOPPA_S = 100, 3, 900
kuoppa = {"auki": 0, "ip": {}}
KUOPPALOKI = f"{HAK}/tervakuoppa.log"
# 20.11. syöttitiedostot: "vuotaneet" salaisuustiedostot, joissa canarytoken-AWS-avain ⇒ käyttö paljastaa varkaan infran
try:
    _S = json.load(open(f"{HAK}/syotit.json"))
except Exception:
    _S = {"id": "AKIAXXXXXXXXXXXXXXXX", "salainen": "x"}
SYOTIT = {
    "/.env": f"""APP_NAME=backup-portal\nAPP_ENV=production\nAPP_DEBUG=false\nDB_CONNECTION=mysql\nDB_HOST=10.0.3.12\nDB_DATABASE=backup\nDB_USERNAME=backup_rw\nDB_PASSWORD=Kv7#pQ2!backup2024\nAWS_ACCESS_KEY_ID={_S['id']}\nAWS_SECRET_ACCESS_KEY={_S['salainen']}\nAWS_DEFAULT_REGION=eu-north-1\nAWS_BUCKET=srv-backup01-archive\n""",
    "/config.json": json.dumps({"storage": {"provider": "s3", "bucket": "srv-backup01-archive", "region": "eu-north-1",
                                "accessKeyId": _S["id"], "secretAccessKey": _S["salainen"]}, "db": {"host": "10.0.3.12", "user": "backup_rw"}}, indent=2) + "\n",
    "/wp-config.php.bak": f"""<?php\ndefine('DB_NAME', 'wp_prod');\ndefine('DB_USER', 'wp_admin');\ndefine('DB_PASSWORD', 'Wp!2024prod#88');\ndefine('DB_HOST', '10.0.3.12');\n// S3 offload\ndefine('AS3CF_SETTINGS', serialize(array('provider' => 'aws', 'access-key-id' => '{_S['id']}', 'secret-access-key' => '{_S['salainen']}')));\n""",
    "/.aws/credentials": f"[default]\naws_access_key_id = {_S['id']}\naws_secret_access_key = {_S['salainen']}\nregion = eu-north-1\n",
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = git@10.0.3.20:infra/backup-portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n",
}
SYOTIT["/.env.bak"] = SYOTIT["/.env.production"] = SYOTIT["/backup/.env"] = SYOTIT["/.env"]
URL = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>;|`$(){}\\]+", re.I)
TUNNISTEET = [(re.compile(p, re.I), n) for p, n in [
    (r"\$\{jndi:", "log4j"), (r"/cgi-bin/|\.cgi\b", "cgi"), (r"wget|curl|tftp|busybox|chmod\s|/bin/sh|sh\s+-c", "komento"),
    (r"GponForm|/diag_Form", "gpon"), (r"/HNAP1", "hnap"), (r"boaform|/formLogin", "boa"), (r"setup\.cgi", "netgear"),
    (r"/shell\?|/bin/bash", "shell"), (r"invokefunction|think\\\\app", "thinkphp"), (r"/\.env\b|/\.git/", "tiedostovuoto"),
    (r"phpunit|eval-stdin", "phpunit"), (r"wp-login|xmlrpc\.php|/wp-admin", "wordpress"), (r"/SDK/webLanguage|/ISAPI/", "hikvision"),
    (r"/goform/", "goform"), (r"\.\./\.\./|%2e%2e%2f", "polku"), (r"/actuator|/solr/|/druid/", "java-palvelu"),
    (r"/vendor/|/owa/|/autodiscover|/ecp/", "exchange/php"), (r"/ws/v1/cluster/apps", "hadoop-yarn")]]
SIVU = b"""<!doctype html><html><head><title>Router Login</title></head><body style="font-family:sans-serif">
<h3>Wireless Router</h3><form method=post action=/login.cgi>User <input name=username><br>Password
<input type=password name=password><br><input type=submit value=Login></form></body></html>"""


class K(BaseHTTPRequestHandler):
    server_version = "uhttpd/1.0"; sys_version = ""
    timeout = 15
    def log_message(self, *a): pass

    def kasittele(self):
        n = min(int(self.headers.get("Content-Length") or 0), 4096)
        runko = self.rfile.read(n).decode("latin-1") if n > 0 else ""
        otsakkeet = [f"{k}: {v}" for k, v in self.headers.items()
                     if not (k.lower() == "user-agent" and re.fullmatch(r"(curl|Wget|python-requests|Go-http-client)/[\w.]+", v.strip()))]
        kaikki = " ".join([self.path, urllib.parse.unquote_plus(self.path), runko, urllib.parse.unquote_plus(runko)] + otsakkeet)
        tun = sorted({nimi for rx, nimi in TUNNISTEET if rx.search(kaikki)})
        rivi = {"aika": int(time.time()), "ip": self.client_address[0].replace("::ffff:", ""), "portti": self.server.server_port,
                "metodi": self.command, "polku": self.path[:500], "host": (self.headers.get("Host") or "")[:100],
                "ua": (self.headers.get("User-Agent") or "")[:200], "runko": runko[:1500], "tunnisteet": tun,
                "urlit": sorted(set(u.rstrip(".,") for u in URL.findall(kaikki)) - {"http://" + (self.headers.get("Host") or "")})[:10]}
        with lukko, open(LOKI, "a") as f:
            f.write(json.dumps(rivi, ensure_ascii=False) + "\n")
        polku = self.path.split("?")[0]
        if polku in SYOTIT and self.command in ("GET", "HEAD"):        # syötti ennen tervakuoppaa: varas saa "saaliin"
            with lukko, open(LOKI, "a") as f:
                f.write(json.dumps({"aika": int(time.time()), "ip": rivi["ip"], "syotti": polku}) + "\n")
            b = SYOTIT[polku].encode()
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(b))); self.end_headers()
            if self.command == "GET":
                self.wfile.write(b)
            return
        if tun and self.tervakuoppa(rivi["ip"]):
            return
        sisalto = SIVU if self.path in ("/", "/index.html", "/login.cgi") else b"Not Found"
        self.send_response(200 if sisalto is SIVU else 404)
        self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(sisalto))); self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(sisalto)

    def tervakuoppa(self, ip) -> bool:
        with lukko:
            if kuoppa["auki"] >= KUOPPA_MAX or kuoppa["ip"].get(ip, 0) >= KUOPPA_IP:
                return False
            kuoppa["auki"] += 1; kuoppa["ip"][ip] = kuoppa["ip"].get(ip, 0) + 1
        alku = time.time()
        try:
            self.connection.settimeout(60)
            self.wfile.write(b"HTTP/1.1 200 OK\r\nServer: uhttpd/1.0\r\n"); self.wfile.flush()
            while time.time() - alku < KUOPPA_S:
                time.sleep(10)
                self.wfile.write(b"X-%x: %x\r\n" % (int(time.time() * 1000) & 0xffff, threading.get_ident() & 0xffffff)); self.wfile.flush()
        except (OSError, ValueError):
            pass
        finally:
            kesto = time.time() - alku
            with lukko:
                kuoppa["auki"] -= 1; kuoppa["ip"][ip] -= 1
                if kuoppa["ip"][ip] <= 0:
                    del kuoppa["ip"][ip]
                if kesto >= 5:
                    with open(KUOPPALOKI, "a") as f:
                        f.write(f"{int(time.time())};{ip};{kesto:.0f};{self.server.server_port}\n")
            self.close_connection = True
        return True

    do_GET = do_POST = do_HEAD = do_PUT = do_OPTIONS = do_DELETE = do_PATCH = kasittele


class Palvelin(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    request_queue_size = 64
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
    def process_request(self, req, osoite):
        if not auki.acquire(blocking=False):
            req.close(); return
        try:
            super().process_request(req, osoite)
        except RuntimeError:
            auki.release(); req.close()
    def process_request_thread(self, req, osoite):
        try:
            super().process_request_thread(req, osoite)
        finally:
            auki.release()


def main():
    h = Palvelin(("::", 80), K)
    s = Palvelin(("::", 443), K)
    kt = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    kt.load_cert_chain(f"{HAK}/varmenne.pem", f"{HAK}/avain.pem")
    s.socket = kt.wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    h.serve_forever()


if __name__ == "__main__":
    main()
