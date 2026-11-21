#!/usr/bin/env python3
"""Telnet-tervakuoppa.
Mirai-tyyppiset botit odottavat login-kehotetta. Lähetämme tavun ~10 s välein loputtomiin ⇒ botti jää odottamaan.
Kaikki tapahtuu OMALLA koneella; emme ota yhteyttä hyökkääjään emmekä lähetä mitään haitallista.
Lokaa $TARPIT_LOG (IP;sekunnit) ⇒ raportoija vie AbuseIPDB:hen, tilastot kojelaudalle.
Prometheus 127.0.0.1:2113 (jumissa nyt / yhteensä / sekunnit). Aja: python3 -I telnet_tarpit.py <portti...>"""
import os, random, signal, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORTIT = [int(x) for x in sys.argv[1:]] or [23]
MAX = 400                                   # systemd TasksMax ~480 ⇒ yli tämän suljetaan heti (18.11.)
threading.stack_size(256 * 1024)            # pieni pino ⇒ vähän muistia/säie
VALI = 10.0
LOKI = Path(os.environ.get("TARPIT_LOG", "/var/log/kotivahdit/telnet_tarpit.log"))
LOKI.parent.mkdir(parents=True, exist_ok=True)
PER_IP = 5                                  # 20.11.: yksi botti avasi 229 yhteyttä ⇒ max 5 samanaikaista / IP
tila = {"auki": 0, "yhteensa": 0, "sekunnit": 0.0, "torjuttu_ip_raja": 0}
ip_auki: dict = {}
avoimet: dict = {}                          # 20.11.: avoimet yhteydet ⇒ kirjataan lokiin myös sammutuksessa
lukko = threading.Lock()


def hoida(s: socket.socket, ip: str):
    with lukko:
        if tila["auki"] >= MAX or ip_auki.get(ip, 0) >= PER_IP:
            if ip_auki.get(ip, 0) >= PER_IP:
                tila["torjuttu_ip_raja"] += 1
            s.close(); return
        tila["auki"] += 1; tila["yhteensa"] += 1
        ip_auki[ip] = ip_auki.get(ip, 0) + 1
    alku = time.time()
    with lukko:
        avoimet[id(s)] = (ip, alku)
    try:
        s.sendall(b"\xff\xfd\x01\xff\xfd\x1f")          # telnet IAC DO ECHO / NAWS ⇒ näyttää oikealta palvelimelta
        while True:
            time.sleep(VALI + random.random())
            s.sendall(bytes([random.randint(97, 122)]))  # yksi kirjain, ei koskaan valmista "login:"-kehotetta
    except OSError:
        pass
    finally:
        kesto = time.time() - alku
        try:
            s.close()
        except OSError:
            pass
        with lukko:
            if avoimet.pop(id(s), None) is None:     # sammutus kirjasi jo
                return
            tila["auki"] -= 1; tila["sekunnit"] += kesto
            ip_auki[ip] -= 1
            if ip_auki[ip] <= 0:
                del ip_auki[ip]
        if kesto >= 5 and not ip.startswith(("10.", "172.17.", "127.")):
            with LOKI.open("a") as f:
                f.write(f"{int(time.time())};{ip};{kesto:.0f}\n")


def kuuntele(portti: int):
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    srv.bind(("::", portti)); srv.listen(128)
    while True:
        try:
            s, a = srv.accept()
        except OSError:
            continue
        ip = a[0].replace("::ffff:", "")
        if tila["auki"] >= MAX or ip_auki.get(ip, 0) >= PER_IP:   # täynnä / IP-raja ⇒ suljetaan heti, ei uutta säiettä
            if ip_auki.get(ip, 0) >= PER_IP:
                tila["torjuttu_ip_raja"] += 1
            s.close(); continue
        s.settimeout(600)
        try:
            threading.Thread(target=hoida, args=(s, ip), daemon=True).start()
        except RuntimeError:                     # säikeitä ei saatu ⇒ kuuntelija ei saa kaatua
            s.close(); time.sleep(1)


class M(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        with lukko:
            b = (f"telnet_tarpit_open {tila['auki']}\ntelnet_tarpit_total {tila['yhteensa']}\ntelnet_tarpit_ip_raja {tila['torjuttu_ip_raja']}\ntelnet_tarpit_eri_ip {len(ip_auki)}\n"
                 f"telnet_tarpit_seconds_total {tila['sekunnit']:.0f}\n").encode()
        self.send_response(200); self.end_headers(); self.wfile.write(b)


def sammutus(*_):
    """SIGTERM (systemctl restart/stop): kirjataan auki olevat yhteydet lokiin, ettei niitä menetetä (20.11.)."""
    nyt = time.time()
    with lukko:
        rivit = [f"{int(nyt)};{ip};{nyt - alku:.0f}\n" for ip, alku in avoimet.values()
                 if nyt - alku >= 5 and not ip.startswith(("10.", "172.17.", "127."))]
        avoimet.clear()
    try:
        with LOKI.open("a") as f:
            f.writelines(rivit)
    finally:
        os._exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, sammutus)
    threading.Thread(target=lambda: ThreadingHTTPServer(("127.0.0.1", 2113), M).serve_forever(), daemon=True).start()
    for p in PORTIT[:-1]:
        threading.Thread(target=kuuntele, args=(p,), daemon=True).start()
    kuuntele(PORTIT[-1])
