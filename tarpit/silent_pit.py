#!/usr/bin/env python3
"""Hiljainen tervakuoppa.
iptables ohjaa toistuvat yrittäjät (yli 20 uutta yhteyttä / 60 s samasta IP:stä portteihin 1433 ym.) tänne.
Yhteys hyväksytään, mutta palvelin ei vastaa koskaan ⇒ hyökkääjän työkalu odottaa omaan aikakatkaisuunsa
(go-mssqldb ~15–30 s) jokaisella yrityksellä ⇒ brute force hidastuu kymmeniä kertoja. Ei lähetä mitään hyökkääjälle.
Aja: python3 -I hiljainen_kuoppa.py PORTTI   (systemd hiljainen-kuoppa.service)
Loki tila/hiljainen_kuoppa.log: ts;ip;kesto_s;alkup_portti   mittarit 127.0.0.1:2114"""
import os, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORTTI = int(sys.argv[1]) if len(sys.argv) > 1 else 14330
MAX = 300                                    # TasksMax-raja huomioiden
threading.stack_size(256 * 1024)
LOKI = Path(os.environ.get("SILENT_PIT_LOG", "/var/log/kotivahdit/silent_pit.log"))
tila = {"auki": 0, "yhteensa": 0, "sekunnit": 0.0}
lukko = threading.Lock()


def alkup_portti(s) -> int:
    """iptables REDIRECTin alkuperäinen kohdeportti (SO_ORIGINAL_DST=80; sockaddr: perhe 2 t + portti 2 t)."""
    for taso in (socket.SOL_IP, socket.IPPROTO_IPV6):
        try:
            return int.from_bytes(s.getsockopt(taso, 80, 28)[2:4], "big")
        except OSError:
            pass
    return 0


def hoida(s, ip):
    alku = time.time()
    portti = alkup_portti(s)
    try:
        s.settimeout(900)
        while s.recv(4096):                  # luetaan ja heitetään pois, ei vastata koskaan
            pass
    except OSError:
        pass
    finally:
        kesto = time.time() - alku
        try:
            s.close()
        except OSError:
            pass
        with lukko:
            tila["auki"] -= 1; tila["sekunnit"] += kesto
        if kesto >= 3:
            with LOKI.open("a") as f:
                f.write(f"{int(time.time())};{ip};{kesto:.0f};{portti}\n")


class M(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        with lukko:
            b = (f"hiljainen_open {tila['auki']}\nhiljainen_total {tila['yhteensa']}\n"
                 f"hiljainen_seconds_total {tila['sekunnit']:.0f}\n").encode()
        self.send_response(200); self.end_headers(); self.wfile.write(b)


def main():
    threading.Thread(target=lambda: ThreadingHTTPServer(("127.0.0.1", 2114), M).serve_forever(), daemon=True).start()
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    srv.bind(("::", PORTTI)); srv.listen(128)
    while True:
        try:
            s, a = srv.accept()
        except OSError:
            continue
        with lukko:
            if tila["auki"] >= MAX:
                s.close(); continue
            tila["auki"] += 1; tila["yhteensa"] += 1
        try:
            threading.Thread(target=hoida, args=(s, a[0].replace("::ffff:", "")), daemon=True).start()
        except RuntimeError:
            with lukko:
                tila["auki"] -= 1
            s.close(); time.sleep(1)


if __name__ == "__main__":
    main()
