#!/usr/bin/env python3
"""Docker-ansa. Portti 2375 näyttää avoimelta Docker Engine API:lta,
jota kryptovarkaat etsivät käynnistääkseen louhijakontteja. EI aja mitään: vastaa uskottavasti ja kirjaa
kontin luonnit (image, Cmd, Env, Entrypoint), image-lataukset ja exec-komennot sekä niistä löytyvät URL:t ja
Monero-lompakot ⇒ louhijat.py (pooleille), raportoija (AbuseIPDB), abusech (URLhaus), kojelauta.
Turvallisuus: DynamicUser, ProtectSystem=strict, ei oikeuksia; vastaukset ovat kiinteää JSONia."""
import json, re, secrets, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HAK = "/var/lib/dockeransa"
LOKI = f"{HAK}/dockeransa.jsonl"
lukko = threading.Lock()
auki = threading.BoundedSemaphore(60)
URL = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>;|`$(){}\\]+", re.I)
XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
VERSIO = {"Platform": {"Name": "Docker Engine - Community"}, "Version": "24.0.7", "ApiVersion": "1.43", "MinAPIVersion": "1.12",
          "GitCommit": "311b9ff", "GoVersion": "go1.20.10", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.1.0-21-amd64",
          "BuildTime": "2023-10-26T09:07:41.000000000+00:00"}
INFO = {"ID": "7Q2K:XW3B:QF6L:T4YJ:2NZA:BKP3:R5UE:J7LS:HG2D:M4VC:Y8NW:F1QX", "Containers": 3, "ContainersRunning": 2,
        "ContainersPaused": 0, "ContainersStopped": 1, "Images": 7, "Driver": "overlay2", "OperatingSystem": "Debian GNU/Linux 12 (bookworm)",
        "OSType": "linux", "Architecture": "x86_64", "NCPU": 8, "MemTotal": 33536954368, "Name": "srv-backup01",
        "ServerVersion": "24.0.7", "KernelVersion": "6.1.0-21-amd64", "DockerRootDir": "/var/lib/docker"}
KONTIT = [{"Id": secrets.token_hex(32), "Names": ["/backup-agent"], "Image": "restic/restic:0.16.2", "State": "running",
           "Status": "Up 3 weeks", "Command": "/usr/bin/restic server"},
          {"Id": secrets.token_hex(32), "Names": ["/postgres"], "Image": "postgres:15", "State": "running", "Status": "Up 3 weeks",
           "Command": "docker-entrypoint.sh postgres"}]


class K(BaseHTTPRequestHandler):
    server_version = "Docker/24.0.7 (linux)"; sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20
    def log_message(self, *a): pass

    def vastaa(self, koodi, data=None, tyyppi="application/json"):
        b = b"" if data is None else (data if isinstance(data, bytes) else json.dumps(data).encode())
        self.send_response(koodi)
        self.send_header("Api-Version", "1.43"); self.send_header("Docker-Experimental", "false"); self.send_header("Ostype", "linux")
        self.send_header("Content-Type", tyyppi); self.send_header("Content-Length", str(len(b))); self.end_headers()
        if self.command != "HEAD" and b:
            self.wfile.write(b)

    def kasittele(self):
        n = min(int(self.headers.get("Content-Length") or 0), 65536)
        runko = self.rfile.read(n).decode("utf-8", "ignore") if n > 0 else ""
        polku = re.sub(r"^/v1\.\d+", "", self.path.split("?")[0])
        kaikki = self.path + " " + runko
        rivi = {"aika": int(time.time()), "ip": self.client_address[0].replace("::ffff:", ""), "metodi": self.command,
                "polku": self.path[:400], "ua": (self.headers.get("User-Agent") or "")[:150], "runko": runko[:8000],
                "urlit": sorted(set(URL.findall(kaikki)))[:20], "lompakot": sorted(set(XMR.findall(kaikki)))[:5]}
        try:
            j = json.loads(runko) if runko.strip().startswith("{") else {}
            if "Image" in j or "Cmd" in j:
                rivi["image"] = str(j.get("Image", ""))[:200]
                rivi["cmd"] = json.dumps(j.get("Cmd") or j.get("Entrypoint") or "")[:2000]
        except Exception:
            pass
        if "fromImage" in self.path:
            rivi["image"] = re.search(r"fromImage=([^&]+)", self.path).group(1)[:200]
        with lukko, open(LOKI, "a") as f:
            f.write(json.dumps(rivi, ensure_ascii=False) + "\n")
        if polku == "/_ping":
            return self.vastaa(200, b"OK", "text/plain")
        if polku == "/version":
            return self.vastaa(200, VERSIO)
        if polku == "/info":
            return self.vastaa(200, INFO)
        if polku == "/containers/json":
            return self.vastaa(200, KONTIT)
        if polku == "/images/json":
            return self.vastaa(200, [{"Id": "sha256:" + secrets.token_hex(32), "RepoTags": ["postgres:15"], "Size": 425000000}])
        if polku == "/containers/create":
            return self.vastaa(201, {"Id": secrets.token_hex(32), "Warnings": []})
        if polku == "/images/create":
            return self.vastaa(200, b'{"status":"Pulling from library","id":"latest"}\r\n{"status":"Download complete"}\r\n')
        if re.fullmatch(r"/containers/[\w.-]+/(start|stop|restart|kill|wait|attach)", polku):
            return self.vastaa(204)
        if re.fullmatch(r"/containers/[\w.-]+/exec", polku):
            return self.vastaa(201, {"Id": secrets.token_hex(32)})
        if re.fullmatch(r"/exec/[\w.-]+/start", polku):
            return self.vastaa(200, b"", "application/vnd.docker.raw-stream")
        if re.fullmatch(r"/containers/[\w.-]+/json", polku):
            return self.vastaa(200, {"Id": secrets.token_hex(32), "State": {"Status": "running", "Running": True}})
        if re.fullmatch(r"/containers/[\w.-]+", polku) and self.command == "DELETE":
            return self.vastaa(204)
        return self.vastaa(404, {"message": "page not found"})

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = kasittele


class Palvelin(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
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


if __name__ == "__main__":
    Palvelin(("::", 2375), K).serve_forever()
