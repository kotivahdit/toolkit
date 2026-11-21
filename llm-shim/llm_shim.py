#!/usr/bin/env python3
"""Tekoälyansan välikappale . Beelzebub → tämä (172.17.0.1:11435) → Ollama (:11434).
Rikolliset tunnistavat LLM-ansan deterministisillä testeillä (sh -c 'set -- a b; printf …', laskut).
Jos komento koostuu VAIN sallituista sisäänrakennetuista komennoista, se ajetaan oikealla dashilla
eristettynä (ei verkkoa: unshare -n, käyttäjä nobody, no-new-privs, 64 Mt, 8 prosessia, 1 s) ⇒ oikea vastaus.
Muut komennot välitetään kielimallille sellaisenaan. Ei tiedostoja, putkia, uudelleenohjauksia eikä $( )-alikomentoja."""
import json, re, subprocess, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OLLAMA = "http://172.17.0.1:11434"
SALLITUT = {"set", "printf", "echo", "expr", "test", "[", "]", "true", "false", ":", "export", "unset", "shift", "local", "return", "exit"}
KIELLETTY = re.compile(r"`|\$\((?!\()|\b(eval|exec|source|trap|read|ulimit|umask|cd|kill|wait)\b")   # myös lainausten sisällä
KIELLETTY_ULKO = re.compile(r"[<>|&]|/")                                                         # vain lainausten ulkopuolella


def sisus(k: str) -> str:
    k = k.strip()
    m = re.fullmatch(r"(?:/bin/)?(?:ba|da)?sh\s+-c\s+'(.*)'", k, re.S)
    if m:
        return m.group(1).replace("'\"'\"'", "'")
    m = re.fullmatch(r'(?:/bin/)?(?:ba|da)?sh\s+-c\s+"(.*)"', k, re.S)
    return m.group(1) if m else k


def deterministinen(k: str):
    s = sisus(k)
    if not s or len(s) > 2000 or KIELLETTY.search(s):
        return None
    ilman = re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", " Q ", s)          # lainausmerkkien sisältö pois tarkistuksesta
    if KIELLETTY_ULKO.search(re.sub(r"&&|\|\|", " ", ilman)):
        return None
    funktiot = set(re.findall(r"([A-Za-z_]\w*)\s*\(\)\s*\{", ilman))           # omat funktiot (f_check_…() { … })
    ilman = re.sub(r"[A-Za-z_]\w*\s*\(\)\s*\{", ";", ilman).replace("}", ";")
    for osa in re.split(r"[;\n]|&&|\|\|", ilman):
        sanat = osa.split()
        if sanat and sanat[0] not in SALLITUT | funktiot and not re.fullmatch(r"[A-Za-z_]\w*=\S*", sanat[0]):
            return None
    return s


def aja(s: str) -> str:
    c = ["unshare", "-n", "--", "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs",
         "prlimit", "--nproc=8", "--as=67108864", "--", "timeout", "1", "dash", "-c", s]
    r = subprocess.run(c, capture_output=True, text=True, timeout=3, cwd="/tmp", env={"PATH": "/usr/bin:/bin", "HOME": "/root"})
    return (r.stdout + r.stderr)[:4000]


class K(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            j = json.loads(b); viesti = (j.get("messages") or [{}])[-1].get("content", "")
            s = deterministinen(viesti) if j.get("messages") else None
        except Exception:
            j, s = {}, None
        print("pyyntö", "AJA" if s is not None else "LLM", flush=True)
        if s is not None:
            try:
                out = aja(s)
                vas = json.dumps({"model": j.get("model", ""), "created_at": "", "message": {"role": "assistant", "content": out},
                                  "done": True, "done_reason": "stop"}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(vas)))
                self.end_headers(); self.wfile.write(vas); return
            except Exception as e:
                print("aja-virhe", repr(e)[:200], flush=True)
        print("ollamalle", repr(viesti[:80]) if j else "?", flush=True)
        r = urllib.request.urlopen(urllib.request.Request(OLLAMA + self.path, data=b, headers={"Content-Type": "application/json"}), timeout=120)
        vas = r.read()
        self.send_response(r.status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(vas)))
        self.end_headers(); self.wfile.write(vas)

    def do_GET(self):
        r = urllib.request.urlopen(OLLAMA + self.path, timeout=30); vas = r.read()
        self.send_response(r.status); self.send_header("Content-Length", str(len(vas))); self.end_headers(); self.wfile.write(vas)


if __name__ == "__main__":
    ThreadingHTTPServer(("172.17.0.1", 11435), K).serve_forever()
