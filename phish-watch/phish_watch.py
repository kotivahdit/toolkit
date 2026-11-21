#!/usr/bin/env python3
"""Kalastelusivujen metsästäjä.
Kysyy crt.sh:lta (Certificate Transparency) uudet TLS-varmenteet suomalaisille brändeille ~tunnin välein.
Huijarit tarvitsevat varmenteen https-sivulleen, joten uudet "nordea-tunnistautuminen.com"-nimet näkyvät
täällä usein ENNEN kuin ensimmäinen huijausviesti lähtee.

Ehdokkaat Saken Telegramiin. ⚠ EI automaattisia ilmoituksia viranomaisille: ihminen tarkistaa ensin
(vääriä syytöksiä ei saa tehdä), sitten ilmoitus: Kyberturvallisuuskeskus (kyberturvallisuuskeskus.fi/ilmoita),
Netcraft (report.netcraft.com), Google Safe Browsing ja kohdebrändin oma abuse-osoite.
Aja: python3 -I kalastelijat.py [--kuiva]   (systemd kalastelijat.service)"""
import datetime as dt, json, os, re, sys, time, urllib.parse, urllib.request
from pathlib import Path

HAK = Path(os.environ.get("ULKOVAHTI_HAK", "/opt/ulkovahti"))
AS = json.loads((HAK / "asetukset.json").read_text())
TF = HAK / "tila" / "kalastelijat.json"
VALI_S = 3600                                  # kierros tunnin välein
UA = {"User-Agent": "kotivahti-phish-watch/2.0"}
BRANDIT = {   # tunniste: (hakusanat crt.sh:lle, tunnistusregex, viralliset verkkotunnukset)
    "OP": (["osuuspankki", "op-pankki", "op-tunnistus", "op-verkkopankki"], r"osuuspankki|op-?pankki|op-?(tunnistus|verkkopankki|mobiili|login)", ("op.fi", "op-palvelut.fi")),
    "Nordea": (["nordea"], r"nordea", ("nordea.fi", "nordea.com", "nordea.dk", "nordea.se", "nordea.no", "nordea.net")),
    "S-Pankki": (["s-pankki", "spankki"], r"s-?pankki", ("s-pankki.fi",)),
    "Danske": (["danske-bank", "danskebank"], r"danske-?bank", ("danskebank.fi", "danskebank.com", "danskebank.dk", "danskebank.se", "danskebank.no")),
    "Aktia": (["aktia"], r"aktia", ("aktia.fi", "aktia.com")),
    "Säästöpankki": (["saastopankki", "omasp"], r"saastopankki|säästöpankki|omasp", ("saastopankki.fi", "omasp.fi")),
    "Posti": (["posti-seuranta", "posti-paketti", "posti-fi", "posti-tulli", "posti-lahetys"], r"posti-?(fi|seuranta|paketti|toimitus|tulli|lahetys|lähetys)|(seuranta|paketti|tulli)-?posti", ("posti.fi",)),
    "Traficom": (["traficom"], r"traficom|trafi-", ("traficom.fi",)),
    "Kela": (["kela-", "-kela"], r"kela-\w|kela\.\w|\w-kela", ("kela.fi",)),
    "Vero": (["verohallinto", "vero-palautus", "omavero"], r"verohallinto|vero-?(palautus|fi)|omavero", ("vero.fi",)),
    "Suomi.fi": (["suomifi", "suomi-tunnistus", "suomi-fi"], r"suomi-?fi-|suomifi|suomi-?tunnistus", ("suomi.fi",)),
    "MobilePay": (["mobilepay", "mobile-pay"], r"mobile-?pay", ("mobilepay.fi", "mobilepay.dk", "mobilepay.no", "vippsmobilepay.com")),
    "Operaattorit": (["dna-laskut", "elisa-laskut", "telia-laskut", "dna-tili", "elisa-tili"], r"(dna|elisa|telia)-?(laskut|lasku|login|tili|maksu)", ("dna.fi", "elisa.fi", "telia.fi", "telia.com")),
    "VKC Cards": (["vkc-cards", "vkccards"], r"vkc-?cards", ("vkccards.fi",)),
    # 18.11. lisätty: Suomessa yleisimmät huijausbrändit
    "Matkahuolto": (["matkahuolto"], r"matkahuolto", ("matkahuolto.fi",)),
    "Tori": (["tori-fi", "tori-maksu", "tori-kauppa", "tori-turva"], r"tori-?(fi|maksu|kauppa|turva|toimitus|pay)", ("tori.fi",)),
    "POP Pankki": (["poppankki", "pop-pankki"], r"pop-?pankki", ("poppankki.fi",)),
    "Handelsbanken/Ålandsbanken": (["handelsbanken", "alandsbanken"], r"handelsbanken|alandsbanken|ålandsbanken", ("handelsbanken.fi", "handelsbanken.se", "handelsbanken.com", "handelsbanken.no", "handelsbanken.dk", "handelsbanken.co.uk", "handelsbanken.nl", "alandsbanken.fi", "alandsbanken.ax", "alandsbanken.se", "alandsbanken.com")),
    "Tulli": (["tulli-fi", "tulli-maksu", "suomen-tulli"], r"tulli-?(fi|maksu|lasku|palvelu)|suomen-?tulli", ("tulli.fi",)),
    "Poliisi": (["poliisi-fi", "poliisi-sakko", "poliisi-ilmoitus"], r"poliisi-?(fi|sakko|ilmoitus|maksu)", ("poliisi.fi",)),
    "HSL": (["hsl-fi", "hsl-lippu", "hsl-maksu"], r"hsl-?(fi|lippu|maksu|tili|kortti)", ("hsl.fi",)),
}
KOOTTU = [(n, hs, re.compile(r, re.I), viral) for n, (hs, r, viral) in BRANDIT.items()]

# Kalasteluun viittaavat sanat: brändin lisäksi domainissa pitää olla jokin näistä ⇒ karsii lailliset (eri maiden sivut, kumppanit).
TRIGGERIT = re.compile(r"secure|login|log-?in|signin|verif|tunnist|verkkopankki|verkko-?asiointi|update|account|asiak"
                       r"|kirjaudu|maksu|lask|tili|oma-?|palvelu|confirm|vahvist|auth|mobiili|pankki-|-pankki|turva"
                       r"|paivit|päivit|varmist|viesti|ilmoitus|tulli|toimitus|seuranta|paketti|lahetys|lähetys|refund"
                       r"|palautus|bonus|etu|-fi\b|suomi|online|portal|web-?", re.I)
# brändit joissa mikä tahansa lookalike on epäilyttävä (ei vaadi trigger-sanaa)
ITSESSAAN = {"VKC Cards"}


def loki(*a):
    with (HAK / "tila" / "kalastelijat.log").open("a") as f:
        f.write(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} " + " ".join(map(str, a)) + "\n")


def tg(t):
    try:
        urllib.request.urlopen(urllib.request.Request(f"https://api.telegram.org/bot{AS['tg_token']}/sendMessage",
            data=json.dumps({"chat_id": AS["tg_chat"], "text": t[:4000], "disable_web_page_preview": True}).encode(),
            headers={"Content-Type": "application/json"}), timeout=15)
    except Exception as e:
        loki("TG", e)


def crtsh(hakusana: str) -> list[dict]:
    """crt.sh JSON: viim. varmenteet, joiden nimessä hakusana. Palauttaa [{name, id, issuer, alkoi}]."""
    u = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%{hakusana}%", "output": "json"})
    d = None
    for yr in range(3):
        try:
            d = json.loads(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=90).read() or b"[]")
            break
        except Exception as e:
            if yr == 2:
                loki("crt.sh", hakusana, str(e)[:80]); return []
            time.sleep(15 * (yr + 1))
    if d is None:
        return []
    out = []
    for c in d:
        for nimi in (c.get("name_value") or "").splitlines():
            out.append({"nimi": nimi.lower().lstrip("*.").strip(), "id": c.get("id"),
                        "issuer": (c.get("issuer_name") or "")[:70], "alkoi": c.get("not_before", "")[:10]})
    return out


# yleisimmät 2-tason päätteet (muuten rekisteröity domain = viimeiset 2 labelia)
_KAKSITASO = {"co.uk", "org.uk", "com.au", "co.nz", "com.br", "co.jp", "or.jp", "com.tr"}


def rek_label(d: str) -> str:
    """Rekisteröidyn verkkotunnuksen label (esim. 'nordea-login.com' ⇒ 'nordea-login', 'x.nordeafinans.dk' ⇒ 'nordeafinans')."""
    osat = d.split(".")
    if len(osat) >= 3 and ".".join(osat[-2:]) in _KAKSITASO:
        return osat[-3] if len(osat) >= 3 else ""
    return osat[-2] if len(osat) >= 2 else ""


def virallinen(d: str, viral: tuple) -> bool:
    return any(d == v or d.endswith("." + v) for v in viral)


SALASANA = re.compile(r'type=["\']?password|name=["\']?(pin|tunnus|password|salasana|userid|kayttajatunnus)|tunnistaudu|kirjaudu|verkkopankki|card.?number|kortinnumero|cvv', re.I)
PARKKI = re.compile(r"domain (is )?for sale|parked|this domain|coming soon|sedo|dan\.com|afternic|godaddy|index of /|default web page|welcome to nginx|apache2 .*default", re.I)


def tarkista(d: str, brandi: str) -> str:
    """automaattinen esitarkistus. Avataan sivu; jos siinä on kirjautumis-/korttilomake
    eikä se ole parkkisivu ⇒ 'kalastelu'. Netcraft tarkistaa jokaisen ilmoituksen itse ennen toimenpiteitä."""
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"https://{d}/", headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131 Mobile Safari/537.36"}), timeout=15)
        h = r.read(400_000).decode("utf-8", "ignore")
    except Exception:
        return "ei vastaa"
    if PARKKI.search(h[:20000]) and not SALASANA.search(h):
        return "parkki"
    if SALASANA.search(h):
        return "kalastelu"
    return "epäselvä"


def netcraft(urlit: list) -> str:
    tf = HAK / "tila" / "kalastelu_ilmoitetut.json"
    tila = json.loads(tf.read_text()) if tf.exists() else {}
    uudet = [u for u in urlit if u[0] not in tila]
    if not uudet:
        return ""
    runko = {"email": os.environ.get("REPORT_EMAIL", ""), "urls": [{"url": u, "reason": f"Suspected phishing page impersonating {b} (Finland): "
             "brand name in a newly registered domain (fresh TLS certificate) serving a login/credential form. Auto-detected via "
             "Certificate Transparency monitoring by a volunteer project – please verify."} for u, b in uudet]}
    r = urllib.request.Request("https://report.netcraft.com/api/v3/report/urls", data=json.dumps(runko).encode(),
                               headers={"Content-Type": "application/json", "User-Agent": "kotivahdit-phish-report/1.0"}, method="POST")
    v = json.loads(urllib.request.urlopen(r, timeout=30).read() or b"{}")
    for u, b in uudet:
        tila[u] = {"aika": dt.datetime.now().isoformat(timespec="seconds"), "netcraft": v.get("uuid"), "automaattinen": True, "brandi": b}
    tf.write_text(json.dumps(tila, indent=1))
    return v.get("uuid", "?")


def kierros(nahdyt: set, kuiva=False) -> set:
    tanaan = dt.date.today().isoformat()
    eilen = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    loydot = {}
    for nimi, hakusanat, rx, viral in KOOTTU:
        osumat = {}
        for hs in hakusanat:
            for c in crtsh(hs):
                d = c["nimi"]
                if not d or d in nahdyt or virallinen(d, viral):
                    continue
                label = rek_label(d)                        # huijaus on rekisteröidyssä domainissa, ei laillisen alisivulla
                if not rx.search(label):
                    continue
                if nimi not in ITSESSAAN and not TRIGGERIT.search(label):   # brändi + kalasteluvihje SAMASSA rekisteröidyssä labelissa
                    continue
                # vain tuoreet (eilen/tänään myönnetyt) ⇒ aito ennakkovaroitus, ei vanhoja
                if c["alkoi"] not in (tanaan, eilen):
                    continue
                osumat[d] = c
            time.sleep(2)                       # crt.sh ystävällinen tahti
        for d, c in osumat.items():
            nahdyt.add(d); loydot.setdefault(nimi, []).append((d, c["issuer"]))
    # seuranta: aiemmin "epäselvä"/"ei vastaa" ⇒ tarkistetaan uudelleen 3 pv (kalastelusarja asennetaan usein myöhemmin)
    sf = HAK / "tila" / "kalastelu_seuranta.json"
    seuranta = json.loads(sf.read_text()) if sf.exists() else {}
    myoh = []
    for d, (brandi, alku) in list(seuranta.items()):
        if time.time() - alku > 3 * 86400:
            del seuranta[d]; continue
        if tarkista(d, brandi) == "kalastelu":
            myoh.append((f"https://{d}/", brandi)); del seuranta[d]
    if myoh and not kuiva:
        try:
            u2 = netcraft(myoh)
            if u2:
                tg("🚨 Seurannassa ollut sivu muuttui kalastelusivuksi – ilmoitettu Netcraftille:\n" + "\n".join(f"• {b}: {u}" for u, b in myoh))
        except Exception as e:
            loki("netcraft", str(e)[:120])
    if loydot:
        rivit, ilmoitettavat = [], []
        for brandi, lista in loydot.items():
            for d, issuer in sorted(set(lista))[:8]:
                t = tarkista(d, brandi)
                if t == "kalastelu":
                    ilmoitettavat.append((f"https://{d}/", brandi))
                elif t in ("epäselvä", "ei vastaa"):
                    seuranta[d] = (brandi, time.time())
                rivit.append(f"• {brandi}: {d}  ({issuer.split(',')[0][:40]}) – {t}")
        uuid = ""
        if ilmoitettavat and not kuiva:
            try:
                uuid = netcraft(ilmoitettavat)
            except Exception as e:
                loki("netcraft", str(e)[:120])
        viesti = ("🎣 Uusia mahdollisia kalastelusivuja (tuoreet TLS-varmenteet):\n" + "\n".join(rivit[:25])
                  + (f"\n\n🚨 {len(ilmoitettavat)} kirjautumislomakkeellista sivua ilmoitettu automaattisesti Netcraftille (sulkeminen + selainvaroitukset), tunniste {uuid}."
                     " Ilmoita halutessasi myös: kyberturvallisuuskeskus.fi/ilmoita" if uuid else "")
                  + ("\n'epäselvä' = sivu vastaa mutta ei lomaketta (vielä) – seurataan." if any("epäselvä" in r for r in rivit) else ""))
        loki(f"{sum(len(v) for v in loydot.values())} ehdokasta: {list(loydot)}")
        print(viesti) if kuiva else tg(viesti)
    else:
        loki("ei uusia ehdokkaita")
    sf.write_text(json.dumps(seuranta))
    return nahdyt


def main():
    nahdyt = set(json.loads(TF.read_text())) if TF.exists() else set()
    kuiva = "--kuiva" in sys.argv
    while True:
        try:
            nahdyt = kierros(nahdyt, kuiva)
            TF.write_text(json.dumps(sorted(nahdyt)[-50000:]))
        except Exception as e:
            loki("kierros", str(e)[:120])
        if kuiva:
            break
        time.sleep(VALI_S)


if __name__ == "__main__":
    main()
