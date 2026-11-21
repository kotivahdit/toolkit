# Kotivahdit-työkalupakki

**Pieniä, riippuvuuksettomia ansoja, jotka tuhlaavat hyökkääjien aikaa ja muuttavat heidän toimintansa ilmoituksiksi.**
Ylläpitäjä: *Kotivahdit*, suomalainen vapaaehtoinen hunajapurkkiverkosto (sensorit Tukholmassa ja Iowassa).

| Työkalu | Mitä tekee |
|---|---|
| `tarpit/telnet_tarpit.py` | Telnet-tervakuoppa Mirai-boteille: ei koskaan login-kehotetta, tavu ~10 s välein. Enintään 5 yhteyttä / IP. |
| `tarpit/silent_pit.py` | "Hiljainen kuoppa": tietokanta- ja etätyöpöytämurtautujat ohjataan kuoppaan, joka ei vastaa koskaan. |
| `web-trap/web_trap.py` | Reititinmäinen web-ansa: tunnistaa murtoyritykset, jumittaa ne ja tarjoaa syöttitiedostoja (`.env` ym.) syöttiavaimilla. |
| `docker-trap/docker_trap.py` | Väärennetty avoin Docker-rajapinta: kerää kryptovarkaiden käskyt, imaget ja lompakot, ei aja mitään. |
| `llm-shim/llm_shim.py` | Tekoälyansan välikappale: rikollisten tunnistustestit (laskut, printf, parametrit) ajetaan oikeassa eristetyssä shellissä, muut tekoälylle. |
| `phish-watch/phish_watch.py` | Kalastelijavahti: uusien TLS-varmenteiden seuranta suomalaisille brändeille ja automaattinen Netcraft-ilmoitus. |

**Periaatteet:** vain passiivinen (ei vastaiskuja eikä skannausta), ansat eristettyinä ja ilman ulospäin lähtevää liikennettä, raportointi AbuseIPDB:hen, abuse.ch:lle, SANS ISC:lle, OTX:ään, CrowdSeciin, GreyNoiselle ja Netcraftille.

Lisenssi: MIT.
