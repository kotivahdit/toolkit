# Attackers are fingerprinting LLM honeypots – with a structured probe battery

*Kotivahdit field note, 21 November 2026*

## Summary

Within hours of exposing an LLM-backed SSH honeypot (Beelzebub + a small local model) we observed a **structured, automated
probe battery** whose only purpose is to tell an emulated or LLM-generated shell apart from a real one. Over ~20 hours:

| | |
|---|---|
| Commands received | **7 934** |
| SSH sessions | **4 310** |
| Source IPs | **12**, in three /24 clusters (`195.178.110.0/24`, `109.160.32.0/24`, `92.118.39.0/24`) |
| Client banner | mostly `SSH-2.0-Go` |
| Probe types | **7**, each executed **604 times** in lock-step |

## The probe battery

Every run uses a fresh random 32-hex nonce (`<N>`) and wraps it in markers so the answer can be checked byte-for-byte:

| Probe | Command (shape) | What a real shell returns | Why an LLM fails |
|---|---|---|---|
| `small_control` | `sh -c 'printf "\n%s|%s\n" check_<N>_small_control check_<N>'` | the two strings, exactly | LLMs paraphrase, add code fences or explanations |
| `small_math` | `printf … "$((153*51+24))"` | `7827` | small models get arithmetic wrong |
| `small_pid` | `printf … "$$"` | a plausible PID | LLMs return constants or text |
| `arg` / positional | `set -- check_<N>_arg1 check_<N>_arg2; printf … "$#|$1|$2"` | `2|…arg1|…arg2` | quoting / `$#` handling breaks |
| `small_function` | `f_check_<N>() { printf … "$1|$#"; }; f_check_<N> …` | exact echo of args | shell function semantics are rarely emulated |
| `small_done` | `printf "\n%s\n" check_<N>_small_done` | marker | end-of-battery sentinel |
| `transport_done` | `echo; echo 'check_<N>_transport_done'` | marker | transport/session sanity check |

The battery is followed by classic recon (`uname -s -v -n -r -m`, …) only on hosts that pass – i.e. **failing the battery
gets a honeypot silently ignored**, and its operator never sees the interesting second stage.

Recent academic work (CTU Prague, *"Ghost Without Shell"*, 2026) documents simpler correctness probes (`echo $((7*6))`,
base64 round-trips). We have not found the nonce-marked multi-probe battery above described publicly.

## Countermeasure: answer deterministic probes with a real (isolated) shell

[`llm-shim/llm_shim.py`](../llm-shim/llm_shim.py) sits between the honeypot and the model. If a command consists **only** of
safe shell builtins (`printf`, `echo`, `set`, `expr`, `test`, arithmetic, locally defined functions) and contains no
command substitution, redirection, pipes or paths, it is executed by a real `dash` with:
no network namespace (`unshare -n`), user `nobody`, `no_new_privs`, 64 MB address space, 8 processes, 1 s timeout.
Everything else still goes to the LLM.

Replaying all 7 934 observed commands: **471 / 471 distinct probe commands** were answered exactly like a real shell
(~0.03 s each); all tested dangerous commands (`$(…)`, back-ticks, redirection, pipes, `cat /etc/…`, `wget`) were routed to the LLM.

## Indicators

Source networks: `195.178.110.0/24`, `109.160.32.0/24`, `92.118.39.0/24` (all reported to AbuseIPDB).
Marker regex: `check_[0-9a-f]{32}_(small_(control|math|pid|function|done|positional)|arg[12]|transport_done)`

## Takeaways for LLM-honeypot builders

1. Assume you **will be fingerprinted**; measure your pass rate against a probe corpus, not against humans.
2. Route deterministic builtins to a real, sandboxed interpreter; keep the LLM for the open-ended parts.
3. Never let the model add prose, code fences or explanations to command output.

*Kotivahdit is a volunteer honeypot network. Passive only – no hack-back. Contact: kotivahdit@proton.me*
