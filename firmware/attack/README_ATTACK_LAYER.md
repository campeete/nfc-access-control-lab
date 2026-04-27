# Phase 4 — Attack Layer

This directory contains red team tools demonstrating vulnerabilities in each firmware phase. Each tool is paired with a defense lesson explaining why Phase 3 resists the attack.

## Tools

| Tool | Target Phase | Attack Type | MITRE |
|------|-------------|-------------|-------|
| `uid_bruteforce.py` | Phase 1 | Brute force UID enumeration | T1110.001 |
| `timing_sidechannel.py` | Phase 1/2 | Statistical timing analysis | T1552 |
| `apdu_fuzzer.py` | All phases | Malformed input fuzzing | T1203 |
| `flipper_nfc_attacks.txt` | Phase 1/2 | Hardware NFC emulation | T1557 |
| `uid_spoof.py` | Phase 1 | Card cloning/emulation | T1557 |
| `replay_attack.py` | Phase 1/2 | Session replay | T1550 |

## Quick Start

```bash
# Run all tools in simulation mode (no hardware needed)
python3 uid_bruteforce.py --mode common --simulate
python3 timing_sidechannel.py --phase 1 --samples 50
python3 apdu_fuzzer.py --simulate

# Compare Phase 1 vs Phase 3 timing vulnerability
python3 timing_sidechannel.py --phase 1 --plot
python3 timing_sidechannel.py --phase 3 --plot
```

## Attack vs Defense Matrix

| Attack | Phase 1 | Phase 2 | Phase 3 |
|--------|---------|---------|---------|
| UID Brute Force | VULNERABLE | Slow (lockout) | IMMUNE (UID irrelevant) |
| Card Cloning | VULNERABLE | VULNERABLE | IMMUNE (needs secret) |
| Replay Attack | VULNERABLE | VULNERABLE | IMMUNE (random challenge) |
| Timing Side-Channel | VULNERABLE | VULNERABLE | IMMUNE (constant-time) |
| APDU Fuzzing | Possible | Possible | Hardened |

## Database Logs

All attacks log to SQLite for dashboard integration:
- `brute_results.db` — UID brute force attempts + hits
- `fuzz_results.db` — APDU fuzzing results + interesting findings
