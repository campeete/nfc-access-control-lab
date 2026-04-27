# NFC/RFID Access Control Lab

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-orange.svg)
![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)
![Platform: ESP32](https://img.shields.io/badge/Platform-ESP32-red.svg)

A hardware security research lab demonstrating NFC/RFID access control vulnerabilities, cryptographic defenses, and red team attack techniques using real embedded systems.

> Built as part of a cybersecurity portfolio targeting federal security roles. All attack research is conducted in a controlled lab environment on owned hardware.

---

## What This Project Does

This lab implements a three-phase NFC access control system on ESP32/Arduino hardware, progressing from basic UID allowlisting through rate limiting to full HMAC-SHA256 cryptographic authentication — then attacks each phase to demonstrate real-world vulnerabilities in physical access control systems.

**The core research question:** How does cryptographic strength of NFC authentication affect resistance to replay, brute force, and cloning attacks?

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ATTACK LAYER                          │
│         Replay | Brute Force | Card Clone | Fuzzing     │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                 FIRMWARE STACK                           │
│  Phase 1: UID Allowlist  →  Phase 2: Rate Limit         │
│  Phase 3: HMAC-SHA256 Challenge-Response                 │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                 HARDWARE LAYER                           │
│   ESP32 + PN532 NFC Module + OLED Display + MIFARE      │
└─────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│              WEB DASHBOARD (Premium)                     │
│   Node.js/Express + React/Vite + SQLite                  │
│   Access logs | Anomaly detection | Alert system         │
└─────────────────────────────────────────────────────────┘
```

---

## Repo Structure

```
nfc-access-control-lab/
├── firmware/
│   ├── core/              # Phase 1 & 2 firmware (MIT)
│   └── crypto/            # Phase 3 HMAC-SHA256 module (GPL v3)
│   └── attack/            # Red team attack scripts (MIT)
├── dashboard/
│   ├── frontend/          # React/Vite web dashboard (Proprietary)
│   └── backend/           # Node.js/Express API (Proprietary)
├── docs/
│   ├── diagrams/          # Architecture diagrams
│   └── runbooks/          # Step-by-step lab runbooks
├── scripts/               # Setup and flash scripts
└── .github/workflows/     # CI/CD
```

---

## Firmware Phases

| Phase | Description | Auth Method | Status |
|-------|-------------|-------------|--------|
| 1 | UID Allowlist | Static UID match | ✅ Complete |
| 2 | Rate Limiting | UID + lockout | ✅ Complete |
| 3 | HMAC-SHA256 | Challenge-response | ✅ Complete |
| 4 | Attack Layer | Red team tools | 🔄 In Progress |

---

## Hardware Requirements

| Component | Part | Purpose |
|-----------|------|---------|
| Microcontroller | ESP32 DevKit or Arduino Uno/Mega | Main controller |
| NFC Module | PN532 | Card read/write |
| Display | SSD1306 OLED (128x64) | Status display |
| Cards | MIFARE Classic 1K, Ultralight-C | Target cards |
| Dev Machine | Kali Linux | Attack + flash platform |

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/campeete/nfc-access-control-lab.git
cd nfc-access-control-lab

# Flash Phase 1 firmware
cd firmware/core
# Open in Arduino IDE or PlatformIO
# Select board: ESP32 Dev Module
# Upload phase1_uid_allowlist.ino

# Run the dashboard (requires Node.js 18+)
cd dashboard/backend
npm install
npm run dev
```

---

## Attack Research

The `firmware/attack/` directory contains tools for:
- **Replay attacks** — capture and retransmit valid NFC authentication sequences
- **UID spoofing** — clone card UIDs using Flipper Zero or PN532
- **Brute force** — enumerate valid UIDs against Phase 1 systems
- **Fuzzing** — malformed APDU command injection

> All attack tools are for use on owned hardware in lab environments only.

---

## Licensing

This project uses a split licensing model:

| Layer | License | Details |
|-------|---------|---------|
| `firmware/core/` | MIT | Free to use, modify, distribute |
| `firmware/crypto/` | GPL v3 | Modifications must stay open-source |
| `firmware/attack/` | MIT | Free to use, modify, distribute |
| `dashboard/` | Proprietary | See `dashboard/LICENSE` |

---

## Roadmap

- [x] Phase 1: UID Allowlist firmware
- [x] Phase 2: Rate limiting firmware  
- [x] Phase 3: HMAC-SHA256 firmware
- [ ] Phase 4: Attack layer tools
- [ ] PN532 hardware bring-up
- [ ] Web dashboard v1
- [ ] Unsaflok vulnerability research module
- [ ] Hotel keycard security research integration

---

## Author

**Cameron Peete** — Cybersecurity hardware researcher based in Chicago, IL.
Targeting federal cybersecurity roles (NSA, DHS, CISA).

[![GitHub](https://img.shields.io/badge/GitHub-campeete-black)](https://github.com/campeete)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Cameron_Peete-blue)](https://linkedin.com/in/cameronpeete)

---

## References

- [MIFARE Classic Security Analysis](https://www.cs.ru.nl/~flaviog/publications/Attack.MIFARE.pdf)
- [Unsaflok Vulnerability Disclosure](https://unsaflok.com)
- [PN532 User Manual](https://www.nxp.com/docs/en/user-guide/141520.pdf)
- [HMAC-SHA256 RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)
