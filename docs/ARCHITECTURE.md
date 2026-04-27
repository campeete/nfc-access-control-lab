# Architecture Decision Log

## ADR-001: Split Licensing Model
**Date:** 2026-04-28 | **Status:** Accepted

**Decision:** MIT for core firmware, GPL v3 for crypto modules, Proprietary for dashboard.
**Reason:** Core is recruiter-accessible. Crypto forces open-source derivatives. Dashboard monetizable as SaaS.

---

## ADR-002: ESP32 over Arduino Uno as Primary Controller
**Date:** 2026-04-28 | **Status:** Accepted

**Decision:** ESP32 as primary, Arduino as secondary/fallback.
**Reason:** WiFi/BT built in for dashboard comms. More flash for crypto operations.

---

## ADR-003: HMAC-SHA256 for Phase 3 Authentication
**Date:** 2026-04-28 | **Status:** Accepted

**Decision:** HMAC-SHA256 with 128-bit random challenge, 32-byte response.
**Reason:** Prevents replay attacks. Demonstrates real-world secure element concepts.

---

## ADR-004: SQLite for Dashboard v1
**Date:** 2026-04-28 | **Status:** Accepted

**Decision:** SQLite for v1, PostgreSQL migration path documented.
**Reason:** Zero-config setup. Easy demo. PostgreSQL upgrade path for SaaS deployment.
