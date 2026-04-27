#!/usr/bin/env python3
"""
NFC Access Control Lab — Phase 4 Attack: APDU Command Fuzzer
License: MIT
Author: Cameron Peete

CONCEPT: Send malformed, unexpected, or boundary-case APDU commands
to the NFC reader firmware to discover crashes, hangs, or unexpected behavior.

BACKGROUND:
  APDU (Application Protocol Data Unit) is the communication format used
  between NFC cards and readers. Malformed APDUs can cause:
  - Buffer overflows (if firmware doesn't validate length)
  - Infinite loops (malformed state machine input)
  - Unexpected auth bypass (edge case in UID comparison logic)
  - Information disclosure (error messages revealing internal state)

FUZZING STRATEGY:
  1. Mutation-based: take valid APDU, flip bytes, truncate, extend
  2. Generation-based: build APDUs from spec with invalid field values
  3. Boundary: test min/max lengths, all-zero, all-FF payloads

MITRE ATT&CK: T1203 — Exploitation for Client Execution

Requirements: pip install nfcpy scapy
"""

import random
import time
import struct
import sqlite3
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from tqdm import tqdm

# ── APDU structure ────────────────────────────────────────────────────────────
@dataclass
class APDU:
    """
    ISO 7816-4 APDU format:
    CLA | INS | P1 | P2 | Lc | Data | Le
    """
    cla: int = 0x00
    ins: int = 0x00
    p1: int = 0x00
    p2: int = 0x00
    data: bytes = b''
    le: Optional[int] = None
    
    def to_bytes(self) -> bytes:
        result = bytes([self.cla, self.ins, self.p1, self.p2])
        if self.data:
            result += bytes([len(self.data)]) + self.data
        if self.le is not None:
            result += bytes([self.le])
        return result
    
    def __repr__(self):
        return (f"APDU(CLA={self.cla:02X} INS={self.ins:02X} "
                f"P1={self.p1:02X} P2={self.p2:02X} "
                f"DATA={self.data.hex().upper()} LE={self.le})")

# ── Valid APDU templates (baseline for mutation) ──────────────────────────────
VALID_APDUS = [
    APDU(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=b'\xD2\x76\x00\x00\x85\x01\x01'),  # SELECT
    APDU(cla=0x00, ins=0xB0, p1=0x00, p2=0x00, le=0x10),  # READ BINARY
    APDU(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=b'\x00' * 16),  # UPDATE BINARY
    APDU(cla=0xFF, ins=0xCA, p1=0x00, p2=0x00, le=0x00),  # GET UID
    APDU(cla=0x60, ins=0x00, p1=0x00, p2=0x00),  # MIFARE auth block 0
]

# ── Fuzz generators ───────────────────────────────────────────────────────────
class APDUFuzzer:
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.generated = []
    
    def boundary_cases(self):
        """Test boundary values — max lengths, zero lengths, overflow."""
        cases = []
        
        # Empty APDU
        cases.append(APDU())
        
        # All zeros
        cases.append(APDU(cla=0x00, ins=0x00, p1=0x00, p2=0x00, data=b'\x00'*255))
        
        # All 0xFF
        cases.append(APDU(cla=0xFF, ins=0xFF, p1=0xFF, p2=0xFF, data=b'\xFF'*255))
        
        # Max length data
        cases.append(APDU(data=b'\xAA' * 255))
        
        # Le = 0 (means 256 in ISO 7816)
        cases.append(APDU(cla=0x00, ins=0xB0, p1=0x00, p2=0x00, le=0x00))
        
        # Lc/Le mismatch
        cases.append(APDU(data=b'\x01\x02\x03', le=0xFF))
        
        # Wrong class byte
        for cla in [0x01, 0x10, 0x20, 0x40, 0x80, 0x90, 0xA0, 0xC0, 0xE0]:
            cases.append(APDU(cla=cla, ins=0xA4, p1=0x04, p2=0x00))
        
        return cases
    
    def mutation_fuzz(self, base: APDU, count: int = 50):
        """Mutate a valid APDU in random ways."""
        mutations = []
        base_bytes = base.to_bytes()
        
        for _ in range(count):
            mutated = bytearray(base_bytes)
            
            mutation_type = random.choice([
                'flip_bit', 'random_byte', 'truncate',
                'extend', 'duplicate', 'zero_field'
            ])
            
            if mutation_type == 'flip_bit' and mutated:
                pos = random.randint(0, len(mutated) - 1)
                bit = random.randint(0, 7)
                mutated[pos] ^= (1 << bit)
            
            elif mutation_type == 'random_byte' and mutated:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
            
            elif mutation_type == 'truncate' and len(mutated) > 1:
                cut = random.randint(1, len(mutated))
                mutated = mutated[:cut]
            
            elif mutation_type == 'extend':
                extra = random.randint(1, 50)
                mutated += bytes([random.randint(0, 255) for _ in range(extra)])
            
            elif mutation_type == 'duplicate' and mutated:
                pos = random.randint(0, len(mutated) - 1)
                mutated = mutated[:pos] + bytes([mutated[pos]]) + mutated[pos:]
            
            elif mutation_type == 'zero_field':
                field = random.choice([0, 1, 2, 3])
                if field < len(mutated):
                    mutated[field] = 0
            
            mutations.append(bytes(mutated))
        
        return mutations
    
    def generate_all(self, mutations_per_base: int = 20):
        """Generate full fuzzing corpus."""
        corpus = []
        
        # Boundary cases
        corpus.extend([(str(a), a.to_bytes()) for a in self.boundary_cases()])
        
        # Mutations of valid APDUs
        for base in VALID_APDUS:
            muts = self.mutation_fuzz(base, mutations_per_base)
            corpus.extend([(f"mut_{base.ins:02X}_{i}", m) 
                          for i, m in enumerate(muts)])
        
        return corpus

# ── Simulated fuzzing runner ──────────────────────────────────────────────────
class FuzzRunner:
    def __init__(self, simulate: bool = True):
        self.simulate = simulate
        self.results = []
    
    def send_apdu(self, raw: bytes) -> tuple[str, float, str]:
        """Send APDU and return (response_code, time_ms, notes)."""
        start = time.perf_counter()
        
        if self.simulate:
            time.sleep(random.uniform(0.01, 0.05))
            
            # Simulate interesting responses for certain inputs
            if len(raw) == 0:
                response = "6700"  # Wrong length
                notes = "Empty APDU — wrong length error"
            elif len(raw) > 200:
                response = "6700"
                notes = "Oversized APDU — length error"
            elif raw[0] == 0xFF and len(raw) >= 5:
                response = "9000"  # Success
                notes = "Valid class byte"
            elif raw == b'\x00' * 4:
                response = "CRASH_SIM"
                notes = "All-zero APDU — simulated crash"
            else:
                response = random.choice(["9000", "6A82", "6900", "6700", "6F00"])
                notes = ""
        else:
            # Hardware implementation
            raise NotImplementedError("Hardware fuzzing requires NFC hardware")
        
        elapsed = (time.perf_counter() - start) * 1000
        return response, elapsed, notes
    
    def run(self, corpus: list, db_path: str = "fuzz_results.db"):
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fuzz_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, label TEXT, raw_hex TEXT,
                response TEXT, time_ms REAL, notes TEXT,
                interesting INTEGER DEFAULT 0
            )
        """)
        
        interesting = []
        
        print(f"[*] Fuzzing {len(corpus)} APDU variants...")
        for label, raw in tqdm(corpus, desc="Fuzzing"):
            response, time_ms, notes = self.send_apdu(raw)
            
            # Flag interesting responses
            is_interesting = 0
            if response in ["CRASH_SIM", "TIMEOUT"] or time_ms > 100:
                is_interesting = 1
                interesting.append((label, raw.hex(), response, time_ms, notes))
            
            conn.execute(
                "INSERT INTO fuzz_results VALUES (NULL,?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), label, raw.hex().upper(),
                 response, time_ms, notes, is_interesting)
            )
        
        conn.commit()
        
        print(f"\n[+] Fuzzing complete — {len(corpus)} cases")
        print(f"[!] Interesting findings: {len(interesting)}")
        for label, raw, resp, ms, notes in interesting:
            print(f"    [{label}] {raw[:20]}... → {resp} ({ms:.1f}ms) {notes}")
        
        print(f"[*] Results saved to {db_path}")
        conn.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='NFC APDU Fuzzer')
    parser.add_argument('--mutations', type=int, default=20)
    parser.add_argument('--simulate', action='store_true', default=True)
    parser.add_argument('--db', default='fuzz_results.db')
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════╗
║        NFC APDU FUZZER — PHASE 4             ║
║   Finding crashes in NFC firmware            ║
╚══════════════════════════════════════════════╝
    """)

    fuzzer = APDUFuzzer()
    corpus = fuzzer.generate_all(args.mutations)
    print(f"[*] Generated {len(corpus)} APDU test cases")

    runner = FuzzRunner(simulate=args.simulate)
    runner.run(corpus, args.db)

if __name__ == '__main__':
    main()
