#!/usr/bin/env python3
"""
NFC Access Control Lab — Attack Tool: Replay Attack Demonstrator
License: MIT
Author: Cameron Peete

CONCEPT: Captures a valid authentication sequence and replays it.
Demonstrates why Phase 1/2 are vulnerable and why Phase 3's random
challenge prevents this attack entirely.

SECURITY LESSON:
  Without a nonce/challenge, any recorded auth sequence can be replayed.
  HMAC with random challenge means each auth is unique — replay fails
  because the challenge changes on every authentication attempt.

Cryptographic concepts:
  Replay attack: attacker records auth(UID) and retransmits
  Prevention: auth(HMAC(secret, random_challenge)) — unique every time
"""

import time
import json
from datetime import datetime

class ReplayAttackDemo:
    def __init__(self):
        self.captured_sessions = []
    
    def capture_session(self, uid: str, phase: int):
        """Simulate capturing an auth session."""
        session = {
            'uid': uid,
            'phase': phase,
            'timestamp': datetime.now().isoformat(),
            'raw_bytes': f"AUTH_REQUEST:{uid}",
        }
        if phase == 3:
            # Phase 3 includes challenge — different every time
            import os
            session['challenge'] = os.urandom(16).hex()
            session['mac'] = f"HMAC(secret, {session['challenge']})"
        
        self.captured_sessions.append(session)
        print(f"[CAPTURE] Session captured: {json.dumps(session, indent=2)}")
        return session
    
    def replay_session(self, session: dict):
        """Attempt to replay a captured session."""
        print(f"\n[REPLAY] Attempting replay of session from {session['timestamp']}")
        
        if session['phase'] in [1, 2]:
            print(f"[REPLAY] Phase {session['phase']} — Static UID auth")
            print(f"[REPLAY] Sending: {session['raw_bytes']}")
            print(f"[REPLAY] RESULT: SUCCESS — Phase {session['phase']} accepts replay")
            print(f"[REPLAY] Vulnerability confirmed: no nonce, same UID always works")
            return True
        
        elif session['phase'] == 3:
            print(f"[REPLAY] Phase 3 — HMAC challenge-response auth")
            print(f"[REPLAY] Old challenge: {session['challenge']}")
            print(f"[REPLAY] Old MAC: {session['mac']}")
            print(f"[REPLAY] Reader generates NEW challenge — old MAC is invalid")
            print(f"[REPLAY] RESULT: FAILED — Phase 3 immune to replay attacks")
            print(f"[REPLAY] Lesson: random challenge = unique MAC = replay impossible")
            return False

def demo():
    """Run a full replay attack demonstration across all phases."""
    demo = ReplayAttackDemo()
    uid = "DE:AD:BE:EF"
    
    print("=" * 60)
    print("NFC REPLAY ATTACK DEMONSTRATION")
    print("=" * 60)
    
    for phase in [1, 2, 3]:
        print(f"\n--- PHASE {phase} ATTACK ---")
        session = demo.capture_session(uid, phase)
        time.sleep(0.5)
        result = demo.replay_session(session)
        print(f"[RESULT] Replay {'succeeded' if result else 'failed'} on Phase {phase}")
    
    print("\n" + "=" * 60)
    print("SUMMARY: Phase 1 and 2 are vulnerable to replay attacks.")
    print("Phase 3 HMAC-SHA256 with random challenge prevents replay.")
    print("=" * 60)

if __name__ == '__main__':
    demo()
