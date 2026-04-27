#!/usr/bin/env python3
"""
NFC Access Control Lab — Attack Tool: UID Spoofer
License: MIT
Author: Cameron Peete

CONCEPT: Demonstrates why Phase 1 (UID-only) auth is insecure.
Reads a target card's UID and replays it to the reader.

SECURITY LESSON:
  UIDs are publicly readable — no authentication required to read them.
  Any NFC reader (including phones) can read a MIFARE UID in milliseconds.
  This tool shows how trivial cloning is against Phase 1 systems.

Requirements: pip install nfcpy
Hardware: PN532 or ACR122U connected via USB
"""

import nfc
import binascii
import time
import argparse

def read_uid(tag):
    """Read and return UID from scanned card."""
    uid = binascii.hexlify(tag.identifier).decode('utf-8').upper()
    print(f"[READ] Card UID: {uid}")
    print(f"[READ] Card type: {tag.type}")
    return uid

def spoof_uid(target_uid_hex: str):
    """
    Emulate a card with the specified UID.
    
    Note: UID spoofing requires a 'magic card' (Chinese clone) that allows
    block 0 to be overwritten. Standard MIFARE cards have fixed UIDs.
    
    Cryptographic note: This is why Phase 3 (HMAC challenge-response) is
    necessary — even with the correct UID, an attacker cannot forge the MAC
    without the shared secret.
    """
    print(f"[SPOOF] Attempting to emulate UID: {target_uid_hex}")
    print("[SPOOF] Note: Requires magic/writable card for hardware emulation")
    print("[SPOOF] Flipper Zero BadCard mode can also perform this attack")
    
    uid_bytes = bytes.fromhex(target_uid_hex)
    
    # In full implementation: write UID to magic card block 0
    # Magic card commands are vendor-specific (e.g., 0x40, 0x43 unlock sequence)
    print(f"[SPOOF] Target UID bytes: {[hex(b) for b in uid_bytes]}")
    print("[SPOOF] Present magic card to writer to complete spoof")

def main():
    parser = argparse.ArgumentParser(description='NFC UID Spoofer — Lab Demo Tool')
    parser.add_argument('--mode', choices=['read', 'spoof'], required=True,
                        help='read: scan and print UID | spoof: emulate target UID')
    parser.add_argument('--uid', type=str, help='Target UID to spoof (hex, e.g. DEADBEEF)')
    args = parser.parse_args()

    if args.mode == 'read':
        print("[*] Waiting for card — tap now...")
        with nfc.ContactlessFrontend('usb') as clf:
            tag = clf.connect(rdwr={'on-connect': lambda tag: False})
            if tag:
                read_uid(tag)
    
    elif args.mode == 'spoof':
        if not args.uid:
            print("[ERROR] --uid required for spoof mode")
            return
        spoof_uid(args.uid.upper().replace(':', '').replace(' ', ''))

if __name__ == '__main__':
    main()
