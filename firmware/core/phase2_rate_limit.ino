/*
 * NFC Access Control Lab — Phase 2: Rate Limiting + Lockout
 * License: MIT
 * Author: Cameron Peete
 *
 * CONCEPT: Adds brute-force protection via failed attempt tracking per UID.
 * VULNERABILITY: Still uses static UID — replay attack still works.
 * Phase 2 adds lockout but doesn't fix the fundamental cloning problem.
 *
 * Security concept: This is defense-in-depth layer 1 — rate limiting
 * slows attackers but doesn't prevent cloned card attacks.
 */

#include <SPI.h>
#include <Adafruit_PN532.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <map>
#include <vector>
#include <string>

#define PN532_SCK  18
#define PN532_MISO 19
#define PN532_MOSI 23
#define PN532_SS   5

Adafruit_PN532 nfc(PN532_SS);
Adafruit_SSD1306 display(128, 64, &Wire, -1);

// ── Config ───────────────────────────────────────────────────────────────────
const uint8_t MAX_ATTEMPTS    = 3;    // Failed attempts before lockout
const uint32_t LOCKOUT_MS     = 30000; // 30 second lockout
const uint32_t WINDOW_MS      = 60000; // 1 minute attempt window

// ── Allowlist ────────────────────────────────────────────────────────────────
const uint8_t ALLOWLIST[][4] = {
  { 0xDE, 0xAD, 0xBE, 0xEF },
  { 0x12, 0x34, 0x56, 0x78 },
};
const uint8_t ALLOWLIST_SIZE = sizeof(ALLOWLIST) / sizeof(ALLOWLIST[0]);

// ── Rate limit tracking ───────────────────────────────────────────────────────
struct CardRecord {
  uint8_t failCount;
  uint32_t firstFailTime;
  uint32_t lockoutStart;
};

std::map<std::string, CardRecord> cardRecords;

// ── UID to string key ─────────────────────────────────────────────────────────
std::string uidToKey(const uint8_t *uid, uint8_t len) {
  std::string key = "";
  for (uint8_t i = 0; i < len; i++) {
    char buf[3];
    sprintf(buf, "%02X", uid[i]);
    key += buf;
  }
  return key;
}

bool uidMatch(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 4) == 0;
}

void showMessage(const char *line1, const char *line2 = "", bool invert = false) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(invert ? BLACK : WHITE, invert ? WHITE : BLACK);
  display.setCursor(0, 20);
  display.println(line1);
  display.setCursor(0, 36);
  display.println(line2);
  display.display();
}

void setup() {
  Serial.begin(115200);
  Wire.begin(21, 22);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  nfc.begin();
  nfc.SAMConfig();
  showMessage("NFC LAB P2", "SCAN CARD");
  Serial.println("[NFC Lab] Phase 2: Rate Limiting Ready");
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen)) return;

  std::string key = uidToKey(uid, uidLen);
  uint32_t now = millis();

  // Initialize record if first time seeing this UID
  if (cardRecords.find(key) == cardRecords.end()) {
    cardRecords[key] = { 0, 0, 0 };
  }
  CardRecord &rec = cardRecords[key];

  // Check lockout
  if (rec.lockoutStart > 0 && (now - rec.lockoutStart) < LOCKOUT_MS) {
    uint32_t remaining = (LOCKOUT_MS - (now - rec.lockoutStart)) / 1000;
    Serial.print("[LOCKED] UID locked out for ");
    Serial.print(remaining);
    Serial.println("s");
    char buf[20];
    sprintf(buf, "WAIT %lus", remaining);
    showMessage("LOCKED OUT", buf, true);
    delay(2000);
    showMessage("NFC LAB P2", "SCAN CARD");
    return;
  }

  // Reset window if expired
  if (rec.firstFailTime > 0 && (now - rec.firstFailTime) > WINDOW_MS) {
    rec.failCount = 0;
    rec.firstFailTime = 0;
  }

  // Check allowlist
  bool granted = false;
  for (uint8_t i = 0; i < ALLOWLIST_SIZE; i++) {
    if (uidMatch(uid, ALLOWLIST[i])) { granted = true; break; }
  }

  if (granted) {
    rec.failCount = 0;
    rec.firstFailTime = 0;
    rec.lockoutStart = 0;
    Serial.println("[AUTH] ACCESS GRANTED");
    showMessage("ACCESS", "GRANTED");
  } else {
    if (rec.firstFailTime == 0) rec.firstFailTime = now;
    rec.failCount++;
    Serial.print("[AUTH] DENIED — fail ");
    Serial.print(rec.failCount);
    Serial.print("/");
    Serial.println(MAX_ATTEMPTS);

    if (rec.failCount >= MAX_ATTEMPTS) {
      rec.lockoutStart = now;
      Serial.println("[LOCKOUT] Card locked out");
      showMessage("LOCKED OUT", "30 SECONDS", true);
    } else {
      showMessage("ACCESS", "DENIED", true);
    }
  }

  delay(2000);
  showMessage("NFC LAB P2", "SCAN CARD");
}
