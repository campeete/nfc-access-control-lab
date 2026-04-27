/*
 * NFC Access Control Lab — Phase 1: UID Allowlist
 * License: MIT
 * Author: Cameron Peete
 *
 * CONCEPT: Static UID matching — the simplest form of NFC auth.
 * VULNERABILITY: UIDs are readable by any NFC reader and trivially clonable.
 * This phase demonstrates WHY static UID auth is insufficient.
 *
 * Hardware: ESP32 + PN532 (SPI) + SSD1306 OLED
 */

#include <SPI.h>
#include <Adafruit_PN532.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>

// ── Pin definitions ──────────────────────────────────────────────────────────
#define PN532_SCK  18
#define PN532_MISO 19
#define PN532_MOSI 23
#define PN532_SS   5
#define OLED_SDA   21
#define OLED_SCL   22

// ── Hardware objects ─────────────────────────────────────────────────────────
Adafruit_PN532 nfc(PN532_SS);
Adafruit_SSD1306 display(128, 64, &Wire, -1);

// ── Allowlist — add authorized UIDs here ─────────────────────────────────────
// Format: { 0xAA, 0xBB, 0xCC, 0xDD } — read from serial monitor on first scan
const uint8_t ALLOWLIST[][4] = {
  { 0xDE, 0xAD, 0xBE, 0xEF },  // Card 1 — replace with real UID
  { 0x12, 0x34, 0x56, 0x78 },  // Card 2 — replace with real UID
};
const uint8_t ALLOWLIST_SIZE = sizeof(ALLOWLIST) / sizeof(ALLOWLIST[0]);

// ── Helper: compare two 4-byte UIDs ──────────────────────────────────────────
bool uidMatch(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 4) == 0;
}

// ── Helper: display message on OLED ──────────────────────────────────────────
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

// ── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial.println("[NFC Lab] Phase 1: UID Allowlist starting...");

  Wire.begin(PN532_SS, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("[ERROR] OLED not found");
  }

  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("[ERROR] PN532 not found — check wiring");
    showMessage("PN532 ERROR", "Check wiring");
    while (1);
  }
  Serial.print("[OK] PN532 firmware v");
  Serial.println((versiondata >> 16) & 0xFF, DEC);

  nfc.SAMConfig();
  showMessage("NFC LAB", "SCAN CARD");
  Serial.println("[NFC Lab] Phase 1 Ready");
}

// ── Main loop ────────────────────────────────────────────────────────────────
void loop() {
  uint8_t uid[7];
  uint8_t uidLen;

  // Wait for card — blocks until card detected
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen)) return;

  // Print UID to serial — useful for adding new cards to allowlist
  Serial.print("[SCAN] UID: ");
  for (uint8_t i = 0; i < uidLen; i++) {
    Serial.print(uid[i], HEX);
    if (i < uidLen - 1) Serial.print(":");
  }
  Serial.println();

  // Check allowlist
  bool granted = false;
  for (uint8_t i = 0; i < ALLOWLIST_SIZE; i++) {
    if (uidMatch(uid, ALLOWLIST[i])) {
      granted = true;
      break;
    }
  }

  if (granted) {
    Serial.println("[AUTH] ACCESS GRANTED");
    showMessage("ACCESS", "GRANTED", false);
  } else {
    Serial.println("[AUTH] ACCESS DENIED");
    showMessage("ACCESS", "DENIED", true);
  }

  delay(2000);
  showMessage("NFC LAB", "SCAN CARD");
}
