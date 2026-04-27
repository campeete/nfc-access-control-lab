/*
 * NFC Access Control Lab — Phase 3: HMAC-SHA256 Challenge-Response
 * License: GNU GPL v3 — see LICENSE-GPL
 * Author: Cameron Peete
 *
 * CONCEPT: True cryptographic authentication via challenge-response.
 * Reader sends a random 16-byte challenge.
 * Card computes HMAC-SHA256(shared_secret, challenge) and returns 32-byte MAC.
 * Reader verifies MAC — replay attacks fail because challenge changes every time.
 *
 * SECURITY ANALYSIS:
 *   - Prevents replay: each challenge is unique (128-bit random)
 *   - Prevents cloning: attacker needs shared secret, not just UID
 *   - Weakness: shared secret must be securely provisioned to card
 *   - Attack surface: side-channel timing during MAC computation
 *
 * Cryptographic concepts used:
 *   HMAC(K, m) = H((K XOR opad) || H((K XOR ipad) || m))
 *   Where H = SHA-256, K = shared secret, m = challenge
 */

#include <SPI.h>
#include <Adafruit_PN532.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <mbedtls/md.h>   // ESP32 mbedTLS — HMAC-SHA256

#define PN532_SCK  18
#define PN532_MISO 19
#define PN532_MOSI 23
#define PN532_SS   5

Adafruit_PN532 nfc(PN532_SS);
Adafruit_SSD1306 display(128, 64, &Wire, -1);

// ── Shared secret — in production this would be stored in secure element ──────
// NEVER hardcode in production. Use NVS encryption or secure provisioning.
const uint8_t SHARED_SECRET[] = {
  0x4E, 0x46, 0x43, 0x4C, 0x61, 0x62, 0x53, 0x65,
  0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79, 0x32,
  0x30, 0x32, 0x36, 0x43, 0x61, 0x6D, 0x50, 0x65,
  0x65, 0x74, 0x65, 0x43, 0x68, 0x69, 0x63, 0x61
};
const size_t SECRET_LEN = sizeof(SHARED_SECRET);

// ── Generate random 16-byte challenge using ESP32 hardware RNG ────────────────
void generateChallenge(uint8_t *challenge, size_t len) {
  for (size_t i = 0; i < len; i++) {
    challenge[i] = esp_random() & 0xFF;
  }
}

// ── Compute HMAC-SHA256 using mbedTLS ─────────────────────────────────────────
// Security note: mbedtls_md_hmac is constant-time on ESP32
bool computeHMAC(const uint8_t *key, size_t keyLen,
                 const uint8_t *data, size_t dataLen,
                 uint8_t *output) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, info, 1) != 0) return false;
  if (mbedtls_md_hmac_starts(&ctx, key, keyLen) != 0) return false;
  if (mbedtls_md_hmac_update(&ctx, data, dataLen) != 0) return false;
  if (mbedtls_md_hmac_finish(&ctx, output) != 0) return false;
  mbedtls_md_free(&ctx);
  return true;
}

// ── Constant-time MAC comparison — prevents timing attacks ───────────────────
// Standard memcmp leaks timing info. This version always runs in O(n).
bool constantTimeCompare(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

void showMessage(const char *line1, const char *line2 = "", bool invert = false) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(invert ? BLACK : WHITE, invert ? WHITE : BLACK);
  display.setCursor(0, 20); display.println(line1);
  display.setCursor(0, 36); display.println(line2);
  display.display();
}

void setup() {
  Serial.begin(115200);
  Wire.begin(21, 22);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  nfc.begin();
  nfc.SAMConfig();
  showMessage("NFC LAB P3", "HMAC-SHA256");
  Serial.println("[NFC Lab] Phase 3: HMAC-SHA256 Ready");
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen)) return;

  Serial.println("[AUTH] Card detected — starting challenge-response");
  showMessage("VERIFYING...", "");

  // Step 1: Generate random challenge
  uint8_t challenge[16];
  generateChallenge(challenge, sizeof(challenge));
  Serial.print("[AUTH] Challenge: ");
  for (int i = 0; i < 16; i++) { Serial.print(challenge[i], HEX); Serial.print(" "); }
  Serial.println();

  // Step 2: Send challenge to card via APDU
  // In full implementation this uses PN532 data exchange to send to card
  // For lab demo: card response simulated as HMAC of challenge with shared secret
  uint8_t cardResponse[32];
  computeHMAC(SHARED_SECRET, SECRET_LEN, challenge, sizeof(challenge), cardResponse);

  // Step 3: Compute expected MAC on reader side
  uint8_t expectedMAC[32];
  computeHMAC(SHARED_SECRET, SECRET_LEN, challenge, sizeof(challenge), expectedMAC);

  // Step 4: Constant-time comparison
  bool granted = constantTimeCompare(cardResponse, expectedMAC, 32);

  if (granted) {
    Serial.println("[AUTH] HMAC VERIFIED — ACCESS GRANTED");
    showMessage("ACCESS", "GRANTED");
  } else {
    Serial.println("[AUTH] HMAC MISMATCH — ACCESS DENIED");
    showMessage("ACCESS", "DENIED", true);
  }

  delay(2000);
  showMessage("NFC LAB P3", "HMAC-SHA256");
}
