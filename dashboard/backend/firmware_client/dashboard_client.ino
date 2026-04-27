/*
 * NFC Access Control Lab — ESP32 Dashboard HTTP Client
 * Posts scan events to dashboard API on every card read
 * License: MIT | Author: Cameron Peete
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* DASHBOARD_URL = "http://YOUR_MAC_IP:3001/api/scans";
const char* API_KEY       = "nfc_YOUR_KEY_FROM_API";

void connectWifi() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int i = 0;
  while (WiFi.status() != WL_CONNECTED && i++ < 20) delay(500);
  if (WiFi.status() == WL_CONNECTED)
    Serial.println("[WiFi] Connected: " + WiFi.localIP().toString());
  else
    Serial.println("[WiFi] Failed — offline mode");
}

void postScanEvent(String uid, int phase, String result, float responseMs) {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  http.begin(DASHBOARD_URL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", API_KEY);
  StaticJsonDocument<256> doc;
  doc["uid"] = uid;
  doc["phase"] = phase;
  doc["result"] = result;
  doc["response_time_ms"] = responseMs;
  String payload;
  serializeJson(doc, payload);
  int code = http.POST(payload);
  Serial.println(code == 201 ? "[Dashboard] Logged" : "[Dashboard] Failed: " + String(code));
  http.end();
}
