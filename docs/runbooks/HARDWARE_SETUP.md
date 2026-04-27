# Hardware Setup Runbook

## Required Components
- ESP32 DevKit v1 or Arduino Uno/Mega
- PN532 NFC/RFID module (SPI or I2C)
- SSD1306 OLED display 128x64
- MIFARE Classic 1K cards (x3 minimum)
- Breadboard + jumper wires

## Wiring — ESP32 + PN532 (SPI)

| PN532 Pin | ESP32 Pin |
|-----------|-----------|
| VCC | 3.3V |
| GND | GND |
| SCK | GPIO18 |
| MISO | GPIO19 |
| MOSI | GPIO23 |
| SS/CS | GPIO5 |

## Wiring — OLED (I2C)

| OLED Pin | ESP32 Pin |
|----------|-----------|
| VCC | 3.3V |
| GND | GND |
| SCL | GPIO22 |
| SDA | GPIO21 |

## Flash Firmware

```bash
pip install platformio
cd firmware/core
pio run --target upload
pio device monitor --baud 115200
```

## Verify
1. Serial monitor at 115200 baud → `[NFC Lab] Phase 1 Ready`
2. Tap MIFARE card → UID printed to serial
3. OLED displays `SCAN CARD`
