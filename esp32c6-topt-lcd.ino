#include "Display_ST7789.h"
#include "LVGL_Driver.h"
#include "ui.h"
#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <time.h>
#include <RTClib.h>
#include "mbedtls/md.h"
#include "config.h"
#include <Adafruit_NeoPixel.h>

#define BOOT_KEY_PIN     9

// ====== User Config ======
#ifndef WIFI_SSID_VALUE
#define WIFI_SSID_VALUE ""
#warning "WIFI_SSID_VALUE not defined. Define it via build flags or an untracked header to set the Wi-Fi SSID securely."
#endif
#ifndef WIFI_PASS_VALUE
#define WIFI_PASS_VALUE ""
#warning "WIFI_PASS_VALUE not defined. Define it via build flags or an untracked header to set the Wi-Fi password securely."
#endif
#ifndef TOTP_SECRET_BASE32_VALUE
#define TOTP_SECRET_BASE32_VALUE "9999999999999999999999"
#warning "TOTP_SECRET_BASE32_VALUE not defined. Define it via build flags or an untracked header to set the TOTP secret securely."
#endif
// ==== End user Config ====

static const char *WIFI_SSID = WIFI_SSID_VALUE;
static const char *WIFI_PASS = WIFI_PASS_VALUE;
static const char *TOTP_SECRET_BASE32 = TOTP_SECRET_BASE32_VALUE;
static const uint32_t TOTP_INTERVAL = 30; // seconds

// I2C pins for DS3231 on ESP32-C6
static const int I2C_SDA = 0;
static const int I2C_SCL = 1;

// WS2812B (NeoPixel) setup
static const int WS2812B_PIN = 8;
static const uint16_t WS2812B_LED_COUNT = 1;
static const uint8_t WS2812B_BRIGHTNESS = 40; // 0-255

// ====== Globals ======
RTC_DS3231 rtc;

unsigned long lastTickMs = 0;
String lastTotp = "";
float lastTempC = NAN;
unsigned long lastLedMs = 0;
uint16_t ledHue = 0;

Adafruit_NeoPixel ws2812b(WS2812B_LED_COUNT, WS2812B_PIN, NEO_GRB + NEO_KHZ800);

// ====== UI Helpers ======
void updateWifiIcons(bool connected) {
  if (ui_WifiOn == NULL || ui_WifiOff == NULL) {
    return;
  }

  if (connected) {
    lv_obj_remove_flag(ui_WifiOn, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(ui_WifiOff, LV_OBJ_FLAG_HIDDEN);
  } else {
    lv_obj_add_flag(ui_WifiOn, LV_OBJ_FLAG_HIDDEN);
    lv_obj_remove_flag(ui_WifiOff, LV_OBJ_FLAG_HIDDEN);
  }
}

void updateWs2812b() {
  const unsigned long nowMs = millis();
  if (nowMs - lastLedMs < 20) {
    return;
  }
  lastLedMs = nowMs;

  ledHue += 256;
  uint32_t color = ws2812b.gamma32(ws2812b.ColorHSV(ledHue));
  for (uint16_t i = 0; i < WS2812B_LED_COUNT; i++) {
    ws2812b.setPixelColor(i, color);
  }
  ws2812b.show();
}

// ====== TOTP Implementation (as provided) ======
size_t base32ToBytes(const char *input, uint8_t *output) {
  int buffer = 0;
  int bitsLeft = 0;
  size_t count = 0;

  for (const char *ptr = input; *ptr; ptr++) {
      char c = *ptr;

      if (c >= 'a' && c <= 'z') c -= 32;
      if (c == '=') break;

      int val;
      if (c >= 'A' && c <= 'Z') val = c - 'A';
      else if (c >= '2' && c <= '7') val = c - '2' + 26;
      else continue;

      buffer = (buffer << 5) | val;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
          output[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
          bitsLeft -= 8;
      }
  }
  return count;
}

void hmac_sha1(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[20]
) {
    const mbedtls_md_info_t *md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    mbedtls_md_hmac(md, key, key_len, msg, msg_len, out);
}

String generateTotp(const char* base32Secret, unsigned long timestamp) {
  uint64_t counter = (uint64_t)timestamp / TOTP_INTERVAL;

  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; i--) {
      counterBytes[i] = counter & 0xFF;
      counter >>= 8;
  }

  uint8_t secretBytes[32];
  size_t secretLen = base32ToBytes(base32Secret, secretBytes);

  uint8_t hash[20];
  hmac_sha1(secretBytes, secretLen, counterBytes, 8, hash);

  int offset = hash[19] & 0x0F;
  uint32_t binary =
      ((hash[offset] & 0x7F) << 24) |
      (hash[offset + 1] << 16) |
      (hash[offset + 2] << 8) |
      (hash[offset + 3]);

  uint32_t otp = binary % 1000000;

  char result[7];
  snprintf(result, sizeof(result), "%06lu", otp);
  return String(result);
}

// ====== Helpers ======
bool syncTimeWithNtp() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  const unsigned long connectStart = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - connectStart > 15000) {
      updateWifiIcons(false);
      return false;
    }
    delay(100);
  }

  updateWifiIcons(true);

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  struct tm timeinfo;
  const unsigned long ntpStart = millis();
  while (!getLocalTime(&timeinfo)) {
    if (millis() - ntpStart > 15000) {
      WiFi.disconnect(true);
      WiFi.mode(WIFI_OFF);
      updateWifiIcons(false);
      return false;
    }
    delay(200);
  }

  time_t now = time(nullptr);
  rtc.adjust(DateTime((uint32_t)now));

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  updateWifiIcons(false);
  return true;
}

void setup() {
  pinMode(BOOT_KEY_PIN, INPUT);   
  Wire.begin(I2C_SDA, I2C_SCL);
  ws2812b.begin();
  ws2812b.setBrightness(WS2812B_BRIGHTNESS);
  ws2812b.show();
  LCD_Init();
  LCD_Clear(0x0000);
  Lvgl_Init();
  ui_init();
  updateWifiIcons(false);
    
    
  if (!rtc.begin()) {
    
    lv_label_set_text(ui_Logo_Label, "ERROR");
    lv_label_set_text(ui_TOTP, "RTC not Found");
    while (true) { delay(1000); }
  }

  if (rtc.lostPower()) {
    lv_label_set_text(ui_Logo_Label, "Syncing Time");
    lv_label_set_text(ui_TOTP, "...");
    bool ok = syncTimeWithNtp();
    
    lv_label_set_text(ui_TOTP, ok ? "OK" : "Failed");
    delay(1000);
  }

  lastTickMs = millis();
}

void loop() {
  unsigned long nowMs = millis();
  if (nowMs - lastTickMs >= 1000) {
    lastTickMs = nowMs;

    DateTime now = rtc.now();
    unsigned long unixTime = now.unixtime();
    String totp = generateTotp(TOTP_SECRET_BASE32, unixTime);
    float tempC = rtc.getTemperature();

    if (totp != lastTotp || tempC != lastTempC) {
      lv_label_set_text(ui_TOTP, totp.c_str());
      lv_label_set_text(ui_Temperature, (String(tempC) + "°C").c_str());

      lastTotp = totp;
      lastTempC = tempC;
    }
  }
  updateWs2812b();
  Timer_Loop();
  delay(1);
}
