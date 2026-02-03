I have a ESP32-C6 1.47inch Display Development Board, 172×320, 262K Color, 160MHz Running Frequency Single-core Processor, Supports WiFi 6 & Bluetooth, ESP32 With Display, and want to set it up as a an TOTP display.

I also have a DS3231 attahed via I2C, on pins 0, 1. 

I want you to write the code for me to download that:

During Startup:
- Checks to see if the clock is set
- If it is continue, otherwise, try and connect to a wifi network with SSID: "Hotspot" and password "Password", once connected use NTP to determine the time and then set it in the DS3231.

Durring Loop (1s):
- Calculate the TOTP code
- Read the current temperature from the DS3231
- Update the display with the TOTP code and Temperature


Here is the code to calculate the OTP Code:
```
// Convert base32 secret to bytes
size_t base32ToBytes(const char *input, uint8_t *output) {
  int buffer = 0;
  int bitsLeft = 0;
  size_t count = 0;

  for (const char *ptr = input; *ptr; ptr++) {
      char c = *ptr;

      if (c >= 'a' && c <= 'z') c -= 32;  // to uppercase
      if (c == '=') break;

      int val;
      if (c >= 'A' && c <= 'Z') val = c - 'A';
      else if (c >= '2' && c <= '7') val = c - '2' + 26;
      else continue; // skip invalid chars

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

// Generate TOTP code using real time
String generateTotp(const char* base32Secret, unsigned long timestamp) {
  // 1. Time counter
  uint64_t counter = (uint64_t)timestamp / TOTP_INTERVAL;

  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; i--) {
      counterBytes[i] = counter & 0xFF;
      counter >>= 8;
  }

  // 2. Decode Base32 secret
  uint8_t secretBytes[32];
  size_t secretLen = base32ToBytes(base32Secret, secretBytes);

  // 3. HMAC-SHA1
  uint8_t hash[20];
  hmac_sha1(secretBytes, secretLen, counterBytes, 8, hash);

  // 4. Dynamic truncation
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
```