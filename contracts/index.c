#include "./utils/hookapi.h"

extern int64_t util_sha256(uint32_t, uint32_t, uint32_t, uint32_t);
extern int64_t util_verify_p256(uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t);
extern int64_t prepare(uint32_t, uint32_t, uint32_t, uint32_t);

#define MAX_INPUT_LENGTH 200
#define MAX_GROUPS ((MAX_INPUT_LENGTH + 2) / 3)
#define MAX_OUTPUT_LENGTH (MAX_GROUPS * 4 + 1)

char b64_table_url[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "abcdefghijklmnopqrstuvwxyz"
                         "0123456789-_";

int mod_table[3] = {0, 2, 1};

/**
 * BASE64_ENCODE macro
 *
 * ・DATA:         uint8_t*（input byte sequence）
 * ・LEN:          uint32_t（input length）
 * ・ENC:          uint8_t*（output buffer, size must be MAX_OUTPUT_LENGTH or
 * more ・OUTLENPTR:   uint32_t*（pointer to receive the actual output length）
 */
#define BASE64_ENCODE(DATA, LEN, ENC, OUTLEN_PTR)                              \
  do {                                                                         \
    /* limit input length */                                                   \
    uint32_t _in_len =                                                         \
        (uint32_t)((LEN) > MAX_INPUT_LENGTH ? MAX_INPUT_LENGTH : (LEN));       \
    /* required output length (excluding null termination) */                  \
    uint32_t _needed = 4 * ((_in_len + 2) / 3);                                \
    *(OUTLEN_PTR) = _needed;                                                   \
                                                                               \
    /* loop fixed number of times for each 3 bytes (MAX_GROUPS) */             \
    for (uint32_t i = 0; _g(1, MAX_GROUPS + 1), i < MAX_GROUPS; ++i) {         \
      uint32_t _idx = i * 3;                                                   \
      uint32_t _a = (_idx + 0 < _in_len) ? (DATA)[_idx + 0] : 0;               \
      uint32_t _b = (_idx + 1 < _in_len) ? (DATA)[_idx + 1] : 0;               \
      uint32_t _c = (_idx + 2 < _in_len) ? (DATA)[_idx + 2] : 0;               \
      uint32_t _tri = (_a << 16) | (_b << 8) | _c;                             \
                                                                               \
      /* extract 6 bits and look up table */                                   \
      (ENC)[i * 4 + 0] = (uint8_t)b64_table_url[(_tri >> 18) & 0x3F];          \
      (ENC)[i * 4 + 1] = (uint8_t)b64_table_url[(_tri >> 12) & 0x3F];          \
      (ENC)[i * 4 + 2] = (uint8_t)b64_table_url[(_tri >> 6) & 0x3F];           \
      (ENC)[i * 4 + 3] = (uint8_t)b64_table_url[_tri & 0x3F];                  \
    }                                                                          \
                                                                               \
    /* padding */                                                              \
    uint32_t _pad = mod_table[_in_len % 3];                                    \
    *(OUTLEN_PTR) -= _pad;                                                     \
    for (uint32_t _k = 0; _g(2, 2 + 1), _k < _pad; ++_k) {                     \
      (ENC)[_needed - 1 - _k] = (uint8_t)'=';                                  \
    }                                                                          \
  } while (0)

int64_t hook(uint32_t reserved) {
  uint8_t sig_r[32], sig_s[32], pub_x[32], pub_y[32];
  otxn_param(SBUF(sig_r), "r", 1);
  otxn_param(SBUF(sig_s), "s", 1);
  otxn_param(SBUF(pub_x), "x", 1);
  otxn_param(SBUF(pub_y), "y", 1);

  uint8_t authData[1000];
  uint16_t authData_offset = otxn_param(SBUF(authData), "auth", 4);

  uint8_t txblob[1000];
  uint16_t txblob_len = otxn_field(SBUF(txblob), sfBlob);

  uint8_t blob_offset = 0;
  if (txblob_len < 193) {
    blob_offset = 1;
  } else if (txblob_len < 12481) {
    blob_offset = 2;
  } else {
    blob_offset = 3;
  }

  uint8_t *txblob_ptr = txblob + blob_offset;
  txblob_len -= blob_offset;

  // clientDataJson
  // pre + base64(txblob) + post
  uint8_t clientDataJson[1000];
  uint16_t clientDataJson_len = 0;

  uint8_t *pre = clientDataJson;
  uint16_t pre_len = otxn_param(pre, 100, "pre", 3);
  clientDataJson_len += pre_len;

  // base64(txblob)
  uint8_t *txblob_base64 = clientDataJson + pre_len;
  uint32_t txblob_base64_len;
  BASE64_ENCODE(txblob_ptr, txblob_len, txblob_base64, &txblob_base64_len);
  clientDataJson_len += txblob_base64_len;

  uint8_t *post = clientDataJson + pre_len + txblob_base64_len;
  uint16_t post_len = otxn_param(post, 100, "post", 4);
  clientDataJson_len += post_len;

  // sha256(authData + sha256(clientDataJSON))
  uint8_t *message = authData;
  uint8_t message_len = authData_offset;
  uint8_t *clientDataHash = message + authData_offset;
  message_len += 32;

  util_sha256(clientDataHash, 32, clientDataJson, clientDataJson_len);

  uint8_t message_hash[32];
  util_sha256(SBUF(message_hash), message, message_len);

  if (!util_verify_p256(SBUF(message_hash), SBUF(sig_r), SBUF(sig_s),
                        SBUF(pub_x), SBUF(pub_y)))
    return rollback(SBUF("Invalid signature"), __LINE__);

  etxn_reserve(1);

  uint8_t prepared_tx[1000];
  int64_t preapared_tx_len = prepare(SBUF(prepared_tx), txblob_ptr, txblob_len);

  uint8_t tx_hash[32];
  int64_t result = emit(SBUF(tx_hash), prepared_tx, preapared_tx_len);
  if (result != 32)
    return rollback(SBUF("Failed to emit"), __LINE__);

  _g(3, 1);
  return accept(SBUF("passkey-hook: Finished."), __LINE__);
}
