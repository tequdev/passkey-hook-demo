#include "./utils/hookapi.h"

extern int64_t util_sha256(uint32_t, uint32_t, uint32_t, uint32_t);
extern int64_t util_verify_p256(uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t);
extern int64_t prepare(uint32_t, uint32_t, uint32_t, uint32_t);

int64_t hook(uint32_t reserved) {
  uint8_t hash[32], sig_r[32], sig_s[32], pub_x[32], pub_y[32];
  otxn_param(SBUF(hash), "hash", 4);
  otxn_param(SBUF(sig_r), "r", 1);
  otxn_param(SBUF(sig_s), "s", 1);
  otxn_param(SBUF(pub_x), "x", 1);
  otxn_param(SBUF(pub_y), "y", 1);

  uint8_t authData[1000];
  uint16_t authData_offset = otxn_param(SBUF(authData), "auth", 4);

  TRACEHEX(hash);
  TRACEHEX(sig_r);
  TRACEHEX(sig_s);
  TRACEHEX(pub_x);
  TRACEHEX(pub_y);

  trace(SBUF("authData"), authData, authData_offset, 1);

  uint16_t challenge_ptr, challenge_len;
  otxn_param(SBUF(challenge_ptr), "ptr", 3);
  otxn_param(SBUF(challenge_len), "len", 3);

  // trace_num(SBUF("challenge_ptr"), &challenge_ptr);
  // trace_num(SBUF("challenge_len"), &challenge_len);

  uint8_t data[1000];
  uint16_t data_len = otxn_field(SBUF(data), sfBlob);

  uint8_t blob_offset = 0;
  if (data_len < 193) {
    blob_offset = 1;
  } else if (data_len < 12481) {
    blob_offset = 2;
  } else {
    blob_offset = 3;
  }

  uint8_t *data_ptr = data + blob_offset;
  data_len -= blob_offset;

  trace(SBUF("blob"), data_ptr, data_len, 1);

  // sha256(authData + sha256(clientDataJSON))
  uint8_t *message = authData;
  uint8_t message_len = authData_offset;
  uint8_t *clientDataHash = message + authData_offset;
  message_len += 32;

  util_sha256(clientDataHash, 32, data_ptr, data_len);

  // uint8_t clientMessageHash[32];
  // util_sha256(SBUF(clientMessageHash), message, authData_offset + 32);

  // trace(SBUF("clientMessageHash"), clientMessageHash, 32, 1);

  uint8_t message_hash[32];
  util_sha256(SBUF(message_hash), message, message_len);

  TRACEHEX(message_hash);

  if (!BUFFER_EQUAL_32(message_hash, hash))
    return rollback(SBUF("Invalid hash"), __LINE__);

  if (!util_verify_p256(SBUF(hash), SBUF(sig_r), SBUF(sig_s), SBUF(pub_x),
                        SBUF(pub_y)))
    return rollback(SBUF("Invalid signature"),
                    util_verify_p256(SBUF(hash), SBUF(sig_r), SBUF(sig_s),
                                     SBUF(pub_x), SBUF(pub_y)));

  uint8_t txblob[1000];
  uint16_t txblob_len =
      prepare(SBUF(txblob), data_ptr + challenge_ptr, challenge_len);

  uint8_t tx_hash[32];
  if (emit(SBUF(tx_hash), txblob, txblob_len) != 32)
    return rollback(SBUF("Failed to emit"), __LINE__);

  _g(1, 1);
  return accept(SBUF("func_one: Finished."), __LINE__);
}
