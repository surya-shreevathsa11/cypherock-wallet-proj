#include "scalar256.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

extern "C" {
#include "rand.h"
#include "secp256k1.h"
}

namespace cypherock::crypto {

namespace {

const bignum256& order() { return secp256k1.order; }

void reduce(bignum256* bn) { bn_mod(bn, &order()); }

}  // namespace

Scalar256::Scalar256() { bn_zero(&bn_); }

Scalar256 Scalar256::zero() { return Scalar256(); }

Scalar256 Scalar256::random() {
  uint8_t buf[32];
  random_buffer(buf, sizeof(buf));
  return from_bytes(buf, sizeof(buf));
}

Scalar256 Scalar256::from_bytes(const uint8_t* data, size_t len) {
  Scalar256 s;
  uint8_t tmp[32] = {0};
  const size_t copy_len = len > 32 ? 32 : len;
  if (len > 32) {
    std::memcpy(tmp, data + len - 32, 32);
  } else {
    std::memcpy(tmp + (32 - copy_len), data, copy_len);
  }
  bn_read_be(tmp, &s.bn_);
  bn_mod(&s.bn_, &order());
  return s;
}

void Scalar256::to_bytes(uint8_t out[32]) const {
  bignum256 reduced = bn_;
  reduce(&reduced);
  bn_write_be(&reduced, out);
}

std::vector<uint8_t> Scalar256::to_bytes() const {
  std::vector<uint8_t> out(32);
  to_bytes(out.data());
  return out;
}

std::string Scalar256::to_hex() const {
  const auto bytes = to_bytes();
  std::ostringstream oss;
  for (uint8_t b : bytes) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  return oss.str();
}

int Scalar256::bit(size_t index) const {
  if (index >= 256) {
    return 0;
  }
  bignum256 copy = bn_;
  return bn_testbit(&copy, static_cast<uint8_t>(index)) ? 1 : 0;
}

Scalar256 Scalar256::add(const Scalar256& a, const Scalar256& b) {
  Scalar256 r;
  bn_copy(&a.bn_, &r.bn_);
  bn_addmod(&r.bn_, &b.bn_, &order());
  reduce(&r.bn_);
  return r;
}

Scalar256 Scalar256::sub(const Scalar256& a, const Scalar256& b) {
  Scalar256 r;
  bn_subtractmod(&a.bn_, &b.bn_, &r.bn_, &order());
  reduce(&r.bn_);
  return r;
}

Scalar256 Scalar256::mul(const Scalar256& a, const Scalar256& b) {
  Scalar256 r;
  bn_copy(&a.bn_, &r.bn_);
  bn_multiply(&b.bn_, &r.bn_, &order());
  reduce(&r.bn_);
  return r;
}

Scalar256 Scalar256::neg(const Scalar256& a) {
  Scalar256 zero;
  bn_zero(&zero.bn_);
  Scalar256 r = sub(zero, a);
  reduce(&r.bn_);
  return r;
}

bool Scalar256::equal(const Scalar256& a, const Scalar256& b) {
  bignum256 lhs = a.bn_;
  bignum256 rhs = b.bn_;
  reduce(&lhs);
  reduce(&rhs);
  return bn_is_equal(&lhs, &rhs) != 0;
}

}  // namespace cypherock::crypto
