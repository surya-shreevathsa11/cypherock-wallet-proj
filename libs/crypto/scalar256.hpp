#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "bignum.h"
}

namespace cypherock::crypto {

class Scalar256 {
 public:
  Scalar256();

  static Scalar256 random();
  static Scalar256 from_bytes(const uint8_t* data, size_t len);
  static Scalar256 zero();

  void to_bytes(uint8_t out[32]) const;
  std::vector<uint8_t> to_bytes() const;
  std::string to_hex() const;

  int bit(size_t index) const;

  static Scalar256 add(const Scalar256& a, const Scalar256& b);
  static Scalar256 sub(const Scalar256& a, const Scalar256& b);
  static Scalar256 mul(const Scalar256& a, const Scalar256& b);
  static Scalar256 neg(const Scalar256& a);

  const bignum256& bn() const { return bn_; }
  bignum256& bn() { return bn_; }

 private:
  bignum256 bn_;
};

}  // namespace cypherock::crypto
