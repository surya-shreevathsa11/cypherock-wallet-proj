#include "ec_ops.hpp"

#include <cstring>

extern "C" {
#include "sha2.h"
}

namespace cypherock::crypto {

const ecdsa_curve* curve() { return &secp256k1; }

void point_negate(curve_point* p) {
  bn_subtract(&curve()->prime, &p->y, &p->y);
}

void point_subtract(const curve_point* a, curve_point* b) {
  curve_point neg_a = *a;
  point_negate(&neg_a);
  point_add(curve(), &neg_a, b);
}

std::vector<uint8_t> compress_point(const curve_point& p) {
  std::vector<uint8_t> out(kCompressedPointBytes);
  compress_coords(&p, out.data());
  return out;
}

bool decompress_point(const uint8_t* data, size_t len, curve_point* out) {
  if (len != kCompressedPointBytes) {
    return false;
  }
  return ecdsa_read_pubkey(curve(), data, out) != 0;
}

void scalar_mult_base(const bignum256& k, curve_point* out) {
  scalar_multiply(curve(), &k, out);
}

void point_mult(const bignum256& k, const curve_point& p, curve_point* out) {
  point_multiply(curve(), &k, &p, out);
}

void x_coord_bytes(const bignum256& x, uint8_t out[kScalarBytes]) {
  bn_write_be(&x, out);
}

}  // namespace cypherock::crypto
