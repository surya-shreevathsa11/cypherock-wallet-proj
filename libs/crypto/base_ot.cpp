#include "base_ot.hpp"

#include <cstring>
#include <stdexcept>

#include "ec_ops.hpp"

extern "C" {
#include "rand.h"
}

namespace cypherock::crypto {

namespace {

// A.3.1: encryption key is the x-coordinate (abscissa) of the shared EC point.
std::vector<uint8_t> ot_key_from_x(const bignum256& x) {
  std::vector<uint8_t> key(32);
  x_coord_bytes(x, key.data());
  return key;
}

std::vector<uint8_t> encrypt_scalar(const Scalar256& msg, const std::vector<uint8_t>& key) {
  uint8_t plain[32];
  msg.to_bytes(plain);
  std::vector<uint8_t> out(32);
  for (size_t i = 0; i < 32; ++i) {
    out[i] = plain[i] ^ key[i];
  }
  return out;
}

Scalar256 decrypt_scalar(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& key) {
  uint8_t plain[32];
  for (size_t i = 0; i < 32; ++i) {
    plain[i] = cipher[i] ^ key[i];
  }
  return Scalar256::from_bytes(plain, sizeof(plain));
}

}  // namespace

BaseOtSenderOutput BaseOtSender::begin(const Scalar256& m0, const Scalar256& m1,
                                       uint32_t bit_index) {
  m0_ = m0;
  m1_ = m1;
  bit_index_ = bit_index;

  uint8_t a_bytes[32];
  random_buffer(a_bytes, sizeof(a_bytes));
  bn_read_be(a_bytes, &a_);
  bn_mod(&a_, &curve()->order);

  curve_point A;
  scalar_mult_base(a_, &A);

  BaseOtSenderOutput out;
  out.point_a = compress_point(A);
  ready_ = true;
  return out;
}

BaseOtSenderOutput BaseOtSender::finish(const std::vector<uint8_t>& point_b) const {
  if (!ready_) {
    throw std::runtime_error("BaseOtSender not initialized");
  }

  curve_point A;
  scalar_mult_base(a_, &A);

  curve_point B;
  if (!decompress_point(point_b.data(), point_b.size(), &B)) {
    throw std::runtime_error("invalid OT point B");
  }

  curve_point aB;
  point_mult(a_, B, &aB);
  const auto k0 = ot_key_from_x(aB.x);

  curve_point BminusA = B;
  point_subtract(&A, &BminusA);

  curve_point aBmA;
  point_mult(a_, BminusA, &aBmA);
  const auto k1 = ot_key_from_x(aBmA.x);

  BaseOtSenderOutput out;
  out.e0 = encrypt_scalar(m0_, k0);
  out.e1 = encrypt_scalar(m1_, k1);
  return out;
}

BaseOtReceiverOutput BaseOtReceiver::receive(const std::vector<uint8_t>& point_a, int choice_bit,
                                             uint32_t bit_index) {
  choice_bit_ = choice_bit ? 1 : 0;
  bit_index_ = bit_index;
  point_a_ = point_a;

  curve_point A;
  if (!decompress_point(point_a.data(), point_a.size(), &A)) {
    throw std::runtime_error("invalid OT point A");
  }

  uint8_t b_bytes[32];
  random_buffer(b_bytes, sizeof(b_bytes));
  bn_read_be(b_bytes, &b_);
  bn_mod(&b_, &curve()->order);

  curve_point B;
  scalar_mult_base(b_, &B);
  if (choice_bit_ == 1) {
    point_add(curve(), &A, &B);
  }

  BaseOtReceiverOutput out;
  out.point_b = compress_point(B);
  ready_ = true;
  return out;
}

Scalar256 BaseOtReceiver::decrypt(const std::vector<uint8_t>& point_a,
                                   const std::vector<uint8_t>& e0,
                                   const std::vector<uint8_t>& e1, uint32_t bit_index) const {
  curve_point A;
  if (!decompress_point(point_a.data(), point_a.size(), &A)) {
    throw std::runtime_error("invalid OT point A");
  }

  curve_point bA;
  point_mult(b_, A, &bA);
  (void)bit_index;
  const auto kc = ot_key_from_x(bA.x);

  const auto& cipher = (choice_bit_ == 0) ? e0 : e1;
  return decrypt_scalar(cipher, kc);
}

}  // namespace cypherock::crypto
