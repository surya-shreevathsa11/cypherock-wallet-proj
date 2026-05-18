#pragma once

#include <cstdint>
#include <vector>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "secp256k1.h"
}

namespace cypherock::crypto {

constexpr size_t kScalarBytes = 32;
constexpr size_t kCompressedPointBytes = 33;

const ecdsa_curve* curve();

void point_negate(curve_point* p);
void point_subtract(const curve_point* a, curve_point* b);

std::vector<uint8_t> compress_point(const curve_point& p);
bool decompress_point(const uint8_t* data, size_t len, curve_point* out);

void scalar_mult_base(const bignum256& k, curve_point* out);
void point_mult(const bignum256& k, const curve_point& p, curve_point* out);

void x_coord_bytes(const bignum256& x, uint8_t out[kScalarBytes]);

}  // namespace cypherock::crypto
