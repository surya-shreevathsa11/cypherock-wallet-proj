#pragma once

#include "ot_transport.hpp"
#include "scalar256.hpp"

namespace cypherock::crypto {

constexpr uint32_t kMtaBitCount = 256;

struct MtaResult {
  Scalar256 additive_share;
  bool verified = false;
};

class CotMtaAlice {
 public:
  explicit CotMtaAlice(const Scalar256& x);

  MtaResult run(IOtTransport& transport, const Scalar256& y_peer_check);

 private:
  Scalar256 x_;
  Scalar256 U_i_[kMtaBitCount];
};

class CotMtaBob {
 public:
  explicit CotMtaBob(const Scalar256& y);

  MtaResult run(IOtTransport& transport, const Scalar256& x_peer_check);

 private:
  Scalar256 y_;
  Scalar256 mc_[kMtaBitCount];
};

Scalar256 weighted_sum(const Scalar256* values, uint32_t count);

}  // namespace cypherock::crypto
