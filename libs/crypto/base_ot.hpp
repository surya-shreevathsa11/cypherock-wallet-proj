#pragma once

#include <cstdint>
#include <vector>

#include "scalar256.hpp"

namespace cypherock::crypto {

struct BaseOtSenderOutput {
  std::vector<uint8_t> point_a;
  std::vector<uint8_t> e0;
  std::vector<uint8_t> e1;
};

struct BaseOtReceiverOutput {
  std::vector<uint8_t> point_b;
  Scalar256 message;
};

class BaseOtSender {
 public:
  BaseOtSenderOutput begin(const Scalar256& m0, const Scalar256& m1, uint32_t bit_index);

  BaseOtSenderOutput finish(const std::vector<uint8_t>& point_b) const;

 private:
  bool ready_ = false;
  uint32_t bit_index_ = 0;
  bignum256 a_{};
  Scalar256 m0_;
  Scalar256 m1_;
};

class BaseOtReceiver {
 public:
  BaseOtReceiverOutput receive(const std::vector<uint8_t>& point_a, int choice_bit,
                               uint32_t bit_index);

  Scalar256 decrypt(const std::vector<uint8_t>& point_a,
                    const std::vector<uint8_t>& e0, const std::vector<uint8_t>& e1,
                    uint32_t bit_index) const;

 private:
  bool ready_ = false;
  uint32_t bit_index_ = 0;
  int choice_bit_ = 0;
  bignum256 b_{};
  std::vector<uint8_t> point_a_;
};

}  // namespace cypherock::crypto
