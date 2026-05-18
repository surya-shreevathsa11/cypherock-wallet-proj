#pragma once

#include <cstdint>
#include <vector>

namespace cypherock::crypto {

struct OtRound1Wire {
  uint32_t bit_index = 0;
  std::vector<uint8_t> point_a;
};

struct OtRound2Wire {
  uint32_t bit_index = 0;
  std::vector<uint8_t> point_b;
};

struct OtRound3Wire {
  uint32_t bit_index = 0;
  std::vector<uint8_t> e0;
  std::vector<uint8_t> e1;
};

class IOtTransport {
 public:
  virtual ~IOtTransport() = default;

  virtual void send_round1(const OtRound1Wire& msg) = 0;
  virtual OtRound1Wire recv_round1() = 0;

  virtual void send_round2(const OtRound2Wire& msg) = 0;
  virtual OtRound2Wire recv_round2() = 0;

  virtual void send_round3(const OtRound3Wire& msg) = 0;
  virtual OtRound3Wire recv_round3() = 0;
};

}  // namespace cypherock::crypto
