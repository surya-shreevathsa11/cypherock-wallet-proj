#include "cot_mta.hpp"

#include <iostream>
#include <stdexcept>

#include "base_ot.hpp"

extern "C" {
#include "secp256k1.h"
}

namespace cypherock::crypto {

namespace {

// A.3.3: U = -sum_i (2^i * U_i), V = sum_i (2^i * m_c_i); i = 1..k, bit y_i.
Scalar256 accumulate_weighted(const Scalar256* values, uint32_t count) {
  Scalar256 acc = Scalar256::zero();
  Scalar256 pow2;
  bn_one(&pow2.bn());

  for (uint32_t i = 1; i <= count; ++i) {
    const uint32_t idx = i - 1;
    Scalar256 term;
    bn_copy(&values[idx].bn(), &term.bn());
    bn_multiply(&pow2.bn(), &term.bn(), &secp256k1.order);
    bn_mod(&term.bn(), &secp256k1.order);
    acc = Scalar256::add(acc, term);
    if (i < count) {
      bn_lshift(&pow2.bn());
      bn_mod(&pow2.bn(), &secp256k1.order);
    }
  }
  bn_mod(&acc.bn(), &secp256k1.order);
  return acc;
}

}  // namespace

Scalar256 weighted_sum(const Scalar256* values, uint32_t count) {
  return accumulate_weighted(values, count);
}

CotMtaAlice::CotMtaAlice(const Scalar256& x) : x_(x) {}

MtaResult CotMtaAlice::run(IOtTransport& transport, const Scalar256& y_peer_check) {
  (void)y_peer_check;

  for (uint32_t i = 1; i <= kMtaBitCount; ++i) {
    const uint32_t idx = i - 1;
    U_i_[idx] = Scalar256::random();
    const Scalar256 m0 = U_i_[idx];
    const Scalar256 m1 = Scalar256::add(U_i_[idx], x_);

    BaseOtSender sender;
    auto r1 = sender.begin(m0, m1, idx);
    OtRound1Wire wire1{idx, r1.point_a};
    transport.send_round1(wire1);

    const auto wire2 = transport.recv_round2();
    if (wire2.bit_index != idx) {
      throw std::runtime_error("OT round2 bit_index mismatch");
    }

    auto r3 = sender.finish(wire2.point_b);
    OtRound3Wire wire3{idx, r3.e0, r3.e1};
    transport.send_round3(wire3);

    if (i % 32 == 0) {
      std::cout << "[server] OT progress: " << i << "/" << kMtaBitCount << std::endl;
    }
  }

  const Scalar256 sum_u = accumulate_weighted(U_i_, kMtaBitCount);
  MtaResult result;
  result.additive_share = Scalar256::neg(sum_u);
  result.verified = true;
  return result;
}

CotMtaBob::CotMtaBob(const Scalar256& y) : y_(y) {}

MtaResult CotMtaBob::run(IOtTransport& transport, const Scalar256& x_peer_check) {
  (void)x_peer_check;

  for (uint32_t i = 1; i <= kMtaBitCount; ++i) {
    const uint32_t idx = i - 1;
    const int choice = y_.bit(idx);

    const auto wire1 = transport.recv_round1();
    if (wire1.bit_index != idx) {
      throw std::runtime_error("OT round1 bit_index mismatch");
    }

    BaseOtReceiver receiver;
    auto r2 = receiver.receive(wire1.point_a, choice, idx);
    OtRound2Wire wire2{idx, r2.point_b};
    transport.send_round2(wire2);

    const auto wire3 = transport.recv_round3();
    if (wire3.bit_index != idx) {
      throw std::runtime_error("OT round3 bit_index mismatch");
    }

    mc_[idx] = receiver.decrypt(wire1.point_a, wire3.e0, wire3.e1, idx);

    if (i % 32 == 0) {
      std::cout << "[client] OT progress: " << i << "/" << kMtaBitCount << std::endl;
    }
  }

  MtaResult result;
  result.additive_share = accumulate_weighted(mc_, kMtaBitCount);
  result.verified = true;
  return result;
}

}  // namespace cypherock::crypto
