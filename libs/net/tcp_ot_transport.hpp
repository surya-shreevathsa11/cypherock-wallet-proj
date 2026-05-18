#pragma once

#include "libs/crypto/ot_transport.hpp"
#include "protobuf_framing.hpp"

namespace cypherock::net {

class TcpOtTransport : public crypto::IOtTransport {
 public:
  explicit TcpOtTransport(TcpConnection& conn);

  void send_round1(const crypto::OtRound1Wire& msg) override;
  crypto::OtRound1Wire recv_round1() override;

  void send_round2(const crypto::OtRound2Wire& msg) override;
  crypto::OtRound2Wire recv_round2() override;

  void send_round3(const crypto::OtRound3Wire& msg) override;
  crypto::OtRound3Wire recv_round3() override;

 private:
  TcpConnection& conn_;
};

void send_hello(TcpConnection& conn, uint32_t version);
void recv_hello(TcpConnection& conn);

}  // namespace cypherock::net
