#pragma once

#include "libs/crypto/scalar256.hpp"
#include "protobuf_framing.hpp"

namespace cypherock::net {

void send_share(TcpConnection& conn, const crypto::Scalar256& share);
crypto::Scalar256 recv_share(TcpConnection& conn);

}  // namespace cypherock::net
