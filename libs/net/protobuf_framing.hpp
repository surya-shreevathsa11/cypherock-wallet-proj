#pragma once

#include <cstdint>
#include <vector>

#include <asio.hpp>

extern "C" {
#include "mta.pb.h"
#include "pb_decode.h"
#include "pb_encode.h"
}

namespace cypherock::net {

class TcpConnection {
 public:
  explicit TcpConnection(asio::ip::tcp::socket socket);

  void send_bytes(const std::vector<uint8_t>& payload);
  std::vector<uint8_t> recv_bytes();

  asio::ip::tcp::socket& socket() { return socket_; }

 private:
  asio::ip::tcp::socket socket_;
};

bool encode_message(const pb_msgdesc_t* fields, const void* message, std::vector<uint8_t>& out);
bool decode_message(const pb_msgdesc_t* fields, void* message, const uint8_t* data, size_t len);

}  // namespace cypherock::net
