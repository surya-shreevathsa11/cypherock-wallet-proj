#include "protobuf_framing.hpp"

#include <array>
#include <stdexcept>

namespace cypherock::net {

namespace {

uint32_t read_u32_be(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

void write_u32_be(uint32_t value, uint8_t* data) {
  data[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  data[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  data[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  data[3] = static_cast<uint8_t>(value & 0xFF);
}

}  // namespace

TcpConnection::TcpConnection(asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

void TcpConnection::send_bytes(const std::vector<uint8_t>& payload) {
  std::array<uint8_t, 4> header{};
  write_u32_be(static_cast<uint32_t>(payload.size()), header.data());
  asio::write(socket_, asio::buffer(header));
  if (!payload.empty()) {
    asio::write(socket_, asio::buffer(payload));
  }
}

std::vector<uint8_t> TcpConnection::recv_bytes() {
  std::array<uint8_t, 4> header{};
  asio::read(socket_, asio::buffer(header));
  const uint32_t len = read_u32_be(header.data());
  if (len > 1 << 20) {
    throw std::runtime_error("frame too large");
  }
  std::vector<uint8_t> payload(len);
  if (len > 0) {
    asio::read(socket_, asio::buffer(payload));
  }
  return payload;
}

bool encode_message(const pb_msgdesc_t* fields, const void* message, std::vector<uint8_t>& out) {
  pb_ostream_t stream = pb_ostream_from_buffer(nullptr, 0);
  if (!pb_get_encoded_size(&stream.bytes_written, fields, message)) {
    return false;
  }
  out.resize(stream.bytes_written);
  stream = pb_ostream_from_buffer(out.data(), out.size());
  return pb_encode(&stream, fields, message);
}

bool decode_message(const pb_msgdesc_t* fields, void* message, const uint8_t* data, size_t len) {
  pb_istream_t stream = pb_istream_from_buffer(data, len);
  return pb_decode(&stream, fields, message);
}

}  // namespace cypherock::net
