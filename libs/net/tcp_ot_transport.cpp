#include "tcp_ot_transport.hpp"

#include <cstring>
#include <stdexcept>

namespace cypherock::net {

namespace {

template <size_t MaxSize, typename BytesT>
void assign_bytes(BytesT* dest, const std::vector<uint8_t>& src) {
  if (src.size() > MaxSize) {
    throw std::runtime_error("protobuf bytes overflow");
  }
  dest->size = static_cast<pb_size_t>(src.size());
  std::memcpy(dest->bytes, src.data(), src.size());
}

template <size_t MaxSize, typename BytesT>
std::vector<uint8_t> bytes_to_vector(const BytesT* src) {
  const size_t len = src->size;
  if (len > MaxSize) {
    throw std::runtime_error("protobuf bytes length invalid");
  }
  return std::vector<uint8_t>(src->bytes, src->bytes + len);
}

}  // namespace

TcpOtTransport::TcpOtTransport(TcpConnection& conn) : conn_(conn) {}

void TcpOtTransport::send_round1(const crypto::OtRound1Wire& msg) {
  cypherock_OtRound1Msg pb{};
  pb.bit_index = msg.bit_index;
  assign_bytes<33>(&pb.point_a, msg.point_a);

  std::vector<uint8_t> encoded;
  if (!encode_message(cypherock_OtRound1Msg_fields, &pb, encoded)) {
    throw std::runtime_error("encode OtRound1 failed");
  }
  conn_.send_bytes(encoded);
}

crypto::OtRound1Wire TcpOtTransport::recv_round1() {
  const auto frame = conn_.recv_bytes();
  cypherock_OtRound1Msg pb{};
  if (!decode_message(cypherock_OtRound1Msg_fields, &pb, frame.data(), frame.size())) {
    throw std::runtime_error("decode OtRound1 failed");
  }
  crypto::OtRound1Wire wire;
  wire.bit_index = pb.bit_index;
  wire.point_a = bytes_to_vector<33>(&pb.point_a);
  return wire;
}

void TcpOtTransport::send_round2(const crypto::OtRound2Wire& msg) {
  cypherock_OtRound2Msg pb{};
  pb.bit_index = msg.bit_index;
  assign_bytes<33>(&pb.point_b, msg.point_b);

  std::vector<uint8_t> encoded;
  if (!encode_message(cypherock_OtRound2Msg_fields, &pb, encoded)) {
    throw std::runtime_error("encode OtRound2 failed");
  }
  conn_.send_bytes(encoded);
}

crypto::OtRound2Wire TcpOtTransport::recv_round2() {
  const auto frame = conn_.recv_bytes();
  cypherock_OtRound2Msg pb{};
  if (!decode_message(cypherock_OtRound2Msg_fields, &pb, frame.data(), frame.size())) {
    throw std::runtime_error("decode OtRound2 failed");
  }
  crypto::OtRound2Wire wire;
  wire.bit_index = pb.bit_index;
  wire.point_b = bytes_to_vector<33>(&pb.point_b);
  return wire;
}

void TcpOtTransport::send_round3(const crypto::OtRound3Wire& msg) {
  cypherock_OtRound3Msg pb{};
  pb.bit_index = msg.bit_index;
  assign_bytes<32>(&pb.e0, msg.e0);
  assign_bytes<32>(&pb.e1, msg.e1);

  std::vector<uint8_t> encoded;
  if (!encode_message(cypherock_OtRound3Msg_fields, &pb, encoded)) {
    throw std::runtime_error("encode OtRound3 failed");
  }
  conn_.send_bytes(encoded);
}

crypto::OtRound3Wire TcpOtTransport::recv_round3() {
  const auto frame = conn_.recv_bytes();
  cypherock_OtRound3Msg pb{};
  if (!decode_message(cypherock_OtRound3Msg_fields, &pb, frame.data(), frame.size())) {
    throw std::runtime_error("decode OtRound3 failed");
  }
  crypto::OtRound3Wire wire;
  wire.bit_index = pb.bit_index;
  wire.e0 = bytes_to_vector<32>(&pb.e0);
  wire.e1 = bytes_to_vector<32>(&pb.e1);
  return wire;
}

void send_hello(TcpConnection& conn, uint32_t version) {
  cypherock_SessionHello pb{};
  pb.version = version;
  std::vector<uint8_t> encoded;
  if (!encode_message(cypherock_SessionHello_fields, &pb, encoded)) {
    throw std::runtime_error("encode SessionHello failed");
  }
  conn.send_bytes(encoded);
}

void recv_hello(TcpConnection& conn) {
  const auto frame = conn.recv_bytes();
  cypherock_SessionHello pb{};
  if (!decode_message(cypherock_SessionHello_fields, &pb, frame.data(), frame.size())) {
    throw std::runtime_error("decode SessionHello failed");
  }
  if (pb.version != 1) {
    throw std::runtime_error("unsupported protocol version");
  }
}

}  // namespace cypherock::net
