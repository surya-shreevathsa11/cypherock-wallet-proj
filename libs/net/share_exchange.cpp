#include "share_exchange.hpp"

#include <cstring>
#include <stdexcept>

namespace cypherock::net {

namespace {

template <size_t MaxSize, typename BytesT>
void assign_bytes(BytesT* dest, const std::vector<uint8_t>& src) {
  if (src.size() > MaxSize) {
    throw std::runtime_error("share bytes overflow");
  }
  dest->size = static_cast<pb_size_t>(src.size());
  std::memcpy(dest->bytes, src.data(), src.size());
}

}  // namespace

void send_share(TcpConnection& conn, const crypto::Scalar256& share) {
  cypherock_ShareRevealMsg pb{};
  assign_bytes<32>(&pb.share, share.to_bytes());

  std::vector<uint8_t> encoded;
  if (!encode_message(cypherock_ShareRevealMsg_fields, &pb, encoded)) {
    throw std::runtime_error("encode ShareReveal failed");
  }
  conn.send_bytes(encoded);
}

crypto::Scalar256 recv_share(TcpConnection& conn) {
  const auto frame = conn.recv_bytes();
  cypherock_ShareRevealMsg pb{};
  if (!decode_message(cypherock_ShareRevealMsg_fields, &pb, frame.data(), frame.size())) {
    throw std::runtime_error("decode ShareReveal failed");
  }
  if (pb.share.size != 32) {
    throw std::runtime_error("invalid share length");
  }
  return crypto::Scalar256::from_bytes(pb.share.bytes, 32);
}

}  // namespace cypherock::net
