#include <iostream>
#include <stdexcept>
#include <string>

#include <asio.hpp>

#include "libs/crypto/cot_mta.hpp"
#include "libs/crypto/mta_verify.hpp"
#include "libs/crypto/scalar256.hpp"
#include "libs/net/protobuf_framing.hpp"
#include "libs/net/share_exchange.hpp"
#include "libs/net/tcp_ot_transport.hpp"

namespace {

uint16_t parse_port(int argc, char** argv) {
  uint16_t port = 9000;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      const long value = std::stol(argv[++i]);
      if (value < 1 || value > 65535) {
        throw std::runtime_error("port must be between 1 and 65535");
      }
      port = static_cast<uint16_t>(value);
    }
  }
  return port;
}

std::string parse_host(int argc, char** argv) {
  std::string host = "127.0.0.1";
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--host" && i + 1 < argc) {
      host = argv[++i];
    }
  }
  return host;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const uint16_t port = parse_port(argc, argv);
    const std::string host = parse_host(argc, argv);

    const auto y = cypherock::crypto::Scalar256::random();
    std::cout << "[client] multiplicative share y: " << y.to_hex() << std::endl;

    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address(host), port));
    std::cout << "[client] connected to " << host << ":" << port << std::endl;

    cypherock::net::TcpConnection conn(std::move(socket));
    cypherock::net::send_hello(conn, 1);
    cypherock::net::recv_hello(conn);

    const auto x_peer = cypherock::net::recv_share(conn);
    cypherock::net::send_share(conn, y);

    cypherock::net::TcpOtTransport transport(conn);
    cypherock::crypto::CotMtaBob session(y);
    const auto result = session.run(transport, x_peer);

    std::cout << "[client] additive share V: " << result.additive_share.to_hex() << std::endl;

    cypherock::net::send_share(conn, result.additive_share);
    const auto U_peer = cypherock::net::recv_share(conn);

    const bool verified = cypherock::crypto::verify_additive_shares(
        x_peer, y, U_peer, result.additive_share);
    std::cout << "[client] MTA verify (U + V == x * y): "
              << (verified ? "PASS" : "FAIL") << std::endl;
    return verified ? 0 : 1;
  } catch (const std::exception& ex) {
    std::cerr << "[client] error: " << ex.what() << std::endl;
    return 1;
  }
}
