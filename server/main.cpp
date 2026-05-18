#include <iostream>
#include <string>

#include <asio.hpp>

#include "libs/crypto/cot_mta.hpp"
#include "libs/crypto/scalar256.hpp"
#include "libs/net/protobuf_framing.hpp"
#include "libs/crypto/mta_verify.hpp"
#include "libs/net/share_exchange.hpp"
#include "libs/net/tcp_ot_transport.hpp"

namespace {

uint16_t parse_port(int argc, char** argv) {
  uint16_t port = 9000;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::stoi(argv[++i]));
    }
  }
  return port;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const uint16_t port = parse_port(argc, argv);

    const auto x = cypherock::crypto::Scalar256::random();
    std::cout << "[server] multiplicative share x: " << x.to_hex() << std::endl;

    asio::io_context io;
    asio::ip::tcp::acceptor acceptor(
        io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));
    std::cout << "[server] listening on port " << port << std::endl;

    asio::ip::tcp::socket socket(io);
    acceptor.accept(socket);
    std::cout << "[server] client connected" << std::endl;

    cypherock::net::TcpConnection conn(std::move(socket));
    cypherock::net::recv_hello(conn);
    cypherock::net::send_hello(conn, 1);

    cypherock::net::send_share(conn, x);
    const auto y_peer = cypherock::net::recv_share(conn);

    cypherock::net::TcpOtTransport transport(conn);
    cypherock::crypto::CotMtaAlice session(x);
    const auto result = session.run(transport, y_peer);

    std::cout << "[server] additive share U: " << result.additive_share.to_hex() << std::endl;

    const auto V_peer = cypherock::net::recv_share(conn);
    cypherock::net::send_share(conn, result.additive_share);

    const bool verified = cypherock::crypto::verify_additive_shares(
        x, y_peer, result.additive_share, V_peer);
    std::cout << "[server] MTA verify (U + V == x * y): "
              << (verified ? "PASS" : "FAIL") << std::endl;
    return verified ? 0 : 1;
  } catch (const std::exception& ex) {
    std::cerr << "[server] error: " << ex.what() << std::endl;
    return 1;
  }
}
