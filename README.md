# cypherock-wallet-proj

A TCP client–server system that converts **multiplicative shares** to **additive shares** using **Correlated Oblivious Transfer (CoT)** on the **secp256k1** curve. Cryptography is provided by [trezor-crypto](https://github.com/trezor/trezor-crypto); networking uses standalone [Boost.Asio](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html); messages on the wire use [nanopb](https://github.com/nanopb/nanopb).

The protocol follows Appendix A.3.1–A.3.3 of the CoT specification (`COT.pdf`):

- **A.3.1** — 1-of-2 base oblivious transfer (EC Diffie–Hellman style)
- **A.3.2** — Correlated OT with `m1 = m0 + x`
- **A.3.3** — Multiplicative-to-additive (MTA) conversion via 256 parallel OTs

| Role | Binary | Multiplicative share | Additive share |
|------|--------|----------------------|----------------|
| Server (Alice) | `cypherock_server` | `x` | `U` |
| Client (Bob) | `cypherock_client` | `y` | `V` |

Goal: `x · y ≡ U + V (mod n)` where `n` is the secp256k1 curve order.

---

## Project layout

```
cypherock-wallet-proj/
├── client/main.cpp          # Bob: connects, runs OT receiver, prints shares
├── server/main.cpp          # Alice: listens, runs OT sender, verifies MTA
├── libs/
│   ├── crypto/              # Scalars, EC ops, base OT, CoT/MTA
│   └── net/                 # TCP framing, nanopb transport, share exchange
├── proto/mta.proto          # Wire messages
├── generated/               # Pre-generated nanopb C sources (mta.pb.c/h)
├── cmake/                   # CMake helpers
├── scripts/run_demo.sh      # Local end-to-end demo
└── third_party/
    ├── asio/                # Standalone Asio headers
    ├── nanopb/
    └── trezor-crypto/
```

**CMake targets**

| Target | Description |
|--------|-------------|
| `cypherock_server` | TCP server executable |
| `cypherock_client` | TCP client executable |
| `cypherock_crypto` | OT + MTA + secp256k1 helpers |
| `cypherock_net` | TCP + protobuf framing |
| `cypherock_proto` | nanopb encode/decode |
| `trezor_crypto` | Vendored trezor-crypto (secp256k1, bignum, SHA-256, RNG) |

---

## Implementation

### Scalars and curve

- All secret values are **32-byte scalars** reduced modulo the secp256k1 order `n` (`Scalar256` in `libs/crypto/scalar256.cpp`).
- Random multiplicative shares are drawn with trezor-crypto’s `random_buffer`.
- Point arithmetic, compression, and scalar multiply use trezor-crypto’s secp256k1 implementation (`libs/crypto/ec_ops.cpp`).

### Base OT (A.3.1)

Implemented in `libs/crypto/base_ot.cpp` (`BaseOtSender`, `BaseOtReceiver`):

1. Alice samples scalar `a`, sends `A = a·G`.
2. Bob samples scalar `b`. If choice bit `c = 0`, sends `B = b·G`; if `c = 1`, sends `B = b·G + A`.
3. Alice derives keys `k0` and `k1` from the x-coordinates (abscissae) of `a·B` and `a·(B − A)`, encrypts `m0` and `m1`, sends `e0`, `e1`.
4. Bob derives `b·A`, decrypts `e_c` to obtain `m_c`.

Messages `m0` and `m1` are 32-byte scalars XOR-encrypted under the derived keys.

### Correlated OT (A.3.2)

For each OT index `i = 1 … 256` (bit `y_i` is the `(i−1)`th bit of `y`, LSB first), Alice sets:

- `m0 = U_i` (random scalar)
- `m1 = U_i + x` (correlation `D = x`)

Bob’s choice bit is `y_i`, the `i`th bit of his multiplicative share `y`. He receives:

`m_c = U_i + y_i · x`

### MTA (A.3.3)

`libs/crypto/cot_mta.cpp` runs **256 OT rounds** (one per bit of a full scalar).

After all rounds (per A.3.3, with weights `2^i` for `i = 1 … k`):

- Alice: `U = −Σ_{i=1}^{k} 2^i · U_i`
- Bob: `V = Σ_{i=1}^{k} 2^i · m_c`

This yields `x · y ≡ U + V (mod n)`.

`CotMtaAlice` and `CotMtaBob` drive the protocol; `IOtTransport` (`libs/crypto/ot_transport.hpp`) abstracts the network layer so crypto stays independent of I/O.

### Networking

- **TCP** via Boost.Asio (`ASIO_STANDALONE`, headers in `third_party/asio`).
- **Framing:** each message is a 4-byte big-endian length prefix followed by a nanopb payload (`libs/net/protobuf_framing.cpp`).
- **OT messages** (`libs/net/tcp_ot_transport.cpp`): `OtRound1Msg`, `OtRound2Msg`, `OtRound3Msg` per bit index.
- **Session handshake:** `SessionHello` (version `1`) exchanged before OT.
- **Session flow:** after handshake, multiplicative shares `x` and `y` are exchanged, then 256 OT rounds run, then additive shares `U` and `V` are exchanged for verification only.
- **Verification:** both sides check `U + V == x · y` locally (`libs/crypto/mta_verify.cpp`) and print `PASS` or `FAIL`.

### Protocol buffers

`proto/mta.proto` defines all wire types. Options in `proto/mta.options` cap field sizes (33-byte compressed points, 32-byte scalars/ciphertexts). Generated code lives in `generated/mta.pb.c` and `generated/mta.pb.h`.

To regenerate protobuf C code (optional):

```bash
python3 -m venv .venv
.venv/bin/pip install grpcio-tools
.venv/bin/python third_party/nanopb/generator/nanopb_generator.py \
  -I proto -fproto/mta.options -D generated proto/mta.proto
```

---

## Prerequisites

- Linux
- C++17 compiler (`g++` or `clang++`)
- CMake 3.16+
- POSIX threads (`pthread`)

All third-party libraries are vendored; no system install of Boost, protobuf, or trezor-crypto is required.

---

## Build

From the project root:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Outputs:

- `build/cypherock_server`
- `build/cypherock_client`

Debug build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

---

## Run

A full run performs 256 OT rounds and takes about **25–35 seconds**. Default TCP port is **9000**.

### Two terminals

**Terminal 1 — start the server:**

```bash
./build/cypherock_server --port 9000
```

**Terminal 2 — start the client** (after the server is listening):

```bash
./build/cypherock_client --port 9000
```

Client options:

```bash
./build/cypherock_client --host 127.0.0.1 --port 9000
```

### Expected output

Both sides print multiplicative shares, additive shares, and a verification line:

```
[server] multiplicative share x: <64 hex chars>
[client] multiplicative share y: <64 hex chars>
...
[server] additive share U: <64 hex chars>
[client] additive share V: <64 hex chars>
[server] MTA verify (U + V == x * y): PASS
[client] MTA verify (U + V == x * y): PASS
```

### Demo script

From the project root, after building:

```bash
./scripts/run_demo.sh 9000
```

This starts the server in the background, runs the client, then stops the server.
