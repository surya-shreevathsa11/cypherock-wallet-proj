#include "mta_verify.hpp"

namespace cypherock::crypto {

bool verify_additive_shares(const Scalar256& x, const Scalar256& y, const Scalar256& U,
                            const Scalar256& V) {
  const Scalar256 product = Scalar256::mul(x, y);
  const Scalar256 sum = Scalar256::add(U, V);
  return Scalar256::equal(product, sum);
}

}  // namespace cypherock::crypto
