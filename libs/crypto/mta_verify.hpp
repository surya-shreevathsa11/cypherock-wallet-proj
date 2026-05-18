#pragma once

#include "scalar256.hpp"

namespace cypherock::crypto {

bool verify_additive_shares(const Scalar256& x, const Scalar256& y, const Scalar256& U,
                            const Scalar256& V);

}  // namespace cypherock::crypto
