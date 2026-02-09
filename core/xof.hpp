#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <algorithm>

#include "../PetoronHash/include/petoron/hash.hpp"

namespace ph1654::xof {

inline void generate(
  const std::vector<std::uint8_t>& key,
  const std::vector<std::uint8_t>& nonce,
  std::uint64_t counter,
  std::uint8_t* out,
  std::size_t out_len
) {
  std::vector<std::uint8_t> msg;
  msg.reserve(nonce.size() + 8);
  msg.insert(msg.end(), nonce.begin(), nonce.end());
  for (int i = 0; i < 8; ++i) msg.push_back((std::uint8_t)((counter >> (8 * i)) & 0xFF));

  petoron::HashParams p;
  p.out_bits = std::max<std::size_t>(256, out_len * 8);

  const auto m = std::span<const std::uint8_t>(msg.data(), msg.size());
  const auto s = std::span<const std::uint8_t>(key.data(), key.size());

  std::vector<std::uint8_t> ks = petoron::petoron_hash_strong(m, s, "1654|XOF", p);

  if (ks.size() < out_len) {
    throw std::runtime_error("xof: PetoronHash returned too few bytes");
  }

  for (std::size_t i = 0; i < out_len; ++i) out[i] = ks[i];
}

} // namespace ph1654::xof


