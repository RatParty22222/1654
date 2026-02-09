#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#include <span>
#include <algorithm>
#include <stdexcept>

#include "params.hpp"
#include "../PetoronHash/include/petoron/hash.hpp"

namespace ph1654::mac {

inline std::vector<std::uint8_t> compute(
  const std::vector<std::uint8_t>& key,
  const std::uint8_t* data,
  std::size_t len
) {
  petoron::HashParams p;
  p.out_bits = std::max<std::size_t>(256, TAG_SIZE * 8);

  const auto m = std::span<const std::uint8_t>(data, len);
  const auto s = std::span<const std::uint8_t>(key.data(), key.size());

  std::vector<std::uint8_t> full = petoron::petoron_hash_strong(m, s, "1654|MAC", p);

  if (full.size() < TAG_SIZE) {
    throw std::runtime_error("mac: PetoronHash returned too few bytes");
  }

  full.resize(TAG_SIZE);
  return full;
}

inline bool verify(
  const std::vector<std::uint8_t>& key,
  const std::uint8_t* data,
  std::size_t len,
  const std::vector<std::uint8_t>& tag
) {
  auto t = compute(key, data, len);
  return t == tag;
}

} // namespace ph1654::mac
