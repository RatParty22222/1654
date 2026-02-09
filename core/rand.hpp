#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>
#include <random>

namespace ph1654::rnd {

inline std::vector<std::uint8_t> bytes(std::size_t n) {
  std::vector<std::uint8_t> out(n);
  std::random_device rd;
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<std::uint8_t>(rd());
  }
  return out;
}

} // namespace ph1654::rnd

