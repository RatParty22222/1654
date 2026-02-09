#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <span>
#include <stdexcept>

#include "../PetoronHash/include/petoron/hash.hpp"

namespace ph1654::kdf {

struct Keys {
  std::vector<std::uint8_t> enc;
  std::vector<std::uint8_t> mac;
};

inline Keys derive(
  const std::string& password,
  const std::vector<std::uint8_t>& salt,
  std::size_t key_bytes,
  std::uint32_t cost
) {
  if (key_bytes == 0) throw std::runtime_error("kdf: key_bytes=0");
  if (cost == 0) cost = 1;

  petoron::HashParams p;
  p.out_bits = (key_bytes * 2) * 8;

  const auto pw = std::span<const std::uint8_t>(
    reinterpret_cast<const std::uint8_t*>(password.data()),
    password.size()
  );
  const auto s = std::span<const std::uint8_t>(salt.data(), salt.size());

  std::vector<std::uint8_t> state = petoron::petoron_hash_strong(pw, s, "1654|KDF|0", p);

  for (std::uint32_t i = 1; i < cost; ++i) {
    std::vector<std::uint8_t> msg = state;
    msg.push_back((std::uint8_t)(i & 0xFF));
    msg.push_back((std::uint8_t)((i >> 8) & 0xFF));
    msg.push_back((std::uint8_t)((i >> 16) & 0xFF));
    msg.push_back((std::uint8_t)((i >> 24) & 0xFF));

    const auto m = std::span<const std::uint8_t>(msg.data(), msg.size());
    state = petoron::petoron_hash_strong(m, s, "1654|KDF|R", p);
  }

  if (state.size() < key_bytes * 2) throw std::runtime_error("kdf: too few bytes");

  Keys k;
  k.enc.assign(state.begin(), state.begin() + key_bytes);
  k.mac.assign(state.begin() + key_bytes, state.begin() + key_bytes * 2);
  return k;
}

} // namespace ph1654::kdf


