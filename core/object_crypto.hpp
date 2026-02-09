#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <istream>
#include <ostream>

#include "errors.hpp"

namespace ph1654::obj {

Status encrypt_stream(
  std::istream& in,
  std::ostream& out,
  const std::vector<std::uint8_t>& key_enc,
  const std::vector<std::uint8_t>& key_mac,
  const std::vector<std::uint8_t>& nonce,
  std::uint64_t& out_bytes_written,
  std::vector<std::uint8_t>& out_tag
);

Status decrypt_stream(
  std::istream& in,
  std::ostream& out,
  const std::vector<std::uint8_t>& key_enc,
  const std::vector<std::uint8_t>& key_mac,
  const std::vector<std::uint8_t>& nonce,
  std::uint64_t data_size,
  const std::vector<std::uint8_t>& expected_tag
);

} // namespace ph1654::obj

