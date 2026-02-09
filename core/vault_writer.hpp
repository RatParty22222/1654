#pragma once
#include <string>
#include <cstddef>
#include <cstdint>

#include "errors.hpp"

namespace ph1654::vault {

Status create_vault_from_path(
  const std::string& input_path,
  const std::string& out_path,
  const std::string& password,
  std::size_t key_bits,
  std::uint32_t kdf_cost
);

} // namespace ph1654::vault

