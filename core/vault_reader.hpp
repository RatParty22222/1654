#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#include "errors.hpp"
#include "vault_format.hpp"
#include "index.hpp"
#include "kdf.hpp"

namespace ph1654::vault {

struct VaultOpen {
  fmt::GlobalHeader header{};
  fmt::IndexTrailer trailer{};
  index::Index idx{};
  kdf::Keys keys{};
};

Status read_global_header(const std::string& path, fmt::GlobalHeader& out);
Status read_index_trailer(const std::string& path, fmt::IndexTrailer& out);
Status read_index_bytes(const std::string& path, const fmt::IndexTrailer& tr, std::vector<std::uint8_t>& out_index_bytes);

Status open_for_view(const std::string& path, const std::string& password, VaultOpen& out);

} // namespace ph1654::vault

