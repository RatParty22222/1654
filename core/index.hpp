#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#include "errors.hpp"
#include "vault_format.hpp"
#include "params.hpp"

namespace ph1654::index {

struct Entry {
  std::string path;
  fmt::ObjType type = fmt::ObjType::File;
  std::uint32_t flags = fmt::F_VISIBLE;
  std::uint64_t size = 0;

  std::uint64_t data_offset = 0;
  std::uint64_t data_size = 0;

  std::vector<std::uint8_t> nonce;
  std::vector<std::uint8_t> tag;
};

struct Index {
  std::vector<Entry> entries;
};

Status decode_index(const std::uint8_t* data, std::size_t len, Index& out);
std::vector<std::uint8_t> encode_index(const Index& idx);

static inline bool is_deleted(const Entry& e) { return (e.flags & fmt::F_DELETED) != 0; }
static inline bool is_hidden(const Entry& e)  { return (e.flags & fmt::F_HIDDEN)  != 0; }

} // namespace ph1654::index

