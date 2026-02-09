#pragma once
#include <cstdint>
#include <cstddef>
#include <array>

#include "defs.hpp"
#include "params.hpp"

namespace ph1654::fmt {

static constexpr std::array<std::uint8_t, 4> VAULT_MAGIC = { '1','6','5','4' };
static constexpr std::array<std::uint8_t, 4> INDEX_MAGIC = { 'I','D','X','1' };

enum class ObjType : std::uint8_t {
  File = 1,
  Dir  = 2
};

using ph1654::SALT_SIZE;
using ph1654::NONCE_SIZE;
using ph1654::TAG_SIZE;
using ph1654::VERSION;

enum ObjFlags : std::uint32_t {
  F_VISIBLE = 1u << 0,
  F_HIDDEN  = 1u << 1,
  F_DELETED = 1u << 2
};

struct GlobalHeader {
  std::array<std::uint8_t, 4> magic = VAULT_MAGIC;
  std::uint32_t version = VERSION;
  std::uint32_t header_size = 0;
  std::array<std::uint8_t, SALT_SIZE>  salt{};
  std::array<std::uint8_t, NONCE_SIZE> nonce{};
  std::array<std::uint8_t, 32> reserved{};
};

static constexpr std::size_t GLOBAL_HEADER_SIZE =
  4 + 4 + 4 + SALT_SIZE + NONCE_SIZE + 32;

struct IndexTrailer {
  std::array<std::uint8_t, 4> magic = INDEX_MAGIC;
  std::uint32_t trailer_size = 0;
  std::uint64_t index_offset = 0;
  std::uint64_t index_size = 0;
  std::array<std::uint8_t, TAG_SIZE> index_tag{};
};

static constexpr std::size_t INDEX_TRAILER_SIZE =
  4 + 4 + 8 + 8 + TAG_SIZE;

} // namespace ph1654::fmt

