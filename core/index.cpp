#include "index.hpp"
#include "endian.hpp"

#include <cstring>

namespace ph1654::index {

static constexpr std::uint32_t IDX_VER = 1;
static constexpr std::uint32_t IDX_MAGIC = 0x31584449u;

static bool read_u32(const std::uint8_t* data, std::size_t len, std::size_t& off, std::uint32_t& out) {
  if (off + 4 > len) return false;
  out = endian::load_u32_le(data + off);
  off += 4;
  return true;
}

static bool read_u64(const std::uint8_t* data, std::size_t len, std::size_t& off, std::uint64_t& out) {
  if (off + 8 > len) return false;
  out = endian::load_u64_le(data + off);
  off += 8;
  return true;
}

static bool read_bytes(const std::uint8_t* data, std::size_t len, std::size_t& off, std::uint8_t* out, std::size_t n) {
  if (off + n > len) return false;
  std::memcpy(out, data + off, n);
  off += n;
  return true;
}

static bool read_string(const std::uint8_t* data, std::size_t len, std::size_t& off, std::string& out) {
  std::uint32_t n = 0;
  if (!read_u32(data, len, off, n)) return false;
  if (off + n > len) return false;
  out.assign(reinterpret_cast<const char*>(data + off), reinterpret_cast<const char*>(data + off + n));
  off += n;
  return true;
}

Status decode_index(const std::uint8_t* data, std::size_t len, Index& out) {
  out.entries.clear();
  std::size_t off = 0;

  std::uint32_t magic = 0;
  std::uint32_t ver = 0;
  std::uint32_t count = 0;

  if (!read_u32(data, len, off, magic)) return Status::err(ExitCode::IntegrityError, "index: truncated (magic)");
  if (!read_u32(data, len, off, ver))   return Status::err(ExitCode::IntegrityError, "index: truncated (ver)");
  if (!read_u32(data, len, off, count)) return Status::err(ExitCode::IntegrityError, "index: truncated (count)");

  if (magic != IDX_MAGIC) return Status::err(ExitCode::IntegrityError, "index: bad magic");
  if (ver != IDX_VER) return Status::err(ExitCode::IntegrityError, "index: unsupported version");

  out.entries.reserve(count);

  for (std::uint32_t i = 0; i < count; ++i) {
    Entry e;

    std::uint8_t type_u8 = 0;
    std::uint32_t flags = 0;
    std::uint64_t size = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;

    if (!read_string(data, len, off, e.path)) return Status::err(ExitCode::IntegrityError, "index: truncated (path)");

    if (!read_bytes(data, len, off, &type_u8, 1)) return Status::err(ExitCode::IntegrityError, "index: truncated (type)");
    e.type = (type_u8 == (std::uint8_t)fmt::ObjType::Dir) ? fmt::ObjType::Dir : fmt::ObjType::File;

    if (!read_u32(data, len, off, flags)) return Status::err(ExitCode::IntegrityError, "index: truncated (flags)");
    e.flags = flags;

    if (!read_u64(data, len, off, size)) return Status::err(ExitCode::IntegrityError, "index: truncated (size)");
    e.size = size;

    if (!read_u64(data, len, off, data_offset)) return Status::err(ExitCode::IntegrityError, "index: truncated (data_offset)");
    e.data_offset = data_offset;

    if (!read_u64(data, len, off, data_size)) return Status::err(ExitCode::IntegrityError, "index: truncated (data_size)");
    e.data_size = data_size;

    e.nonce.resize(NONCE_SIZE);
    e.tag.resize(TAG_SIZE);

    if (!read_bytes(data, len, off, e.nonce.data(), e.nonce.size())) return Status::err(ExitCode::IntegrityError, "index: truncated (nonce)");
    if (!read_bytes(data, len, off, e.tag.data(), e.tag.size()))     return Status::err(ExitCode::IntegrityError, "index: truncated (tag)");

    out.entries.push_back(std::move(e));
  }

  if (off != len) {
    return Status::err(ExitCode::IntegrityError, "index: trailing bytes");
  }

  return Status::ok();
}

static void push_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  std::uint8_t b[4];
  endian::store_u32_le(b, v);
  out.insert(out.end(), b, b + 4);
}

static void push_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
  std::uint8_t b[8];
  endian::store_u64_le(b, v);
  out.insert(out.end(), b, b + 8);
}

static void push_bytes(std::vector<std::uint8_t>& out, const std::uint8_t* p, std::size_t n) {
  out.insert(out.end(), p, p + n);
}

static void push_string(std::vector<std::uint8_t>& out, const std::string& s) {
  push_u32(out, (std::uint32_t)s.size());
  out.insert(out.end(), s.begin(), s.end());
}

std::vector<std::uint8_t> encode_index(const Index& idx) {
  std::vector<std::uint8_t> out;
  out.reserve(64 + idx.entries.size() * 128);

  push_u32(out, IDX_MAGIC);
  push_u32(out, IDX_VER);
  push_u32(out, (std::uint32_t)idx.entries.size());

  for (const auto& e : idx.entries) {
    push_string(out, e.path);
    const std::uint8_t type_u8 = (std::uint8_t)e.type;
    push_bytes(out, &type_u8, 1);
    push_u32(out, e.flags);
    push_u64(out, e.size);
    push_u64(out, e.data_offset);
    push_u64(out, e.data_size);

    std::vector<std::uint8_t> nonce = e.nonce;
    std::vector<std::uint8_t> tag = e.tag;

    nonce.resize(NONCE_SIZE, 0);
    tag.resize(TAG_SIZE, 0);

    push_bytes(out, nonce.data(), nonce.size());
    push_bytes(out, tag.data(), tag.size());
  }

  return out;
}

} // namespace ph1654::index

