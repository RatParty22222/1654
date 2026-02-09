#include "vault_reader.hpp"

#include "endian.hpp"
#include "mac.hpp"
#include "index.hpp"
#include "kdf.hpp"
#include "defs.hpp"
#include "vault_format.hpp"

#include <fstream>
#include <cstring>
#include <vector>
#include <cstdint>

namespace ph1654::vault {

static Status io_err(const char* m) {
  return Status::err(ExitCode::IoError, m);
}

static Status integrity_err(const char* m) {
  return Status::err(ExitCode::IntegrityError, m);
}

static bool read_exact(std::ifstream& ifs, std::uint8_t* dst, std::size_t n) {
  ifs.read(reinterpret_cast<char*>(dst), (std::streamsize)n);
  return (std::size_t)ifs.gcount() == n;
}

static bool seek_abs(std::ifstream& ifs, std::uint64_t pos) {
  ifs.clear();
  ifs.seekg((std::streamoff)pos, std::ios::beg);
  return (bool)ifs;
}

Status open_for_view(
  const std::string& path,
  const std::string& password,
  VaultOpen& out
) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return io_err("open vault failed");

  ifs.seekg(0, std::ios::end);
  std::streamoff end_off = ifs.tellg();
  if (end_off < 0) return io_err("tellg failed");
  const std::uint64_t fsz = (std::uint64_t)end_off;

  if (fsz < (std::uint64_t)fmt::GLOBAL_HEADER_SIZE)
    return integrity_err("truncated vault (too small header)");

  if (fsz < (std::uint64_t)fmt::INDEX_TRAILER_SIZE)
    return integrity_err("truncated vault (too small trailer)");

  if (!seek_abs(ifs, 0)) return io_err("seek header failed");

  std::vector<std::uint8_t> hdr(fmt::GLOBAL_HEADER_SIZE);
  if (!read_exact(ifs, hdr.data(), hdr.size()))
    return io_err("read header failed");

  std::size_t off = 0;
  std::memcpy(out.header.magic.data(), hdr.data() + off, 4); off += 4;
  out.header.version = endian::load_u32_le(hdr.data() + off); off += 4;
  out.header.header_size = endian::load_u32_le(hdr.data() + off); off += 4;
  std::memcpy(out.header.salt.data(), hdr.data() + off, SALT_SIZE); off += SALT_SIZE;
  std::memcpy(out.header.nonce.data(), hdr.data() + off, NONCE_SIZE); off += NONCE_SIZE;
  std::memcpy(out.header.reserved.data(), hdr.data() + off, 32); off += 32;

  if (out.header.magic != fmt::VAULT_MAGIC)
    return integrity_err("bad magic");

  if (out.header.header_size < (std::uint32_t)fmt::GLOBAL_HEADER_SIZE)
    return integrity_err("bad header_size");
  if ((std::uint64_t)out.header.header_size > fsz)
    return integrity_err("bad header_size");

  const std::uint64_t trailer_pos = fsz - (std::uint64_t)fmt::INDEX_TRAILER_SIZE;
  if (!seek_abs(ifs, trailer_pos))
    return io_err("seek trailer failed");

  std::vector<std::uint8_t> trb(fmt::INDEX_TRAILER_SIZE);
  if (!read_exact(ifs, trb.data(), trb.size()))
    return io_err("read trailer failed");

  off = 0;
  std::memcpy(out.trailer.magic.data(), trb.data() + off, 4); off += 4;
  out.trailer.trailer_size = endian::load_u32_le(trb.data() + off); off += 4;
  out.trailer.index_offset = endian::load_u64_le(trb.data() + off); off += 8;
  out.trailer.index_size   = endian::load_u64_le(trb.data() + off); off += 8;
  std::memcpy(out.trailer.index_tag.data(), trb.data() + off, TAG_SIZE);

  if (out.trailer.magic != fmt::INDEX_MAGIC)
    return integrity_err("bad trailer magic");

  if (out.trailer.trailer_size != (std::uint32_t)fmt::INDEX_TRAILER_SIZE)
    return integrity_err("bad trailer_size");

  const std::uint64_t idx_off = out.trailer.index_offset;
  const std::uint64_t idx_sz  = out.trailer.index_size;

  const std::uint64_t MAX_INDEX_SIZE = 64ull * 1024ull * 1024ull;

  if (idx_sz == 0 || idx_sz > MAX_INDEX_SIZE)
    return integrity_err("bad index_size");

  if (idx_off < (std::uint64_t)out.header.header_size)
    return integrity_err("bad index_offset");

  if (idx_off > trailer_pos)
    return integrity_err("index_offset beyond trailer");

  if (idx_off + idx_sz > trailer_pos)
    return integrity_err("truncated vault (index beyond EOF)");

  if (!seek_abs(ifs, idx_off))
    return io_err("seek index failed");

  std::vector<std::uint8_t> idx_bytes((std::size_t)idx_sz);
  if (!read_exact(ifs, idx_bytes.data(), idx_bytes.size()))
    return io_err("read index failed");

  std::uint32_t bits_u32 = read_u32_le(out.header.reserved.data() + 0);
  std::uint32_t cost_u32 = read_u32_le(out.header.reserved.data() + 4);

  std::size_t key_bits = bits_u32 ? (std::size_t)bits_u32 : 512;
  std::uint32_t kdf_cost = cost_u32 ? cost_u32 : 1;

  const std::size_t key_bytes = bits_to_bytes(key_bits);
  const auto salt = std::vector<std::uint8_t>(out.header.salt.begin(), out.header.salt.end());

  out.keys = kdf::derive(password, salt, key_bytes, kdf_cost);

  if (!mac::verify(
        out.keys.mac,
        idx_bytes.data(),
        idx_bytes.size(),
        std::vector<std::uint8_t>(out.trailer.index_tag.begin(), out.trailer.index_tag.end())
      )) {
    return Status::err(ExitCode::IntegrityError, "wrong password or corrupted vault");
  }

  return index::decode_index(idx_bytes.data(), idx_bytes.size(), out.idx);
}

} // namespace ph1654::vault

