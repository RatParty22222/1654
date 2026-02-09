#include "vault_transfer.hpp"

#include "vault_reader.hpp"
#include "vault_format.hpp"
#include "index.hpp"
#include "rand.hpp"
#include "kdf.hpp"
#include "mac.hpp"
#include "object_crypto.hpp"
#include "endian.hpp"
#include "defs.hpp"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>

namespace ph1654::vault {
namespace fs = std::filesystem;

static Status io_err(const char* m) {
  return Status::err(ExitCode::IoError, m);
}

static bool match_prefix(const std::string& wanted, const std::string& entry) {
  if (wanted == entry) return true;
  if (entry.size() > wanted.size() &&
      entry.compare(0, wanted.size(), wanted) == 0 &&
      entry[wanted.size()] == '/') return true;
  return false;
}

static void write_global_header(std::ofstream& ofs, fmt::GlobalHeader& h) {
  h.magic = fmt::VAULT_MAGIC;
  h.version = VERSION;
  h.header_size = (std::uint32_t)fmt::GLOBAL_HEADER_SIZE;

  std::vector<std::uint8_t> buf(fmt::GLOBAL_HEADER_SIZE);
  std::size_t off = 0;

  std::memcpy(buf.data() + off, h.magic.data(), 4); off += 4;
  endian::store_u32_le(buf.data() + off, h.version); off += 4;
  endian::store_u32_le(buf.data() + off, h.header_size); off += 4;

  std::memcpy(buf.data() + off, h.salt.data(), SALT_SIZE); off += SALT_SIZE;
  std::memcpy(buf.data() + off, h.nonce.data(), NONCE_SIZE); off += NONCE_SIZE;
  std::memcpy(buf.data() + off, h.reserved.data(), 32); off += 32;

  ofs.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
}

static void write_index_trailer(std::ofstream& ofs, const fmt::IndexTrailer& tr) {
  std::vector<std::uint8_t> buf(fmt::INDEX_TRAILER_SIZE);
  std::size_t off = 0;

  std::memcpy(buf.data() + off, tr.magic.data(), 4); off += 4;
  endian::store_u32_le(buf.data() + off, tr.trailer_size); off += 4;
  endian::store_u64_le(buf.data() + off, tr.index_offset); off += 8;
  endian::store_u64_le(buf.data() + off, tr.index_size); off += 8;
  std::memcpy(buf.data() + off, tr.index_tag.data(), TAG_SIZE); off += TAG_SIZE;

  ofs.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
}

Status transfer_to_vault(
  const std::string& src_vault,
  const std::string& src_password,
  const std::string& dst_vault,
  const std::string& dst_password,
  const std::vector<std::string>& select_paths,
  bool include_hidden
) {
  VaultOpen src;
  auto st = open_for_view(src_vault, src_password, src);
  if (!st.is_ok()) return st;

  fmt::GlobalHeader dst_h{};
  dst_h.magic = fmt::VAULT_MAGIC;
  dst_h.version = VERSION;

  {
    auto salt = rnd::bytes(SALT_SIZE);
    auto nonce = rnd::bytes(NONCE_SIZE);
    std::memcpy(dst_h.salt.data(), salt.data(), SALT_SIZE);
    std::memcpy(dst_h.nonce.data(), nonce.data(), NONCE_SIZE);
  }

  const std::size_t key_bits = DEFAULT_KEY_BITS;
  const std::uint32_t kdf_cost = DEFAULT_KDF_COST;
  const std::size_t key_bytes = bits_to_bytes(key_bits);

  write_u32_le(dst_h.reserved.data() + 0, (std::uint32_t)key_bits);
  write_u32_le(dst_h.reserved.data() + 4, kdf_cost);

  const auto dst_salt_vec = std::vector<std::uint8_t>(dst_h.salt.begin(), dst_h.salt.end());
  auto dst_keys = kdf::derive(dst_password, dst_salt_vec, key_bytes, kdf_cost);

  std::ifstream ifs(src_vault, std::ios::binary);
  if (!ifs) return io_err("transfer: cannot open source vault");

  std::ofstream ofs(dst_vault, std::ios::binary | std::ios::trunc);
  if (!ofs) return io_err("transfer: cannot create destination vault");

  write_global_header(ofs, dst_h);
  if (!ofs) return io_err("transfer: write header failed");

  index::Index dst_idx;

  for (const auto& e : src.idx.entries) {
    if ((e.flags & fmt::F_DELETED) != 0) continue;
    if (!include_hidden && (e.flags & fmt::F_HIDDEN) != 0) continue;

    if (!select_paths.empty()) {
      bool ok = false;
      for (const auto& w : select_paths) {
        if (match_prefix(w, e.path)) { ok = true; break; }
      }
      if (!ok) continue;
    }

    if (e.type == fmt::ObjType::Dir) {
      index::Entry d = e;
      d.data_offset = 0;
      d.data_size = 0;
      d.nonce.assign(NONCE_SIZE, 0);
      d.tag.assign(TAG_SIZE, 0);
      dst_idx.entries.push_back(std::move(d));
      continue;
    }

    ifs.clear();
    ifs.seekg((std::streamoff)e.data_offset);
    if (!ifs) return io_err("transfer: seek source failed");

    std::vector<std::uint8_t> cipher((std::size_t)e.data_size);
    ifs.read(reinterpret_cast<char*>(cipher.data()), (std::streamsize)cipher.size());
    if (!ifs) return io_err("transfer: read source object failed");

    std::string cipher_str(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    std::istringstream cin(cipher_str);
    std::ostringstream pout;

    auto st2 = obj::decrypt_stream(
      cin,
      pout,
      src.keys.enc,
      src.keys.mac,
      e.nonce,
      e.data_size,
      e.tag
    );
    if (!st2.is_ok()) return st2;

    const std::string plain_str = pout.str();
    std::istringstream pin(plain_str);

    index::Entry fe = e;
    fe.flags = e.flags;
    fe.size = (std::uint64_t)plain_str.size();
    fe.nonce = rnd::bytes(NONCE_SIZE);

    fe.data_offset = (std::uint64_t)ofs.tellp();

    std::uint64_t written = 0;
    std::vector<std::uint8_t> tag;

    auto st3 = obj::encrypt_stream(
      pin,
      ofs,
      dst_keys.enc,
      dst_keys.mac,
      fe.nonce,
      written,
      tag
    );
    if (!st3.is_ok()) return st3;

    fe.data_size = written;
    fe.tag = tag;

    dst_idx.entries.push_back(std::move(fe));
  }

  const std::uint64_t index_offset = (std::uint64_t)ofs.tellp();
  auto idx_bytes = index::encode_index(dst_idx);

  ofs.write(reinterpret_cast<const char*>(idx_bytes.data()), (std::streamsize)idx_bytes.size());
  if (!ofs) return io_err("transfer: write index failed");

  const auto idx_tag = mac::compute(dst_keys.mac, idx_bytes.data(), idx_bytes.size());

  fmt::IndexTrailer tr{};
  tr.magic = fmt::INDEX_MAGIC;
  tr.trailer_size = (std::uint32_t)fmt::INDEX_TRAILER_SIZE;
  tr.index_offset = index_offset;
  tr.index_size = (std::uint64_t)idx_bytes.size();
  std::memcpy(tr.index_tag.data(), idx_tag.data(), TAG_SIZE);

  write_index_trailer(ofs, tr);
  if (!ofs) return io_err("transfer: write trailer failed");

  return Status::ok();
}

} // namespace ph1654::vault

