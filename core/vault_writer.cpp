#include "vault_writer.hpp"

#include "vault_format.hpp"
#include "index.hpp"
#include "kdf.hpp"
#include "mac.hpp"
#include "rand.hpp"
#include "endian.hpp"
#include "object_crypto.hpp"
#include "defs.hpp"

#include <filesystem>
#include <fstream>
#include <cstring>

namespace ph1654::vault {
namespace fs = std::filesystem;

static Status io_err(const char* m) {
  return Status::err(ExitCode::IoError, m);
}

static std::string default_out_name(const fs::path& in) {
  fs::path base = in;
  if (fs::is_directory(in)) {
    if (!in.filename().empty()) base = in.filename();
    else base = "vault";
  } else {
    base = in.filename().empty() ? "vault" : in.filename();
  }
  return (in.parent_path() / (base.string() + ".1654")).string();
}

static void write_global_header(std::ofstream& ofs, fmt::GlobalHeader& h) {
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

static bool has_dir_entry(const index::Index& idx, const std::string& path) {
  for (const auto& e : idx.entries) {
    if (e.type == fmt::ObjType::Dir && e.path == path && (e.flags & fmt::F_DELETED) == 0)
      return true;
  }
  return false;
}

static void ensure_parent_dirs(index::Index& idx, const std::string& full_path) {
  std::size_t pos = 0;
  while (true) {
    pos = full_path.find('/', pos);
    if (pos == std::string::npos) break;
    const std::string dir = full_path.substr(0, pos);
    if (!dir.empty() && !has_dir_entry(idx, dir)) {
      index::Entry d;
      d.path = dir;
      d.type = fmt::ObjType::Dir;
      d.flags = fmt::F_VISIBLE;
      d.size = 0;
      d.data_offset = 0;
      d.data_size = 0;
      d.nonce.assign(NONCE_SIZE, 0);
      d.tag.assign(TAG_SIZE, 0);
      idx.entries.push_back(std::move(d));
    }
    ++pos;
  }
}

static Status write_one_file(
  std::ofstream& ofs,
  const fs::path& file_path,
  const std::string& in_vault_path,
  const kdf::Keys& keys,
  index::Index& idx
) {
  std::ifstream ifs(file_path, std::ios::binary);
  if (!ifs) return io_err("encrypt: cannot open input file");

  index::Entry e;
  e.path = in_vault_path;
  e.type = fmt::ObjType::File;
  e.flags = fmt::F_VISIBLE;

  std::error_code ec;
  const auto sz = fs::file_size(file_path, ec);
  e.size = ec ? 0 : (std::uint64_t)sz;

  ensure_parent_dirs(idx, e.path);

  e.nonce = rnd::bytes(NONCE_SIZE);
  e.data_offset = (std::uint64_t)ofs.tellp();

  std::uint64_t written = 0;
  std::vector<std::uint8_t> tag;

  auto st = obj::encrypt_stream(
    ifs, ofs,
    keys.enc, keys.mac,
    e.nonce,
    written,
    tag
  );
  if (!st.is_ok()) return st;

  e.data_size = written;
  e.tag = tag;

  idx.entries.push_back(std::move(e));
  return Status::ok();
}

Status create_vault_from_path(
  const std::string& input_path,
  const std::string& out_path,
  const std::string& password,
  std::size_t key_bits,
  std::uint32_t kdf_cost
) {
  fs::path in = fs::path(input_path);
  if (!fs::exists(in))
    return Status::err(ExitCode::IoError, "encrypt: input path not found");

  std::string out = out_path.empty() ? default_out_name(in) : out_path;
  fs::path outp = fs::path(out);
  if (outp.extension() != ".1654") {
    outp += ".1654";
    out = outp.string();
  }

  fmt::GlobalHeader gh{};
  gh.magic = fmt::VAULT_MAGIC;
  gh.version = VERSION;

  auto salt = rnd::bytes(SALT_SIZE);
  auto nonce = rnd::bytes(NONCE_SIZE);
  std::memcpy(gh.salt.data(), salt.data(), SALT_SIZE);
  std::memcpy(gh.nonce.data(), nonce.data(), NONCE_SIZE);

  write_u32_le(gh.reserved.data() + 0, (std::uint32_t)key_bits);
  write_u32_le(gh.reserved.data() + 4, kdf_cost);

  const auto salt_vec = std::vector<std::uint8_t>(gh.salt.begin(), gh.salt.end());
  const std::size_t key_bytes = bits_to_bytes(key_bits);
  kdf::Keys keys = kdf::derive(password, salt_vec, key_bytes, kdf_cost);

  std::ofstream ofs(out, std::ios::binary | std::ios::trunc);
  if (!ofs) return io_err("encrypt: cannot create vault output file");

  write_global_header(ofs, gh);
  if (!ofs) return io_err("encrypt: write header failed");

  index::Index idx;

  if (fs::is_regular_file(in)) {
    const std::string name = in.filename().string().empty() ? "file" : in.filename().string();
    auto st = write_one_file(ofs, in, name, keys, idx);
    if (!st.is_ok()) return st;
  } else if (fs::is_directory(in)) {
    const std::string root = in.filename().string().empty() ? "folder" : in.filename().string();

    if (!has_dir_entry(idx, root)) {
      index::Entry d;
      d.path = root;
      d.type = fmt::ObjType::Dir;
      d.flags = fmt::F_VISIBLE;
      d.size = 0;
      d.data_offset = 0;
      d.data_size = 0;
      d.nonce.assign(NONCE_SIZE, 0);
      d.tag.assign(TAG_SIZE, 0);
      idx.entries.push_back(std::move(d));
    }

    for (auto it = fs::recursive_directory_iterator(in); it != fs::recursive_directory_iterator(); ++it) {
      const fs::path sub = it->path();
      const fs::path rel = fs::relative(sub, in);
      const std::string in_vault = root + "/" + rel.generic_string();

      if (it->is_directory()) {
        if (!has_dir_entry(idx, in_vault)) {
          index::Entry d;
          d.path = in_vault;
          d.type = fmt::ObjType::Dir;
          d.flags = fmt::F_VISIBLE;
          d.size = 0;
          d.data_offset = 0;
          d.data_size = 0;
          d.nonce.assign(NONCE_SIZE, 0);
          d.tag.assign(TAG_SIZE, 0);
          idx.entries.push_back(std::move(d));
        }
      } else if (it->is_regular_file()) {
        auto st = write_one_file(ofs, sub, in_vault, keys, idx);
        if (!st.is_ok()) return st;
      }
    }
  } else {
    return Status::err(ExitCode::IoError, "encrypt: unsupported input type");
  }

  const std::uint64_t index_offset = (std::uint64_t)ofs.tellp();
  auto idx_bytes = index::encode_index(idx);
  ofs.write(reinterpret_cast<const char*>(idx_bytes.data()), (std::streamsize)idx_bytes.size());
  if (!ofs) return io_err("encrypt: write index failed");

  const auto idx_tag = mac::compute(keys.mac, idx_bytes.data(), idx_bytes.size());

  fmt::IndexTrailer tr{};
  tr.magic = fmt::INDEX_MAGIC;
  tr.trailer_size = (std::uint32_t)fmt::INDEX_TRAILER_SIZE;
  tr.index_offset = index_offset;
  tr.index_size = (std::uint64_t)idx_bytes.size();
  std::memcpy(tr.index_tag.data(), idx_tag.data(), TAG_SIZE);

  write_index_trailer(ofs, tr);
  if (!ofs) return io_err("encrypt: write trailer failed");

  return Status::ok();
}

} // namespace ph1654::vault
