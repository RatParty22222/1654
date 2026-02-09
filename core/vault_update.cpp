#include "vault_update.hpp"

#include "vault_format.hpp"
#include "endian.hpp"
#include "mac.hpp"
#include "kdf.hpp"
#include "rand.hpp"
#include "object_crypto.hpp"
#include "vault_reader.hpp"

#include <filesystem>
#include <fstream>
#include <cstring>
#include <vector>
#include <chrono>

#if defined(__unix__) || defined(__APPLE__)
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
#endif

namespace ph1654::vault {
namespace fs = std::filesystem;

static Status io_err(const char* m) {
  return Status::err(ExitCode::IoError, m);
}

static Status integrity_err(const char* m) {
  return Status::err(ExitCode::IntegrityError, m);
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

static bool is_prefix_path(const std::string& prefix, const std::string& p) {
  if (prefix == p) return true;
  if (p.size() > prefix.size() &&
      p.compare(0, prefix.size(), prefix) == 0 &&
      p[prefix.size()] == '/') return true;
  return false;
}

static bool entry_exists_not_deleted(const index::Index& idx, const std::string& path) {
  for (const auto& e : idx.entries) {
    if (e.path == path && (e.flags & fmt::F_DELETED) == 0) return true;
  }
  return false;
}

static bool has_dir_entry(const index::Index& idx, const std::string& path) {
  for (const auto& e : idx.entries) {
    if (e.path == path && e.type == fmt::ObjType::Dir && (e.flags & fmt::F_DELETED) == 0) return true;
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

static void add_dir_entry(index::Index& idx, const std::string& path) {
  if (path.empty()) return;
  if (has_dir_entry(idx, path)) return;

  index::Entry d;
  d.path = path;
  d.type = fmt::ObjType::Dir;
  d.flags = fmt::F_VISIBLE;
  d.size = 0;
  d.data_offset = 0;
  d.data_size = 0;
  d.nonce.assign(NONCE_SIZE, 0);
  d.tag.assign(TAG_SIZE, 0);
  idx.entries.push_back(std::move(d));
}

static bool copy_prefix_bytes(
  const std::string& src_path,
  std::ofstream& dst,
  std::uint64_t nbytes
) {
  std::ifstream src(src_path, std::ios::binary);
  if (!src) return false;

  constexpr std::size_t CHUNK = 1u << 20;
  std::vector<char> buf(CHUNK);

  std::uint64_t remain = nbytes;
  while (remain > 0) {
    const std::size_t take = (remain > CHUNK) ? CHUNK : (std::size_t)remain;
    src.read(buf.data(), (std::streamsize)take);
    if ((std::size_t)src.gcount() != take) return false;
    dst.write(buf.data(), (std::streamsize)take);
    if (!dst) return false;
    remain -= take;
  }
  return true;
}

static fs::path make_temp_path(const fs::path& vault_path) {
  auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()
            ).count();

#if defined(__unix__) || defined(__APPLE__)
  int pid = (int)getpid();
#else
  int pid = 0;
#endif

  fs::path tmp = vault_path;
  tmp += ".tmp.";
  tmp += std::to_string((long long)pid);
  tmp += ".";
  tmp += std::to_string((long long)now);
  return tmp;
}

static bool fsync_path_best_effort(const fs::path& p) {
#if defined(__unix__) || defined(__APPLE__)
  int fd = ::open(p.c_str(), O_RDONLY);
  if (fd < 0) return false;
  int rc = ::fsync(fd);
  ::close(fd);
  return rc == 0;
#else
  (void)p;
  return true;
#endif
}

static bool fsync_dir_best_effort(const fs::path& dir) {
#if defined(__unix__) || defined(__APPLE__)
  int fd = ::open(dir.c_str(), O_RDONLY);
  if (fd < 0) return false;
  int rc = ::fsync(fd);
  ::close(fd);
  return rc == 0;
#else
  (void)dir;
  return true;
#endif
}

static Status write_index_and_trailer_to_stream(
  std::ofstream& ofs,
  const kdf::Keys& keys,
  const index::Index& idx
) {
  auto idx_bytes = index::encode_index(idx);
  const std::uint64_t index_offset = (std::uint64_t)ofs.tellp();

  ofs.write(reinterpret_cast<const char*>(idx_bytes.data()), (std::streamsize)idx_bytes.size());
  if (!ofs) return io_err("update: write index failed");

  const auto idx_tag = mac::compute(keys.mac, idx_bytes.data(), idx_bytes.size());

  fmt::IndexTrailer tr{};
  tr.magic = fmt::INDEX_MAGIC;
  tr.trailer_size = (std::uint32_t)fmt::INDEX_TRAILER_SIZE;
  tr.index_offset = index_offset;
  tr.index_size = (std::uint64_t)idx_bytes.size();
  std::memcpy(tr.index_tag.data(), idx_tag.data(), TAG_SIZE);

  write_index_trailer(ofs, tr);
  if (!ofs) return io_err("update: write trailer failed");

  return Status::ok();
}

static Status open_for_mutation(const std::string& vault_path, const std::string& password, VaultOpen& vo) {
  auto st = open_for_view(vault_path, password, vo);
  if (!st.is_ok()) return st;
  return Status::ok();
}

static Status append_file_object(
  std::ofstream& ofs,
  const fs::path& src,
  const kdf::Keys& keys,
  index::Entry& out_entry
) {
  std::ifstream ifs(src, std::ios::binary);
  if (!ifs) return io_err("add: cannot open input file");

  const auto nonce = rnd::bytes(NONCE_SIZE);
  out_entry.nonce = nonce;

  const std::uint64_t offset = (std::uint64_t)ofs.tellp();
  out_entry.data_offset = offset;

  std::uint64_t written = 0;
  std::vector<std::uint8_t> tag;

  auto st = obj::encrypt_stream(
    ifs, ofs,
    keys.enc, keys.mac,
    nonce,
    written,
    tag
  );
  if (!st.is_ok()) return st;

  out_entry.data_size = written;
  out_entry.tag = tag;

  return Status::ok();
}

template <class ExtraWriter>
static Status atomic_rewrite_vault(
  const std::string& vault_path,
  const VaultOpen& vo,
  index::Index& new_idx,
  ExtraWriter extra_writer
) {
  const std::uint64_t prefix_len = vo.trailer.index_offset;
  if (prefix_len < (std::uint64_t)fmt::GLOBAL_HEADER_SIZE) {
    return integrity_err("update: bad old index_offset");
  }

  fs::path vp(vault_path);
  fs::path tmp = make_temp_path(vp);

  std::error_code ec;
  const auto old_perm = fs::status(vp, ec).permissions();

  {
    std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
    if (!ofs) return io_err("update: cannot create temp vault");

    if (!copy_prefix_bytes(vault_path, ofs, prefix_len))
      return io_err("update: copy prefix failed");

    auto stx = extra_writer(ofs);
    if (!stx.is_ok()) return stx;

    auto st2 = write_index_and_trailer_to_stream(ofs, vo.keys, new_idx);
    if (!st2.is_ok()) return st2;

    ofs.flush();
    if (!ofs) return io_err("update: flush temp failed");
  }

  if (!ec) {
    std::error_code ec2;
    fs::permissions(tmp, old_perm, ec2);
  }

  (void)fsync_path_best_effort(tmp);
  (void)fsync_dir_best_effort(tmp.parent_path());

  {
    std::error_code ec3;
    fs::rename(tmp, vp, ec3);
    if (ec3) {
      std::error_code ec4;
      fs::remove(vp, ec4);
      fs::rename(tmp, vp, ec3);
      if (ec3) {
        std::error_code ec5;
        fs::remove(tmp, ec5);
        return io_err("update: rename temp->vault failed");
      }
    }
  }

  (void)fsync_dir_best_effort(vp.parent_path());

  return Status::ok();
}

Status add_paths_to_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths
) {
  VaultOpen vo;
  auto st = open_for_mutation(vault_path, password, vo);
  if (!st.is_ok()) return st;

  index::Index new_idx = vo.idx;

  auto extra = [&](std::ofstream& ofs) -> Status {
    for (const auto& pstr : paths) {
      fs::path p = fs::path(pstr);
      if (!fs::exists(p)) return Status::err(ExitCode::IoError, "add: input path not found");

      if (fs::is_directory(p)) {
        const std::string root = p.filename().string().empty() ? "folder" : p.filename().string();
        if (entry_exists_not_deleted(new_idx, root) || has_dir_entry(new_idx, root)) {
          return Status::err(ExitCode::IoError, "add: path collision in vault");
        }

        add_dir_entry(new_idx, root);

        for (auto it = fs::recursive_directory_iterator(p); it != fs::recursive_directory_iterator(); ++it) {
          const fs::path sub = it->path();
          const fs::path rel = fs::relative(sub, p);
          const std::string in_vault = root + "/" + rel.generic_string();

          if (it->is_directory()) {
            add_dir_entry(new_idx, in_vault);
          } else if (it->is_regular_file()) {
            if (entry_exists_not_deleted(new_idx, in_vault)) {
              return Status::err(ExitCode::IoError, "add: file collision in vault");
            }

            ensure_parent_dirs(new_idx, in_vault);

            index::Entry e;
            e.path = in_vault;
            e.type = fmt::ObjType::File;
            e.flags = fmt::F_VISIBLE;

            std::error_code ec;
            const auto sz = fs::file_size(sub, ec);
            e.size = ec ? 0 : (std::uint64_t)sz;

            auto st2 = append_file_object(ofs, sub, vo.keys, e);
            if (!st2.is_ok()) return st2;

            new_idx.entries.push_back(std::move(e));
          }
        }
      } else if (fs::is_regular_file(p)) {
        const std::string name = p.filename().string().empty() ? "file" : p.filename().string();
        if (entry_exists_not_deleted(new_idx, name)) {
          return Status::err(ExitCode::IoError, "add: file collision in vault");
        }

        index::Entry e;
        e.path = name;
        e.type = fmt::ObjType::File;
        e.flags = fmt::F_VISIBLE;

        std::error_code ec;
        const auto sz = fs::file_size(p, ec);
        e.size = ec ? 0 : (std::uint64_t)sz;

        auto st2 = append_file_object(ofs, p, vo.keys, e);
        if (!st2.is_ok()) return st2;

        new_idx.entries.push_back(std::move(e));
      } else {
        return Status::err(ExitCode::IoError, "add: unsupported path type");
      }
    }
    return Status::ok();
  };

  return atomic_rewrite_vault(vault_path, vo, new_idx, extra);
}

Status delete_paths_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths
) {
  VaultOpen vo;
  auto st = open_for_mutation(vault_path, password, vo);
  if (!st.is_ok()) return st;

  index::Index new_idx = vo.idx;

  bool any = false;
  for (auto& e : new_idx.entries) {
    for (const auto& p : paths) {
      if (is_prefix_path(p, e.path)) {
        if ((e.flags & fmt::F_DELETED) == 0) {
          e.flags |= fmt::F_DELETED;
          any = true;
        }
      }
    }
  }
  if (!any) return Status::err(ExitCode::IoError, "delete: no matching paths");

  auto extra = [&](std::ofstream&) -> Status { return Status::ok(); };
  return atomic_rewrite_vault(vault_path, vo, new_idx, extra);
}

Status set_hidden_paths_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths,
  bool hidden
) {
  VaultOpen vo;
  auto st = open_for_mutation(vault_path, password, vo);
  if (!st.is_ok()) return st;

  index::Index new_idx = vo.idx;

  bool any = false;
  for (auto& e : new_idx.entries) {
    for (const auto& p : paths) {
      if (is_prefix_path(p, e.path)) {
        if ((e.flags & fmt::F_DELETED) != 0) continue;

        if (hidden) {
          if ((e.flags & fmt::F_HIDDEN) == 0) { e.flags |= fmt::F_HIDDEN; any = true; }
        } else {
          if ((e.flags & fmt::F_HIDDEN) != 0) { e.flags &= ~fmt::F_HIDDEN; any = true; }
        }
      }
    }
  }
  if (!any) return Status::err(ExitCode::IoError, "stealth: no matching paths");

  auto extra = [&](std::ofstream&) -> Status { return Status::ok(); };
  return atomic_rewrite_vault(vault_path, vo, new_idx, extra);
}

Status replace_file_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::string& target_path_in_vault,
  const std::string& new_os_path
) {
  VaultOpen vo;
  auto st = open_for_mutation(vault_path, password, vo);
  if (!st.is_ok()) return st;

  fs::path src = fs::path(new_os_path);
  if (!fs::exists(src) || !fs::is_regular_file(src)) {
    return Status::err(ExitCode::IoError, "edit: --from must be a regular file");
  }

  index::Index new_idx = vo.idx;

  bool found = false;
  for (auto& e : new_idx.entries) {
    if (e.path == target_path_in_vault && e.type == fmt::ObjType::File && (e.flags & fmt::F_DELETED) == 0) {
      e.flags |= fmt::F_DELETED;
      found = true;
    }
  }
  if (!found) return Status::err(ExitCode::IoError, "edit: target path not found");

  ensure_parent_dirs(new_idx, target_path_in_vault);

  auto extra = [&](std::ofstream& ofs) -> Status {
    index::Entry e;
    e.path = target_path_in_vault;
    e.type = fmt::ObjType::File;
    e.flags = fmt::F_VISIBLE;

    std::error_code ec;
    const auto sz = fs::file_size(src, ec);
    e.size = ec ? 0 : (std::uint64_t)sz;

    auto st2 = append_file_object(ofs, src, vo.keys, e);
    if (!st2.is_ok()) return st2;

    new_idx.entries.push_back(std::move(e));
    return Status::ok();
  };

  return atomic_rewrite_vault(vault_path, vo, new_idx, extra);
}

} // namespace ph1654::vault
