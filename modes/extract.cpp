#include "modes.hpp"

#include "../core/vault_reader.hpp"
#include "../core/object_crypto.hpp"
#include "../core/vault_transfer.hpp"
#include "../core/pass.hpp"
#include "../core/vault_format.hpp"

#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

namespace ph1654::modes {
namespace fs = std::filesystem;

static bool match_path_prefix(const std::string& wanted, const std::string& entry) {
  if (wanted == entry) return true;
  if (entry.size() > wanted.size() &&
      entry.compare(0, wanted.size(), wanted) == 0 &&
      entry[wanted.size()] == '/') {
    return true;
  }
  return false;
}

Status extract_cmd(const Args& args) {
  if (args.size() < 2) {
    return Status::err(ExitCode::Usage, "Usage: 1654 extract <vault.1654> <path...> [--out <dir>] [--to <vault2.1654> --pass-out <p>]");
  }

  const std::string vault_path = args[0];

  std::vector<std::string> wanted;
  std::string out_dir = ".";
  std::string to_vault;
  std::string pass_out;
  bool include_hidden = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    if (args[i] == "--out" && i + 1 < args.size()) {
      out_dir = args[i + 1];
      ++i;
    } else if (args[i] == "--to" && i + 1 < args.size()) {
      to_vault = args[i + 1];
      ++i;
    } else if (args[i] == "--pass-out" && i + 1 < args.size()) {
      pass_out = args[i + 1];
      ++i;
    } else if (args[i] == "--hidden") {
      include_hidden = true;
    } else {
      wanted.push_back(args[i]);
    }
  }

  if (wanted.empty()) return Status::err(ExitCode::Usage, "extract: no paths specified");

  const std::string password = pass::prompt_password();

  if (!to_vault.empty()) {
    if (pass_out.empty()) pass_out = pass::prompt_password("New password: ");
    return vault::transfer_to_vault(vault_path, password, to_vault, pass_out, wanted, include_hidden);
  }

  vault::VaultOpen vo;
  auto st = vault::open_for_view(vault_path, password, vo);
  if (!st.is_ok()) return st;

  std::ifstream ifs(vault_path, std::ios::binary);
  if (!ifs) return Status::err(ExitCode::IoError, "extract: cannot open vault file");

  fs::create_directories(out_dir);

  bool any = false;

  for (const auto& e : vo.idx.entries) {
    if (e.type != fmt::ObjType::File) continue;
    if ((e.flags & fmt::F_DELETED) != 0) continue;
    if (!include_hidden && (e.flags & fmt::F_HIDDEN) != 0) continue;

    bool want = false;
    for (const auto& w : wanted) {
      if (match_path_prefix(w, e.path)) { want = true; break; }
    }
    if (!want) continue;

    fs::path out_path = fs::path(out_dir) / fs::path(e.path);
    fs::create_directories(out_path.parent_path());

    std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
    if (!ofs) return Status::err(ExitCode::IoError, "extract: cannot create output file");

    ifs.clear();
    ifs.seekg((std::streamoff)e.data_offset);
    if (!ifs) return Status::err(ExitCode::IoError, "extract: seek failed");

    auto st2 = obj::decrypt_stream(
      ifs,
      ofs,
      vo.keys.enc,
      vo.keys.mac,
      e.nonce,
      e.data_size,
      e.tag
    );
    if (!st2.is_ok()) return st2;

    any = true;
  }

  if (!any) return Status::err(ExitCode::IoError, "extract: no matching files");

  return Status::ok();
}

} // namespace ph1654::modes

