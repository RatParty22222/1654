#include "modes.hpp"

#include "../core/vault_reader.hpp"
#include "../core/pass.hpp"
#include "../core/path.hpp"
#include "../core/vault_format.hpp"

#include <iostream>

namespace ph1654::modes {

static void parse_flags(const Args& args, std::string& pattern, bool& show_hidden, bool& show_all) {
  pattern.clear();
  show_hidden = false;
  show_all = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    if (args[i] == "--search" && i + 1 < args.size()) {
      pattern = args[i + 1];
      ++i;
    } else if (args[i] == "--hidden") {
      show_hidden = true;
    } else if (args[i] == "--all") {
      show_all = true;
    }
  }
}

Status view_cmd(const Args& args) {
  if (args.size() < 1) {
    return Status::err(ExitCode::Usage, "Usage: 1654 view <vault.1654> [--search <pattern>] [--hidden] [--all]");
  }

  const std::string vault_path = args[0];

  std::string pattern;
  bool show_hidden = false;
  bool show_all = false;
  parse_flags(args, pattern, show_hidden, show_all);

  const std::string password = pass::prompt_password();

  vault::VaultOpen vo;
  auto st = vault::open_for_view(vault_path, password, vo);
  if (!st.is_ok()) return st;

  for (const auto& e : vo.idx.entries) {
    const bool deleted = (e.flags & fmt::F_DELETED) != 0;
    const bool hidden  = (e.flags & fmt::F_HIDDEN)  != 0;

    if (deleted && !show_all) continue;
    if (hidden && !show_hidden) continue;

    if (!pattern.empty() && !path::match(pattern, e.path)) continue;

    std::cout << e.path;
    if (e.type == fmt::ObjType::Dir) std::cout << "/";
    if (deleted) std::cout << " [deleted]";
    else if (hidden) std::cout << " [hidden]";
    std::cout << "\n";
  }

  return Status::ok();
}

} // namespace ph1654::modes

