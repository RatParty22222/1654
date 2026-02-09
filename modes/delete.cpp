#include "modes.hpp"

#include "../core/vault_update.hpp"
#include "../core/pass.hpp"

namespace ph1654::modes {

Status delete_cmd(const Args& args) {
  if (args.size() < 2) {
    return Status::err(ExitCode::Usage, "Usage: 1654 delete <vault.1654> <path...>");
  }

  const std::string vault_path = args[0];
  std::vector<std::string> paths(args.begin() + 1, args.end());

  const std::string password = pass::prompt_password();

  return vault::delete_paths_in_vault(vault_path, password, paths);
}

} // namespace ph1654::modes

