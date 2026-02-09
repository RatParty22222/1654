#include "modes.hpp"

#include "../core/vault_update.hpp"
#include "../core/pass.hpp"

namespace ph1654::modes {

Status edit_cmd(const Args& args) {
  if (args.size() < 3) {
    return Status::err(ExitCode::Usage, "Usage: 1654 edit <vault.1654> <target_path> --from <new_file>");
  }

  const std::string vault_path = args[0];
  const std::string target_path = args[1];

  std::string from;
  for (std::size_t i = 2; i + 1 < args.size(); ++i) {
    if (args[i] == "--from") {
      from = args[i + 1];
      break;
    }
  }
  if (from.empty()) {
    return Status::err(ExitCode::Usage, "edit: missing --from <new_file>");
  }

  const std::string password = pass::prompt_password();

  return vault::replace_file_in_vault(vault_path, password, target_path, from);
}

} // namespace ph1654::modes

