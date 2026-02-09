#include "modes.hpp"

namespace ph1654::modes {

Status add_cmd(const Args& args) {
  if (args.size() < 2) {
    return Status::err(ExitCode::Usage, "Usage: 1654 add <vault.1654> <path...>");
  }
  (void)args;
  return Status::err(ExitCode::NotImplemented, "add: not implemented yet");
}

} // namespace ph1654::modes

