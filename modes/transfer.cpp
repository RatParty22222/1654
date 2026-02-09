#include "modes.hpp"

#include "../core/vault_transfer.hpp"
#include "../core/pass.hpp"

namespace ph1654::modes {

Status transfer_cmd(const Args& args) {
  if (args.size() < 2) {
    return Status::err(
      ExitCode::Usage,
      "Usage: 1654 transfer <src.1654> <dst.1654> [paths...] [--hidden]"
    );
  }

  const std::string src_vault = args[0];
  const std::string dst_vault = args[1];

  std::vector<std::string> paths;
  bool include_hidden = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    if (args[i] == "--hidden") {
      include_hidden = true;
    } else {
      paths.push_back(args[i]);
    }
  }

  const std::string src_pass = pass::prompt_password("Source password: ");
  const std::string dst_pass = pass::prompt_password("Destination password: ");

  return vault::transfer_to_vault(
    src_vault,
    src_pass,
    dst_vault,
    dst_pass,
    paths,
    include_hidden
  );
}

} // namespace ph1654::modes

