#include "modes.hpp"

#include "../core/vault_writer.hpp"
#include "../core/pass.hpp"
#include "../core/defs.hpp"

#include <cstdlib>

namespace ph1654::modes {

Status encrypt_cmd(const Args& args) {
  if (args.size() < 1) {
    return Status::err(ExitCode::Usage, "Usage: 1654 encrypt <path> [--out <vault.1654>] [--bits N] [--cost N]");
  }

  std::string in_path = args[0];
  std::string out_vault;

  std::size_t bits = DEFAULT_KEY_BITS;
  std::uint32_t cost = DEFAULT_KDF_COST;

  for (std::size_t i = 1; i < args.size(); ++i) {
    if (args[i] == "--out" && i + 1 < args.size()) {
      out_vault = args[i + 1];
      ++i;
    } else if (args[i] == "--bits" && i + 1 < args.size()) {
      bits = (std::size_t)std::strtoull(args[i + 1].c_str(), nullptr, 10);
      ++i;
    } else if (args[i] == "--cost" && i + 1 < args.size()) {
      cost = (std::uint32_t)std::strtoul(args[i + 1].c_str(), nullptr, 10);
      ++i;
    }
  }

  if (bits < 256 || (bits % 8) != 0) {
    return Status::err(ExitCode::Usage, "encrypt: --bits must be >= 256 and divisible by 8");
  }
  if (cost < 1) {
    return Status::err(ExitCode::Usage, "encrypt: --cost must be >= 1");
  }

  const std::string password = pass::prompt_password();
  return vault::create_vault_from_path(in_path, out_vault, password, bits, cost);
}

} // namespace ph1654::modes

