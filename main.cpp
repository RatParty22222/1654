#include <iostream>
#include <string>
#include <vector>

#include "core/defs.hpp"
#include "core/errors.hpp"
#include "modes/modes.hpp"

namespace {

static void print_help() {
  using namespace ph1654;
  std::cout
    << TOOL_NAME << " — encrypted vault tool (PetoronHash-only)\n\n"
    << "Usage:\n"
    << "  1654 <command> [args...]\n\n"
    << "Commands:\n"
    << "  encrypt <path>             Create vault from file/folder -> .1654\n"
    << "  decrypt <vault.1654>       Decrypt whole vault to OS (or later: --to)\n"
    << "  view <vault.1654>          Show structure (use --search)\n"
    << "  extract <vault.1654> <p..> Extract selected paths\n"
    << "  add <vault.1654> <path..>  Append new files/folders\n"
    << "  delete <vault.1654> <p..>  Logical delete (index only)\n"
    << "  edit <vault.1654> ...      Replace object (add+delete)\n"
    << "  stealth+ <vault.1654> <p..> Hide objects from view\n"
    << "  stealth- <vault.1654> <p..> Unhide objects\n\n"
    << "Notes:\n"
    << "  - Verify is automatic; output only on failure.\n";
}

static std::vector<std::string> to_args(int argc, char** argv, int start) {
  std::vector<std::string> out;
  for (int i = start; i < argc; ++i) out.emplace_back(argv[i]);
  return out;
}

} // namespace

int main(int argc, char** argv) {
  using namespace ph1654;

  if (argc < 2) {
    print_help();
    return static_cast<int>(ExitCode::Usage);
  }

  const std::string cmd = argv[1];
  const auto args = to_args(argc, argv, 2);

  Status st;

  if (cmd == "encrypt") st = modes::encrypt_cmd(args);
  else if (cmd == "decrypt") st = modes::decrypt_cmd(args);
  else if (cmd == "view") st = modes::view_cmd(args);
  else if (cmd == "extract") st = modes::extract_cmd(args);
  else if (cmd == "add") st = modes::add_cmd(args);
  else if (cmd == "delete") st = modes::delete_cmd(args);
  else if (cmd == "edit") st = modes::edit_cmd(args);
  else if (cmd == "stealth+") st = modes::stealth_plus_cmd(args);
  else if (cmd == "stealth-") st = modes::stealth_minus_cmd(args);
  else if (cmd == "transfer") st = modes::transfer_cmd(args);
  else if (cmd == "-h" || cmd == "--help" || cmd == "help") {
    print_help();
    return static_cast<int>(ExitCode::Ok);
  } else {
    std::cerr << "Unknown command: " << cmd << "\n\n";
    print_help();
    return static_cast<int>(ExitCode::Usage);
  }

  if (!st.is_ok()) {
    if (!st.message.empty()) std::cerr << st.message << "\n";
    return static_cast<int>(st.code);
  }
  return static_cast<int>(ExitCode::Ok);
}

