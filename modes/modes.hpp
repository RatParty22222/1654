#pragma once
#include <vector>
#include <string>

#include "../core/errors.hpp"

namespace ph1654::modes {

using Args = std::vector<std::string>;

Status encrypt_cmd(const Args& args);
Status decrypt_cmd(const Args& args);
Status view_cmd(const Args& args);
Status extract_cmd(const Args& args);
Status add_cmd(const Args& args);
Status delete_cmd(const Args& args);
Status edit_cmd(const Args& args);
Status stealth_plus_cmd(const Args& args);
Status stealth_minus_cmd(const Args& args);
Status transfer_cmd(const Args& args);

} // namespace ph1654::modes

