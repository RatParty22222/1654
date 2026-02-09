#pragma once
#include <string>
#include <vector>

#include "errors.hpp"

namespace ph1654::vault {

Status transfer_to_vault(
  const std::string& src_vault,
  const std::string& src_password,
  const std::string& dst_vault,
  const std::string& dst_password,
  const std::vector<std::string>& select_paths,
  bool include_hidden
);

} // namespace ph1654::vault

