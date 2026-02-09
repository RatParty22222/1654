#pragma once
#include <string>
#include <vector>

#include "errors.hpp"
#include "vault_reader.hpp"
#include "index.hpp"

namespace ph1654::vault {

Status append_index_and_trailer(
  const std::string& vault_path,
  const kdf::Keys& keys,
  const index::Index& idx
);

Status add_paths_to_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths
);

Status delete_paths_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths
);

Status set_hidden_paths_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::vector<std::string>& paths,
  bool hidden
);

Status replace_file_in_vault(
  const std::string& vault_path,
  const std::string& password,
  const std::string& target_path_in_vault,
  const std::string& new_os_path
);

} // namespace ph1654::vault

