#pragma once
#include <string>

namespace ph1654 {

enum class ExitCode : int {
  Ok = 0,
  Usage = 2,
  IoError = 10,
  CryptoError = 20,
  IntegrityError = 30,
  NotImplemented = 90,
  InternalError = 99
};

struct Status {
  ExitCode code = ExitCode::Ok;
  std::string message;

  static Status ok() { return {ExitCode::Ok, {}}; }
  static Status err(ExitCode c, std::string m) { return {c, std::move(m)}; }
  bool is_ok() const { return code == ExitCode::Ok; }
};

} // namespace ph1654

