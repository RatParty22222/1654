#pragma once
#include <string>

namespace ph1654::path {

static inline bool match_glob(const char* pat, const char* s) {
  while (*pat) {
    if (*pat == '*') {
      ++pat;
      if (!*pat) return true;
      while (*s) {
        if (match_glob(pat, s)) return true;
        ++s;
      }
      return false;
    } else if (*pat == '?') {
      if (!*s) return false;
      ++pat; ++s;
    } else {
      if (*pat != *s) return false;
      ++pat; ++s;
    }
  }
  return *s == '\0';
}

static inline bool match(const std::string& pattern, const std::string& value) {
  if (pattern.empty()) return true;
  return match_glob(pattern.c_str(), value.c_str());
}

} // namespace ph1654::path

