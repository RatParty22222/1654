#include "pass.hpp"

#include <iostream>
#include <string>
#include <cstdlib>

#if defined(__unix__) || defined(__APPLE__)
  #include <unistd.h>
  #include <termios.h>
#endif

namespace ph1654::pass {

static bool stdin_is_tty() {
#if defined(__unix__) || defined(__APPLE__)
  return ::isatty(STDIN_FILENO);
#else
  return true;
#endif
}

#if defined(__unix__) || defined(__APPLE__)
struct TermiosGuard {
  termios old{};
  bool ok = false;

  TermiosGuard() {
    if (!stdin_is_tty()) return;
    if (::tcgetattr(STDIN_FILENO, &old) != 0) return;

    termios t = old;
    t.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (::tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0) return;

    ok = true;
  }

  ~TermiosGuard() {
    if (ok) {
      ::tcsetattr(STDIN_FILENO, TCSANOW, &old);
    }
  }
};
#endif

std::string prompt_password(const char* prompt) {
  if (!stdin_is_tty()) {
    std::cerr << "Error: password input requires a TTY (interactive terminal)\n";
    std::exit(1);
  }

  if (prompt && *prompt) {
    std::cerr << prompt;
    std::cerr.flush();
  }

#if defined(__unix__) || defined(__APPLE__)
  TermiosGuard guard;
#endif

  std::string pw;
  std::getline(std::cin, pw);

#if defined(__unix__) || defined(__APPLE__)
  std::cerr << "\n";
  std::cerr.flush();
#endif

  return pw;
}

std::string read_password() {
  return prompt_password("Password: ");
}

} // namespace ph1654::pass


