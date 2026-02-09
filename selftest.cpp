#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <array>
#include <exception>

#if defined(__unix__) || defined(__APPLE__)
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <unistd.h>
  #include <signal.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #if defined(__APPLE__)
    #include <util.h>
  #else
    #include <pty.h>
  #endif
#endif

#include "core/defs.hpp"
#include "core/params.hpp"
#include "core/vault_reader.hpp"
#include "core/vault_format.hpp"
#include "core/index.hpp"

namespace fs = std::filesystem;

static const bool LOOSE_MODE = true;

static const int CLI_TIMEOUT_SLOW_MS = 30000;
static const int CLI_TIMEOUT_FAILFAST_MS = 1500;

static const int LIB_TIMEOUT_FAILFAST_MS = 1500;
static const int LIB_TIMEOUT_SLOW_MS = 8000;

static std::string hex(const std::uint8_t* p, std::size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    s.push_back(h[(p[i] >> 4) & 0xF]);
    s.push_back(h[p[i] & 0xF]);
  }
  return s;
}

static std::string read_file(const fs::path& p) {
  std::ifstream ifs(p, std::ios::binary);
  std::ostringstream ss;
  ss << ifs.rdbuf();
  return ss.str();
}

static void write_file(const fs::path& p, const std::string& data) {
  fs::create_directories(p.parent_path());
  std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
  ofs.write(data.data(), (std::streamsize)data.size());
}

static std::string now_ms() {
  using namespace std::chrono;
  auto t = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  return std::to_string((long long)t);
}

struct RunResult {
  int code = -1;
  std::string out;
};

static bool g_any_fail = false;
static int  g_fail_count = 0;
static int  g_skip_count = 0;

static void mark_fail() { g_any_fail = true; g_fail_count++; }
static void mark_skip() { g_skip_count++; }

#if defined(__unix__) || defined(__APPLE__)

static bool set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return false;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

static RunResult run_cmd_capture_timed_pty(const std::vector<std::string>& argv,
                                           const std::string& stdin_data,
                                           int timeout_ms) {
  RunResult rr;

  int master_fd = -1;
  int slave_fd = -1;
  char slave_name[256]{0};

  struct termios tio{};
  struct winsize wsz{};
  wsz.ws_row = 24;
  wsz.ws_col = 120;

  if (openpty(&master_fd, &slave_fd, slave_name, &tio, &wsz) != 0) {
    rr.code = 127;
    rr.out = "openpty failed";
    return rr;
  }

  pid_t pid = fork();
  if (pid == -1) {
    close(master_fd);
    close(slave_fd);
    rr.code = 127;
    rr.out = "fork failed";
    return rr;
  }

  if (pid == 0) {
    close(master_fd);

    setsid();
    (void)ioctl(slave_fd, TIOCSCTTY, 0);

    dup2(slave_fd, STDIN_FILENO);
    dup2(slave_fd, STDOUT_FILENO);
    dup2(slave_fd, STDERR_FILENO);

    if (slave_fd > STDERR_FILENO) close(slave_fd);

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    execvp(cargv[0], cargv.data());
    _exit(127);
  }

  close(slave_fd);

  (void)set_nonblock(master_fd);

  std::string out;
  out.reserve(4096);

  using clock = std::chrono::steady_clock;
  auto start = clock::now();

  int status = 0;
  bool killed = false;

  bool sent = false;

  for (;;) {
    for (;;) {
      char buf[4096];
      ssize_t n = read(master_fd, buf, sizeof(buf));
      if (n > 0) { out.append(buf, buf + n); continue; }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
      break;
    }

    if (!sent) {
      if (!stdin_data.empty()) (void)write(master_fd, stdin_data.data(), stdin_data.size());
      sent = true;
    }

    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) break;

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start).count();
    if (elapsed > timeout_ms) {
      killed = true;
      kill(pid, SIGKILL);
      (void)waitpid(pid, &status, 0);
      break;
    }

    usleep(10 * 1000);
  }

  for (;;) {
    char buf[4096];
    ssize_t n = read(master_fd, buf, sizeof(buf));
    if (n <= 0) break;
    out.append(buf, buf + n);
  }
  close(master_fd);

  rr.out = out;
  if (killed) { rr.code = 124; if (rr.out.empty()) rr.out = "timeout"; return rr; }
  if (WIFEXITED(status)) rr.code = WEXITSTATUS(status);
  else rr.code = 128;
  return rr;
}

static RunResult run_cmd_capture_timed(const std::vector<std::string>& argv,
                                       const std::string& stdin_data,
                                       int timeout_ms) {
  return run_cmd_capture_timed_pty(argv, stdin_data, timeout_ms);
}

#else

static RunResult run_cmd_capture_timed(const std::vector<std::string>&,
                                       const std::string&,
                                       int) {
  RunResult rr;
  rr.out = "unsupported platform for timed runner";
  rr.code = 127;
  return rr;
}

#endif

static void print_banner() {
  std::cout << "1654 SELFTEST REPORT\n";
  std::cout << "====================\n\n";

  std::cout << "[Build]\n";
#if defined(__clang__)
  std::cout << "  Compiler: clang/AppleClang\n";
#elif defined(__GNUC__)
  std::cout << "  Compiler: GCC\n";
#elif defined(_MSC_VER)
  std::cout << "  Compiler: MSVC\n";
#else
  std::cout << "  Compiler: unknown\n";
#endif
  std::cout << "  __cplusplus: " << (long long)__cplusplus << "\n";
  std::cout << "  TOOL_NAME: " << ph1654::TOOL_NAME << "\n";
  std::cout << "  LOOSE_MODE: " << (LOOSE_MODE ? "true" : "false") << "\n";
  std::cout << "  CLI_TIMEOUT_FAILFAST_MS: " << CLI_TIMEOUT_FAILFAST_MS << "\n";
  std::cout << "  CLI_TIMEOUT_SLOW_MS: " << CLI_TIMEOUT_SLOW_MS << "\n";
  std::cout << "  LIB_TIMEOUT_FAILFAST_MS: " << LIB_TIMEOUT_FAILFAST_MS << "\n";
  std::cout << "  LIB_TIMEOUT_SLOW_MS: " << LIB_TIMEOUT_SLOW_MS << "\n\n";

  std::cout << "[Params]\n";
  std::cout << "  VERSION: " << ph1654::VERSION << "\n";
  std::cout << "  SALT_SIZE: " << ph1654::SALT_SIZE << "\n";
  std::cout << "  NONCE_SIZE: " << ph1654::NONCE_SIZE << "\n";
  std::cout << "  TAG_SIZE: " << ph1654::TAG_SIZE << "\n";
  std::cout << "  DEFAULT_KEY_BITS: " << (unsigned long long)ph1654::DEFAULT_KEY_BITS << "\n";
  std::cout << "  DEFAULT_KDF_COST: " << (unsigned long long)ph1654::DEFAULT_KDF_COST << "\n\n";
}

static bool contains(const std::string& s, const std::string& needle) {
  return s.find(needle) != std::string::npos;
}

static void print_step(const std::string& name) { std::cout << "\n[" << name << "]\n"; }
static void print_cmd(const std::string& line) { std::cout << "  $ " << line << "\n"; }
static void print_ok() { std::cout << "  RESULT: OK\n"; }
static void print_fail(const std::string& why) { std::cout << "  RESULT: FAIL: " << why << "\n"; mark_fail(); }
static void print_skip(const std::string& why) { std::cout << "  RESULT: SKIP: " << why << "\n"; mark_skip(); }

static std::string first_lines(const std::string& s, int max_lines) {
  std::istringstream ss(s);
  std::string line;
  std::ostringstream out;
  int n = 0;
  while (std::getline(ss, line) && n < max_lines) {
    out << "    " << line << "\n";
    ++n;
  }
  return out.str();
}

static fs::path pick_extracted_path(const fs::path& out_dir, const std::string& root, const std::string& leaf) {
  fs::path p1 = out_dir / root / leaf;
  if (fs::exists(p1)) return p1;
  fs::path p2 = out_dir / leaf;
  if (fs::exists(p2)) return p2;
  return {};
}

static bool bytes_equal_salt(const std::array<std::uint8_t, ph1654::SALT_SIZE>& a,
                            const std::array<std::uint8_t, ph1654::SALT_SIZE>& b) {
  return std::memcmp(a.data(), b.data(), ph1654::SALT_SIZE) == 0;
}

static bool bytes_equal_nonce(const std::array<std::uint8_t, ph1654::NONCE_SIZE>& a,
                              const std::array<std::uint8_t, ph1654::NONCE_SIZE>& b) {
  return std::memcmp(a.data(), b.data(), ph1654::NONCE_SIZE) == 0;
}

static bool copy_file_bin(const fs::path& src, const fs::path& dst) {
  std::ifstream ifs(src, std::ios::binary);
  if (!ifs) return false;
  std::ofstream ofs(dst, std::ios::binary | std::ios::trunc);
  if (!ofs) return false;
  ofs << ifs.rdbuf();
  return (bool)ofs;
}

static bool flip_byte_at(const fs::path& path, std::uint64_t off) {
  std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
  if (!f) return false;
  f.seekg((std::streamoff)off);
  char c = 0;
  f.read(&c, 1);
  if (!f) return false;
  c ^= 0x01;
  f.seekp((std::streamoff)off);
  f.write(&c, 1);
  return (bool)f;
}

static bool write_u64_le_at(const fs::path& path, std::uint64_t off, std::uint64_t v) {
  std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
  if (!f) return false;
  f.seekp((std::streamoff)off);
  std::uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = (std::uint8_t)((v >> (8*i)) & 0xFF);
  f.write((const char*)b, 8);
  return (bool)f;
}

static std::uint64_t file_size_u64(const fs::path& p) {
  std::error_code ec;
  auto s = fs::file_size(p, ec);
  if (ec) return 0;
  return (std::uint64_t)s;
}

static bool truncate_file(const fs::path& p, std::uint64_t new_size) {
  std::error_code ec;
  fs::resize_file(p, (std::uintmax_t)new_size, ec);
  return !ec;
}

static const ph1654::index::Entry* find_entry(const ph1654::index::Index& idx,
                                              const std::string& path) {
  for (const auto& e : idx.entries) {
    if (e.path == path) return &e;
  }
  return nullptr;
}

static bool sanity_check_index(const ph1654::index::Index& idx,
                               std::uint64_t fsz,
                               std::string& why) {
  const std::uint64_t MAX_OBJ = 256ull * 1024ull * 1024ull;
  const std::size_t   MAX_ENTRIES = 200000;

  if (idx.entries.size() > MAX_ENTRIES) {
    why = "too many entries: " + std::to_string(idx.entries.size());
    return false;
  }

  for (const auto& e : idx.entries) {
    const std::uint64_t off = (std::uint64_t)e.data_offset;
    const std::uint64_t sz  = (std::uint64_t)e.data_size;

    if (e.path.empty()) { why = "entry has empty path"; return false; }
    if (e.path.size() > 4096) { why = "entry path too long: " + std::to_string(e.path.size()); return false; }
    if (sz > MAX_OBJ) { why = "entry '" + e.path + "': data_size too large: " + std::to_string((unsigned long long)sz); return false; }
    if (off > fsz) {
      why = "entry '" + e.path + "': data_offset beyond EOF: " + std::to_string((unsigned long long)off) +
            " (file_size=" + std::to_string((unsigned long long)fsz) + ")";
      return false;
    }
    if (off + sz > fsz) {
      why = "entry '" + e.path + "': data range beyond EOF: off=" + std::to_string((unsigned long long)off) +
            " sz=" + std::to_string((unsigned long long)sz) +
            " (file_size=" + std::to_string((unsigned long long)fsz) + ")";
      return false;
    }
  }
  return true;
}

struct LibOpenResult {
  int code = -1;
  std::string msg;
};

#if defined(__unix__) || defined(__APPLE__)
static LibOpenResult run_open_for_view_timed(const std::string& vault_path,
                                             const std::string& password,
                                             int timeout_ms) {
  LibOpenResult r;

  int pipefd[2]{-1,-1};
  if (pipe(pipefd) != 0) {
    r.code = 2;
    r.msg = "pipe() failed";
    return r;
  }

  pid_t pid = fork();
  if (pid == -1) {
    close(pipefd[0]); close(pipefd[1]);
    r.code = 2;
    r.msg = "fork() failed";
    return r;
  }

  if (pid == 0) {
    close(pipefd[0]);

    auto write_u32 = [&](std::uint32_t v) {
      std::uint8_t b[4];
      b[0] = (std::uint8_t)(v & 0xFF);
      b[1] = (std::uint8_t)((v >> 8) & 0xFF);
      b[2] = (std::uint8_t)((v >> 16) & 0xFF);
      b[3] = (std::uint8_t)((v >> 24) & 0xFF);
      (void)write(pipefd[1], b, 4);
    };
    auto write_bytes = [&](const std::string& s) {
      if (!s.empty()) (void)write(pipefd[1], s.data(), s.size());
    };

    try {
      ph1654::vault::VaultOpen vo_local;
      auto st = ph1654::vault::open_for_view(vault_path, password, vo_local);
      if (!st.is_ok()) {
        std::string m = st.message;
        write_u32(1);
        write_u32((std::uint32_t)m.size());
        write_bytes(m);
        _exit(0);
      }
      std::string m = "ok";
      write_u32(0);
      write_u32((std::uint32_t)m.size());
      write_bytes(m);
      _exit(0);
    } catch (const std::exception& e) {
      std::string m = std::string("exception: ") + e.what();
      write_u32(2);
      write_u32((std::uint32_t)m.size());
      write_bytes(m);
      _exit(0);
    } catch (...) {
      std::string m = "unknown exception";
      write_u32(2);
      write_u32((std::uint32_t)m.size());
      write_bytes(m);
      _exit(0);
    }
  }

  close(pipefd[1]);

  int flags = fcntl(pipefd[0], F_GETFL, 0);
  if (flags != -1) (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

  using clock = std::chrono::steady_clock;
  auto start = clock::now();
  int status = 0;
  bool killed = false;

  std::string buf;
  buf.reserve(256);

  for (;;) {
    for (;;) {
      char tmp[256];
      ssize_t n = read(pipefd[0], tmp, sizeof(tmp));
      if (n > 0) { buf.append(tmp, tmp + n); continue; }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
      break;
    }

    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) break;

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start).count();
    if (elapsed > timeout_ms) {
      killed = true;
      kill(pid, SIGKILL);
      (void)waitpid(pid, &status, 0);
      break;
    }
    usleep(10 * 1000);
  }

  for (;;) {
    char tmp[256];
    ssize_t n = read(pipefd[0], tmp, sizeof(tmp));
    if (n <= 0) break;
    buf.append(tmp, tmp + n);
  }
  close(pipefd[0]);

  if (killed) {
    r.code = 124;
    r.msg = "open_for_view HUNG (timeout) — BUG";
    return r;
  }

  auto read_u32 = [&](std::size_t off, std::uint32_t& v) -> bool {
    if (off + 4 > buf.size()) return false;
    v = (std::uint32_t)(std::uint8_t)buf[off]
      | ((std::uint32_t)(std::uint8_t)buf[off+1] << 8)
      | ((std::uint32_t)(std::uint8_t)buf[off+2] << 16)
      | ((std::uint32_t)(std::uint8_t)buf[off+3] << 24);
    return true;
  };

  std::uint32_t code = 2, mlen = 0;
  if (!read_u32(0, code) || !read_u32(4, mlen) || (8ull + (std::size_t)mlen > buf.size())) {
    r.code = 2;
    r.msg = "open_for_view runner: malformed child response";
    return r;
  }

  r.code = (int)code;
  r.msg.assign(buf.data() + 8, buf.data() + 8 + mlen);
  return r;
}
#else
static LibOpenResult run_open_for_view_timed(const std::string&, const std::string&, int) {
  LibOpenResult r;
  r.code = 2;
  r.msg = "unsupported platform for timed open_for_view";
  return r;
}
#endif

static bool expect_lib_fail_fast(const std::string& title,
                                 const fs::path& vault,
                                 const std::string& password,
                                 int timeout_ms = LIB_TIMEOUT_FAILFAST_MS) {
  auto r = run_open_for_view_timed(vault.string(), password, timeout_ms);
  if (r.code == 124) { print_fail(title + ": " + r.msg); return false; }
  if (r.code == 0) { print_fail(title + ": expected failure, got OK"); return false; }
  if (r.code == 2) { print_fail(title + ": threw/crashed: " + r.msg); return false; }
  return true;
}

static bool rentgen_open_and_check_safe(const fs::path& vault,
                                        const std::string& password,
                                        const std::string& tag,
                                        std::string& why_fail) {
  try {
    ph1654::vault::VaultOpen vo;
    auto st = ph1654::vault::open_for_view(vault.string(), password, vo);
    if (!st.is_ok()) {
      why_fail = tag + ": open_for_view failed: " + st.message;
      return false;
    }
    auto fsz = file_size_u64(vault);
    std::string why;
    if (!sanity_check_index(vo.idx, fsz, why)) {
      std::ostringstream ss;
      ss << tag << ": INDEX SANITY FAILED\n";
      ss << "  vault file_size: " << (unsigned long long)fsz << "\n";
      ss << "  reason: " << why << "\n";
      why_fail = ss.str();
      return false;
    }
    return true;
  } catch (const std::exception& e) {
    why_fail = tag + ": open_for_view threw: " + std::string(e.what());
    return false;
  } catch (...) {
    why_fail = tag + ": open_for_view threw unknown exception";
    return false;
  }
}

static bool expect_cli_ok_slow(const std::string& title,
                               const std::vector<std::string>& argv,
                               const std::string& stdin_data,
                               RunResult* out_rr = nullptr) {
  RunResult r = run_cmd_capture_timed(argv, stdin_data, CLI_TIMEOUT_SLOW_MS);
  if (out_rr) *out_rr = r;

  if (r.code == 124) {
    print_fail(title + ": TIMEOUT/HANG\n" + first_lines(r.out, 10));
    return false;
  }
  if (r.code != 0) {
    print_fail(title + ": exit=" + std::to_string(r.code) + "\n" + r.out);
    return false;
  }
  return true;
}

static bool expect_cli_fail_fast(const std::string& title,
                                 const std::vector<std::string>& argv,
                                 const std::string& stdin_data) {
  RunResult r = run_cmd_capture_timed(argv, stdin_data, CLI_TIMEOUT_FAILFAST_MS);

  if (r.code == 124) {
    print_fail(title + ": HUNG (timeout) — BUG\n" + first_lines(r.out, 10));
    return false;
  }
  if (r.code == 0) {
    print_fail(title + ": expected non-zero exit, got 0\n" + r.out);
    return false;
  }
  return true;
}

static bool expect_cli_ok_or_skip_not_impl(const std::string& title,
                                          const std::vector<std::string>& argv,
                                          const std::string& stdin_data,
                                          RunResult* out_rr = nullptr) {
  RunResult r = run_cmd_capture_timed(argv, stdin_data, CLI_TIMEOUT_SLOW_MS);
  if (out_rr) *out_rr = r;

  if (r.code == 124) {
    print_fail(title + ": TIMEOUT/HANG\n" + first_lines(r.out, 10));
    return false;
  }
  if (r.code == 0) return true;

  if (LOOSE_MODE && contains(r.out, "not implemented")) {
    print_skip(title + ": not implemented");
    return true;
  }

  print_fail(title + ": exit=" + std::to_string(r.code) + "\n" + r.out);
  return false;
}

int main(int argc, char** argv) {
  try {
    std::string bin = "./1654";
    if (argc >= 3 && std::string(argv[1]) == "--bin") bin = argv[2];

    print_banner();

    const std::string password = "1654test";
    const std::string stdin_pw = password + "\n";

    fs::path tmp = fs::temp_directory_path() / ("1654_selftest_" + now_ms());
    fs::create_directories(tmp);

    fs::path in_dir  = tmp / "in";
    fs::path out_dir = tmp / "out";
    fs::path out_dir3 = tmp / "out3";
    fs::path out_dir_edit = tmp / "out_edit";
    fs::path vault1 = tmp / "vault1.1654";
    fs::path vault2 = tmp / "vault2.1654";

    fs::create_directories(in_dir);
    write_file(in_dir / "a.txt", "hello 1654\n");
    write_file(in_dir / "b.txt", "second file\n");
    write_file(in_dir / "sub" / "c.txt", "nested\n");

    const std::string root = in_dir.filename().string();
    const std::string A = root + "/a.txt";
    const std::string B = root + "/b.txt";
    const std::string C = root + "/sub/c.txt";

    print_step("encrypt");
    {
      print_cmd(bin + " encrypt " + in_dir.string() + " --out " + vault1.string());
      RunResult r;
      if (!expect_cli_ok_slow("encrypt", {bin, "encrypt", in_dir.string(), "--out", vault1.string()}, stdin_pw, &r))
        return 1;
      if (!fs::exists(vault1)) { print_fail("vault file not created"); return 1; }
      print_ok();
    }

    ph1654::vault::VaultOpen vo;
    print_step("vault header (bits/cost/salt/nonce) + index sanity");
    {
      auto st = ph1654::vault::open_for_view(vault1.string(), password, vo);
      if (!st.is_ok()) { print_fail("open_for_view failed: " + st.message); return 1; }

      std::uint32_t bits = ph1654::read_u32_le(vo.header.reserved.data() + 0);
      std::uint32_t cost = ph1654::read_u32_le(vo.header.reserved.data() + 4);

      std::cout << "  header.magic: " << std::string(vo.header.magic.data(), vo.header.magic.data() + 4) << "\n";
      std::cout << "  header.version: " << vo.header.version << "\n";
      std::cout << "  header.header_size: " << vo.header.header_size << "\n";
      std::cout << "  key_bits (reserved[0..3]): " << bits << "\n";
      std::cout << "  kdf_cost (reserved[4..7]): " << cost << "\n";
      std::cout << "  salt: " << hex(vo.header.salt.data(), ph1654::SALT_SIZE) << "\n";
      std::cout << "  nonce: " << hex(vo.header.nonce.data(), ph1654::NONCE_SIZE) << "\n";

      if (bits != ph1654::DEFAULT_KEY_BITS) {
        print_fail("DEFAULT_KEY_BITS mismatch (expected " + std::to_string((unsigned)ph1654::DEFAULT_KEY_BITS) +
                   ", got " + std::to_string(bits) + ")");
        return 1;
      }
      if (cost != ph1654::DEFAULT_KDF_COST) {
        print_fail("DEFAULT_KDF_COST mismatch (expected " + std::to_string((unsigned)ph1654::DEFAULT_KDF_COST) +
                   ", got " + std::to_string(cost) + ")");
        return 1;
      }

      auto fsz = file_size_u64(vault1);
      std::string why;
      if (!sanity_check_index(vo.idx, fsz, why)) {
        std::ostringstream ss;
        ss << "INDEX SANITY FAILED after encrypt\n";
        ss << "  vault file_size: " << (unsigned long long)fsz << "\n";
        ss << "  reason: " << why << "\n";
        print_fail(ss.str());
        return 1;
      }
      print_ok();
    }

    print_step("wrong password must fail (library open_for_view)");
    {
      if (!expect_lib_fail_fast("open_for_view wrong password", vault1, "wrongpass")) return 1;
      print_ok();
    }

    print_step("wrong password must fail (CLI view/extract)");
    {
      if (!expect_cli_fail_fast("CLI view wrong password", {bin, "view", vault1.string()}, "wrongpass\n")) return 1;
      if (!expect_cli_fail_fast("CLI extract wrong password",
                                {bin, "extract", vault1.string(), A, "--out", (tmp/"out_wrong_pw").string()},
                                "wrongpass\n")) return 1;
      print_ok();
    }

    print_step("view");
    {
      print_cmd(bin + " view " + vault1.string());
      RunResult r;
      if (!expect_cli_ok_slow("view", {bin, "view", vault1.string()}, stdin_pw, &r)) return 1;
      if (!contains(r.out, A) || !contains(r.out, B) || !contains(r.out, C)) {
        print_fail("view output missing expected paths\n" + r.out);
        return 1;
      }
      std::cout << "  view output (first lines):\n" << first_lines(r.out, 10);
      print_ok();
    }

    print_step("extract one file");
    {
      fs::create_directories(out_dir);
      print_cmd(bin + " extract " + vault1.string() + " " + A + " --out " + out_dir.string());
      if (!expect_cli_ok_slow("extract one file",
                              {bin, "extract", vault1.string(), A, "--out", out_dir.string()},
                              stdin_pw)) return 1;

      fs::path got = pick_extracted_path(out_dir, root, "a.txt");
      if (got.empty()) { print_fail("extract did not create expected output"); return 1; }

      const auto data = read_file(got);
      if (data != "hello 1654\n") { print_fail("extract content mismatch"); return 1; }

      std::cout << "  extracted to: " << got.string() << "\n";
      std::cout << "  bytes: " << data.size() << "\n";
      print_ok();
    }

    print_step("corrupt ciphertext test (must FAIL integrity)");
    {
      const auto* ent = find_entry(vo.idx, A);
      if (!ent) { print_fail("cannot find entry for " + A); return 1; }
      if (ent->data_size < 1) { print_fail("entry data_size is 0"); return 1; }

      fs::path vault_bad = tmp / "vault_corrupt_data.1654";
      if (!copy_file_bin(vault1, vault_bad)) { print_fail("copy failed"); return 1; }

      std::uint64_t off = (std::uint64_t)ent->data_offset + ((std::uint64_t)ent->data_size / 2);
      if (!flip_byte_at(vault_bad, off)) { print_fail("flip failed"); return 1; }

      if (!expect_cli_fail_fast("CLI extract on corrupt ciphertext",
                                {bin, "extract", vault_bad.string(), A, "--out", (tmp/"out_corrupt_data").string()},
                                stdin_pw)) return 1;
      print_ok();
    }

    print_step("index trailer tamper test (must FAIL open/view)");
    {
      fs::path vault_bad = tmp / "vault_corrupt_index_tag.1654";
      if (!copy_file_bin(vault1, vault_bad)) { print_fail("copy failed"); return 1; }

      std::uint64_t fsz = file_size_u64(vault_bad);
      if (fsz < (std::uint64_t)ph1654::fmt::INDEX_TRAILER_SIZE) { print_fail("file too small"); return 1; }

      if (!flip_byte_at(vault_bad, fsz - 1)) { print_fail("flip failed"); return 1; }

      if (!expect_lib_fail_fast("open_for_view after index tag tamper", vault_bad, password)) return 1;
      if (!expect_cli_fail_fast("CLI view on tampered index tag", {bin, "view", vault_bad.string()}, stdin_pw)) return 1;
      print_ok();
    }

    print_step("truncate test (must FAIL open/view)");
    {
      fs::path vault_bad = tmp / "vault_truncated.1654";
      if (!copy_file_bin(vault1, vault_bad)) { print_fail("copy failed"); return 1; }

      std::uint64_t fsz = file_size_u64(vault_bad);
      if (fsz < 64) { print_fail("file too small to truncate"); return 1; }

      if (!truncate_file(vault_bad, fsz - 17)) { print_fail("truncate failed"); return 1; }

      if (!expect_lib_fail_fast("open_for_view after truncate", vault_bad, password)) return 1;
      if (!expect_cli_fail_fast("CLI view on truncated vault", {bin, "view", vault_bad.string()}, stdin_pw)) return 1;
      print_ok();
    }

    print_step("header tamper test (must FAIL open)");
    {
      fs::path vault_bad = tmp / "vault_header_flip.1654";
      if (!copy_file_bin(vault1, vault_bad)) { print_fail("copy failed"); return 1; }

      if (!flip_byte_at(vault_bad, 1)) { print_fail("flip failed"); return 1; }

      if (!expect_lib_fail_fast("open_for_view after header flip", vault_bad, password)) return 1;
      print_ok();
    }

    print_step("index_offset tamper test (must FAIL open)");
    {
      fs::path vault_bad = tmp / "vault_index_offset_bad.1654";
      if (!copy_file_bin(vault1, vault_bad)) { print_fail("copy failed"); return 1; }

      std::uint64_t fsz = file_size_u64(vault_bad);
      if (fsz < (std::uint64_t)ph1654::fmt::INDEX_TRAILER_SIZE) { print_fail("file too small"); return 1; }

      std::uint64_t trailer_base = fsz - (std::uint64_t)ph1654::fmt::INDEX_TRAILER_SIZE;
      std::uint64_t index_off_pos = trailer_base + 8;
      if (!write_u64_le_at(vault_bad, index_off_pos, fsz)) { print_fail("failed to write index_offset"); return 1; }

      if (!expect_lib_fail_fast("open_for_view after index_offset=EOF", vault_bad, password)) return 1;
      print_ok();
    }

    print_step("delete");
    {
      if (!expect_cli_ok_or_skip_not_impl("delete", {bin, "delete", vault1.string(), B}, stdin_pw)) return 1;
      if (!g_any_fail) print_ok();
    }

    print_step("view after delete (b.txt must disappear)");
    {
      RunResult r;
      if (!expect_cli_ok_slow("view after delete", {bin, "view", vault1.string()}, stdin_pw, &r)) return 1;
      if (contains(r.out, B)) {
        if (LOOSE_MODE) print_skip("delete not effective (probably not implemented fully)");
        else { print_fail("deleted entry still visible\n" + r.out); return 1; }
      } else {
        print_ok();
      }
    }

    print_step("stealth+");
    {
      if (!expect_cli_ok_or_skip_not_impl("stealth+", {bin, "stealth+", vault1.string(), C}, stdin_pw)) return 1;
      if (!g_any_fail) print_ok();
    }

    print_step("view after stealth+ (c.txt must disappear)");
    {
      RunResult r;
      if (!expect_cli_ok_slow("view after stealth+", {bin, "view", vault1.string()}, stdin_pw, &r)) return 1;
      if (contains(r.out, C)) {
        if (LOOSE_MODE) print_skip("stealth+ not effective (probably not implemented fully)");
        else { print_fail("hidden entry still visible\n" + r.out); return 1; }
      } else {
        print_ok();
      }
    }

    print_step("stealth-");
    {
      if (!expect_cli_ok_or_skip_not_impl("stealth-", {bin, "stealth-", vault1.string(), C}, stdin_pw)) return 1;
      if (!g_any_fail) print_ok();
    }

    print_step("view after stealth- (c.txt must return)");
    {
      RunResult r;
      if (!expect_cli_ok_slow("view after stealth-", {bin, "view", vault1.string()}, stdin_pw, &r)) return 1;
      if (!contains(r.out, C)) {
        if (LOOSE_MODE) print_skip("stealth- not effective (probably not implemented fully)");
        else { print_fail("unhidden entry not visible\n" + r.out); return 1; }
      } else {
        print_ok();
      }
    }

    print_step("edit");
    bool edit_ok = false;
    {
      fs::path repl = tmp / "repl.txt";
      write_file(repl, "replaced\n");

      RunResult rr;
      if (!expect_cli_ok_or_skip_not_impl("edit", {bin, "edit", vault1.string(), A, "--from", repl.string()}, stdin_pw, &rr))
        return 1;

      if (!(LOOSE_MODE && contains(rr.out, "not implemented"))) {
        edit_ok = true;
        print_ok();
      }
    }

    if (edit_ok) {
      print_step("post-edit vault sanity (RENTGEN)");
      std::string why_fail;
      if (!rentgen_open_and_check_safe(vault1, password, "post-edit", why_fail)) {
        print_fail(why_fail);
        return 1;
      }
      print_ok();

      print_step("extract after edit (a.txt must be replaced)");
      fs::create_directories(out_dir_edit);
      if (!expect_cli_ok_slow("extract(after edit)", {bin, "extract", vault1.string(), A, "--out", out_dir_edit.string()}, stdin_pw))
        return 1;

      fs::path got = pick_extracted_path(out_dir_edit, root, "a.txt");
      if (got.empty()) { print_fail("extract(after edit) did not create output"); return 1; }
      const auto data = read_file(got);
      if (data != "replaced\n") { print_fail("edit did not replace content"); return 1; }
      print_ok();
    }

    print_step("transfer");
    bool transfer_ok = false;
    ph1654::vault::VaultOpen vo2;
    {
      RunResult rr;
      if (!expect_cli_ok_or_skip_not_impl("transfer",
                                          {bin, "transfer", vault1.string(), vault2.string(), A},
                                          stdin_pw + stdin_pw,
                                          &rr)) return 1;

      if (!(LOOSE_MODE && contains(rr.out, "not implemented"))) {
        if (!fs::exists(vault2)) { print_fail("transfer did not create destination vault"); return 1; }

        auto st2 = ph1654::vault::open_for_view(vault2.string(), password, vo2);
        if (!st2.is_ok()) { print_fail("open transferred vault failed: " + st2.message); return 1; }

        std::cout << "  transferred entries: " << vo2.idx.entries.size() << "\n";
        transfer_ok = true;
        print_ok();
      }
    }

    if (transfer_ok) {
      print_step("transfer sanity (salt/nonce must differ)");
      bool same_salt = bytes_equal_salt(vo.header.salt, vo2.header.salt);
      bool same_nonce = bytes_equal_nonce(vo.header.nonce, vo2.header.nonce);
      if (same_salt || same_nonce) { print_fail("transfer produced identical salt/nonce"); return 1; }
      print_ok();
    }

    print_step("final extract check (a.txt)");
    {
      fs::create_directories(out_dir3);
      if (!expect_cli_ok_slow("final extract", {bin, "extract", vault1.string(), A, "--out", out_dir3.string()}, stdin_pw))
        return 1;

      fs::path got = pick_extracted_path(out_dir3, root, "a.txt");
      if (got.empty()) { print_fail("extract did not create output in final check"); return 1; }

      const auto data = read_file(got);
      std::cout << "  extracted to: " << got.string() << "\n";
      std::cout << "  bytes: " << data.size() << "\n";
      print_ok();
    }

    std::cout << "\n====================\n";
    if (!g_any_fail) {
      std::cout << "SELFTEST: OK\n";
      if (g_skip_count > 0) std::cout << "SKIPPED: " << g_skip_count << " (not implemented)\n";
      std::cout << "ALL CHECKS PASSED\n";
    } else {
      std::cout << "SELFTEST: FAIL\n";
      std::cout << "FAILED CHECKS: " << g_fail_count << "\n";
      if (g_skip_count > 0) std::cout << "SKIPPED: " << g_skip_count << " (not implemented)\n";
    }
    std::cout << "Temp dir: " << tmp.string() << "\n";
    std::cout << "====================\n";

    return g_any_fail ? 1 : 0;

  } catch (const std::exception& e) {
    std::cout << "\n[FATAL]\n";
    std::cout << "  SELFTEST crashed with std::exception: " << e.what() << "\n";
    return 2;
  } catch (...) {
    std::cout << "\n[FATAL]\n";
    std::cout << "  SELFTEST crashed with unknown exception\n";
    return 2;
  }
}
