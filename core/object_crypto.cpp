#include "object_crypto.hpp"

#include "xof.hpp"
#include "mac.hpp"

#include <array>
#include <vector>
#include <cstring>

namespace ph1654::obj {

static constexpr std::size_t CHUNK = 64 * 1024;

Status encrypt_stream(
  std::istream& in,
  std::ostream& out,
  const std::vector<std::uint8_t>& key_enc,
  const std::vector<std::uint8_t>& key_mac,
  const std::vector<std::uint8_t>& nonce,
  std::uint64_t& out_bytes_written,
  std::vector<std::uint8_t>& out_tag
) {
  out_bytes_written = 0;

  std::vector<std::uint8_t> mac_buf;
  mac_buf.reserve(CHUNK);

  std::array<std::uint8_t, CHUNK> buf{};
  std::array<std::uint8_t, CHUNK> ks{};

  std::uint64_t counter = 0;

  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), buf.size());
    const std::streamsize got = in.gcount();
    if (got <= 0) break;

    xof::generate(
      key_enc,
      nonce,
      counter++,
      ks.data(),
      static_cast<std::size_t>(got)
    );

    for (std::size_t i = 0; i < (std::size_t)got; ++i) {
      buf[i] ^= ks[i];
    }

    out.write(reinterpret_cast<const char*>(buf.data()), got);
    if (!out) {
      return Status::err(ExitCode::IoError, "encrypt: write failed");
    }

    mac_buf.insert(mac_buf.end(), buf.data(), buf.data() + (std::size_t)got);

    out_bytes_written += (std::uint64_t)got;
  }

  out_tag = mac::compute(key_mac, mac_buf.data(), mac_buf.size());
  return Status::ok();
}

Status decrypt_stream(
  std::istream& in,
  std::ostream& out,
  const std::vector<std::uint8_t>& key_enc,
  const std::vector<std::uint8_t>& key_mac,
  const std::vector<std::uint8_t>& nonce,
  std::uint64_t data_size,
  const std::vector<std::uint8_t>& expected_tag
) {
  std::vector<std::uint8_t> mac_buf;
  mac_buf.reserve((std::size_t)data_size);

  std::array<std::uint8_t, CHUNK> buf{};
  std::array<std::uint8_t, CHUNK> ks{};

  std::uint64_t remaining = data_size;
  std::uint64_t counter = 0;

  while (remaining > 0) {
    const std::size_t want = (remaining > CHUNK) ? CHUNK : (std::size_t)remaining;
    in.read(reinterpret_cast<char*>(buf.data()), want);
    if (in.gcount() != (std::streamsize)want) {
      return Status::err(ExitCode::IoError, "decrypt: read failed");
    }

    mac_buf.insert(mac_buf.end(), buf.data(), buf.data() + want);

    xof::generate(
      key_enc,
      nonce,
      counter++,
      ks.data(),
      want
    );

    for (std::size_t i = 0; i < want; ++i) {
      buf[i] ^= ks[i];
    }

    out.write(reinterpret_cast<const char*>(buf.data()), want);
    if (!out) {
      return Status::err(ExitCode::IoError, "decrypt: write failed");
    }

    remaining -= want;
  }

  if (!mac::verify(key_mac, mac_buf.data(), mac_buf.size(), expected_tag)) {
    return Status::err(ExitCode::IntegrityError, "integrity check failed");
  }

  return Status::ok();
}

} // namespace ph1654::obj

