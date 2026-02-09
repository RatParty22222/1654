#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include <string_view>

namespace petoron {

class PhashXof {
public:
    explicit PhashXof(std::size_t rate_bytes = 136) : r_(rate_bytes) { reset(); }

    void reset();
    void absorb(std::span<const std::uint8_t> data);
    void absorb_domain_pad(std::uint8_t domain);
    void squeeze(std::span<std::uint8_t> out);

private:
    void permute();
    void absorb_block(const std::uint8_t* block);
    void extract_block(std::uint8_t* block);

    static constexpr int ROUNDS = 24;
    std::uint64_t a_[25]{};
    std::size_t r_{136};
    std::size_t queued_ = 0;
    std::uint8_t q_[200]{};
};

std::vector<std::uint8_t> phash_xof(std::span<const std::uint8_t> in, std::size_t out_bytes);
void absorb_len_le(PhashXof& x, std::uint64_t L);
void absorb_tagged(PhashXof& x, std::string_view tag, std::span<const std::uint8_t> data);

} // namespace petoron

