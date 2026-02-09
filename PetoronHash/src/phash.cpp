#include "phash.hpp"
#include <cstring>
#include <algorithm>

namespace petoron {

static constexpr std::uint64_t RC[24] = {
 0x0000000000000001ULL, 0x0000000000008082ULL,
 0x800000000000808aULL, 0x8000000080008000ULL,
 0x000000000000808bULL, 0x0000000080000001ULL,
 0x8000000080008081ULL, 0x8000000000008009ULL,
 0x000000000000008aULL, 0x0000000000000088ULL,
 0x0000000080008009ULL, 0x000000008000000aULL,
 0x000000008000808bULL, 0x800000000000008bULL,
 0x8000000000008089ULL, 0x8000000000008003ULL,
 0x8000000000008002ULL, 0x8000000000000080ULL,
 0x000000000000800aULL, 0x800000008000000aULL,
 0x8000000080008081ULL, 0x8000000000008080ULL,
 0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline std::uint64_t rol64(std::uint64_t x, unsigned n) {
    return (x << n) | (x >> (64U - n));
}

static constexpr unsigned RHO[25] = {
  0,  1, 62, 28, 27,
 36, 44,  6, 55, 20,
  3, 10, 43, 25, 39,
 41, 45, 15, 21,  8,
 18,  2, 61, 56, 14
};

void PhashXof::reset() {
    std::memset(a_, 0, sizeof(a_));
    std::memset(q_, 0, sizeof(q_));
    queued_ = 0;
}

static inline std::uint64_t load_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (std::uint64_t)p[i] << (8U * i);
    return v;
}
static inline void store_le64(std::uint8_t* p, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (std::uint8_t)((v >> (8U * i)) & 0xFF);
}

void PhashXof::absorb_block(const std::uint8_t* block) {
    for (std::size_t off = 0, li = 0; off < r_; off += 8, ++li) {
        a_[li] ^= load_le64(block + off);
    }
    permute();
}

void PhashXof::extract_block(std::uint8_t* block) {
    for (std::size_t off = 0, li = 0; off < r_; off += 8, ++li) {
        store_le64(block + off, a_[li]);
    }
}

void PhashXof::absorb(std::span<const std::uint8_t> data) {
    std::size_t off = 0;

    if (queued_ && !data.empty()) {
        const std::size_t take = std::min<std::size_t>(r_ - queued_, data.size());
        std::memcpy(q_ + queued_, data.data(), take);
        queued_ += take; off += take;
        if (queued_ == r_) {
            absorb_block(q_);
            std::memset(q_, 0, r_);
            queued_ = 0;
        }
    }
    while (off + r_ <= data.size()) {
        absorb_block(data.data() + off);
        off += r_;
    }
    if (off < data.size()) {
        const std::size_t rem = data.size() - off;
        std::memcpy(q_, data.data() + off, rem);
        queued_ = rem;
    }
}

void PhashXof::absorb_domain_pad(std::uint8_t domain) {
    q_[queued_] ^= domain;
    q_[r_ - 1]   ^= 0x80;
    absorb_block(q_);
    std::memset(q_, 0, r_);
    queued_ = 0;
}

void PhashXof::squeeze(std::span<std::uint8_t> out) {
    std::size_t produced = 0;
    while (produced < out.size()) {
        std::uint8_t block[200];
        extract_block(block);
        const std::size_t take = std::min<std::size_t>(r_, out.size() - produced);
        std::memcpy(out.data() + produced, block, take);
        produced += take;
        if (produced < out.size()) permute();
    }
}

void PhashXof::permute() {
    std::uint64_t b[25];
    std::uint64_t C[5], D[5];

    for (int round = 0; round < ROUNDS; ++round) {
        for (int x = 0; x < 5; ++x) {
            C[x] = a_[x] ^ a_[x + 5] ^ a_[x + 10] ^ a_[x + 15] ^ a_[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                a_[x + 5*y] ^= D[x];
            }
        }

        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                const int xp = y;
                const int yp = (2*x + 3*y) % 5;
                b[xp + 5*yp] = rol64(a_[x + 5*y], RHO[x + 5*y]);
            }
        }

        for (int y = 0; y < 5; ++y) {
            const int y5 = 5*y;
            const std::uint64_t b0 = b[y5 + 0], b1 = b[y5 + 1], b2 = b[y5 + 2], b3 = b[y5 + 3], b4 = b[y5 + 4];
            a_[y5 + 0] = b0 ^ ((~b1) & b2);
            a_[y5 + 1] = b1 ^ ((~b2) & b3);
            a_[y5 + 2] = b2 ^ ((~b3) & b4);
            a_[y5 + 3] = b3 ^ ((~b4) & b0);
            a_[y5 + 4] = b4 ^ ((~b0) & b1);
        }

        a_[0] ^= RC[round];
    }
}

std::vector<std::uint8_t> phash_xof(std::span<const std::uint8_t> in, std::size_t out_bytes) {
    PhashXof x(136);
    x.absorb(in);
    x.absorb_domain_pad(0x1F);
    std::vector<std::uint8_t> out(out_bytes);
    x.squeeze(out);
    return out;
}

void absorb_len_le(PhashXof& x, std::uint64_t L) {
    std::uint8_t le[8];
    for (int i = 0; i < 8; ++i) le[i] = static_cast<std::uint8_t>((L >> (8*i)) & 0xFF);
    x.absorb(std::span<const std::uint8_t>(le, 8));
}

void absorb_tagged(PhashXof& x, std::string_view tag, std::span<const std::uint8_t> data) {
    x.absorb(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(tag.data()), tag.size()));
    absorb_len_le(x, static_cast<std::uint64_t>(data.size()));
    if (!data.empty()) x.absorb(data);
}

} // namespace petoron
