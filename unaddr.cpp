#include "unaddr.hpp"
#include "ntohl.h"

#include <array>
#include <cstring>
#include <cstdint>
#include <cstdio>

#include <openssl/sha.h>


typedef struct
{
    std::uint64_t v[4];
} uint256_t;

using hash256_t = std::array<std::uint8_t, 32>;


static
std::array<std::uint8_t, 256> make_b58_lut()
{
    static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::array<std::uint8_t, 256> rv = {0};

    for (auto ix = 0u; ix < 58; ++ix)
    {
        rv[alphabet[ix]] = ix;
    }

    return rv;
}


static
void mul(uint256_t & b, unsigned int val)
{
    using u128 = unsigned __int128;

    std::uint64_t p;

    {
        u128 x = b.v[3];
        x *= val;
        b.v[3] = x;
        p = (x >> 64);
    }

    {
        u128 x = b.v[2];
        x *= val;
        x += p;
        b.v[2] = x;
        p = (x >> 64);
    }

    {
        u128 x = b.v[1];
        x *= val;
        x += p;
        b.v[1] = x;
        p = (x >> 64);
    }

    {
        u128 x = b.v[0];
        x *= val;
        x += p;
        b.v[0] = x;
    }
}


static
void add(uint256_t & b, unsigned int val)
{
    using u128 = unsigned __int128;

    u128 x = b.v[3];
    x += val;
    b.v[3] = x;

    x = b.v[2];
    x += (x >> 64);
    b.v[2] = x;

    x = b.v[1];
    x += (x >> 64);
    b.v[1] = x;

    b.v[0] += (x >> 64);
}


hash160_t unaddr(std::string const &addr)
{
    static const std::array<std::uint8_t, 256> lut = make_b58_lut();
    uint256_t u256 = {0};

    for (auto it = addr.begin(); it != addr.end(); ++it)
    {
        auto const val = lut[*it];
        mul(u256, 58);
        add(u256, val);
    }

    for (auto & x : u256.v)
    {
        x = htonll(x);
    }

    auto u256_as_u8 = reinterpret_cast<std::uint8_t const *>(u256.v);

    {
        std::array<std::uint8_t, 21> payload;
        std::memcpy(payload.data(), u256_as_u8 + 7, payload.size());

        hash256_t h1;
        SHA256(payload.data(), payload.size(), h1.data());

        hash256_t h2;
        SHA256(h1.data(), h1.size(), h2.data());

        if (std::memcmp(h2.data(), u256_as_u8 + 7 + 21, 4) != 0)
        {
            fprintf(stderr, "[!] Address checksum mismatch: %s\n", addr.c_str());
        }
    }

    hash160_t rv;
    std::memcpy(rv.data(), u256_as_u8 + 8, rv.size());

    return rv;
}
