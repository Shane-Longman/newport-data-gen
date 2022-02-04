#include "parse_args.hpp"
#include "unaddr.hpp"

#include <cstdlib>
#include <cstdint>
#include <array>

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include <immintrin.h>
#include <unistd.h>


using uncompressed_key_t = std::array<std::uint8_t, 65>;
using hash256_t = std::array<std::uint8_t, 32>;

typedef union
{
    __v32qi v32;
    __m256i m256;
    hash160_t h160;
    hash256_t h256;
} hash_4_simd_t;
static_assert(sizeof (hash160_t) == 20u);
static_assert(sizeof (hash256_t) == 32u);


static inline
__v32qi SHR(__v32qi iv, unsigned int imm)
{
    // [1234][5678][9ABC][DEFG]
    __m256i data = (__m256i)iv;

    while (imm >= 64)
    {
        imm -= 64;
        data = _mm256_permute4x64_epi64(data, 0b00'11'10'01);
        data = _mm256_blend_epi32(_mm256_setzero_si256(), data, 0b0'0'1'1'1'1'1'1);
    }

    if (imm == 0)
    {
        return (__v32qi)data;
    }

    // [4...][8...][C...][G...] <- [1234][5678][9ABC][DEFG]
    __m256i innerCarry = _mm256_slli_epi64(data, 64 - imm);

    // [G...][4...][8...][C...] <- [4...][8...][C...][G...]
    __m256i rotate = _mm256_permute4x64_epi64(innerCarry, 0b00'11'10'01);

    // [....][4...][8...][C...] <- [G...][4...][8...][C...]
    innerCarry = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, 0b0'0'1'1'1'1'1'1);

    // [.123][.567][.9AB][.DEF] <- [1234][5678][9ABC][DEFG]
    data = _mm256_srli_epi64(data, imm);

    // [.123][4567][89AB][CDEF]
    data = _mm256_or_si256(data, innerCarry);
    return (__v32qi)data;
}

static inline
__v32qi SHL(__v32qi iv, unsigned int imm)
{
    // [1234][5678][9ABC][DEFG]
    __m256i data = (__m256i)iv;

    while (imm >= 64)
    {
        imm -= 64;
        data = _mm256_permute4x64_epi64(data, 0b10'01'00'11);
        data = _mm256_blend_epi32(_mm256_setzero_si256(), data, 0b1'1'1'1'1'1'0'0);
    }

    if (imm == 0)
    {
        return (__v32qi)data;
    }

    // [...1][...5][...9][...D] <- [1234][5678][9ABC][DEFG]
    __m256i innerCarry = _mm256_srli_epi64(data, 64 - imm);

    // [...5][...9][...D][...1] <- [...1][...5][...9][...D]
    __m256i rotate = _mm256_permute4x64_epi64(innerCarry, 0b10'01'00'11);

    // [...5][...9][...D][....] <- [...5][...9][...D][...1]
    innerCarry = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, 0b1'1'1'1'1'1'0'0);

    // [234.][678.][ABC.][EFG.] <- [1234][5678][9ABC][DEFG]
    data = _mm256_slli_epi64(data, imm);

    // [2345][6789][ABCD][EFG.]
    data = _mm256_or_si256(data, innerCarry);
    return (__v32qi)data;
}


static inline
std::array<__v32qi, 160> make_masks(unsigned int match_nbits)
{
    auto const NMASK_CHECKS = 1 + 160 - match_nbits;
    std::array<__v32qi, 160> masks;

    __v32qi mask = SHR((__v32qi)(~_mm256_setzero_si256()), 256 - match_nbits);

    for (auto ix = 0u; ix < NMASK_CHECKS; ++ix)
    {
        masks[ix] = mask;
        mask = SHL(mask, 1);
    }
    
    return masks;
}


int main(int argc, char **argv)
{
    parsed_args args;

    if (parse_args(argc, argv, args) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    if (args.help)
    {
        return EXIT_SUCCESS;
    }

    // 160-bit hash
    hash_4_simd_t target;
    target.h160 = unaddr(args.pubkey);

    pid_t const pid = getpid();

    EC_KEY *key_p = EC_KEY_new_by_curve_name(NID_secp256k1);
    uncompressed_key_t uncompressed;

    bool const infinite_loop = not args.maybe_ntries.has_value();
    auto const ntries = args.maybe_ntries.has_value() ? *args.maybe_ntries : 0;

    auto const NMASK_CHECKS = 1 + 160 - args.min_match_nbits;
    std::array<__v32qi, 160> const masks = make_masks(args.min_match_nbits);

    hash256_t h256;
    hash_4_simd_t h160;

    for (std::uint64_t it = 0; infinite_loop or (it < ntries); ++it)
    {
        EC_KEY_generate_key(key_p);

        auto uncompressed_p = uncompressed.data();
        i2o_ECPublicKey(key_p, &uncompressed_p);

        SHA256(uncompressed.data(), uncompressed.size(), h256.data());
        RIPEMD160(h256.data(), h256.size(), h160.h160.data());

        auto const diff = target.v32 ^ h160.v32;

        for (auto ix = 0u; ix < NMASK_CHECKS; ++ix)
        {
            if (_mm256_testz_si256((__m256i)diff, (__m256i)masks[ix]) == 1)
            {
                printf("%u\n", ix);
            }
        }
    }

    return EXIT_SUCCESS;
}
