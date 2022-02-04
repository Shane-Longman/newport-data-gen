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


using hash256_t = std::array<std::uint8_t, 32>;


// this is spectacularly optimized by clang, even as old as 5.0:
//        vmovups xmm0, xmmword ptr [rdi]
//        vmovss  xmm1, dword ptr [rdi + 16]      # xmm1 = mem[0],zero,zero,zero
//        vinsertf128     ymm0, ymm0, xmm1, 1
#define HASH160_AS_V32(h) (__v32qi)_mm256_set_epi8( \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        h[19], h[18], h[17], h[16], h[15], h[14], h[13], h[12], h[11], h[10], \
        h[9], h[8], h[7], h[6], h[5], h[4], h[3], h[2], h[1], h[0])


#if 0
static inline
__v32qi hash160_as_v32(std::uint8_t const *p)
{
    // this needs gcc at least 10.0 to compile into efficient
    // AVX assembly
    __m128i hi = _mm_set_epi8(
        p[19], p[18], p[17], p[16], p[15], p[14], p[13], p[12],
        p[11], p[10], p[ 9], p[ 8], p[ 7], p[ 6], p[ 5], p[ 4]);
    hi = (__m128i)_mm_permute_ps((__m128)hi, 0b11111111);
    hi = _mm_blend_epi32(hi, _mm_setzero_si128(), 0b1110);

    __m128i lo = _mm_set_epi8(
        p[15], p[14], p[13], p[12], p[11], p[10], p[ 9], p[ 8],
        p[ 7], p[ 6], p[ 5], p[ 4], p[ 3], p[ 2], p[ 1], p[ 0]);
    __m256i full = _mm256_setr_m128i(lo, hi); // needs gcc at least 8.1

    return full;
}
#endif


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
    auto const ih160 = unaddr(args.pubkey);
    auto const target = HASH160_AS_V32(ih160);

    pid_t const pid = getpid();

    EC_KEY *key_p = EC_KEY_new_by_curve_name(NID_secp256k1);
    std::array<std::uint8_t, 65> uncompressed;

    bool const infinite_loop = not args.maybe_ntries.has_value();
    auto const ntries = args.maybe_ntries.has_value() ? *args.maybe_ntries : 0;
    
    for (std::uint64_t it = 0; infinite_loop or (it < ntries); ++it)
    {
        EC_KEY_generate_key(key_p);

        auto uncompressed_p = uncompressed.data();
        i2o_ECPublicKey(key_p, &uncompressed_p);

        hash256_t h256;
        SHA256(uncompressed.data(), uncompressed.size(), h256.data());

        hash160_t h160;
        RIPEMD160(h256.data(), h256.size(), h160.data());

        auto const diff = target ^ HASH160_AS_V32(h160);

        auto mask = SHR((__v32qi)(~_mm256_setzero_si256()), 256 - args.min_match_nbits);

        auto const NCHECKS = 1 + 160 - args.min_match_nbits;
        // TODO: mask array
        for (auto ix = 0u; ix < NCHECKS; ++ix)
        {
            if (_mm256_testz_si256((__m256i)diff, (__m256i)mask) == 1)
            {
                printf("%u\n", ix);
            }
            mask = SHL(mask, 1);
        }
    }

    return EXIT_SUCCESS;
}
