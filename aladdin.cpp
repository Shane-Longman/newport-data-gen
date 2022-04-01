#include <cstdlib>
#include <string>
#include <optional>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <algorithm>
#include <cctype>
#include <vector>
#include <fstream>

#include <openssl/ec.h>
#include <openssl/objects.h>


#define LIKELY(x) __builtin_expect((x),1)
#define UNLIKELY(x) __builtin_expect((x),0)


struct parsed_args
{
    bool help = false;
    bool with_pubkey = false;
    unsigned int min_match_nbits;
    std::optional<std::string> maybe_pubkey;
    std::optional<std::string> maybe_pubkey_fname;
    std::optional<std::uint64_t> maybe_ntries;
};


using uncompressed_key_t = std::array<std::uint8_t, 65>;
using pubkey_i8_t = std::array<std::uint8_t, 64>;
using pubkey_i64_t = std::array<std::uint64_t, 8>;

typedef union
{
    pubkey_i8_t vi8;
    pubkey_i64_t vi64;
} pubkey_t;


typedef struct
{
    std::vector<std::string> repr;
    std::vector<pubkey_t> pubkeys;
} targets_soa_t;


pubkey_i8_t unhex(std::string const & s)
{
    auto it = s.size() == 65 * 2 ? s.cbegin() + 2 : s.cbegin();

    pubkey_i8_t rv;

    for (auto ix = 0u; ix < rv.size(); ++ix)
    {
        std::uint8_t byte = 0;

        byte += (*it <= '9' ? *it - '0' : (*it <= 'F' ? *it - 'A' : *it - 'a') + 10) & 0xF;

        ++it;
        byte <<= 4;

        byte += (*it <= '9' ? *it - '0' : (*it <= 'F' ? *it - 'A' : *it - 'a') + 10) & 0xF;

        ++it;

        rv[ix] = byte;
    }

    return rv;
}


static
void read_targets_from_file(std::string const & ifname, targets_soa_t & targets)
{
    std::ifstream fcsv(ifname);

    for (std::string line; std::getline(fcsv, line); /* nop */)
    {
        line.erase(
            std::remove_if(line.begin(), line.end(),
                [](unsigned char x){ return std::isspace(x); }),
            line.end());

        pubkey_t k = {.vi8 = unhex(line)};
        targets.repr.push_back(line);
        targets.pubkeys.push_back(k);
    }
    fcsv.close();
}


int parse_args(int argc, char* argv[], parsed_args & parsed)
{
    auto constexpr N_REQUIRED = 1u;
    bool show_help = false;
    int c = 0;

    while (--argc > 0 && (*++argv)[0] == '-')
    {
        while ((c = *++argv[0]))
        {
            switch (c)
            {
                case 'p':
                {
                    parsed.with_pubkey = true;

                    break;
                }
                case 'n':
                {
                    if (--argc > 0)
                    {
                        auto val = atoll(argv[1]);
                        if (val >= 1)
                        {
                            parsed.maybe_ntries = val;
                        }
                        else
                        {
                            fprintf(stderr, "Invalid number of tries passed: %s\n", argv[1]);
                            argc = 0;
                        }

                        argv++;
                        *argv+= strlen(*argv) - 1;
                    }
                    break;
                }
                case 'k':
                {
                    if (--argc > 0)
                    {
                        auto const sz = strlen(argv[1]);

                        if ((sz != 2 * 64) and (sz != 2 * 65))
                        {
                            fprintf(stderr, "Invalid pubkey passed: %s\nMust be 64- or 65-byte long.\n", argv[1]);
                            argc = 0;
                        }
                        else if ((sz == 2 * 65) and not ((argv[1][0] == '0') and (argv[1][1] == '4')))
                        {
                            fprintf(stderr, "Invalid pubkey passed: %s\nIt is 65-byte long but its first byte is not 04.\n", argv[1]);
                            argc = 0;
                        }
                        else if (not std::all_of(argv[1], argv[1] + sz, [](int c){ return std::isxdigit(c); }))
                        {
                            fprintf(stderr, "Invalid pubkey passed: %s\nNon-hex characters.\n", argv[1]);
                            argc = 0;
                        }
                        else
                        {
                            parsed.maybe_pubkey = (sz == 2 * 65) ? (argv[1] + 2) : argv[1];
                        }

                        argv++;
                        *argv+= strlen(*argv) - 1;
                    }
                    break;
                }
                case 'i':
                {
                    if (--argc > 0)
                    {
                        parsed.maybe_pubkey_fname = argv[1];

                        argv++;
                        *argv+= strlen(*argv) - 1;
                    }
                    break;
                }
                case 'h':
                    show_help = true;
                    parsed.help = show_help;
                    break;

                default:
                {
                    fprintf(stderr, "Illegal option [%c]\n", (char)c);
                    argc = 0;
                    break;
                }
            }
        }
    }

    if (argc == N_REQUIRED)
    {
        unsigned int val = atoi(argv[0]);

        if (val < 1)
        {
            fprintf(stderr, "Invalid 'Number of bits to match' passed: %s. Must be an integer greater than zero.\n", argv[0]);
            argc = 0;
        }
    }

    if (show_help or (argc != N_REQUIRED) or (not parsed.maybe_pubkey and not parsed.maybe_pubkey_fname))
    {
        if (argc != N_REQUIRED)
        {
            fprintf(stderr, "Missing required arguments.\n");
        }
        if (not parsed.maybe_pubkey and not parsed.maybe_pubkey_fname)
        {
            fprintf(stderr, "Either or both -k and -i option must be specified.\n");
        }

        fprintf(stderr,
            "\n"
            "Usage: aladdin [options] <Number of bits to match:UINT>\n\n"
            "Options:\n"
            "         -n UINT64 number of tries, >= 1\n"
            "         -k STR    single input pubkey, with or without preceding header byte\n"
            "         -i STR    file name with input pubkey(s), one per line\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.min_match_nbits = atoi(argv[0]);
    }

    return EXIT_SUCCESS;
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

    targets_soa_t targets;
    if (args.maybe_pubkey)
    {
        pubkey_t k = {.vi8 = unhex(*args.maybe_pubkey)};

        targets.repr.push_back(*args.maybe_pubkey);
        targets.pubkeys.push_back(k);
    }
    if (args.maybe_pubkey_fname)
    {
        read_targets_from_file(*args.maybe_pubkey_fname, targets);
    }

    EC_KEY *key_p = EC_KEY_new_by_curve_name(NID_secp256k1);
    uncompressed_key_t uncompressed;

    bool const infinite_loop = not args.maybe_ntries.has_value();
    auto const ntries = args.maybe_ntries.has_value() ? *args.maybe_ntries : 0;

    auto const NTARGETS = targets.pubkeys.size();

    for (std::uint64_t it = 0; infinite_loop or (it < ntries); ++it)
    {
        EC_KEY_generate_key(key_p);

        auto uncompressed_p = uncompressed.data();
        i2o_ECPublicKey(key_p, &uncompressed_p);

        pubkey_t pubkey;
        std::copy(uncompressed.cbegin() + 1, uncompressed.cend(), pubkey.vi8.begin());

        for (auto tix = 0u; tix < NTARGETS; ++tix)
        {
            // count mismatched bits
            auto const & target = targets.pubkeys[tix];

            unsigned int mismatched = 0;
            for (auto ix = 0u; ix < pubkey.vi64.size(); ++ix)
            {
                mismatched += __builtin_popcountl(pubkey.vi64[ix] ^ target.vi64[ix]);
            }

            auto const matched = 64 * 8 - mismatched;
            if (UNLIKELY(matched >= args.min_match_nbits))
            {
                auto * priv_as_bn_p = EC_KEY_get0_private_key(key_p);
                auto * hex_p = BN_bn2hex(priv_as_bn_p);
                if (args.with_pubkey)
                {
                    std::array<char, 2 * 64 + 1> pub_str;

                    for (auto ix = 0u; ix < pubkey.vi8.size(); ++ix)
                    {
                        {
                            auto const nibble = pubkey.vi8[ix] >> 4;

                            pub_str[2 * ix + 0] = nibble >= 10 ? nibble + 'A' - 10 : nibble + '0';
                        }
                        {
                            auto const nibble = pubkey.vi8[ix] & 0xF;

                            pub_str[2 * ix + 1] = nibble >= 10 ? nibble + 'A' - 10 : nibble + '0';
                        }
                    }
                    pub_str.back() = 0;

                    printf("%s\t%03u\t%s\t%s\n", targets.repr[tix].c_str(), matched, hex_p, pub_str.data());
                }
                else
                {
                    printf("%s\t%03u\t%s\n", targets.repr[tix].c_str(), matched, hex_p);
                }
                fflush(stdout);
                OPENSSL_free(hex_p);
            }
        }
    }

    return EXIT_SUCCESS;
}
