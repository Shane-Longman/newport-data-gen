#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <array>

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>

struct parsed_args
{
    bool help = false;
    unsigned int bitsel;
};


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
        int val = atoi(argv[0]);

        if (val < 0)
        {
            fprintf(stderr, "Invalid index of selected bit passed: %s. Must be an integer greater than or equal 0.\n", argv[0]);
            argc = 0;
        }
    }

    if (show_help or (argc != N_REQUIRED))
    {
        if (argc != N_REQUIRED)
        {
            fprintf(stderr, "Missing required arguments.\n");
        }

        fprintf(stderr,
            "\n"
            "Usage: tgen <bit selector:UINT>\n\n"
            "bit selector:\tselect nth bit of input private key as target label\n\n"
            "Options:\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.bitsel = atoi(argv[0]);
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

    EC_KEY *key_p = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (key_p == nullptr)
    {
        fprintf(stderr, "[!] Failed to allocate new EC key\n");
        return EXIT_FAILURE;
    }

    BIGNUM *priv_p = BN_new();

    if (priv_p == nullptr)
    {
        fprintf(stderr, "[!] Failed to allocate new BIGNUM private key\n");
        return EXIT_FAILURE;
    }

    BN_CTX *ctx_p = BN_CTX_new();

    if (ctx_p == nullptr)
    {
        fprintf(stderr, "[!] Failed to allocate new BIGNUM context\n");
        return EXIT_FAILURE;
    }

    // generate dummy key (lazy way to create EC key's group)
    EC_KEY_generate_key(key_p);
    EC_GROUP const *group_p = EC_KEY_get0_group(key_p);
    EC_POINT *pub_p = EC_POINT_new(group_p);
    point_conversion_form_t const form = EC_GROUP_get_point_conversion_form(group_p);

    // read from stdin
    for (std::string line; std::getline(std::cin, line);)
    {
        line.erase(
            std::remove_if(line.begin(), line.end(),
                [](unsigned char x){ return std::isspace(x); }),
            line.end());

        if ((line.size() % 2) or
            (line.find_first_not_of("0123456789ABCDEFabcdef") != line.npos))
        {
            fprintf(stderr, "[w] invalid hex input: %s\n", line.c_str());
            continue;
        }

        auto const bytes_read = BN_hex2bn(&priv_p, line.c_str());
        if (bytes_read != line.size())
        {
            fprintf(stderr, "[w] parsing of hex private key input failed: %s\n", line.c_str());
            continue;
        }

        // derive pub key from priv key
        EC_POINT_mul(group_p, pub_p, priv_p, NULL, NULL, ctx_p);

        char *pub_hex_p = EC_POINT_point2hex(group_p, pub_p, form, ctx_p);

        printf("%d\t%s\n", BN_is_bit_set(priv_p, args.bitsel), pub_hex_p + 2 /* skip '04' header */);

        OPENSSL_free(pub_hex_p);
    }

    BN_free(priv_p);
    EC_KEY_free(key_p);
    BN_CTX_free(ctx_p);
    EC_POINT_free(pub_p);

    return EXIT_SUCCESS;
}
