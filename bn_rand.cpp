#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <vector>
#include <cstdint>

#include <openssl/bn.h>
#include <openssl/crypto.h>


struct parsed_args
{
    bool help = false;
    std::uint64_t ngen;
    unsigned int nbytes;
};


int parse_args(int argc, char* argv[], parsed_args & parsed)
{
    auto constexpr N_REQUIRED = 2u;
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
        int nbytes = atoi(argv[0]);

        if (nbytes < 1)
        {
            fprintf(stderr, "Invalid number of bytes passed: %s. Must be an integer greater than 0.\n", argv[0]);
            argc = 0;
        }

        int ngen = atoll(argv[1]);

        if (ngen < 1)
        {
            fprintf(stderr, "Invalid number of numbers to generate: %s. Must be an integer greater than 0.\n", argv[1]);
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
            "Usage: distanal <number of bytes:UINT> <generate N numbers:UINT64>\n\n"
            "Options:\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.nbytes = atoi(argv[0]);
        parsed.ngen = atoll(argv[1]);
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

    auto * bn_p = BN_new();
    int ok = 0;

    for (auto it = 0u; it < args.ngen; it += ok)
    {
        ok = BN_rand(bn_p, args.nbytes * 8, -1, 0);
        if (ok == 1)
        {
            auto hex_p = BN_bn2hex(bn_p);
            printf("%s\n", hex_p);
            OPENSSL_free(hex_p);
        }
    }

    BN_free(bn_p);

    return EXIT_SUCCESS;
}
