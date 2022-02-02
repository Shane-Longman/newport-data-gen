#include "parse_args.hpp"

#include <cstdlib>
#include <cstdio>
#include <cstring>


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
        unsigned int val = atoi(argv[0]);

        if (val < 1)
        {
            fprintf(stderr, "Invalid 'Number of bits to match' passed: %s. Must be an integer greater than zero.\n", argv[0]);
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
            "Usage: main [options] <Number of bits to match:UINT> <Public key:STRING>\n\n"
            "Options:\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.min_match_nbits = atoi(argv[0]);
        parsed.pubkey = argv[1];
    }

    return EXIT_SUCCESS;
}