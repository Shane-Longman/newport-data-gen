#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <vector>
#include <cstdint>


struct parsed_args
{
    bool help = false;
    unsigned int nbytes;
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

        if (val < 1)
        {
            fprintf(stderr, "Invalid number of bytes passed: %s. Must be an integer greater than 0.\n", argv[0]);
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
            "Usage: distanal <number of bytes:UINT>\n\n"
            "Options:\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.nbytes = atoi(argv[0]);
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

    std::vector<std::uint64_t> bitcounts(args.nbytes * 8, 0);
    std::uint64_t total = 0;

    // read from stdint
    for (std::string line; std::getline(std::cin, line); ++total)
    {
        line.erase(
            std::remove_if(line.begin(), line.end(),
                [](unsigned char x){ return std::isspace(x); }),
            line.end());

        if ((line.size() % 2) or
            (line.size() > (2 * args.nbytes)) or
            (line.find_first_not_of("0123456789ABCDEFabcdef") != line.npos))
        {
            fprintf(stderr, "[w] invalid hex input: %s\n", line.c_str());
            continue;
        }

        auto const read_bytes = line.size() / 2;
        auto const bit_pad_offset = (args.nbytes - read_bytes) * 8;

        for (auto ix = 0u; ix < line.size(); ++ix)
        {
            unsigned int nibble = line[ix];

            if (nibble >= 'a')
            {
                nibble = nibble - 'a' + 10;
            }
            else if (nibble >= 'A')
            {
                nibble = nibble - 'A' + 10;
            }
            else
            {
                nibble = nibble - '0';
            }

            bitcounts[ix * 4 + 0 + bit_pad_offset] += (0b1111'1111'0000'0000ULL >> nibble) & 1;
            bitcounts[ix * 4 + 1 + bit_pad_offset] += (0b1111'0000'1111'0000ULL >> nibble) & 1;
            bitcounts[ix * 4 + 2 + bit_pad_offset] += (0b1100'1100'1100'1100ULL >> nibble) & 1;
            bitcounts[ix * 4 + 3 + bit_pad_offset] += (0b1010'1010'1010'1010ULL >> nibble) & 1;
        }
    }

    // print the stats
    for (auto ix = 0u; ix < bitcounts.size(); ++ix)
    {
        printf("%4u: %16lu (%9.5lf %%)\n", ix, bitcounts[ix], ((double)bitcounts[ix] / total) * 100.);
    }

    return EXIT_SUCCESS;
}
