#include "parse_args.hpp"

#include <cstdlib>
#include <cstdio>
#include <cstring>


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
                case 'a':
                {
                    if (--argc > 0)
                    {
                        parsed.maybe_address = argv[1];

                        argv++;
                        *argv+= strlen(*argv) - 1;
                    }
                    break;
                }
                case 'i':
                {
                    if (--argc > 0)
                    {
                        parsed.maybe_address_fname = argv[1];

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

    if (show_help or (argc != N_REQUIRED) or (not parsed.maybe_address and not parsed.maybe_address_fname))
    {
        if (argc != N_REQUIRED)
        {
            fprintf(stderr, "Missing required arguments.\n");
        }
        if (not parsed.maybe_address and not parsed.maybe_address_fname)
        {
            fprintf(stderr, "Either or both -a and -i option must be specified.\n");
        }

        fprintf(stderr,
            "\n"
            "Usage: main [options] <Number of bits to match:UINT>\n\n"
            "Options:\n"
            "         -n UINT64 number of tries, >= 1\n"
            "         -a STR    single input address\n"
            "         -i STR    file name with input address(es), one per line\n"
            "         -h        show help\n");

        return show_help ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else
    {
        parsed.min_match_nbits = atoi(argv[0]);
    }

    return EXIT_SUCCESS;
}
