#include "parse_args.hpp"

#include <cstdlib>
#include <vector>
#include <cstdint>
#include <string>

#include <openssl/ec.h>
#include <openssl/objects.h>

#include <unistd.h>


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

    pid_t const pid = getpid();


    while (true)
    {
    }


    return EXIT_SUCCESS;
}
