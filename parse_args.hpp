#pragma once

#ifndef PARSE_ARGS_HPP
#define PARSE_ARGS_HPP

#include <string>


struct parsed_args
{
    bool help = false;
    unsigned int min_match_nbits;
    std::string pubkey;
};

int parse_args(int argc, char* argv[], parsed_args & parsed);


#endif /* PARSE_ARGS_HPP */
