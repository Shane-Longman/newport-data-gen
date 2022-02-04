#pragma once

#ifndef PARSE_ARGS_HPP
#define PARSE_ARGS_HPP

#include <string>
#include <optional>
#include <cstdint>


struct parsed_args
{
    bool help = false;
    unsigned int min_match_nbits;
    std::optional<std::string> maybe_address;
    std::optional<std::string> maybe_address_fname;
    std::optional<std::uint64_t> maybe_ntries;
};

int parse_args(int argc, char* argv[], parsed_args & parsed);


#endif /* PARSE_ARGS_HPP */
