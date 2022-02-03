#pragma once

#ifndef UNADDR_HPP
#define UNADDR_HPP

#include <array>
#include <cstdint>
#include <string>


using hash160_t = std::array<std::uint8_t, 20>;


hash160_t unaddr(std::string const &addr);


#endif /* UNADDR_HPP */
