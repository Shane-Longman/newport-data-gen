#pragma once

#ifndef NTOHL_H
#define NTOHL_H


#ifndef __BYTE_ORDER__
#error __BYTE_ORDER__ is not defined
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohl(val) (\
   (((uint32_t)(val) & 0x000000FFUL) << 24)\
 | (((uint32_t)(val) & 0x0000FF00UL) << 8)\
 | (((uint32_t)(val) & 0x00FF0000UL) >> 8)\
 | (((uint32_t)(val) & 0xFF000000UL) >> 24)\
 )
#define ntohll(val) (\
   (((uint64_t)(val) & 0x00000000000000FFULL) << 56)\
 | (((uint64_t)(val) & 0x000000000000FF00ULL) << 40)\
 | (((uint64_t)(val) & 0x0000000000FF0000ULL) << 24)\
 | (((uint64_t)(val) & 0x00000000FF000000ULL) << 8)\
 | (((uint64_t)(val) & 0x000000FF00000000ULL) >> 8)\
 | (((uint64_t)(val) & 0x0000FF0000000000ULL) >> 24)\
 | (((uint64_t)(val) & 0x00FF000000000000ULL) >> 40)\
 | (((uint64_t)(val) & 0xFF00000000000000ULL) >> 56)\
 )
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ntohl(val) (val)
#define ntohll(val) (val)
#else
#error ntohl: Unknown platform
#endif

#define htonl(x) ntohl(x)
#define htonll(x) ntohll(x)


#endif /* NTOHL_H */
