#pragma once
#include <cstddef>
#include <array>
#include <cstdint>
#include <string>

namespace libff_backend {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;


template < size_t N >
std::array< uint8_t, N > hexCStringToBytesArray( const char* hexStr );


template < class T >
std::string fieldElementToString( const T& field_elem, int base );


}